/*
Copyright © 2023 GUILLAUME FOURNIER and JULES DENARDOU

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tracker

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
	"math/rand"
	"os"
	"path"
	"sync"
	"syscall"

	"github.com/Gui774ume/imds-tracker/ebpf/assets"
	"github.com/Gui774ume/imds-tracker/pkg/log"
	"github.com/Gui774ume/imds-tracker/pkg/model"
	"github.com/Gui774ume/imds-tracker/pkg/resolver"
)

// Tracker is the main structure used to instantiate an eBPF IMDS tracker
type Tracker struct {
	options       *model.IMDSTrackerOptions
	manager       *manager.Manager
	stackTraceMap *ebpf.Map

	// TracedBinaries is the list of userspace binaries for which we are collecting stack traces
	PidsToCookie   map[int]model.BinaryCookie
	TracedBinaries map[model.BinaryCookie]*model.TracedBinary

	managerOptions manager.Options
	wg             *sync.WaitGroup
	ctx            context.Context
	cancelFunc     context.CancelFunc

	reader       *ringbuf.Reader
	timeResolver *resolver.TimeResolver
	sender       *log.Datadog
	evt          *model.Event
}

// NewTracker instantiates a new tracker
func NewTracker(options *model.IMDSTrackerOptions) (*Tracker, error) {
	var err error
	t := &Tracker{
		options:        options,
		wg:             &sync.WaitGroup{},
		evt:            &model.Event{},
		PidsToCookie:   make(map[int]model.BinaryCookie),
		TracedBinaries: make(map[model.BinaryCookie]*model.TracedBinary),
	}

	t.timeResolver, err = resolver.NewTimeResolver()
	if err != nil {
		return nil, err
	}
	t.ctx, t.cancelFunc = context.WithCancel(context.Background())

	if t.options.SendToDatadog {
		t.sender = log.NewDatadog(t.ctx, t.options.Unsafe)
	}

	return t, nil
}

// Start starts the IMDS tracker
func (t *Tracker) Start() error {
	// setup a default manager
	t.prepareManager()

	// initialize the manager
	if err := t.manager.InitWithOptions(bytes.NewReader(assets.Probes), t.managerOptions); err != nil {
		return fmt.Errorf("couldn't init manager: %w", err)
	}

	// select kernel space maps
	if err := t.selectMaps(); err != nil {
		return err
	}

	// start the manager
	if err := t.manager.Start(); err != nil {
		return fmt.Errorf("couldn't start manager: %w", err)
	}

	go func(t *Tracker) {
		if t == nil {
			return
		}
		t.wg.Add(1)
		defer func() {
			t.wg.Done()
		}()

		var sample ringbuf.Record
		var err error

		for {
			sample, err = t.reader.Read()
			if err != nil {
				select {
				case <-t.ctx.Done():
					return
				default:
				}
				continue
			}
			t.handleEvent(sample.RawSample)
		}
	}(t)

	logrus.Infof("Tracing started ...")
	return nil
}

// Stop stops the IMDS tracker
func (t *Tracker) Stop() error {
	t.cancelFunc()
	_ = t.reader.Close()
	t.wg.Wait()
	logrus.Infof("Goodbye !")
	return nil
}

// eventZero is used to reset
var eventZero model.Event

func (t *Tracker) resetEvent() *model.Event {
	*t.evt = eventZero
	return t.evt
}

func (t *Tracker) fetchOrInsertTracedBinary(path string, pid int) (*model.TracedBinary, error) {
	// check if this pid has been seen before
	if cookie, ok := t.PidsToCookie[pid]; ok {
		if entry, ok := t.TracedBinaries[cookie]; ok {
			return entry, nil
		}
	}

	// fetch the binary file inode
	fileinfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't load %s: %v", path, err)
	}

	resolvedPath, err := os.Readlink(path)
	if err != nil {
		resolvedPath = ""
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("couldn't load %s: %v", path, err)
	}

	// check if the file has been seen before
	for _, tracedBinary := range t.TracedBinaries {
		// an inode conflict is technically possible between multiple mount points, but checking the binary size and
		// the inode makes it relatively unlikely, and is less overkill than hashing the file. (we don't want to check
		// the path, or even the resolved paths because of hard link collisions)
		if stat.Ino == tracedBinary.Inode && stat.Size == tracedBinary.Size {
			// if a pid is provided, this means that we filter the events from this binary by pid, add it to the list
			if pid != 0 {
				tracedBinary.Pids = append(tracedBinary.Pids, pid)
			}
			t.PidsToCookie[pid] = tracedBinary.Cookie
			return tracedBinary, nil
		}
	}

	// if we reach this point, this is a new entry, add it to the list and generate a cookie
	cookie := rand.Uint32()
	for _, ok = t.TracedBinaries[model.BinaryCookie(cookie)]; ok; {
		cookie = rand.Uint32()
	}
	entry := model.TracedBinary{
		Path:         path,
		ResolvedPath: resolvedPath,
		Inode:        stat.Ino,
		Size:         stat.Size,
		Cookie:       model.BinaryCookie(cookie),
		SymbolsCache: make(map[model.SymbolAddr]elf.Symbol),
	}
	if pid > 0 {
		entry.Pids = []int{pid}
	}

	// fetch the list of symbols of the binary
	f, syms, err := manager.OpenAndListSymbols(entry.Path)
	if err != nil {
		return nil, err
	}

	entry.File = f
	for _, sym := range syms {
		entry.SymbolsCache[model.SymbolAddr(sym.Value)] = sym
	}

	t.TracedBinaries[entry.Cookie] = &entry
	t.PidsToCookie[pid] = entry.Cookie
	return &entry, nil
}

var (
	// SymbolNotFound is used to notify that a symbol could not be resolved
	SymbolNotFound = elf.Symbol{Name: "[symbol_not_found]"}
)

// ResolveUserSymbolAndOffset returns the symbol of the function in which a given address lives, as well as the offset
// inside that function
func (t *Tracker) ResolveUserSymbolAndOffset(address model.SymbolAddr, binary *model.TracedBinary) model.StackTraceNode {
	if binary != nil {
		for symbolAddr, symbol := range binary.SymbolsCache {
			if address >= symbolAddr && address < symbolAddr+model.SymbolAddr(symbol.Size) {
				return model.StackTraceNode{
					Symbol: symbol,
					Offset: address - symbolAddr,
				}
			}
		}
	}

	return model.StackTraceNode{
		Symbol: SymbolNotFound,
		Offset: address,
	}
}

func (t *Tracker) resolveStackTrace(evt *model.Event) error {
	var binary *model.TracedBinary
	cookie, ok := t.PidsToCookie[evt.Process.Pid]
	if ok {
		binary = t.TracedBinaries[cookie]
	}
	if binary == nil {
		var err error
		binary, err = t.fetchOrInsertTracedBinary(path.Join(t.options.HostProcPath, fmt.Sprintf("%d/exe", evt.Process.Pid)), evt.Process.Pid)
		if err != nil || binary == nil {
			logrus.Errorf("couldnt' generate TracedBinary for pid %v: %v", evt.Process.Pid, err)
		}
	}

	// resolve user stack trace
	for _, addr := range evt.UserStackTraceRaw {
		if addr == 0 {
			break
		}
		evt.UserStackTrace = append(evt.UserStackTrace, t.ResolveUserSymbolAndOffset(addr, binary).String())
	}

	return nil
}

func (t *Tracker) handleEvent(data []byte) {
	evt := t.resetEvent()
	_, err := evt.UnmarshalBinary(data, t.timeResolver, t.options.Unsafe)
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}

	// resolve stack trace
	if t.options.UserStackTrace {
		evt.UserStackTraceRaw = make([]model.SymbolAddr, 127)
		if evt.UserStackID > 0 {
			if err = t.stackTraceMap.Lookup(evt.UserStackID, evt.UserStackTraceRaw); err != nil {
				logrus.Errorf("couldn't look up stack trace %v: %v", evt.UserStackID, err)
			} else {
				// resolve binary
				if err = t.resolveStackTrace(evt); err != nil {
					logrus.Errorf("couldn't resolve stack trace for pid %d comm %s: %v", evt.Process.Pid, evt.Process.Comm, err)
				}
			}
		}
	}

	logrus.Debugf("Captured 1 [IMDS%s] %s on %s from %s(%d) - stack trace:\n%v", evt.Packet.IMDSVersion(), evt.Packet.PacketType, evt.NetworkDirection, evt.Process.Comm, evt.Process.Pid, evt.UserStackTrace)

	if t.sender != nil {
		if err = t.sender.Send(evt); err != nil {
			logrus.Errorf("couldn't send event to Datadog: %v", err)
		}
	}
}
