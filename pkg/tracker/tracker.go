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
	"fmt"
	"sync"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/imds-tracker/ebpf/assets"
	"github.com/Gui774ume/imds-tracker/pkg/log"
	"github.com/Gui774ume/imds-tracker/pkg/model"
	"github.com/Gui774ume/imds-tracker/pkg/resolver"
)

// Tracker is the main structure used to instantiate an eBPF IMDS tracker
type Tracker struct {
	options        *model.IMDSTrackerOptions
	manager        *manager.Manager
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
		options: options,
		wg:      &sync.WaitGroup{},
		evt:     &model.Event{},
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

func (t *Tracker) handleEvent(data []byte) {
	evt := t.resetEvent()
	_, err := evt.UnmarshalBinary(data, t.timeResolver, t.options.Unsafe)
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}

	logrus.Debugf("Captured 1 [IMDS%s] %s on %s from %s(%d)", evt.Packet.IMDSVersion(), evt.Packet.PacketType, evt.NetworkDirection, evt.Process.Comm, evt.Process.Pid)

	if t.sender != nil {
		if err = t.sender.Send(evt); err != nil {
			logrus.Errorf("couldn't send event to Datadog: %v", err)
		}
	}
}
