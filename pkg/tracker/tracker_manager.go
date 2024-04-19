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
	"fmt"
	"io"
	"math"
	"net/http"
	"os"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/imds-tracker/pkg/kernel"
)

func (t *Tracker) prepareManager() {
	t.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},

		ActivatedProbes: []manager.ProbesSelector{
			&manager.AllOf{
				Selectors: []manager.ProbesSelector{
					&manager.ProbeSelector{
						ProbeIdentificationPair: manager.ProbeIdentificationPair{
							EBPFFuncName: "kprobe___sock_sendmsg",
						},
					},
					&manager.ProbeSelector{
						ProbeIdentificationPair: manager.ProbeIdentificationPair{
							EBPFFuncName: "kprobe_sock_recvmsg",
						},
					},
					&manager.ProbeSelector{
						ProbeIdentificationPair: manager.ProbeIdentificationPair{
							EBPFFuncName: "kretprobe_sock_recvmsg",
						},
					},
				},
			},
		},
	}

	t.manager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe___sock_sendmsg",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_sock_recvmsg",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kretprobe_sock_recvmsg",
				},
			},
		},
	}
}

func (t *Tracker) selectMaps() error {
	var err error
	ring, _, err := t.manager.GetMap("events")
	if err != nil || ring == nil {
		return fmt.Errorf("couldn't find \"events\" map")
	}
	t.reader, err = ringbuf.NewReader(ring)
	if err != nil {
		return fmt.Errorf("couldn't instantiate a new ring buffer reader: %w", err)
	}

	t.stackTraceMap, _, err = t.manager.GetMap("stack_traces")
	if err != nil || t.stackTraceMap == nil {
		return fmt.Errorf("couldn't find \"stack_trace\" map")
	}
	return nil
}

func (t *Tracker) loadFilters() error {
	return nil
}

func (t *Tracker) loadVMLinux() error {
	var btfSpec *btf.Spec
	var err error

	if len(t.options.VMLinux) > 0 {
		f, err := createBTFReaderFromTarball(t.options.VMLinux)
		if err != nil {
			return err
		}

		// if a vmlinux file was provided, open it now
		btfSpec, err = btf.LoadSpecFromReader(f)
		if err != nil {
			return fmt.Errorf("couldn't load %s: %w", t.options.VMLinux, err)
		}
	} else {
		// try to open vmlinux from the default locations
		btfSpec, err = btf.LoadKernelSpec()
		if err != nil {
			// fetch the BTF spec from btfhub
			btfSpec, err = t.loadSpecFromBTFHub()
			if err != nil {
				return fmt.Errorf("couldn't load kernel BTF specs from BTFHub: %w", err)
			}
		}
	}
	t.managerOptions.VerifierOptions.Programs.KernelTypes = btfSpec
	return nil
}

const (
	// BTFHubURL is the URL to BTFHub github repository
	BTFHubURL = "https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/x86_64/%s.btf.tar.xz"
)

func (t *Tracker) loadSpecFromBTFHub() (*btf.Spec, error) {
	h, err := kernel.NewHost()
	if err != nil {
		return nil, err
	}

	// check the local KRIE cache first
	file := fmt.Sprintf("/tmp/%s.tar.xz", h.UnameRelease)
	if _, err = os.Stat(file); err != nil {
		// download the file now
		url := fmt.Sprintf(BTFHubURL, h.OsRelease["ID"], h.OsRelease["VERSION_ID"], h.UnameRelease)
		logrus.Infof("Downloading BTF specs from %s ...", url)

		// Get the data
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("couldn't download BTF specs from BTFHub: %w", err)
		}
		defer resp.Body.Close()

		// Create the file
		out, err := os.Create(file)
		if err != nil {
			return nil, fmt.Errorf("couldn't create local BTFHub cache at %s: %w", file, err)
		}
		defer out.Close()

		// Write the body to file
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return nil, fmt.Errorf("couldn't create local BTFHub cache at %s: %w", file, err)
		}
	}

	f, err := createBTFReaderFromTarball(file)
	if err != nil {
		return nil, err
	}

	// if a vmlinux file was provided, open it now
	btfSpec, err := btf.LoadSpecFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("couldn't load %s: %w", t.options.VMLinux, err)
	}

	return btfSpec, nil
}
