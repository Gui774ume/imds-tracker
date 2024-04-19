/*
Copyright © 2022 GUILLAUME FOURNIER and JULES DENARDOU

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

package run

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/imds-tracker/pkg/model"
)

// IMDSTrackerOptionsSanitizer is a generic options sanitizer for KRIE
type IMDSTrackerOptionsSanitizer struct {
	field   string
	options *model.IMDSTrackerOptions
}

// NewIMDSTrackerOptionsSanitizer creates a new instance of KRIEOptionsSanitizer
func NewIMDSTrackerOptionsSanitizer(options *model.IMDSTrackerOptions, field string) *IMDSTrackerOptionsSanitizer {
	options.LogLevel = logrus.InfoLevel
	options.HostProcPath = "/proc"
	return &IMDSTrackerOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (itos *IMDSTrackerOptionsSanitizer) String() string {
	switch itos.field {
	case "log-level":
		return itos.options.LogLevel.String()
	case "vmlinux":
		return itos.options.VMLinux
	case "proc":
		return itos.options.HostProcPath
	default:
		return ""
	}
}

func (itos *IMDSTrackerOptionsSanitizer) Set(val string) error {
	var err error
	switch itos.field {
	case "log-level":
		var sanitized logrus.Level
		if len(val) > 0 {
			sanitized, err = logrus.ParseLevel(val)
			if err != nil {
				return err
			}
		} else {
			sanitized = logrus.DebugLevel
		}
		itos.options.LogLevel = sanitized
	case "vmlinux":
		if len(val) == 0 {
			return fmt.Errorf("empty path to \"vmlinux\"")
		}
		itos.options.VMLinux = val
	case "proc":
		if len(val) == 0 {
			return fmt.Errorf("empty path to \"proc\"")
		}
		itos.options.HostProcPath = val
	default:
		return nil
	}
	return nil
}

func (itos *IMDSTrackerOptionsSanitizer) Type() string {
	switch itos.field {
	case "log-level":
		return "string"
	case "vmlinux":
		return "string"
	case "proc":
		return "string"
	default:
		return ""
	}
}
