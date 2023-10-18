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
	"os"

	"github.com/spf13/cobra"

	"github.com/Gui774ume/imds-tracker/pkg/model"
)

// IMDSTracker represents the base command of the IMDS tracker
var IMDSTracker = &cobra.Command{
	Use:  "imds-tracker",
	RunE: imdsTrackerCMD,
}

var options = model.IMDSTrackerOptions{}

func init() {
	IMDSTracker.Flags().Var(
		NewIMDSTrackerOptionsSanitizer(&options, "log-level"),
		"log-level",
		"log level of the IMDS tracker. Options are: panic, fatal, error, warn, info, debug and trace")
	IMDSTracker.Flags().Var(
		NewIMDSTrackerOptionsSanitizer(&options, "vmlinux"),
		"vmlinux",
		"path to a \"vmlinux\" file on the system (this path should be provided only if imds-tracker can't find it by itself)")
	IMDSTracker.Flags().BoolVar(
		&options.Unsafe,
		"unsafe",
		false,
		"when set, the tracker will send the entire response body of all IMDS requests instead of simply the fields known to be free of secrets or credentials.")
	IMDSTracker.Flags().BoolVar(
		&options.SendToDatadog,
		"datadog",
		len(os.Getenv("DD_API_KEY")) > 0,
		"when set, the tracker will send the captured events to Datadog. You can configure the log sender using environment variable (see https://docs.datadoghq.com/api/latest/logs).")
}
