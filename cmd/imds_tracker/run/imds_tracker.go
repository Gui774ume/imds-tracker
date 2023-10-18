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
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/imds-tracker/pkg/tracker"
)

func imdsTrackerCMD(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	// create a new tracker instance
	tracker, err := tracker.NewTracker(&options)
	if err != nil {
		return fmt.Errorf("couldn't create a new instance of the IMDS tracker: %w", err)
	}

	if err := tracker.Start(); err != nil {
		return fmt.Errorf("couldn't start: %w", err)
	}

	wait()

	_ = tracker.Stop()
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
