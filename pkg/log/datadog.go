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

package log

import (
	"context"
	"fmt"
	"os"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"

	"github.com/Gui774ume/imds-tracker/pkg/model"
)

// Datadog is used to forward logs to Datadog
type Datadog struct {
	hostname      string
	scrubbed      bool
	context       context.Context
	configuration *datadog.Configuration
	apiClient     *datadog.APIClient
	api           *datadogV2.LogsApi
}

// NewDatadog returns a new instance of Datadog
func NewDatadog(ctx context.Context, unsafe bool) *Datadog {
	hostname, _ := os.Hostname()
	dd := &Datadog{
		hostname:      hostname,
		context:       datadog.NewDefaultContext(ctx),
		configuration: datadog.NewConfiguration(),
		scrubbed:      !unsafe,
	}
	dd.apiClient = datadog.NewAPIClient(dd.configuration)
	dd.api = datadogV2.NewLogsApi(dd.apiClient)
	return dd
}

func (d *Datadog) Send(evt *model.Event) error {
	raw, err := evt.MarshalJSON()
	if err != nil {
		return err
	}
	body := []datadogV2.HTTPLogItem{
		{
			Ddsource: datadog.PtrString("imds-tracker"),
			Ddtags:   datadog.PtrString(fmt.Sprintf("scrubbed:%v,imds:%s", d.scrubbed, evt.Packet.IMDSVersion())),
			Hostname: datadog.PtrString(d.hostname),
			Message:  string(raw),
			Service:  datadog.PtrString("imds-tracker"),
		},
	}
	_, _, err = d.api.SubmitLog(d.context, body, *datadogV2.NewSubmitLogOptionalParameters().WithContentEncoding(datadogV2.CONTENTENCODING_GZIP))
	return err
}
