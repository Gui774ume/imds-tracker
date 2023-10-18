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

//go:generate go run github.com/mailru/easyjson/easyjson $GOFILE

package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/exp/slices"
)

// IMDSPacket is used to parse an IMDS packet
// easyjson:json
type IMDSPacket struct {
	Size int    `json:"size"`
	Data []byte `json:"-"`

	PacketType string           `json:"packet_type"`
	IsIMDSV2   bool             `json:"is_imds_v2"`
	URL        string           `json:"url,omitempty"`
	Host       string           `json:"host,omitempty"`
	UserAgent  string           `json:"user_agent,omitempty"`
	Server     string           `json:"server,omitempty"`
	Body       IMDSResponseBody `json:"body,omitempty"`
}

// IMDSVersion returns the IMDS version of the
func (p *IMDSPacket) IMDSVersion() string {
	if p.IsIMDSV2 {
		return "v2"
	}
	return "v1"
}

func (p *IMDSPacket) UnmarshalBinary(data []byte, unsafe bool) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("parsing Packet.Size: got len %d, needed %d: %w", len(data), 4, ErrNotEnoughData)
	}
	p.Size = int(ByteOrder.Uint32(data[0:4]))
	p.Data = data[4:]

	if len(data[4:]) < 10 {
		// ignore, this is not an IMDS request
		p.PacketType = "unknown"
		p.Body = NewIMDSResponseBody("unsupported IMDS request", unsafe)
		return 4, nil
	}

	firstWord := strings.SplitN(string(p.Data[0:10]), " ", 2)
	switch {
	case slices.Contains([]string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	}, firstWord[0]):
		// parse HTTP request
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p.Data)))
		if err != nil {
			goto unsupportedRequest
		}
		p.PacketType = "request"

		if req.Header != nil {
			// check if this is an IMDS V2 request
			p.IsIMDSV2 = len(req.Header.Get("x-aws-ec2-metadata-token-ttl-seconds")) > 0 ||
				len(req.Header.Get("x-aws-ec2-metadata-token")) > 0
		}

		// extract other interesting fields
		p.URL = req.URL.String()
		p.Host = req.Host
		p.UserAgent = req.UserAgent()
		break
	case strings.Contains(firstWord[0], "HTTP"):
		// parse HTTP response
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(p.Data)), nil)
		if err != nil {
			goto unsupportedRequest
		}
		p.PacketType = "answer"

		if resp.Header != nil {
			// check if this is an IMDS V2 request
			p.IsIMDSV2 = len(resp.Header.Get("x-aws-ec2-metadata-token-ttl-seconds")) > 0 ||
				len(resp.Header.Get("x-aws-ec2-metadata-token")) > 0

			// extract other interesting fields
			p.Server = resp.Header.Get("server")
		}

		// read body
		b := new(bytes.Buffer)
		io.Copy(b, resp.Body)
		_ = resp.Body.Close()
		p.Body = NewIMDSResponseBody(b.String(), unsafe)
		break
	default:
		goto unsupportedRequest
	}

	return len(data), nil

unsupportedRequest:
	p.PacketType = "unknown"
	p.Body = NewIMDSResponseBody("unsupported IMDS request", unsafe)
	return len(data), nil
}

// IMDSResponseBody is used to parse and serialize an IMDS response body
type IMDSResponseBody struct {
	unsafe bool
	raw    string
}

// NewIMDSResponseBody returns a new instance of IMDSResponseBody
func NewIMDSResponseBody(s string, unsafe bool) IMDSResponseBody {
	return IMDSResponseBody{
		unsafe: unsafe,
		raw:    s,
	}
}

// MarshalJSON supports json.Marshaler interface
func (irb IMDSResponseBody) MarshalJSON() ([]byte, error) {
	if len(irb.raw) == 0 {
		return nil, nil
	}
	// check if the body is already in JSON format
	if irb.raw[0] == '{' {
		if irb.unsafe {
			// return the data as is
			return []byte(strings.ReplaceAll(strings.ReplaceAll(irb.raw, " ", ""), "\n", "")), nil
		}

		// try to parse AWS security credentials
		var sc AWSSecurityCredentials
		err := json.Unmarshal([]byte(irb.raw), &sc)
		if err == nil {
			// return the scrubbed data
			return json.Marshal(sc)
		}

		return []byte("{}"), nil
	}

	if irb.unsafe {
		// return the data as is
		return json.Marshal(map[string]string{
			"raw": irb.raw,
		})
	}
	return []byte("{}"), nil
}

// AWSSecurityCredentials is used to parse the fields that are none to be free of credentials or secrets
type AWSSecurityCredentials struct {
	Code        string `json:"Code"`
	Type        string `json:"Type"`
	AccessKeyID string `json:"AccessKeyId"`
	LastUpdated string `json:"LastUpdated"`
	Expiration  string `json:"Expiration"`
}
