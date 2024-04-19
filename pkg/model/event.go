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
	"debug/elf"
	"fmt"
	"time"

	"github.com/mailru/easyjson/jwriter"

	"github.com/Gui774ume/imds-tracker/pkg/resolver"
)

// NetworkDirection is used to differentiate Ingress from Egress
type NetworkDirection uint64

const (
	// Ingress represents ingress traffic
	Ingress NetworkDirection = 1
	// Egress represents egress traffic
	Egress NetworkDirection = 2
)

func (nd NetworkDirection) String() string {
	switch nd {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return "unknown"
	}
}

func (nd NetworkDirection) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", nd)), nil
}

// SymbolAddr is the address of a symbol
type SymbolAddr uint64

// BinaryCookie is a unique identifier used to select a TracedBinary
type BinaryCookie uint32

type TracedBinary struct {
	Path         string
	ResolvedPath string
	Inode        uint64
	Size         int64
	Cookie       BinaryCookie
	Pids         []int

	SymbolsCache map[SymbolAddr]elf.Symbol
	File         *elf.File
}

type TracedSymbol struct {
	Symbol elf.Symbol
	Binary *TracedBinary
}

// StackTraceNode represents a node of a stack trace
type StackTraceNode struct {
	Offset SymbolAddr
	Symbol elf.Symbol
}

func (stn StackTraceNode) String() string {
	return fmt.Sprintf("(0x%x) %s", stn.Offset, stn.Symbol.Name)
}

// Event is used to parse an IMDS event
// easyjson:json
type Event struct {
	Process          ProcessContext   `json:"process"`
	Ancestors        ProcessList      `json:"ancestors"`
	NetworkDirection NetworkDirection `json:"network_direction"`
	Timestamp        time.Time        `json:"timestamp"`

	UserStackID       uint32       `json:"user_stack_id"`
	UserStackTraceRaw []SymbolAddr `json:"-"`
	UserStackTrace    []string     `json:"stack_trace"`

	Packet IMDSPacket `json:"packet"`
}

func (ie *Event) UnmarshalBinary(data []byte, resolver *resolver.TimeResolver, unsafe bool) (int, error) {
	var cursor, read int
	var err error

	// unmarshall the process context
	read, err = ie.Process.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	// unmarshall ancestors
	for i := range ie.Ancestors {
		read, err = ie.Ancestors[i].UnmarshalBinary(data[cursor:])
		if err != nil {
			return 0, err
		}
		cursor += read
	}

	if len(data[cursor:]) < 24 {
		return 0, fmt.Errorf("parsing Event: got len %d, needed %d: %w", len(data[cursor:]), 16, ErrNotEnoughData)
	}

	ie.NetworkDirection = NetworkDirection(ByteOrder.Uint64(data[cursor : cursor+8]))
	ie.Timestamp = resolver.ResolveMonotonicTimestamp(ByteOrder.Uint64(data[cursor+8 : cursor+16]))
	ie.UserStackID = ByteOrder.Uint32(data[cursor+16 : cursor+20])
	// padding: 4 bytes
	cursor += 24

	read, err = ie.Packet.UnmarshalBinary(data[cursor:], unsafe)
	if err != nil {
		return 0, err
	}
	cursor += read

	return cursor, nil
}

// ProcessList is used to store the process tree of an event
type ProcessList [MaxAncestorsDepth - 1]ProcessContext

func (pl *ProcessList) MarshalEasyJSON(w *jwriter.Writer) {
	// filter the processes we care about
	for i, p := range pl {
		if p.Pid == 0 {
			ProcessListSerializer(pl[0:i]).MarshalEasyJSON(w)
			return
		}
	}
	ProcessListSerializer(pl[:]).MarshalEasyJSON(w)
	return
}

// ProcessListSerializer is used to serialize a ProcessList
// easyjson:json
type ProcessListSerializer []ProcessContext
