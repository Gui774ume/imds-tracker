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
	"bytes"
	"fmt"
)

// CgroupSubsystemID is used to parse and serialize Cgroup subsystems
type CgroupSubsystemID uint32

const (
	CgroupCPUSet CgroupSubsystemID = iota
	CgroupCPU
	CgroupCPUAcct
	CgroupIO
	CgroupMemory
	CgroupDevices
	CgroupFreezer
	CgroupNetCLS
	CgroupPerfEvent
	CgroupNetPrio
	CgroupHugeTLB
	CgroupPIDs
	CgroupRDMA
	CgroupMISC
)

func (csi CgroupSubsystemID) String() string {
	switch csi {
	case CgroupCPUSet:
		return "cpuset"
	case CgroupCPU:
		return "cpu"
	case CgroupCPUAcct:
		return "cpuacct"
	case CgroupIO:
		return "io"
	case CgroupMemory:
		return "memory"
	case CgroupDevices:
		return "devices"
	case CgroupFreezer:
		return "freezer"
	case CgroupNetCLS:
		return "net_cls"
	case CgroupPerfEvent:
		return "perf_event"
	case CgroupNetPrio:
		return "net_prio"
	case CgroupHugeTLB:
		return "hugetlb"
	case CgroupPIDs:
		return "pids"
	case CgroupRDMA:
		return "rdma"
	case CgroupMISC:
		return "misc"
	default:
		return "unknown_cgroup"
	}
}

func (csi CgroupSubsystemID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", csi)), nil
}

// CgroupContext is used to parse the cgroups of a process
// easyjson:json
type CgroupContext struct {
	SubsystemID CgroupSubsystemID `json:"subsystem_id"`
	StateID     uint32            `json:"state_id"`
	Name        string            `json:"name"`
}

func (v *CgroupContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8+CgroupNameLength {
		return 0, fmt.Errorf("parsing CgroupContext, got len %d, needed %d: %w", len(data), 8+CgroupNameLength, ErrNotEnoughData)
	}
	v.SubsystemID = CgroupSubsystemID(ByteOrder.Uint32(data[0:4]))
	v.StateID = ByteOrder.Uint32(data[4:8])
	v.Name = string(bytes.Trim(data[8:8+CgroupNameLength], "\x00"))
	return 8 + CgroupNameLength, nil
}

// CredentialsContext is used to parse the credentials of a process
// easyjson:json
type CredentialsContext struct {
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	SUID           uint32 `json:"suid"`
	SGID           uint32 `json:"sgid"`
	EUID           uint32 `json:"euid"`
	EGID           uint32 `json:"egid"`
	FSUID          uint32 `json:"fsuid"`
	FSGID          uint32 `json:"fsgid"`
	SecureBits     uint32 `json:"secure_bits"`
	CapInheritable uint64 `json:"cap_inheritable"`
	CapPermitted   uint64 `json:"cap_permitted"`
	CapEffective   uint64 `json:"cap_effective"`
	CapBSET        uint64 `json:"cap_bset"`
	CapAmbiant     uint64 `json:"cap_ambiant"`
}

func (v *CredentialsContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 80 {
		return 0, fmt.Errorf("parsing CredentialsContext, got len %d, needed 80: %w", len(data), ErrNotEnoughData)
	}
	v.UID = ByteOrder.Uint32(data[:4])
	v.GID = ByteOrder.Uint32(data[4:8])
	v.SUID = ByteOrder.Uint32(data[8:12])
	v.SGID = ByteOrder.Uint32(data[12:16])
	v.EUID = ByteOrder.Uint32(data[16:20])
	v.EGID = ByteOrder.Uint32(data[20:24])
	v.FSUID = ByteOrder.Uint32(data[24:28])
	v.FSGID = ByteOrder.Uint32(data[28:32])
	v.SecureBits = ByteOrder.Uint32(data[32:36])
	// padding
	v.CapInheritable = ByteOrder.Uint64(data[40:48])
	v.CapPermitted = ByteOrder.Uint64(data[48:56])
	v.CapEffective = ByteOrder.Uint64(data[56:64])
	v.CapBSET = ByteOrder.Uint64(data[64:72])
	v.CapAmbiant = ByteOrder.Uint64(data[72:80])
	return 80, nil
}

// NamespaceContext is used to parse the namespace context of process
// easyjson:json
type NamespaceContext struct {
	CgroupNamespace uint32 `json:"cgroup_namespace"`
	IPCNamespace    uint32 `json:"ipc_namespace"`
	NetNamespace    uint32 `json:"net_namespace"`
	MntNamespace    uint32 `json:"mnt_namespace"`
	PIDNamespace    uint32 `json:"pid_namespace"`
	TimeNamespace   uint32 `json:"time_namespace"`
	UserNamespace   uint32 `json:"user_namespace"`
	UTSNamespace    uint32 `json:"uts_namespace"`
}

func (v *NamespaceContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 32 {
		return 0, fmt.Errorf("parsing NamespaceContext, got len %d, needed 32: %w", len(data), ErrNotEnoughData)
	}
	v.CgroupNamespace = ByteOrder.Uint32(data[:4])
	v.IPCNamespace = ByteOrder.Uint32(data[4:8])
	v.NetNamespace = ByteOrder.Uint32(data[8:12])
	v.MntNamespace = ByteOrder.Uint32(data[12:16])
	v.PIDNamespace = ByteOrder.Uint32(data[16:20])
	v.TimeNamespace = ByteOrder.Uint32(data[20:24])
	v.UserNamespace = ByteOrder.Uint32(data[24:28])
	v.UTSNamespace = ByteOrder.Uint32(data[28:32])
	return 32, nil
}

// ProcessContext is used to parse the process context of an event
// easyjson:json
type ProcessContext struct {
	Cgroups          [CgroupSubSysCount]CgroupContext `json:"cgroups"`
	NamespaceContext NamespaceContext                 `json:"namespace_context"`
	Credentials      CredentialsContext               `json:"credentials"`
	Comm             string                           `json:"comm"`
	Pid              int                              `json:"pid"`
	Tid              int                              `json:"tid"`
}

func (v *ProcessContext) UnmarshalBinary(data []byte) (int, error) {
	var cursor, read int
	var err error

	read, err = v.NamespaceContext.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	read, err = v.Credentials.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	if len(data[cursor:]) < TaskCommLength {
		return 0, fmt.Errorf("parsing ProcessContext.Comm: got len %d, needed %d: %w", len(data[cursor:]), TaskCommLength, ErrNotEnoughData)
	}
	v.Comm = string(bytes.Trim(data[cursor:cursor+TaskCommLength], "\x00"))
	cursor += TaskCommLength

	for i := 0; i < CgroupSubSysCount; i++ {
		read, err = v.Cgroups[i].UnmarshalBinary(data[cursor:])
		if err != nil {
			return 0, err
		}
		cursor += read
	}

	if len(data[cursor:]) < 8 {
		return 0, fmt.Errorf("parsing ProcessContext.Pid: got len %d, needed %d: %w", len(data[cursor:]), 8, ErrNotEnoughData)
	}
	v.Pid = int(ByteOrder.Uint32(data[cursor : cursor+4]))
	v.Tid = int(ByteOrder.Uint32(data[cursor : cursor+4]))
	cursor += 8

	return cursor, nil
}
