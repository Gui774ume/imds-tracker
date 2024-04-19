/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#ifndef _MAPS_H_
#define _MAPS_H_

#include "events.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16384 * 1024 /* 16 MB */);
} events SEC(".maps");

BPF_HASH_MAP(sock_recvmsg_context, u32, struct sock_recvmsg_context_t, 4096)
BPF_STACK_TRACE_MAP(stack_traces, 127, 1000) // PERF_MAX_STACK_DEPTH = 127

#endif