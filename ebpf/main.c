/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// eBPF helpers
#include "include/bpf/all.h"

extern int LINUX_KERNEL_VERSION __kconfig;

#define AWS_IMDS_IP 0xFEA9FEA9 // 169.254.169.254
//#define AWS_IMDS_IP 0x100007f // 127.0.0.1 for debugging

#define NETWORK_INGRESS 1
#define NETWORK_EGRESS 2

// hooks
#include "include/hooks/all.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
