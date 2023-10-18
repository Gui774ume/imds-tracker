/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _STRUCTS_PROCESS_H__
#define _STRUCTS_PROCESS_H__

#define CGROUP_MAX_LENGTH 128
#define TASK_COMM_LEN 16
#define CGROUP_SUBSYS_COUNT 14

struct cgroup_context_t {
    u32 subsystem_id;
    u32 id;
    char name[CGROUP_MAX_LENGTH];
};

struct credentials_context_t {
    kuid_t          uid;		/* real UID of the task */
    kgid_t          gid;		/* real GID of the task */
    kuid_t          suid;		/* saved UID of the task */
    kgid_t          sgid;		/* saved GID of the task */
    kuid_t          euid;		/* effective UID of the task */
    kgid_t          egid;		/* effective GID of the task */
    kuid_t          fsuid;		/* UID for VFS ops */
    kgid_t          fsgid;		/* GID for VFS ops */
    unsigned        securebits;	/* SUID-less security management */
    u32             padding;
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;	/* caps we're permitted */
    kernel_cap_t    cap_effective;	/* caps we can actually use */
    kernel_cap_t    cap_bset;	/* capability bounding set */
    kernel_cap_t    cap_ambient;	/* Ambient capability set */
};

struct namespace_context_t {
    u32 cgroup_namespace;
    u32 ipc_namespace;
    u32 net_namespace;
    u32 mnt_namespace;
    u32 pid_namespace;
    u32 time_namespace;
    u32 user_namespace;
    u32 uts_namespace;
};

struct process_context_t {
    struct namespace_context_t namespaces;
    struct credentials_context_t credentials;
    char comm[TASK_COMM_LEN];
    struct cgroup_context_t cgroups[CGROUP_SUBSYS_COUNT];
    u32 pid;
    u32 tid;
};

#endif