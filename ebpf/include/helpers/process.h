/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HELPERS_PROCESS_H_
#define _HELPERS_PROCESS_H_

#include "structs/all.h"
#include "memory_factory.h"

memory_factory(process_context)

__attribute__((always_inline)) int fill_process_context_from_task(struct task_struct* task, struct process_context_t *ctx, struct imds_event_t *evt) {
    // fetch process comm and ids
    void *comm = BPF_CORE_READ(task, comm);
    bpf_probe_read_str(&ctx->comm, sizeof(ctx->comm), comm);
    ctx->pid = BPF_CORE_READ(task, tgid);
    ctx->tid = BPF_CORE_READ(task, pid);

    // fetch cgroup data
    char *container_id;
    int read = 0;
    #pragma unroll
    for (u32 i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        ctx->cgroups[i].subsystem_id = i;
        BPF_CORE_READ_INTO(&ctx->cgroups[i].id, task, cgroups, subsys[i], id);
        BPF_CORE_READ_INTO(&container_id, task, cgroups, subsys[i], cgroup, kn, name);
        read = bpf_probe_read_str(&ctx->cgroups[i].name[0], CGROUP_MAX_LENGTH, container_id);
        ctx->cgroups[i].name[read & (CGROUP_MAX_LENGTH - 1)] = 0;
    }

    // fetch process credentials
    BPF_CORE_READ_INTO(&ctx->credentials.uid, task, cred, uid);
    BPF_CORE_READ_INTO(&ctx->credentials.gid, task, cred, gid);
    BPF_CORE_READ_INTO(&ctx->credentials.suid, task, cred, suid);
    BPF_CORE_READ_INTO(&ctx->credentials.sgid, task, cred, sgid);
    BPF_CORE_READ_INTO(&ctx->credentials.euid, task, cred, euid);
    BPF_CORE_READ_INTO(&ctx->credentials.egid, task, cred, egid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsuid, task, cred, fsuid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsgid, task, cred, fsgid);
    BPF_CORE_READ_INTO(&ctx->credentials.securebits, task, cred, securebits);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_inheritable, task, cred, cap_inheritable);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_permitted, task, cred, cap_permitted);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_effective, task, cred, cap_effective);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_bset, task, cred, cap_bset);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_ambient, task, cred, cap_ambient);

    // fetch process namespaces
    BPF_CORE_READ_INTO(&ctx->namespaces.cgroup_namespace, task, nsproxy, cgroup_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.ipc_namespace, task, nsproxy, ipc_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.net_namespace, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.mnt_namespace, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.pid_namespace, task, nsproxy, pid_ns_for_children, ns.inum);
    if (bpf_core_field_exists(task->nsproxy->time_ns->ns.inum)) {
        BPF_CORE_READ_INTO(&ctx->namespaces.time_namespace, task, nsproxy, time_ns, ns.inum);
    }
    BPF_CORE_READ_INTO(&ctx->namespaces.user_namespace, task, cred, user_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.uts_namespace, task, nsproxy, uts_ns, ns.inum);
    return 0;
};

__attribute__((always_inline)) int fill_process_context(struct process_context_t *ctx, struct imds_event_t *evt) {
    // fetch current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        fill_process_context_from_task(task, ctx, evt);
        parent = BPF_CORE_READ(task, real_parent);
        if (parent == NULL || parent == task) {
            break;
        }
        ctx = (struct process_context_t *)((void *)ctx + sizeof(struct process_context_t));
        task = parent;
    }
    return 0;
}

__attribute__((always_inline)) void copy_process_ctx(struct process_context_t *dst, struct process_context_t *src) {
    dst->pid = src->pid;
    dst->tid = src->pid;
    __builtin_memmove(dst->comm, src->comm, TASK_COMM_LEN);
    __builtin_memmove(&dst->namespaces, &src->namespaces, sizeof(struct namespace_context_t));
    __builtin_memmove(&dst->credentials, &src->credentials, sizeof(struct credentials_context_t));

    #pragma unroll
    for (u32 i = 0; i <= CGROUP_SUBSYS_COUNT; i++) {
        __builtin_memmove(&dst->cgroups[i], &src->cgroups[i], sizeof(struct cgroup_context_t));
    }
    return;
};

#endif