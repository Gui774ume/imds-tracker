/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HOOKS_SOCK_SENDMSG_H_
#define _HOOKS_SOCK_SENDMSG_H_

#include "maps.h"
#include "helpers/process.h"
#include "helpers/events.h"

SEC("kprobe/sock_sendmsg")
int BPF_KPROBE(kprobe_sock_sendmsg, struct socket *sock, struct msghdr *msg) {
    // fetch destination address
    u32 daddr = 0;
    BPF_CORE_READ_INTO(&daddr, sock, sk, __sk_common.skc_daddr);

    // is this AWS IMDS ?
    if (daddr != AWS_IMDS_IP) {
        // ignore
        return 0;
    }

    struct imds_event_t *event = new_imds_event();
    if (event == NULL) {
        // should never happen, ignore
        return 0;
    }
    event->network_direction = NETWORK_EGRESS;

    // copy the content of the payload
    void *data = 0;
    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    switch (iter_type) {
        case ITER_IOVEC:
        case ITER_KVEC:
        case ITER_BVEC:
            BPF_CORE_READ_INTO(&data, msg, msg_iter.iov, iov_base);
            break;
        default:
            if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0)) {
                if (iter_type == ITER_UBUF) {
                    BPF_CORE_READ_INTO(&data, msg, msg_iter.ubuf);
                }
            } else {
                // TODO: add support for ITER_PIPE on kernels before 6.0.0
            }
            break;
    }
    event->pkt.size = bpf_probe_read_str(&event->pkt.data, sizeof(event->pkt.data), data);

    // add process context
    fill_process_context(&event->process[0], event);

    // send event
    send_event(event, (MAX_IMDS_EVENT_SIZE - MAX_PACKET_LENGTH + event->pkt.size) & (MAX_IMDS_EVENT_SIZE - 1));
    return 0;
};

#endif