/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HELPERS_EVENTS_H_
#define _HELPERS_EVENTS_H_

__attribute__((always_inline)) void send_event(struct imds_event_t *event, int size) {
    event->timestamp = bpf_ktime_get_ns();
    bpf_ringbuf_output(&events, event, size, 0);
};

#endif