/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#ifndef _EVENTS_H_
#define _EVENTS_H_

#include "structs/all.h"
#include "helpers/memory_factory.h"

#define MAX_IMDS_EVENT_SIZE 32*1024
#define MAX_ANCESTORS_DEPTH 10
#define MAX_PACKET_LENGTH (MAX_IMDS_EVENT_SIZE - sizeof(struct process_context_t)*MAX_ANCESTORS_DEPTH - sizeof(u64)*3 - sizeof(u32))

struct packet_t {
    u32 size;
    char data[MAX_PACKET_LENGTH];
};

struct imds_event_t {
    struct process_context_t process[MAX_ANCESTORS_DEPTH];
    u64 network_direction;
    u64 timestamp;
    u32 user_stack_id;
    u32 padding;
    struct packet_t pkt;
};

memory_factory(imds_event)

#endif