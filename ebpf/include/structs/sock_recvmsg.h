/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _STRUCTS_SOCK_RECVMSG_H__
#define _STRUCTS_SOCK_RECVMSG_H__

struct sock_recvmsg_context_t {
    struct socket *sock;
    struct msghdr *msg;
};

#endif