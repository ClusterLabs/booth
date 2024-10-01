/*
 * Copyright (C) 2015 Dejan Muhamedagic <dejan@hello-penguin.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _ATTR_H
#define _ATTR_H

#define ATTR_PROG "geostore"

#include "b_config.h"
#include "log.h"
#include <stdlib.h>
#include <sys/types.h>
#include "booth.h"
#include "timer.h"
#include <glib.h>

void print_geostore_usage(void);
int test_attr_reply(cmd_result_t reply_code, cmd_request_t cmd);

/**
 * @internal
 * Carry out a geo-atribute related command
 *
 * @param[in,out] conf  config object to refer to
 * @param[in]     cmd   what to perform
 *
 * @return 0 or negative value (-1 or -errno) on error
 */
int do_attr_command(struct booth_config *conf, cmd_request_t cmd);

/**
 * @internal
 * Handle geostore related operations
 *
 * @param[in,out] conf       config object to refer to
 * @param[in]     req_client client structure of the sender
 * @param[in]     buf        client message
 *
 * @return 1 or see #attr_list, #attr_get, #attr_set, and #attr_del
 */
int process_attr_request(struct booth_config *conf, struct client *req_client,
			 void *buf);

/**
 * @internal
 * Second stage of incoming message handling (after authentication)
 *
 * @param[in,out] conf   config object to refer to
 * @param[in]     buf    incoming message
 * @param[in]     source site of the sender
 *
 * @return -1 on error, 0 otherwise
 */
int attr_recv(struct booth_config *conf, void *buf, struct booth_site *source);

int store_geo_attr(struct ticket_config *tk, const char *name, const char *val, int notime);

#endif /* _ATTR_H */
