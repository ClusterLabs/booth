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

/**
 * @internal
 * Late handling of the response towards the client
 *
 * @param[in] cl parsed command line form
 * @param[in] reply_code what the inner handling returns
 *
 * @return 0 on success, -1 on failure, 1 when "cannot serve"
 */
int test_attr_reply(struct command_line *cl, cmd_result_t reply_code);

/**
 * @internal
 * Carry out a geo-atribute related command
 *
 * @param[in] cl parsed command line structure
 * @param[inout] conf_ptr config object to refer to
 *
 * @return 0 or negative value (-1 or -errno) on error
 */
int do_attr_command(struct command_line *cl, struct booth_config *conf_ptr);

/**
 * @internal
 * Facade to handle geostore related operations
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] req_client client structure of the sender
 * @param[in] buf message itself
 *
 * @return 1 or see #attr_list, #attr_get, #attr_set, #attr_del
 */
int process_attr_request(struct booth_config *conf_ptr,
                         struct client *req_client, void *buf);

/**
 * @internal
 * Second stage of incoming datagram handling (after authentication)
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] buf message itself
 * @param[in] source site structure of the sender
 *
 * @return -1 on error, 0 otherwise
 */
int attr_recv(struct booth_config *conf_ptr, void *buf,
              struct booth_site *source);

int store_geo_attr(struct ticket_config *tk, const char *name, const char *val, int notime);

#endif /* _ATTR_H */
