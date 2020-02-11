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

#ifndef _REQUEST_H
#define _REQUEST_H

#include "booth.h"
#include "config.h"

/* Requests are coming from clients and get queued in a
 * round-robin queue (fixed size)
 *
 * This is one way to make the server more responsive and less
 * dependent on misbehaving clients. The requests are queued and
 * later served from the server loop.
 */

struct request {
	/** Request ID */
	int id;

	/** The ticket. */
	struct ticket_config *tk;

	/** The client which sent the request */
	int client_fd;

	/** The message containing the request */
	void *msg;
};

typedef int (*req_fp)(struct booth_config *conf_ptr, struct ticket_config *,
                      int, struct boothc_ticket_msg *);

void *add_req(struct ticket_config *tk, struct client *req_client,
	struct boothc_ticket_msg *msg);

/**
 * @internal
 * Handle all pendign requests for given ticket using function @p f
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] f handling function
 *
 * @return 1 on success, 0 when not done with the message, yet
 */
void foreach_tkt_req(struct booth_config *conf_ptr, struct ticket_config *tk,
                     req_fp f);

/* XXX UNUSED */
int get_req_id(const void *rp);

#endif /* _REQUEST_H */
