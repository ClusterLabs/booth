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

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include "booth.h"
#include "ticket.h"
#include "request.h"
#include "log.h"

static GList *req_l = NULL;
static int req_id_cnt;

/* add request to the queue; it is up to the caller to manage
 * memory for the three parameters
 */

void *add_req(
	struct ticket_config *tk,
	struct client *req_client,
	struct boothc_ticket_msg *msg)
{
	struct request *rp;

	rp = g_new(struct request, 1);
	if (!rp)
		return NULL;
	rp->id = req_id_cnt++;
	rp->tk = tk;
	rp->client_fd = req_client->fd;
	rp->msg = msg;
	req_l = g_list_append(req_l, rp);
	return rp;
}

/* XXX UNUSED */
int get_req_id(const void *rp)
{
	if (!rp)
		return -1;
	return ((struct request *)rp)->id;
}

static void del_req(GList *lp)
{
	if (!lp)
		return;
	req_l = g_list_delete_link(req_l, lp);
}

void foreach_tkt_req(struct booth_config *conf_ptr, struct ticket_config *tk,
                     req_fp f)
{
	GList *lp, *next;
	struct request *rp;

	lp = g_list_first(req_l);
	while (lp) {
		next = g_list_next(lp);
		rp = (struct request *)lp->data;
		if (rp->tk == tk &&
				(f)(conf_ptr, rp->tk, rp->client_fd, rp->msg) == 0) {
			log_debug("remove request for client %d", rp->client_fd);
			del_req(lp); /* don't need this request anymore */
		}
		lp = next;
	}
}
