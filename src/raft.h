/*
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
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

#ifndef _RAFT_H
#define _RAFT_H

#include "booth.h"

typedef enum {
	ST_INIT      = CHAR2CONST('I', 'n', 'i', 't'),
	ST_FOLLOWER  = CHAR2CONST('F', 'l', 'l', 'w'),
	ST_CANDIDATE = CHAR2CONST('C', 'n', 'd', 'i'),
	ST_LEADER    = CHAR2CONST('L', 'e', 'a', 'd'),
} server_state_e;

struct ticket_config;

int raft_answer(struct booth_config *conf, struct ticket_config *tk,
	        struct booth_site *from, struct booth_site *leader,
	        struct boothc_ticket_msg *msg);

int new_election(struct booth_config *conf, struct ticket_config *tk,
		 struct booth_site *new_leader, int update_term,
		 cmd_reason_t reason);
void elections_end(struct booth_config *conf, struct ticket_config *tk);


#endif /* _RAFT_H */
