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
#include "config.h"

typedef enum {
	ST_INIT      = CHAR2CONST('I', 'n', 'i', 't'),
	ST_FOLLOWER  = CHAR2CONST('F', 'l', 'l', 'w'),
	ST_CANDIDATE = CHAR2CONST('C', 'n', 'd', 'i'),
	ST_LEADER    = CHAR2CONST('L', 'e', 'a', 'd'),
} server_state_e;

struct ticket_config;

/**
 * @internal
 * Core part of the dealing with obtained message per the consensus protocol
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] from site structure of the sender
 * @param[in] leader site structure of the assumed leader
 * @param[in] msg message to deal with
 *
 * @return 0 on success or negative value (-1 or -errno) on error
 */
int raft_answer(struct booth_config *conf_ptr, struct ticket_config *tk,
                struct booth_site *from, struct booth_site *leader,
                struct boothc_ticket_msg *msg);

/**
 * @internal
 * Jump into new election phase
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] new_leader NULL or #local if we are the assigned leader
 * @param[in] update_term 0 for no, yes otherwise (2 is a special
 *                        case that there was a tie previously)
 * @param[in] reason explains why new election is conducted
 *
 * @return 1 if new election was started, 0 if not for being prevented
 */
int new_election(struct booth_config *conf_ptr, struct ticket_config *tk,
                 struct booth_site *new_leader, int update_term,
                 cmd_reason_t reason);

/**
 * @internal
 * Conclude the election phase
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 */
void elections_end(struct booth_config *conf_ptr,
                   struct ticket_config *tk);

#endif /* _RAFT_H */
