/*
 * Copyright (C) 2017 Chris Kowalczyk <ckowalczyk@suse.com>
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

#ifndef _MANUAL_H
#define _MANUAL_H

#include "booth.h"

struct ticket_config;

int manual_selection(struct booth_config *conf, struct ticket_config *tk,
		     struct booth_site *new_leader, int update_term,
		     cmd_reason_t reason);

int process_REVOKE_for_manual_ticket(struct booth_config *conf,
				     struct ticket_config *tk,
				     struct booth_site *sender,
				     struct boothc_ticket_msg *msg);


#endif /* _MANUAL_H */
