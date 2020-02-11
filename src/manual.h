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

/**
 * @internal
 * Assign a local site as a leader for the ticket
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] preference unused
 * @param[in] update_term unused
 * @param[in] reason explains why new "election" is conducted
 *
 * @return see #send_msg
 */
int manual_selection(struct booth_config *conf_ptr,
                     struct ticket_config *tk, struct booth_site *preference,
                     int update_term, cmd_reason_t reason);

/**
 * @internal
 * Handle REVOKE message
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] sender site structure of the sender
 * @param[in] msg message to deal with
 *
 * @return 0 on success (only possible outcome)
 */
int process_REVOKE_for_manual_ticket(struct booth_config *conf_ptr,
                                     struct ticket_config *tk,
                                     struct booth_site *sender,
                                     struct boothc_ticket_msg *msg);

#endif /* _MANUAL_H */
