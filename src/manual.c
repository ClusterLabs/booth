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

#include "manual.h"

#include "config.h"
#include "transport.h"
#include "ticket.h"
#include "log.h"
#include "request.h"

/* For manual tickets, manual_selection function is an equivalent
 * of new_election function used for assigning automatic tickets.
 * The workflow here is much simplier, as no voting is performed,
 * and the current node doesn't have to wait for any responses
 * from other sites.
 */
int manual_selection(struct booth_config *conf_ptr,
                     struct ticket_config *tk, struct booth_site *preference,
                     int update_term, cmd_reason_t reason)
{
	assert(conf_ptr != NULL);
	assert(conf_ptr->local != NULL);

	if (conf_ptr->local->type != SITE)
		return 0;

	tk_log_debug("starting manual selection (caused by %s %s)",
				state_to_string(reason),
				reason == OR_AGAIN ? state_to_string(tk->election_reason) : "" );

	// Manual selection is done without any delay, the leader is assigned
	set_leader(tk, conf_ptr->local);
	set_state(tk, ST_LEADER);

	// Manual tickets never expire, we don't specify expiration time

	// Make sure that election_end field is empty
	time_reset(&tk->election_end);

	// Make sure that delay commit is empty, as manual tickets don't
	// wait for any kind of confirmation from other nodes
	time_reset(&tk->delay_commit);

	save_committed_tkt(tk);

	// Inform others about the new leader
	ticket_broadcast(conf_ptr, tk, OP_HEARTBEAT, OP_ACK, RLT_SUCCESS, 0);
	tk->ticket_updated = 0;

	return 0;
}

/* This function is called for manual tickets that were
 * revoked from another site, which this site doesn't
 * consider as a leader.
 */
int process_REVOKE_for_manual_ticket(struct booth_config *conf_ptr,
                                     struct ticket_config *tk,
                                     struct booth_site *sender,
                                     struct boothc_ticket_msg *msg)
{
	int rv;

	// For manual tickets, we may end up having two leaders.
	// If one of them is revoked, it will send information 
	// to all members of the GEO cluster.
	
	// We may find ourselves here if this particular site
	// has not been following the leader which had been revoked
	// (and which had sent this message).

	// We send the ACK, to satisfy the requestor.
	rv = send_msg(conf_ptr, OP_ACK, tk, sender, msg);		

	// Mark this ticket as not granted to the sender anymore.
	mark_ticket_as_revoked(tk, sender);
	
	if (tk->state == ST_LEADER) {
		tk_log_warn("%s wants to revoke ticket, "
			"but this site is itself a leader",
			site_string(sender));

		// Because another leader is presumably stepping down,
		// let's notify other sites that now we are the only leader.
		ticket_broadcast(conf_ptr, tk, OP_HEARTBEAT, OP_ACK,
		                 RLT_SUCCESS, 0);
	} else {
		tk_log_warn("%s wants to revoke ticket, "
			"but this site is not following it",
			site_string(sender));
	}

	return rv;
}



