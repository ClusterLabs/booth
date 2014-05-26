/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdint.h>
#include "booth.h"
#include "raft.h"
#include "transport.h"


/** @{ */
/** Definitions for in-RAM data. */

#define MAX_NODES	16
#define TICKET_ALLOC	16


struct exclude_site_config {
	/** site ID (maps site_id of struct booth_site). */
	int id;

	/** IP address of site. */
	char addr[BOOTH_NAME_LEN];
};


struct ticket_config {
	/** \name Configuration items.
	 * @{ */
	/** Name of ticket. */
	boothc_ticket name;

	/** How many seconds a term lasts (if not refreshed). */
	int term_duration;

	/** Network related timeouts. */
	int timeout;

	/** Retries before giving up. */
	int retries;

	/** If >0, time to wait for a site to get fenced.
	 * The ticket may be acquired after that timespan by
	 * another site. */
	int acquire_after; /* TODO: needed? */


	/* Program to ask whether it makes sense to
	 * acquire the ticket */
	char *ext_verifier;

	/** Node weights. */
	int weight[MAX_NODES];
	/** @} */


	/** \name Runtime values.
	 * @{ */
	/** Current state. */
	server_state_e state;

	/** Next state. Used at startup. */
	server_state_e next_state;

	/** When something has to be done */
	struct timeval next_cron;

	/** Current leader. This is effectively the log[] in Raft. */
	struct booth_site *leader;

	/** Leader that got lost. */
	struct booth_site *lost_leader;

	/** Is the ticket granted? */
	int is_granted;
	/** Timestamp of leadership expiration */
	time_t term_expires;
	/** End of election period */
	time_t election_end;
	struct booth_site *voted_for;


	/** Who the various sites vote for.
	 * NO_OWNER = no vote yet. */
	struct booth_site *votes_for[MAX_NODES];
	/* bitmap */
	uint64_t votes_received;

	/** Last voting round that was seen. */
	uint32_t current_term;

	/** Do ticket updates whenever we get enough heartbeats.
	 * But do that only once.
	 * This is reset to 0 whenever we broadcast heartbeat and set
	 * to 1 once enough acks are received.
	 * Increased to 2 when the ticket is commited to the CIB (see
	 * delay_commit).
	 */
	uint32_t ticket_updated;
	/** @} */


	/** */
	uint32_t commit_index;

	/** */
	uint32_t last_applied;
	uint32_t next_index[MAX_NODES];
	uint32_t match_index[MAX_NODES];


	/* Why did we start the elections?
	*/
	cmd_reason_t election_reason;

	/* if it is potentially dangerous to grant the ticket
	 * immediately, then this is set to some point in time,
	 * usually (now + term_duration + acquire_after)
	 */
	time_t delay_commit;

	/* if we expect some acks, then set this to the id of
	 * the RPC which others will send us; it is cleared once all
	 * replies were received
	 */
	uint32_t acks_expected;
	/* bitmask of servers which sent acks
	 */
	uint64_t acks_received;
	/* timestamp of the request, currently unused */
	time_t req_sent_at;
	/* we need to wait for MY_INDEX from other servers,
	 * hold the ticket processing for a while until they reply
	 */
	int start_postpone;

	/* Do we need to update the copy in the CIB?
	 * Normally, the ticket is written only when it changes via
	 * the UPDATE RPC (for followers) and on expiration update
	 * (for leaders)
	*/
	int update_cib;

	/* don't log warnings unnecessarily
	 */
	int expect_more_rejects;
	/** \name Needed while proposals are being done.
	 * @{ */
	/** Whom to vote for the next time.
	 * Needed to push a ticket to someone else. */



#if 0
	/** Bitmap of sites that acknowledge that state. */
	uint64_t proposal_acknowledges;

	/** When an incompletely acknowledged proposal gets done.
	 * If all peers agree, that happens sooner.
	 * See switch_state_to(). */
	struct timeval proposal_switch;

	/** Timestamp of proposal expiration. */
	time_t proposal_expires;

#endif

	/** Number of send retries left.
	 * Used on the new owner.
	 * Starts at 0, counts up. */
	int retry_number;
	/** @} */

	int exclude_site_count;
	int exclude_site_allocated;

	/** Sites which don't grant this ticket. */
	struct exclude_site_config *exclude_site;
};


struct booth_config {
    char name[BOOTH_NAME_LEN];

    transport_layer_t proto;
    uint16_t port;

    /** Stores the OR of sites bitmasks. */
    uint64_t sites_bits;
    /** Stores the OR of all members' bitmasks. */
    uint64_t all_bits;

    char site_user[BOOTH_NAME_LEN];
    char site_group[BOOTH_NAME_LEN];
    char arb_user[BOOTH_NAME_LEN];
    char arb_group[BOOTH_NAME_LEN];
    uid_t uid;
    gid_t gid;

    int site_count;
    struct booth_site site[MAX_NODES];

    int ticket_count;
    int ticket_allocated;
    struct ticket_config *ticket;
};


extern struct booth_config *booth_conf;


int read_config(const char *path, int type);

int check_config(int type);

int find_site_by_name(unsigned char *site, struct booth_site **node, int any_type);
int find_site_by_id(uint32_t site_id, struct booth_site **node);

const char *type_to_string(int type);


#include <stdio.h>
#define R(tk_) do { if (ANYDEBUG) printf("## %12s:%3d state %s, %d:%d, " \
	"leader %s, exp %s", __FILE__, __LINE__, \
	state_to_string(tk_->state), tk_->current_term, \
	tk_->commit_index, site_string(tk_->leader), ctime(&tk_->term_expires)); } while(0)


#endif /* _CONFIG_H */
