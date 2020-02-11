/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdint.h>
#include <sys/stat.h>

struct booth_config;

#include "booth.h"
#include "timer.h"
#include "raft.h"
#include "transport.h"


/** @{ */
/** Definitions for in-RAM data. */

#define MAX_NODES	16
#define MAX_ARGS 	16
#define TICKET_ALLOC	16

#define OTHER_SITE "other"


typedef enum {
	EXTPROG_IDLE,
	EXTPROG_RUNNING,
	EXTPROG_EXITED,
	EXTPROG_IGNORE,
} extprog_state_e;

#define tk_test tk->clu_test

typedef enum {
	ATTR_OP_EQ = 1,
	ATTR_OP_NE,
} attr_op_e;

typedef enum {
	GRANT_AUTO = 1,
	GRANT_MANUAL,
} grant_type_e;

typedef enum {
	TICKET_MODE_AUTO = 1,
	TICKET_MODE_MANUAL,
} ticket_mode_e;

struct toktab {
	const char *str;
	int val;
};

struct attr_prereq {
	grant_type_e grant_type; /* grant type */
	attr_op_e op; /* attribute operation */
	char *attr_name;
	char *attr_val;
};

struct ticket_config {
	/** \name Configuration items.
	 * @{ */
	/** Name of ticket. */
	boothc_ticket name;

	/** How long a term lasts if not refreshed (in ms) */
	int term_duration;

	/** Network related timeouts (in ms) */
	int timeout;

	/** Retries before giving up. */
	int retries;

	/** If >0, time to wait for a site to get fenced.
	 * The ticket may be acquired after that timespan by
	 * another site. */
	int acquire_after;

	/* How often to renew the ticket (in ms)
	 */
	int renewal_freq;


	/* Program to ask whether it makes sense to
	 * acquire the ticket */
	struct clu_test {
		char *path;
		int is_dir;
		char *argv[MAX_ARGS];
		pid_t pid;
		int status; /* child exit status */
		extprog_state_e progstate; /* program running/idle/waited on */
	} clu_test;

	/** Node weights. */
	int weight[MAX_NODES];

	/* Mode operation of the ticket.
	 * Set to MANUAL to make sure that the ticket will be manipulated
	 * only by manual commands of the administrator. In such a case
	 * automatic elections will be disabled.
	 * Manual tickets do not have to be renewed every some time.
	 * The leader will continue to send heartbeat messages to other sites.
	 */
	ticket_mode_e mode;
	/** @} */


	/** \name Runtime values.
	 * @{ */
	/** Current state. */
	server_state_e state;

	/** Next state. Used at startup. */
	server_state_e next_state;

	/** When something has to be done */
	timetype next_cron;

	/** Current leader. This is effectively the log[] in Raft. */
	struct booth_site *leader;

	/** Leader that got lost. */
	struct booth_site *lost_leader;

	/** Is the ticket granted? */
	int is_granted;

	/** Which site considered itself a leader.
	 * For manual tickets it is possible, that
	 * more than one site will act as a leader.
	 * This array is used for tracking that situation
	 * and notifying the user about the issue.
	 *
	 * Possible values for every site:
	 *  0: the site does not claim to be the leader
	 *  1: the site considers itself a leader and
	 *     is sending or used to send heartbeat messages
	 *
	 * The site will be marked as '1' until this site
	 * receives revoke confirmation.
	 *
	 * If more than one site has '1', the geo cluster is
	 * considered to have multiple leadership and proper
	 * warning are generated.
	 */
	int sites_where_granted[MAX_NODES];

	/** Timestamp of leadership expiration */
	timetype term_expires;
	/** End of election period */
	timetype election_end;
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

	/** Outcome of whatever ticket request was processed.
	 * Can also be an intermediate stage.
	 */
	uint32_t outcome;
	/** @} */


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
	timetype delay_commit;

	/* the last request RPC we sent
	 */
	uint32_t last_request;
	/* if we expect some acks, then set this to the id of
	 * the RPC which others will send us; it is cleared once all
	 * replies were received
	 */
	uint32_t acks_expected;
	/* bitmask of servers which sent acks
	 */
	uint64_t acks_received;
	/* timestamp of the request */
	timetype req_sent_at;
	/* we need to wait for MY_INDEX from other servers,
	 * hold the ticket processing for a while until they reply
	 */
	int start_postpone;

	/** Last renewal time */
	timetype last_renewal;

	/* Do we need to update the copy in the CIB?
	 * Normally, the ticket is written only when it changes via
	 * the UPDATE RPC (for followers) and on expiration update
	 * (for leaders)
	*/
	int update_cib;

	/* Is this ticket in election?
	*/
	int in_election;

	/* don't log warnings unnecessarily
	 */
	int expect_more_rejects;
	/** \name Needed while proposals are being done.
	 * @{ */
	/* Need to keep the previous valid ticket in case we moved to
	 * start new elections and another server asks for the ticket
	 * status. It would be wrong to send our candidate ticket.
	*/
	struct ticket_config *last_valid_tk;

	/** Attributes, user defined
	 */
	GHashTable *attr;

	/** Attribute prerequisites
	 */
	GList *attr_prereqs;

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
};

struct booth_config {
    char name[BOOTH_NAME_LEN];

    /** File containing the authentication file. */
	char authfile[BOOTH_PATH_LEN];
	struct stat authstat;
	char authkey[BOOTH_MAX_KEY_LEN];
	int authkey_len;
    /** Maximum time skew between peers allowed */
	int maxtimeskew;

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

    int poll_timeout;
    char path_to_self[BOOTH_PATH_LEN];

    struct booth_site *local;

    const booth_transport_table_t *transport;
    const struct ticket_handler *ticket_handler;
};

#define is_auth_req(b_) ((b_)->authkey[0] != '\0')

/**
 * @internal
 * Parse booth configuration file and store as structured data
 *
 * @param[inout] conf_pptr config object to free-alloc cycle & fill accordingly
 * @param[in] transport transport handlers table
 * @param[in] path where the configuration file is expected
 * @param[in] type role currently being acted as
 *
 * @return 0 or negative value (-1 or -errno) on error
 *
 * @note To eventually dispose the associated memory, use #config_free.
 */
int read_config(struct booth_config **conf_pptr,
                const booth_transport_table_t *transport,
                const struct ticket_handler *ticket_handler,
                const char *path, int type);

/**
 * @internal
 * Memory disposal for the config object
 *
 * @param[inout] conf_ptr config object to free
 */
void config_free(struct booth_config *conf_ptr);

/**
 * @internal
 * Check booth configuration
 *
 * Currently it means checking that login user/group indeed exists,
 * while converting it to respective numeric values for further use.
 *
 * @param[inout] conf_ptr config object to check
 * @param[in] type role currently being acted as
 *
 * @return 0 or negative value (-1 or -errno) on error
 */
int check_config(struct booth_config *conf_ptr, int type);

/**
 * @internal
 * Find site in booth configuration by resolved host name
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] site name to match against previously resolved host names
 * @param[out] node relevant tracked data when found
 * @param[in] any_type whether or not to consider also non-site members
 *
 * @return 0 if nothing found, or 1 when found (node assigned accordingly)
 */
int find_site_by_name(struct booth_config *conf_ptr, const char *site,
                      struct booth_site **node, int any_type);

/**
 * @internal
 * Find site in booth configuration by a hash (id)
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] site_id hash (id) to match against previously resolved ones
 * @param[out] node relevant tracked data when found
 *
 * @return 0 if nothing found, or 1 when found (node assigned accordingly)
 */
int find_site_by_id(struct booth_config *conf_ptr, uint32_t site_id,
                    struct booth_site **node);

const char *type_to_string(int type);

/**
 * @internal
 * Pick a ticket structure based on given name
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] ticket name of the ticket to search for
 * @param[out] found place the reference here when found
 *
 * @return see @list_ticket and @send_header_plus
 */
int find_ticket_by_name(struct booth_config *conf_ptr,
                        const char *ticket, struct ticket_config **found);

#endif /* _CONFIG_H */
