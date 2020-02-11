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

#ifndef _TICKET_H
#define _TICKET_H

#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "timer.h"
#include "config.h"
#include "log.h"

extern int TIME_RES;

#define DEFAULT_TICKET_EXPIRY	(600*TIME_RES)
#define DEFAULT_TICKET_TIMEOUT	(5*TIME_RES)
#define DEFAULT_RETRIES			10


#define FOREACH_TICKET(b_, i_, t_) \
	for (i_ = 0; \
	     (t_ = (b_)->ticket + i_, i_ < (b_)->ticket_count); \
	     i_++)

#define FOREACH_NODE(b_, i_, n_) \
	for (i_ = 0; \
	     (n_ = (b_)->site + i_, i_ < (b_)->site_count); \
	     i_++)

#define set_leader(tk, who) do { \
	if (who == NULL) { \
		mark_ticket_as_revoked_from_leader(tk); \
	} \
	\
	tk->leader = who; \
	tk_log_debug("ticket leader set to %s", ticket_leader_string(tk)); \
	\
	if (tk->leader) { \
		mark_ticket_as_granted(tk, tk->leader); \
	} \
} while(0)

#define mark_ticket_as_granted(tk, who) do { \
	if (is_manual(tk) && (who->index > -1)) { \
		tk->sites_where_granted[who->index] = 1; \
		tk_log_debug("manual ticket marked as granted to %s", ticket_leader_string(tk)); \
	} \
} while(0)

#define mark_ticket_as_revoked(tk, who) do { \
	if (is_manual(tk) && who && (who->index > -1)) { \
		tk->sites_where_granted[who->index] = 0; \
		tk_log_debug("manual ticket marked as revoked from %s", site_string(who)); \
	} \
} while(0)

#define mark_ticket_as_revoked_from_leader(tk) do { \
	if (tk->leader) { \
		mark_ticket_as_revoked(tk, tk->leader); \
	} \
} while(0)

#define set_state(tk, newst) do { \
	tk_log_debug("state transition: %s -> %s", \
		state_to_string(tk->state), state_to_string(newst)); \
	tk->state = newst; \
} while(0)

#define set_next_state(tk, newst) do { \
	if (!(newst)) tk_log_debug("next state reset"); \
	else tk_log_debug("next state set to %s", state_to_string(newst)); \
	tk->next_state = newst; \
} while(0)

#define is_term_invalid(tk, term) \
	((tk)->last_valid_tk && (tk)->last_valid_tk->current_term > (term))

void save_committed_tkt(struct ticket_config *tk);
void disown_ticket(struct ticket_config *tk);

/* XXX UNUSED */
int disown_if_expired(struct ticket_config *tk);

/**
 * @internal
 * Pick a ticket structure based on given name, with some apriori sanity checks
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] ticket name of the ticket to search for
 * @param[out] found place the reference here when found
 *
 * @return 0 on failure, see @find_ticket_by_name otherwise
 */
int check_ticket(struct booth_config *conf_ptr, const char *ticket,
                 struct ticket_config **tc);

/**
 * @internal
 * Check whether given site is valid
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] site which member to look for
 * @param[out] is_local store whether the member is local on success
 *
 * @note XXX UNUSED
 *
 * @return 1 on success (found and valid), 0 otherwise
 */
int check_site(struct booth_config *conf_ptr, const char *site,
               int *local);

/**
 * @internal
 * Second stage of incoming datagram handling (after authentication)
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] buf raw message to act upon
 * @param[in] source member originating this message
 *
 * @return 0 on success or negative value (-1 or -errno) on error
 */
int ticket_recv(struct booth_config *conf_ptr, void *buf,
                struct booth_site *source);

void reset_ticket(struct ticket_config *tk);
void reset_ticket_and_set_no_leader(struct ticket_config *tk);

/**
 * @internal
 * Based on the current state and circumstances, make a state transition
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] sender site structure of the sender
 */
void update_ticket_state(struct booth_config *conf_ptr,
                         struct ticket_config *tk, struct booth_site *sender);

/**
 * @internal
 * Initial "consult local pacemaker and booth peers" inquiries
 *
 * @param[inout] conf_ptr config object to use as a starting point
 *
 * @return 0 (for the time being)
 */
int setup_ticket(struct booth_config *conf_ptr);

/**
 * @internal
 * Apply the next step with the ticket if possible.
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 */
void set_ticket_wakeup(struct booth_config *conf_ptr,
                       struct ticket_config *tk);

/**
 * @internal
 * Implementation of the ticket listing
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] file descriptor of the socket to respond to
 *
 * @return see @list_ticket and @send_header_plus
 */
int ticket_answer_list(struct booth_config *conf_ptr, int fd);

/**
 * @internal
 * Process request from the client (as opposed to peer daemon)
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] req_client client structure of the sender
 * @param[in] buf message itself
 *
 * @return 1 on success, 0 when not done with the message, yet
 */
int process_client_request(struct booth_config *conf_ptr,
                           struct client *req_client, void *buf);

/**
 * @internal
 * Cause the ticket storage backend to persist the ticket
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 *
 * @return 0 on success, 1 when not carried out for being dangerous
 */
int ticket_write(struct booth_config *conf_ptr,
                 struct ticket_config *tk);

/**
 * @internal
 * Mainloop of booth ticket handling
 *
 * @param[inout] conf_ptr config object to refer to
 */
void process_tickets(struct booth_config *conf_ptr);

/**
 * @internal
 * For each ticket, log some notable properties
 *
 * @param[inout] conf_ptr config object to refer to
 */
void tickets_log_info(struct booth_config *conf_ptr);

char *state_to_string(uint32_t state_ho);

/**
 * @internal
 * For a given ticket and recipient site, send a rejection
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] dest site structure of the recipient
 * @param[in] tk ticket at hand
 * @param[in] code further detail for the rejection
 * @param[in] in_msg message this is going to be a response to
 */
int send_reject(struct booth_config *conf_ptr, struct booth_site *dest,
                struct ticket_config *tk, cmd_result_t code,
                struct boothc_ticket_msg *in_msg);

/**
 * @internal
 * For a given ticket, recipient site and possibly its message, send a response
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] cmd what type of message is to be sent
 * @param[in] dest site structure of the recipient
 * @param[in] in_msg message this is going to be a response to
 */
int send_msg(struct booth_config *conf_ptr, int cmd, struct ticket_config *tk,
             struct booth_site *dest, struct boothc_ticket_msg *in_msg);

/**
 * @internal
 * Notify client at particular socket, regarding particular ticket
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] fd file descriptor of the socket to respond to
 * @param[in] msg input message being responded to
 */
int notify_client(struct booth_config *conf_ptr, struct ticket_config *tk,
                  int client_fd, struct boothc_ticket_msg *msg);

/**
 * @internal
 * Broadcast the current state of the ticket as seen from local perspective
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] cmd what type of message is to be sent
 * @param[in] expected_reply what to expect in response
 * @param[in] res may carry further detail with cmd == OP_REJECTED
 * @param[in] reason trigger of this broadcast
 */
int ticket_broadcast(struct booth_config *conf_ptr,
                     struct ticket_config *tk, cmd_request_t cmd,
                     cmd_request_t expected_reply, cmd_result_t res,
                     cmd_reason_t reason);

/**
 * @internal
 * Update the ticket (+broadcast to that effect) and/or write it to the backend
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 *
 * @return 0 or see #ticket_broadcast
 */
int leader_update_ticket(struct booth_config *conf_ptr,
                         struct ticket_config *tk);

void add_random_delay(struct ticket_config *tk);

/**
 * @internal
 * Make it so the nearest ticket swipe will start election
 *
 * @param[inout] conf_ptr config object to refer to
 * @param[in] tk ticket at hand
 * @param[in] reason explains why new election is conducted
 */
void schedule_election(struct booth_config *conf_ptr, struct ticket_config *tk,
                       cmd_reason_t reason);

int is_manual(struct ticket_config *tk);

int check_attr_prereq(struct ticket_config *tk, grant_type_e grant_type);

static inline void ticket_next_cron_at(struct ticket_config *tk, timetype *when)
{
	copy_time(when, &tk->next_cron);
}

static inline void ticket_next_cron_in(struct ticket_config *tk, int interval)
{
	timetype tv;

	set_future_time(&tv, interval);
	ticket_next_cron_at(tk, &tv);
}


static inline void ticket_activate_timeout(struct ticket_config *tk)
{
	/* TODO: increase timeout when no answers */
	tk_log_debug("activate ticket timeout in %d", tk->timeout);
	ticket_next_cron_in(tk, tk->timeout);
}


#endif /* _TICKET_H */
