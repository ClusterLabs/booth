/* 
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

#ifndef _INLINE_FN_H
#define _INLINE_FN_H

#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include "timer.h"
#include "config.h"
#include "transport.h"

inline static int get_local_id(struct booth_config *conf_ptr)
{
	assert(conf_ptr != NULL);

	return conf_ptr->local != NULL ? conf_ptr->local->site_id : -1;
}

inline static uint32_t get_node_id(struct booth_site *node)
{
	return node ? node->site_id : 0;
}


/** Returns number of seconds left, if any. */
inline static int term_time_left(struct ticket_config *tk)
{
	int left = 0;

	if (is_time_set(&tk->term_expires)) {
		left = time_left(&tk->term_expires);
	}
	return (left < 0) ? 0 : left;
}


inline static int leader_and_valid(struct ticket_config *tk,
                                   const struct booth_site *local)
{
	if (tk->leader != local)
		return 0;

	return term_time_left(tk);
}


/** Is this some leader? */
inline static int is_owned(const struct ticket_config *tk)
{
	return (tk->leader && tk->leader != no_leader);
}

inline static int is_resend(struct ticket_config *tk)
{
	timetype now;

	get_time(&now);
	return time_sub_int(&now, &tk->req_sent_at) >= tk->timeout;
}


static inline void init_header_bare(struct booth_config *conf_ptr,
                                    struct boothc_header *h) {
	timetype now;

	assert(conf_ptr != NULL);
	assert(conf_ptr->local != NULL && conf_ptr->local->site_id != 0);

	h->magic   = htonl(BOOTHC_MAGIC);
	h->version = htonl(BOOTHC_VERSION);
	h->from    = htonl(conf_ptr->local->site_id);
	if (is_auth_req(conf_ptr)) {
		get_time(&now);
		h->opts  = htonl(BOOTH_OPT_AUTH);
		h->secs  = htonl(secs_since_epoch(&now));
		h->usecs = htonl(get_usecs(&now));
	} else {
		h->opts  = htonl(0);
		h->secs  = htonl(0);
		h->usecs = htonl(0);
	}
}

/* get the _real_ message length out of the header
 */
#define sendmsglen(msg) ntohl((msg)->header.length)

static inline void init_header(struct booth_config *conf_ptr,
                               struct boothc_header *h, int cmd, int request,
                               int options, int result, int reason,
                               int data_len)
{
	init_header_bare(conf_ptr, h);
	h->length  = htonl(data_len -
		(is_auth_req(conf_ptr) ? 0 : sizeof(struct hmac)));
	h->cmd     = htonl(cmd);
	h->request = htonl(request);
	h->options = htonl(options);
	h->result  = htonl(result);
	h->reason  = htonl(reason);
}

#define my_last_term(tk) \
	(((tk)->state == ST_CANDIDATE && (tk)->last_valid_tk) ? \
	(tk)->last_valid_tk->current_term : (tk)->current_term)

extern int TIME_RES, TIME_MULT;

#define msg_term_time(msg) \
	ntohl((msg)->ticket.term_valid_for)*TIME_RES/TIME_MULT
#define set_msg_term_time(msg, tk) \
	(msg)->ticket.term_valid_for = htonl(term_time_left(tk)*TIME_MULT/TIME_RES)

static inline void init_ticket_msg(struct booth_config *conf_ptr,
                                   struct boothc_ticket_msg *msg, int cmd,
                                   int request, int rv, int reason,
                                   struct ticket_config *tk)
{
	assert(sizeof(msg->ticket.id) == sizeof(tk->name));

	init_header(conf_ptr, &msg->header, cmd, request, 0, rv, reason,
	            sizeof(*msg));

	if (!tk) {
		memset(&msg->ticket, 0, sizeof(msg->ticket));
	} else {
		memcpy(msg->ticket.id, tk->name, sizeof(msg->ticket.id));

		msg->ticket.leader         = htonl(get_node_id(
			(tk->leader && tk->leader != no_leader) ? tk->leader :
				(tk->voted_for ? tk->voted_for : no_leader)));
		msg->ticket.term           = htonl(tk->current_term);
		set_msg_term_time(msg, tk);
	}
}

static inline struct booth_transport const *transport(struct booth_config *conf_ptr)
{
	assert(conf_ptr != NULL && conf_ptr->transport != NULL);

	return *conf_ptr->transport + conf_ptr->proto;
}

static inline const char *site_string(const struct booth_site *site)
{
	return site ? site->addr_string : "NONE";
}

/**
 * @internal
 * Parse booth configuration file and store as structured data
 *
 * @param[in] site subject of TCP/UDP port extraction
 *
 * @return 0 for "undefined", actual port number otherwise
 */
static inline uint16_t site_port(const struct booth_site *site)
{
	assert(site != NULL);

	return site
		? site->family == AF_INET
			? ntohs(site->sa4.sin_port)
			: site->family == AF_INET6
				? ntohs(site->sa6.sin6_port)
				: 0
		: 0;
}

static inline const char *ticket_leader_string(struct ticket_config *tk)
{
	return site_string(tk->leader);
}


/* We allow half of the uint32_t to be used;
 * half of that below, half of that above the current known "good" value.
 *   0                                                     UINT32_MAX
 *   |--------------------------+----------------+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current commit index
 *
 * So, on overflow it looks like that:
 *                                UINT32_MAX  0
 *   |--------------------------+-----------||---+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current commit index
 *
 * This should be possible by using the same datatype and relying
 * on the under/overflow semantics.
 *
 *
 * Having 30 bits available, and assuming an expire time of
 * one minute and a (high) commit index step of 64 == 2^6 (because
 * of weights), we get 2^24 minutes of range - which is ~750
 * years. "Should be enough for everybody."
 */
static inline int index_is_higher_than(uint32_t c_high, uint32_t c_low)
{
	uint32_t diff;

	if (c_high == c_low)
		return 0;

	diff = c_high - c_low;
	if (diff < UINT32_MAX/4)
		return 1;

	diff = c_low - c_high;
	if (diff < UINT32_MAX/4)
		return 0;

	assert(!"commit index out of range - invalid");
}


static inline uint32_t index_max2(uint32_t a, uint32_t b)
{
	return index_is_higher_than(a, b) ? a : b;
}

static inline uint32_t index_max3(uint32_t a, uint32_t b, uint32_t c)
{
	return index_max2( index_max2(a, b), c);
}


/* only invoked when ticket leader */
static inline void get_next_election_time(struct ticket_config *tk,
                                          timetype *next,
                                          struct booth_site *local)
{
	assert(local != NULL);
	assert(tk->leader == local);

	/* if last_renewal is not set, which is unusual, it may mean
	 * that the ticket never got updated, i.e. nobody acked
	 * ticket updates (say, due to a temporary connection
	 * problem)
	 * we may try a bit later again */
	if (!is_time_set(&tk->last_renewal)) {
		time_reset(next);
	} else {
		interval_add(&tk->last_renewal, tk->renewal_freq, next);
	}

	/* if delay_commit is earlier than next, then set next to
	 * delay_commit */
	if (is_time_set(&tk->delay_commit) &&
			time_cmp(next, &tk->delay_commit, >)) {
		copy_time(&tk->delay_commit, next);
	}
}


static inline void expect_replies(struct ticket_config *tk,
		int reply_type, struct booth_site *local)
{
	assert(local != NULL);

	tk->retry_number = 0;
	tk->acks_expected = reply_type;
	tk->acks_received = local->bitmask;
	get_time(&tk->req_sent_at);
}

static inline void no_resends(struct ticket_config *tk)
{
	tk->retry_number = 0;
	tk->acks_expected = 0;
}

/* XXX UNUSED */
static inline struct booth_site *my_vote(struct ticket_config *tk,
                                         struct booth_site *local)
{
	assert(local != NULL);

	return tk->votes_for[local->index];
}

static inline int count_bits(uint64_t val) {
	return __builtin_popcount(val);
}

static inline int majority_of_bits(struct booth_config *conf_ptr,
                                   struct ticket_config *tk, uint64_t val)
{
	assert(conf_ptr != NULL);

	/* Use ">" to get majority decision, even for an even number
	 * of participants. */
	return count_bits(val) * 2 > conf_ptr->site_count;
}


static inline int all_replied(struct booth_config *conf_ptr,
                              struct ticket_config *tk)
{
	assert(conf_ptr != NULL);

	return !(tk->acks_received ^ conf_ptr->all_bits);
}

static inline int all_sites_replied(struct booth_config *conf_ptr,
                                    struct ticket_config *tk)
{
	assert(conf_ptr != NULL);

	return !((tk->acks_received & conf_ptr->sites_bits) \
	         ^ conf_ptr->sites_bits);
}

#endif
