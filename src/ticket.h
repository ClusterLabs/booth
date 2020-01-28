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


#define FOREACH_TICKET(i_, t_) \
	for (i_ = 0; \
	     (t_ = booth_conf->ticket + i_, i_ < booth_conf->ticket_count); \
	     i_++)

#define FOREACH_NODE(i_, n_) \
	for (i_ = 0; \
	     (n_ = booth_conf->site + i_, i_ < booth_conf->site_count); \
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
int disown_if_expired(struct ticket_config *tk);
int check_ticket(char *ticket, struct ticket_config **tc);
int check_site(char *site, int *local);
int grant_ticket(struct ticket_config *ticket);
int revoke_ticket(struct ticket_config *ticket);
int list_ticket(char **pdata, unsigned int *len);

int ticket_recv(void *buf, struct booth_site *source);
void reset_ticket(struct ticket_config *tk);
void reset_ticket_and_set_no_leader(struct ticket_config *tk);
void update_ticket_state(struct ticket_config *tk, struct booth_site *sender);
int setup_ticket(void);
int check_max_len_valid(const char *s, int max);

int do_grant_ticket(struct ticket_config *ticket, int options);
int do_revoke_ticket(struct ticket_config *tk);

int find_ticket_by_name(const char *ticket, struct ticket_config **found);

void set_ticket_wakeup(struct ticket_config *tk);
int postpone_ticket_processing(struct ticket_config *tk);

int acquire_ticket(struct ticket_config *tk, cmd_reason_t reason);

int ticket_answer_list(int fd);
int process_client_request(struct client *req_client, void *buf);

int ticket_write(struct ticket_config *tk);

void process_tickets(void);
void tickets_log_info(void);
char *state_to_string(uint32_t state_ho);
int send_reject(struct booth_site *dest, struct ticket_config *tk,
	cmd_result_t code, struct boothc_ticket_msg *in_msg);
int send_msg (int cmd, struct ticket_config *tk,
	struct booth_site *dest, struct boothc_ticket_msg *in_msg);
int notify_client(struct ticket_config *tk, int client_fd,
	struct boothc_ticket_msg *msg);
int ticket_broadcast(struct ticket_config *tk, cmd_request_t cmd, cmd_request_t expected_reply, cmd_result_t res, cmd_reason_t reason);

int leader_update_ticket(struct ticket_config *tk);
void add_random_delay(struct ticket_config *tk);
void schedule_election(struct ticket_config *tk, cmd_reason_t reason);

int is_manual(struct ticket_config *tk);
int number_sites_marked_as_granted(struct ticket_config *tk);

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
