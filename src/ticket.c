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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <clplumbing/cl_random.h>
#include "b_config.h"
#include "ticket.h"
#include "config.h"
#include "pacemaker.h"
#include "inline-fn.h"
#include "log.h"
#include "booth.h"
#include "raft.h"
#include "handler.h"
#include "request.h"

#define TK_LINE			256

extern int TIME_RES;

/* Untrusted input, must fit (incl. \0) in a buffer of max chars. */
int check_max_len_valid(const char *s, int max)
{
	int i;
	for(i=0; i<max; i++)
		if (s[i] == 0)
			return 1;
	return 0;
}

int find_ticket_by_name(const char *ticket, struct ticket_config **found)
{
	int i;

	if (found)
		*found = NULL;

	for (i = 0; i < booth_conf->ticket_count; i++) {
		if (!strncmp(booth_conf->ticket[i].name, ticket,
			     sizeof(booth_conf->ticket[i].name))) {
			if (found)
				*found = booth_conf->ticket + i;
			return 1;
		}
	}

	return 0;
}

int check_ticket(char *ticket, struct ticket_config **found)
{
	if (found)
		*found = NULL;
	if (!booth_conf)
		return 0;

	if (!check_max_len_valid(ticket, sizeof(booth_conf->ticket[0].name)))
		return 0;
	return find_ticket_by_name(ticket, found);
}

int check_site(char *site, int *is_local)
{
	struct booth_site *node;

	if (!check_max_len_valid(site, sizeof(node->addr_string)))
		return 0;

	if (find_site_by_name(site, &node, 0)) {
		*is_local = node->local;
		return 1;
	}

	return 0;
}


/* is it safe to commit the grant?
 * if we didn't hear from all sites on the initial grant, we may
 * need to delay the commit
 *
 * TODO: investigate possibility to devise from history whether a
 * missing site could be holding a ticket or not
 */
static int ticket_dangerous(struct ticket_config *tk)
{
	int tdiff;
	/* we may be invoked often, don't spam the log unnecessarily
	 */
	static int no_log_delay_msg;

	if (!is_time_set(&tk->delay_commit))
		return 0;

	if (is_past(&tk->delay_commit) || all_sites_replied(tk)) {
		if (tk->leader == local) {
			tk_log_info("%s, committing to CIB",
				is_past(&tk->delay_commit) ?
				"ticket delay expired" : "all sites replied");
		}
		time_reset(&tk->delay_commit);
		no_log_delay_msg = 0;
		return 0;
	}

	tdiff = time_left(&tk->delay_commit);
	tk_log_debug("delay ticket commit for another " intfmt(tdiff));
	if (!no_log_delay_msg) {
		tk_log_info("delaying ticket commit to CIB for " intfmt(tdiff));
		tk_log_info("(or all sites are reached)");
		no_log_delay_msg = 1;
	}

	return 1;
}


int ticket_write(struct ticket_config *tk)
{
	if (local->type != SITE)
		return -EINVAL;

	if (ticket_dangerous(tk))
		return 1;

	if (tk->leader == local) {
		if (tk->state != ST_LEADER) {
			tk_log_info("ticket state not yet consistent, "
				"delaying ticket grant to CIB");
			return 1;
		}
		pcmk_handler.grant_ticket(tk);
	} else {
		pcmk_handler.revoke_ticket(tk);
	}
	tk->update_cib = 0;

	return 0;
}


void save_committed_tkt(struct ticket_config *tk)
{
	if (!tk->last_valid_tk) {
		tk->last_valid_tk = malloc(sizeof(struct ticket_config));
		if (!tk->last_valid_tk) {
			log_error("out of memory");
			return;
		}
	}
	memcpy(tk->last_valid_tk, tk, sizeof(struct ticket_config));
}


static void ext_prog_failed(struct ticket_config *tk,
		int start_election)
{
	/* Give it to somebody else.
	 * Just send a VOTE_FOR message, so the
	 * others can start elections. */
	if (leader_and_valid(tk)) {
		save_committed_tkt(tk);
		reset_ticket(tk);
		ticket_write(tk);
		if (start_election) {
			ticket_broadcast(tk, OP_VOTE_FOR, OP_REQ_VOTE, RLT_SUCCESS, OR_LOCAL_FAIL);
		}
	}
}

#define attr_found(geo_ap, ap) \
	((geo_ap) && !strcmp((geo_ap)->val, (ap)->attr_val))

int check_attr_prereq(struct ticket_config *tk, grant_type_e grant_type)
{
	GList *el;
	struct attr_prereq *ap;
	struct geo_attr *geo_ap;

	for (el = g_list_first(tk->attr_prereqs); el; el = g_list_next(el))
	{
		ap = (struct attr_prereq *)el->data;
		if (ap->grant_type != grant_type)
			continue;
		geo_ap = (struct geo_attr *)g_hash_table_lookup(tk->attr, ap->attr_name);
		switch(ap->op) {
		case ATTR_OP_EQ:
			if (!attr_found(geo_ap, ap))
				goto fail;
			break;
		case ATTR_OP_NE:
			if (attr_found(geo_ap, ap))
				goto fail;
			break;
		default:
			break;
		}
	}
	return 0;

fail:
	tk_log_warn("'%s' attr-prereq failed", ap->attr_name);
	return 1;
}

/* do we need to run the external program?
 * or we already done that and waiting for the outcome
 * or program exited and we can collect the status
 * return codes
 * 0: no program defined
 * RUNCMD_MORE: program forked, results later
 * != 0: executing program failed (or some other failure)
 */

static int do_ext_prog(struct ticket_config *tk,
		int start_election)
{
	int rv = 0;

	if (!tk_test.path)
		return 0;

	switch(tk_test.progstate) {
	case EXTPROG_IDLE:
		rv = run_handler(tk);
		if (rv == RUNCMD_ERR) {
			tk_log_warn("couldn't run external test, not allowed to acquire ticket");
			ext_prog_failed(tk, start_election);
		}
		break;
	case EXTPROG_RUNNING:
		/* should never get here, but just in case */
		rv = RUNCMD_MORE;
		break;
	case EXTPROG_EXITED:
		rv = tk_test_exit_status(tk);
		if (rv) {
			ext_prog_failed(tk, start_election);
		}
		break;
	case EXTPROG_IGNORE:
		/* nothing to do here */
		break;
	}

	return rv;
}


/* Try to acquire a ticket
 * Could be manual grant or after start (if the ticket is granted
 * and still valid in the CIB)
 * If the external program needs to run, this is run twice, once
 * to start the program, and then to get the result and start
 * elections.
 */
int acquire_ticket(struct ticket_config *tk, cmd_reason_t reason)
{
	int rv;

	if (reason == OR_ADMIN && check_attr_prereq(tk, GRANT_MANUAL))
		return RLT_ATTR_PREREQ;

	switch(do_ext_prog(tk, 0)) {
	case 0:
		/* everything fine */
		break;
	case RUNCMD_MORE:
		/* need to wait for the outcome before starting elections */
		return 0;
	default:
		return RLT_EXT_FAILED;
	}

	rv = new_election(tk, local, 1, reason);
	return rv ? RLT_SYNC_FAIL : 0;
}


/** Try to get the ticket for the local site.
 * */
int do_grant_ticket(struct ticket_config *tk, int options)
{
	int rv;

	tk_log_info("granting ticket");

	if (tk->leader == local)
		return RLT_SUCCESS;
	if (is_owned(tk))
		return RLT_OVERGRANT;

	set_future_time(&tk->delay_commit, tk->term_duration + tk->acquire_after);

	if (options & OPT_IMMEDIATE) {
		tk_log_warn("granting ticket immediately! If there are "
				"unreachable sites, _hope_ you are sure that they don't "
				"have the ticket!");
		time_reset(&tk->delay_commit);
	}

	rv = acquire_ticket(tk, OR_ADMIN);
	if (rv) {
		time_reset(&tk->delay_commit);
		return rv;
	} else {
		return RLT_MORE;
	}
}

static void start_revoke_ticket(struct ticket_config *tk)
{
	tk_log_info("revoking ticket");

	save_committed_tkt(tk);
	reset_ticket(tk);
	set_leader(tk, no_leader);
	ticket_write(tk);
	ticket_broadcast(tk, OP_REVOKE, OP_ACK, RLT_SUCCESS, OR_ADMIN);
}

/** Ticket revoke.
 * Only to be started from the leader. */
int do_revoke_ticket(struct ticket_config *tk)
{
	if (tk->acks_expected) {
		tk_log_info("delay ticket revoke until the current operation finishes");
		set_next_state(tk, ST_INIT);
		return RLT_MORE;
	} else {
		start_revoke_ticket(tk);
		return RLT_SUCCESS;
	}
}


int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket_config *tk;
	char timeout_str[64];
	char pending_str[64];
	char *data, *cp;
	int i, alloc;
	time_t ts;

	*pdata = NULL;
	*len = 0;

	alloc = 256 +
		booth_conf->ticket_count * (BOOTH_NAME_LEN * 2 + 128);
	data = malloc(alloc);
	if (!data)
		return -ENOMEM;

	cp = data;
	foreach_ticket(i, tk) {
		if (is_time_set(&tk->term_expires)) {
			ts = wall_ts(&tk->term_expires);
			strftime(timeout_str, sizeof(timeout_str), "%F %T",
					localtime(&ts));
		} else
			strcpy(timeout_str, "INF");

		if (tk->leader == local && is_time_set(&tk->delay_commit)
				&& !is_past(&tk->delay_commit)) {
			ts = wall_ts(&tk->delay_commit);
			strcpy(pending_str, " (commit pending until ");
			strftime(pending_str + strlen(" (commit pending until "),
					sizeof(pending_str) - strlen(" (commit pending until ") - 1,
					"%F %T", localtime(&ts));
			strcat(pending_str, ")");
		} else
			*pending_str = '\0';

		cp += snprintf(cp,
				alloc - (cp - data),
				"ticket: %s, leader: %s",
				tk->name,
				ticket_leader_string(tk));

		if (is_owned(tk)) {
			cp += snprintf(cp,
					alloc - (cp - data),
					", expires: %s%s\n",
					timeout_str,
					pending_str);
		} else {
			cp += snprintf(cp, alloc - (cp - data), "\n");
		}

		if (alloc - (cp - data) <= 0)
			return -ENOMEM;
	}

	*pdata = data;
	*len = cp - data;

	return 0;
}


void disown_ticket(struct ticket_config *tk)
{
	set_leader(tk, NULL);
	tk->is_granted = 0;
	get_time(&tk->term_expires);
}

int disown_if_expired(struct ticket_config *tk)
{
	if (is_past(&tk->term_expires) ||
			!tk->leader) {
		disown_ticket(tk);
		return 1;
	}

	return 0;
}

void reset_ticket(struct ticket_config *tk)
{
	ignore_ext_test(tk);
	disown_ticket(tk);
	no_resends(tk);
	set_state(tk, ST_INIT);
	tk->voted_for = NULL;
}


static void log_reacquire_reason(struct ticket_config *tk)
{
	int valid;
	const char *where_granted = "\0";
	char buff[64];

	valid = is_time_set(&tk->term_expires) && !is_past(&tk->term_expires);

	if (tk->leader == local) {
		where_granted = "granted here";
	} else {
		snprintf(buff, sizeof(buff), "granted to %s",
			site_string(tk->leader));
		where_granted = buff;
	}

	if (!valid) {
		tk_log_warn("%s, but not valid "
			"anymore (will try to reacquire)", where_granted);
	}
	if (tk->is_granted && tk->leader != local) {
		if (tk->leader && tk->leader != no_leader) {
			tk_log_error("granted here, but also %s, "
				"that's really too bad (will try to reacquire)",
				where_granted);
		} else {
			tk_log_warn("granted here, but we're "
				"not recorded as the grantee (will try to reacquire)");
		}
	}
}

void update_ticket_state(struct ticket_config *tk, struct booth_site *sender)
{
	if (tk->state == ST_CANDIDATE) {
		tk_log_info("learned from %s about "
				"newer ticket, stopping elections",
				site_string(sender));
		/* there could be rejects coming from others; don't log
		 * warnings unnecessarily */
		tk->expect_more_rejects = 1;
	}

	if (tk->leader == local || tk->is_granted) {
		/* message from a live leader with valid ticket? */
		if (sender == tk->leader && term_time_left(tk)) {
			if (tk->is_granted) {
				tk_log_warn("ticket was granted here, "
						"but it's live at %s (revoking here)",
						site_string(sender));
			} else {
				tk_log_info("ticket live at %s",
						site_string(sender));
			}
			disown_ticket(tk);
			ticket_write(tk);
			set_state(tk, ST_FOLLOWER);
			set_next_state(tk, ST_FOLLOWER);
		} else {
			if (tk->state == ST_CANDIDATE) {
				set_state(tk, ST_FOLLOWER);
			}
			set_next_state(tk, ST_LEADER);
		}
	} else {
		if (!tk->leader || tk->leader == no_leader) {
			if (sender)
				tk_log_info("ticket is not granted");
			else
				tk_log_info("ticket is not granted (from CIB)");
			set_state(tk, ST_INIT);
		} else {
			if (sender)
				tk_log_info("ticket granted to %s (says %s)",
					site_string(tk->leader),
					tk->leader == sender ? "they" : site_string(sender));
			else
				tk_log_info("ticket granted to %s (from CIB)",
					site_string(tk->leader));
			set_state(tk, ST_FOLLOWER);
			/* just make sure that we check the ticket soon */
			set_next_state(tk, ST_FOLLOWER);
		}
	}
}

int setup_ticket(void)
{
	struct ticket_config *tk;
	int i;

	foreach_ticket(i, tk) {
		reset_ticket(tk);

		if (local->type == SITE) {
			if (!pcmk_handler.load_ticket(tk)) {
				update_ticket_state(tk, NULL);
			}
			tk->update_cib = 1;
		}

		tk_log_info("broadcasting state query");
		/* wait until all send their status (or the first
		 * timeout) */
		tk->start_postpone = 1;
		ticket_broadcast(tk, OP_STATUS, OP_MY_INDEX, RLT_SUCCESS, 0);
	}

	return 0;
}


int ticket_answer_list(int fd)
{
	char *data;
	int rv;
	unsigned int olen;
	struct boothc_hdr_msg hdr;

	rv = list_ticket(&data, &olen);
	if (rv < 0)
		goto out;

	init_header(&hdr.header, CL_LIST, 0, 0, RLT_SUCCESS, 0, sizeof(hdr) + olen);
	rv = send_header_plus(fd, &hdr, data, olen);

out:
	if (data)
		free(data);
	return rv;
}


int process_client_request(struct client *req_client, void *buf)
{
	int rv, rc = 1;
	struct ticket_config *tk;
	int cmd;
	struct boothc_ticket_msg omsg;
	struct boothc_ticket_msg *msg;

	msg = (struct boothc_ticket_msg *)buf;
	cmd = ntohl(msg->header.cmd);
	if (!check_ticket(msg->ticket.id, &tk)) {
		log_warn("client referenced unknown ticket %s",
				msg->ticket.id);
		rv = RLT_INVALID_ARG;
		goto reply_now;
	}

	if ((cmd == CMD_GRANT) && is_owned(tk)) {
		log_warn("client wants to grant an (already granted!) ticket %s",
				msg->ticket.id);
		rv = RLT_OVERGRANT;
		goto reply_now;
	}

	if ((cmd == CMD_REVOKE) && !is_owned(tk)) {
		log_info("client wants to revoke a free ticket %s",
				msg->ticket.id);
		rv = RLT_TICKET_IDLE;
		goto reply_now;
	}

	if ((cmd == CMD_REVOKE) && tk->leader != local) {
		tk_log_info("not granted here, redirect to %s",
				ticket_leader_string(tk));
		rv = RLT_REDIRECT;
		goto reply_now;
	}

	if (cmd == CMD_REVOKE)
		rv = do_revoke_ticket(tk);
	else
		rv = do_grant_ticket(tk, ntohl(msg->header.options));

	if (rv == RLT_MORE) {
		/* client may receive further notifications, save the
		 * request for further processing */
		add_req(tk, req_client, msg);
		tk_log_debug("queue request %s for client %d",
			state_to_string(cmd), req_client->fd);
		rc = 0; /* we're not yet done with the message */
	}

reply_now:
	init_ticket_msg(&omsg, CL_RESULT, 0, rv, 0, tk);
	send_client_msg(req_client->fd, &omsg);
	return rc;
}

int notify_client(struct ticket_config *tk, int client_fd,
    struct boothc_ticket_msg *msg)
{
	struct boothc_ticket_msg omsg;
	void (*deadfn) (int ci);
	int rv, rc, ci;
	int cmd, options;
	struct client *req_client;

	cmd = ntohl(msg->header.cmd);
	options = ntohl(msg->header.options);
	rv = tk->outcome;
	ci = find_client_by_fd(client_fd);
	if (ci < 0) {
		tk_log_info("client %d (request %s) left before being notified",
			client_fd, state_to_string(cmd));
		return 0;
	}
	tk_log_debug("notifying client %d (request %s)",
		client_fd, state_to_string(cmd));
	init_ticket_msg(&omsg, CL_RESULT, 0, rv, 0, tk);
	rc = send_client_msg(client_fd, &omsg);

	if (rc == 0 && ((rv == RLT_MORE) ||
			(rv == RLT_CIB_PENDING && (options & OPT_WAIT_COMMIT)))) {
		/* more to do here, keep the request */
		return 1;
	} else {
		/* we sent a definite answer or there was a write error, drop
		 * the client */
		if (rc) {
			tk_log_debug("failed to notify client %d (request %s)",
				client_fd, state_to_string(cmd));
		} else {
			tk_log_debug("client %d (request %s) got final notification",
				client_fd, state_to_string(cmd));
		}
		req_client = clients + ci;
		deadfn = req_client->deadfn;
		if(deadfn) {
			deadfn(ci);
		}
		return 0; /* we're done with this request */
	}
}

int ticket_broadcast(struct ticket_config *tk,
		cmd_request_t cmd, cmd_request_t expected_reply,
		cmd_result_t res, cmd_reason_t reason)
{
	struct boothc_ticket_msg msg;

	init_ticket_msg(&msg, cmd, 0, res, reason, tk);
	tk_log_debug("broadcasting '%s' (term=%d, valid=%d)",
			state_to_string(cmd),
			ntohl(msg.ticket.term),
			msg_term_time(&msg));

	tk->last_request = cmd;
	if (expected_reply) {
		expect_replies(tk, expected_reply);
	}
	ticket_activate_timeout(tk);
	return transport()->broadcast_auth(&msg, sendmsglen(&msg));
}


/* update the ticket on the leader, write it to the CIB, and
   send out the update message to others with the new expiry
   time
*/
int leader_update_ticket(struct ticket_config *tk)
{
	int rv = 0, rv2;
	timetype now;

	if (tk->ticket_updated >= 2)
		return 0;

	if (tk->ticket_updated < 1) {
		tk->ticket_updated = 1;
		get_time(&now);
		copy_time(&now, &tk->last_renewal);
		set_future_time(&tk->term_expires, tk->term_duration);
		rv = ticket_broadcast(tk, OP_UPDATE, OP_ACK, RLT_SUCCESS, 0);
	}

	if (tk->ticket_updated < 2) {
		rv2 = ticket_write(tk);
		switch(rv2) {
		case 0:
			tk->ticket_updated = 2;
			tk->outcome = RLT_SUCCESS;
			foreach_tkt_req(tk, notify_client);
			break;
		case 1:
			if (tk->outcome != RLT_CIB_PENDING) {
				tk->outcome = RLT_CIB_PENDING;
				foreach_tkt_req(tk, notify_client);
			}
			break;
		default:
			break;
		}
	}

	return rv;
}


static void log_lost_servers(struct ticket_config *tk)
{
	struct booth_site *n;
	int i;

	if (tk->retry_number > 1)
		/* log those that we couldn't reach, but do
		 * that only on the first retry
		 */
		return;

	for (i = 0; i < booth_conf->site_count; i++) {
		n = booth_conf->site + i;
		if (!(tk->acks_received & n->bitmask)) {
			tk_log_warn("%s %s didn't acknowledge our %s, "
			"will retry %d times",
			(n->type == ARBITRATOR ? "arbitrator" : "site"),
			site_string(n),
			state_to_string(tk->last_request),
			tk->retries);
		}
	}
}

static void resend_msg(struct ticket_config *tk)
{
	struct booth_site *n;
	int i;

	if (!(tk->acks_received ^ local->bitmask)) {
		ticket_broadcast(tk, tk->last_request, 0, RLT_SUCCESS, 0);
	} else {
		for (i = 0; i < booth_conf->site_count; i++) {
			n = booth_conf->site + i;
			if (!(tk->acks_received & n->bitmask)) {
				n->resend_cnt++;
				tk_log_debug("resending %s to %s",
						state_to_string(tk->last_request),
						site_string(n)
						);
				send_msg(tk->last_request, tk, n, NULL);
			}
		}
		ticket_activate_timeout(tk);
	}
}

static void handle_resends(struct ticket_config *tk)
{
	int ack_cnt;

	if (++tk->retry_number > tk->retries) {
		tk_log_info("giving up on sending retries");
		no_resends(tk);
		set_ticket_wakeup(tk);
		return;
	}

	/* try to reach some sites again if we just stepped down */
	if (tk->last_request == OP_VOTE_FOR) {
		tk_log_warn("no answers to our VtFr request to step down (try #%d), "
		"we are alone",
		tk->retry_number);
		goto just_resend;
	}

	if (!majority_of_bits(tk, tk->acks_received)) {
		ack_cnt = count_bits(tk->acks_received) - 1;
		if (!ack_cnt) {
			tk_log_warn("no answers to our request (try #%d), "
			"we are alone",
			tk->retry_number);
		} else {
			tk_log_warn("not enough answers to our request (try #%d): "
			"only got %d answers",
			tk->retry_number,
			ack_cnt);
		}
	} else {
		log_lost_servers(tk);
	}

just_resend:
	resend_msg(tk);
}

int postpone_ticket_processing(struct ticket_config *tk)
{
	extern timetype start_time;

	return tk->start_postpone &&
		(-time_left(&start_time) < tk->timeout);
}

#define has_extprog_exited(tk) ((tk)->clu_test.progstate == EXTPROG_EXITED)

static void process_next_state(struct ticket_config *tk)
{
	int rv;

	switch(tk->next_state) {
	case ST_LEADER:
		if (has_extprog_exited(tk)) {
			if (tk->state != ST_LEADER) {
				rv = acquire_ticket(tk, OR_ADMIN);
				if (rv != 0) { /* external program failed */
					tk->outcome = rv;
					foreach_tkt_req(tk, notify_client);
				}
			}
		} else {
			log_reacquire_reason(tk);
			acquire_ticket(tk, OR_REACQUIRE);
		}
		break;
	case ST_INIT:
		no_resends(tk);
		start_revoke_ticket(tk);
		tk->outcome = RLT_SUCCESS;
		foreach_tkt_req(tk, notify_client);
		break;
	/* wanting to be follower is not much of an ambition; no
	 * processing, just return; don't reset start_postpone until
	 * we got some replies to status */
	case ST_FOLLOWER:
		return;
	default:
		break;
	}
	tk->start_postpone = 0;
}

static void ticket_lost(struct ticket_config *tk)
{
	int reason = OR_TKT_LOST;

	if (tk->leader != local) {
		tk_log_warn("lost at %s", site_string(tk->leader));
	} else {
		if (is_ext_prog_running(tk)) {
			ext_prog_timeout(tk);
			reason = OR_LOCAL_FAIL;
		} else {
			tk_log_warn("lost majority (revoking locally)");
			reason = tk->election_reason ? tk->election_reason : OR_REACQUIRE;
		}
	}

	tk->lost_leader = tk->leader;
	save_committed_tkt(tk);
	reset_ticket(tk);
	set_state(tk, ST_FOLLOWER);
	if (local->type == SITE) {
		ticket_write(tk);
		schedule_election(tk, reason);
	}
}

static void next_action(struct ticket_config *tk)
{
	int rv;

	switch(tk->state) {
	case ST_INIT:
		/* init state, handle resends for ticket revoke */
		/* and rebroadcast if stepping down */
		/* try to acquire ticket on grant */
		if (has_extprog_exited(tk)) {
			rv = acquire_ticket(tk, OR_ADMIN);
			if (rv != 0) { /* external program failed */
				tk->outcome = rv;
				foreach_tkt_req(tk, notify_client);
			}
		} else {
			if (tk->acks_expected) {
				handle_resends(tk);
			}
		}
		break;

	case ST_FOLLOWER:
		/* leader/ticket lost? and we didn't vote yet */
		tk_log_debug("leader: %s, voted_for: %s",
				site_string(tk->leader),
				site_string(tk->voted_for));
		if (!tk->leader) {
			if (!tk->voted_for || !tk->in_election) {
				disown_ticket(tk);
				if (!new_election(tk, NULL, 1, OR_AGAIN)) {
					ticket_activate_timeout(tk);
				}
			} else {
				/* we should restart elections in case nothing
				 * happens in the meantime */
				tk->in_election = 0;
				ticket_activate_timeout(tk);
			}
		}
		break;

	case ST_CANDIDATE:
		/* elections timed out? */
		elections_end(tk);
		break;

	case ST_LEADER:
		/* timeout or ticket renewal? */
		if (tk->acks_expected) {
			handle_resends(tk);
			if (majority_of_bits(tk, tk->acks_received)) {
				leader_update_ticket(tk);
			}
		} else {
			/* this is ticket renewal, run local test */
			if (!do_ext_prog(tk, 1)) {
				ticket_broadcast(tk, OP_HEARTBEAT, OP_ACK, RLT_SUCCESS, 0);
				tk->ticket_updated = 0;
			}
		}
		break;

	default:
		break;
	}
}

static void ticket_cron(struct ticket_config *tk)
{
	/* don't process the tickets too early after start */
	if (postpone_ticket_processing(tk)) {
		tk_log_debug("ticket processing postponed (start_postpone=%d)",
				tk->start_postpone);
		/* but run again soon */
		ticket_activate_timeout(tk);
		return;
	}

	/* no need for status resends, we hope we got at least one
	 * my_index back */
	if (tk->acks_expected == OP_MY_INDEX) {
		no_resends(tk);
	}

	/* after startup, we need to decide what to do based on the
	 * current ticket state; tk->next_state has a hint
	 * also used for revokes which had to be delayed
	 */
	if (tk->next_state) {
		process_next_state(tk);
		goto out;
	}

	/* Has an owner, has an expiry date, and expiry date in the past?
	 * Losing the ticket must happen in _every_ state.
	 */
	if (is_owned(tk) && is_time_set(&tk->term_expires)
			&& is_past(&tk->term_expires)) {
		ticket_lost(tk);
		goto out;
	}

	next_action(tk);

out:
	tk->next_state = 0;
	if (!tk->in_election && tk->update_cib)
		ticket_write(tk);
}


void process_tickets(void)
{
	struct ticket_config *tk;
	int i;
	timetype last_cron;

	foreach_ticket(i, tk) {
		if (!has_extprog_exited(tk) &&
				is_time_set(&tk->next_cron) && !is_past(&tk->next_cron))
			continue;

		tk_log_debug("ticket cron");

		copy_time(&tk->next_cron, &last_cron);
		ticket_cron(tk);
		if (time_cmp(&last_cron, &tk->next_cron, ==)) {
			tk_log_debug("nobody set ticket wakeup");
			set_ticket_wakeup(tk);
		}
	}
}



void tickets_log_info(void)
{
	struct ticket_config *tk;
	int i;
	time_t ts;

	foreach_ticket(i, tk) {
		ts = wall_ts(&tk->term_expires);
		tk_log_info("state '%s' "
				"term %d "
				"leader %s "
				"expires %-24.24s",
				state_to_string(tk->state),
				tk->current_term,
				ticket_leader_string(tk),
				ctime(&ts));
	}
}


static void update_acks(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t cmd;
	uint32_t req;

	cmd = ntohl(msg->header.cmd);
	req = ntohl(msg->header.request);
	if (req != tk->last_request ||
			(tk->acks_expected != cmd &&
			tk->acks_expected != OP_REJECTED))
		return;

	/* got an ack! */
	tk->acks_received |= sender->bitmask;

	if (all_replied(tk) ||
			/* we just stepped down, need only one site to start
			 * elections */
			(cmd == OP_REQ_VOTE && tk->last_request == OP_VOTE_FOR)) {
		no_resends(tk);
		tk->start_postpone = 0;
		set_ticket_wakeup(tk);
	}
}

/* read ticket message */
int ticket_recv(void *buf, struct booth_site *source)
{
	struct boothc_ticket_msg *msg;
	struct ticket_config *tk;
	struct booth_site *leader;
	uint32_t leader_u;

	msg = (struct boothc_ticket_msg *)buf;

	if (!check_ticket(msg->ticket.id, &tk)) {
		log_warn("got invalid ticket name %s from %s",
				msg->ticket.id, site_string(source));
		source->invalid_cnt++;
		return -EINVAL;
	}


	leader_u = ntohl(msg->ticket.leader);
	if (!find_site_by_id(leader_u, &leader)) {
		tk_log_error("message with unknown leader %u received", leader_u);
		source->invalid_cnt++;
		return -EINVAL;
	}

	update_acks(tk, source, leader, msg);

	return raft_answer(tk, source, leader, msg);
}


static void log_next_wakeup(struct ticket_config *tk)
{
	int left;

	left = time_left(&tk->next_cron);
	tk_log_debug("set ticket wakeup in " intfmt(left));
}

/* New vote round; §5.2 */
/* delay the next election start for some random time
 * (up to 1 second)
 */
void add_random_delay(struct ticket_config *tk)
{
	timetype tv;

	interval_add(&tk->next_cron, rand_time(min(1000, tk->timeout)), &tv);
	ticket_next_cron_at(tk, &tv);
	if (ANYDEBUG) {
		log_next_wakeup(tk);
	}
}

void set_ticket_wakeup(struct ticket_config *tk)
{
	timetype near_future, tv, next_vote;

	/* At least every hour, perhaps sooner (default) */
	ticket_next_cron_in(tk, 3600*TIME_RES);
	set_future_time(&near_future, 10);

	switch (tk->state) {
	case ST_LEADER:
		assert(tk->leader == local);

		get_next_election_time(tk, &next_vote);

		/* If timestamp is in the past, wakeup in
		 * near future */
		if (!is_time_set(&next_vote)) {
			tk_log_debug("next ts unset, wakeup soon");
			ticket_next_cron_at(tk, &near_future);
		} else if (is_past(&next_vote)) {
			int tdiff = time_left(&next_vote);
			tk_log_debug("next ts in the past " intfmt(tdiff));
			ticket_next_cron_at(tk, &near_future);
		} else {
			ticket_next_cron_at(tk, &next_vote);
		}
		break;

	case ST_CANDIDATE:
		assert(is_time_set(&tk->election_end));
		ticket_next_cron_at(tk, &tk->election_end);
		break;

	case ST_INIT:
	case ST_FOLLOWER:
		/* If there is (or should be) some owner, check on it later on.
		 * If no one is interested - don't care. */
		if (is_owned(tk)) {
			interval_add(&tk->term_expires, tk->acquire_after, &tv);
			ticket_next_cron_at(tk, &tv);
		}
		break;

	default:
		tk_log_error("unknown ticket state: %d", tk->state);
	}

	if (tk->next_state) {
		/* we need to do something soon here */
		if (!tk->acks_expected) {
			ticket_next_cron_at(tk, &near_future);
		} else {
			ticket_activate_timeout(tk);
		}
	}

	if (ANYDEBUG) {
		log_next_wakeup(tk);
	}
}


void schedule_election(struct ticket_config *tk, cmd_reason_t reason)
{
	if (local->type != SITE)
		return;

	tk->election_reason = reason;
	get_time(&tk->next_cron);
	/* introduce a short delay before starting election */
	add_random_delay(tk);
}


/* Given a state (in host byte order), return a human-readable (char*).
 * An array is used so that multiple states can be printed in a single printf(). */
char *state_to_string(uint32_t state_ho)
{
	union mu { cmd_request_t s; char c[5]; };
	static union mu cache[6] = { { 0 } }, *cur;
	static int current = 0;

	current ++;
	if (current >= sizeof(cache)/sizeof(cache[0]))
		current = 0;

	cur = cache + current;

	cur->s = htonl(state_ho);
	/* Shouldn't be necessary, union array is initialized with zeroes, and
	 * these bytes never get written. */
	cur->c[4] = 0;
	return cur->c;
}


int send_reject(struct booth_site *dest, struct ticket_config *tk,
		cmd_result_t code, struct boothc_ticket_msg *in_msg)
{
	int req = ntohl(in_msg->header.cmd);
	struct boothc_ticket_msg msg;

	tk_log_debug("sending reject to %s",
			site_string(dest));
	init_ticket_msg(&msg, OP_REJECTED, req, code, 0, tk);
	return booth_udp_send_auth(dest, &msg, sendmsglen(&msg));
}

int send_msg (
		int cmd,
		struct ticket_config *tk,
		struct booth_site *dest,
		struct boothc_ticket_msg *in_msg
	       )
{
	int req = 0;
	struct ticket_config *valid_tk = tk;
	struct boothc_ticket_msg msg;

	/* if we want to send the last valid ticket, then if we're in
	 * the ST_CANDIDATE state, the last valid ticket is in
	 * tk->last_valid_tk
	 */
	if (cmd == OP_MY_INDEX) {
		if (tk->state == ST_CANDIDATE && tk->last_valid_tk) {
			valid_tk = tk->last_valid_tk;
		}
		tk_log_info("sending status to %s",
				site_string(dest));
	}

	if (in_msg)
		req = ntohl(in_msg->header.cmd);

	init_ticket_msg(&msg, cmd, req, RLT_SUCCESS, 0, valid_tk);
	return booth_udp_send_auth(dest, &msg, sendmsglen(&msg));
}
