/*
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
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

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <clplumbing/cl_random.h>
#include "booth.h"
#include "transport.h"
#include "inline-fn.h"
#include "config.h"
#include "raft.h"
#include "ticket.h"
#include "log.h"



inline static void clear_election(struct ticket_config *tk)
{
	int i;
	struct booth_site *site;

	tk_log_debug("clear election");
	tk->votes_received = 0;
	foreach_node(i, site)
		tk->votes_for[site->index] = NULL;
}


inline static void record_vote(struct ticket_config *tk,
		struct booth_site *who,
		struct booth_site *vote)
{
	tk_log_debug("site %s votes for %s",
			site_string(who),
			site_string(vote));

	if (!tk->votes_for[who->index]) {
		tk->votes_for[who->index] = vote;
		tk->votes_received |= who->bitmask;
	} else {
		if (tk->votes_for[who->index] != vote)
			tk_log_warn("%s voted previously "
					"for %s and now wants to vote for %s (ignored)",
					site_string(who),
					site_string(tk->votes_for[who->index]),
					site_string(vote));
	}
}


static int cmp_msg_ticket(struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg)
{
	if (tk->current_term != ntohl(msg->ticket.term)) {
		return tk->current_term - ntohl(msg->ticket.term);
	}
	/* compare commit_index only from the leader */
	if (sender == leader) {
		return tk->commit_index - ntohl(msg->ticket.leader_commit);
	}
	return 0;
}

static void update_term_from_msg(struct ticket_config *tk,
		struct boothc_ticket_msg *msg)
{
	uint32_t i;


	i = ntohl(msg->ticket.term);
	/* if we failed to start the election, then accept the term
	 * from the leader
	 * */
	if (tk->state == ST_CANDIDATE) {
		tk->current_term = i;
	} else {
		tk->current_term = max(i, tk->current_term);
	}

	/* § 5.3 */
	i = ntohl(msg->ticket.leader_commit);
	tk->commit_index = max(i, tk->commit_index);
}


static void update_ticket_from_msg(struct ticket_config *tk,
		struct boothc_ticket_msg *msg)
{
	int duration;

	duration = tk->term_duration;
	if (msg)
		duration = min(duration, ntohl(msg->ticket.term_valid_for));
	tk->term_expires = time(NULL) + duration;

	if (msg) {
		update_term_from_msg(tk, msg);
	}
}


static void copy_ticket_from_msg(struct ticket_config *tk,
		struct boothc_ticket_msg *msg)
{
	if (msg) {
		tk->term_expires = time(NULL) + ntohl(msg->ticket.term_valid_for);
		tk->current_term = ntohl(msg->ticket.term);
		tk->commit_index = ntohl(msg->ticket.leader_commit);
	} else {
		tk->term_expires = time(NULL) + tk->term_duration;
	}
}

static void become_follower(struct ticket_config *tk,
		struct boothc_ticket_msg *msg)
{
	copy_ticket_from_msg(tk, msg);
	tk->state = ST_FOLLOWER;
	tk->delay_commit = 0;
	/* if we're following and the ticket was granted here
	 * then commit to CIB right away (we're probably restarting)
	 */
	if (tk->is_granted) {
		disown_ticket(tk);
		ticket_write(tk);
	}
}


static void won_elections(struct ticket_config *tk)
{
	tk->leader = local;
	tk->state = ST_LEADER;

	tk->term_expires = time(NULL) + tk->term_duration;
	tk->election_end = 0;
	tk->voted_for = NULL;

	tk->commit_index++;
	send_heartbeat(tk);
	ticket_activate_timeout(tk);
}


static int is_tie(struct ticket_config *tk)
{
	int i;
	struct booth_site *v;
	int count[MAX_NODES] = { 0, };
	int max_votes = 0, max_cnt = 0;

	for(i=0; i<booth_conf->site_count; i++) {
		v = tk->votes_for[i];
		if (!v)
			continue;
		count[v->index]++;
		max_votes = max(max_votes, count[v->index]);
	}

	for(i=0; i<booth_conf->site_count; i++) {
		if (count[i] == max_votes)
			max_cnt++;
	}

	return max_cnt > 1;
}

static struct booth_site *majority_votes(struct ticket_config *tk)
{
	int i, n;
	struct booth_site *v;
	int count[MAX_NODES] = { 0, };


	for(i=0; i<booth_conf->site_count; i++) {
		v = tk->votes_for[i];
		if (!v)
			continue;

		n = v->index;
		count[n]++;
		tk_log_debug("Majority: %d %s wants %d %s => %d",
				i, site_string(&booth_conf->site[i]),
				n, site_string(v),
				count[n]);

		if (count[n]*2 <= booth_conf->site_count)
			continue;


		tk_log_debug("Majority reached: %d of %d for %s",
				count[n], booth_conf->site_count,
				site_string(v));
		return v;
	}

	return NULL;
}


void elections_end(struct ticket_config *tk)
{
	time_t now;
	struct booth_site *new_leader;

	now = time(NULL);
	if (now > tk->election_end) {
		/* This is previous election timed out */
		tk_log_info("election timed out");
	}

	new_leader = majority_votes(tk);
	if (new_leader == local) {
		tk_log_info("granted successfully here");
		won_elections(tk);
	} else if (new_leader) {
		tk_log_info("ticket granted at %s",
				site_string(new_leader));
		become_follower(tk, NULL);
		set_ticket_wakeup(tk);
	} else {
		tk_log_info("nobody won elections, new elections");
		new_election(tk, NULL, is_tie(tk), OR_AGAIN);
	}
}


static int newer_term(struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg,
		int in_election)
{
	uint32_t term;

	/* it may happen that we hear about our newer term */
	if (leader == local)
		return 0;

	term = ntohl(msg->ticket.term);
	/* §5.1 */
	if (term > tk->current_term) {
		tk->state = ST_FOLLOWER;
		if (!in_election) {
			tk->leader = leader;
			tk_log_info("from %s: higher term %d vs. %d, following %s",
					site_string(sender),
					term, tk->current_term,
					ticket_leader_string(tk));
		} else {
			tk->leader = no_leader;
			tk_log_debug("from %s: higher term %d vs. %d (election)",
					site_string(sender),
					term, tk->current_term);
		}

		tk->current_term = term;
		return 1;
	}

	return 0;
}

static int term_too_low(struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg)
{
	uint32_t term;

	term = ntohl(msg->ticket.term);
	/* §5.1 */
	if (term < tk->current_term) {
		tk_log_info("sending reject to %s, its term too low "
			"(%d vs. %d)", site_string(sender),
			term, tk->current_term
			);
		send_reject(sender, tk, RLT_TERM_OUTDATED);
		return 1;
	}

	return 0;
}




/* For follower. */
static int answer_HEARTBEAT (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;
	struct boothc_ticket_msg omsg;


	term = ntohl(msg->ticket.term);
	tk_log_debug("leader: %s, have %s; term %d vs %d",
			site_string(leader), ticket_leader_string(tk),
			term, tk->current_term);

	/* got heartbeat, no rejects expected anymore */
	tk->expect_more_rejects = 0;

	/* if we're candidate, it may be that we got a heartbeat from
	 * a legitimate leader, so don't ignore a lower term
	 */
	if (tk->state != ST_CANDIDATE && term < tk->current_term) {
		tk_log_info("ignoring lower term %d vs. %d, from %s",
				term, tk->current_term,
				ticket_leader_string(tk));
		return 0;
	}

	/* Needed? */
	newer_term(tk, sender, leader, msg, 0);

	become_follower(tk, msg);
	/* Racy??? */
	assert(sender == leader || !leader);

	tk->leader = leader;

	/* Ack the heartbeat (we comply). */
	init_ticket_msg(&omsg, OP_HEARTBEAT, RLT_SUCCESS, 0, tk);
	return booth_udp_send(sender, &omsg, sizeof(omsg));
}


static int process_UPDATE (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;


	term = ntohl(msg->ticket.term);
	tk_log_debug("leader: %s, have %s; term %d vs %d",
			site_string(leader), ticket_leader_string(tk),
			term, tk->current_term);

	/* No reject. (?) */
	if (term < tk->current_term) {
		tk_log_info("ignoring lower term %d vs. %d, from %s",
				term, tk->current_term,
				ticket_leader_string(tk));
		return 0;
	}

	update_ticket_from_msg(tk, msg);
	ticket_write(tk);

	/* run ticket_cron if the ticket expires */
	set_ticket_wakeup(tk);

	return 0;
}

static int process_REVOKE (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	if (tk->leader != sender) {
		tk_log_error("%s wants to revoke ticket, "
				"but it is not granted there (ignoring)",
				site_string(sender));
		return 1;
	} else if (tk->state != ST_FOLLOWER) {
		tk_log_error("unexpected ticket revoke from %s "
				"(in state %s) (ignoring)",
				site_string(sender),
				state_to_string(tk->state));
		return 1;
	} else {
		tk_log_info("%s revokes ticket",
				site_string(tk->leader));
		reset_ticket(tk);
		tk->leader = no_leader;
		ticket_write(tk);
	}

	return 0;
}


/* For leader. */
static int process_HEARTBEAT(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;

	term = ntohl(msg->ticket.term);

	if (newer_term(tk, sender, leader, msg, 0)) {
		/* unexpected higher term */
		tk_log_warn("got higher term from %s (%d vs. %d)",
				site_string(sender),
				term, tk->current_term);
		return 0;
	}

	/* Don't send a reject. */
	if (term < tk->current_term) {
		/* Doesn't know what he's talking about - perhaps
		 * doesn't receive our packets? */
		tk_log_warn("unexpected term "
				"from %s (%d vs. %d) (ignoring)",
				site_string(sender),
				term, tk->current_term);
		return 0;
	}


	if (term == tk->current_term &&
			leader == tk->leader) {

		if (majority_of_bits(tk, tk->acks_received)) {
			/* OK, at least half of the nodes are reachable;
			 * Update the ticket and send update messages out
			 */
			return leader_update_ticket(tk);
		}
	}

	return 0;
}


static int process_VOTE_FOR(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	if (term_too_low(tk, sender, leader, msg))
		return 0;

	if (newer_term(tk, sender, leader, msg, 0)) {
		clear_election(tk);
	}


	/* leader wants to step down? */
	if (leader == no_leader && sender == tk->leader &&
			(tk->state == ST_FOLLOWER || tk->state == ST_CANDIDATE)) {
		tk_log_info("%s wants to give the ticket away",
			site_string(tk->leader));
		return new_round(tk, OR_STEPDOWN);
	}

	record_vote(tk, sender, leader);


	if (tk->state != ST_CANDIDATE) {
		/* lost candidate status, somebody rejected our proposal */
		return 0;
	}


	/* only if all voted can we take the ticket now, otherwise
	 * wait for timeout in ticket_cron */
	if (!tk->acks_expected) {
		/* §5.2 */
		elections_end(tk);
	}

	return 0;
}


static int process_REJECTED(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	uint32_t rv;

	rv   = ntohl(msg->header.result);

	if (tk->state == ST_CANDIDATE &&
			leader == local) {
		/* the sender has us as the leader (!)
		 * the elections will time out, then we can try again
		 */
		tk_log_warn("ticket was granted to us "
				"(and we didn't know)");
		tk->expect_more_rejects = 1;
		return 0;
	}

	if (tk->state == ST_CANDIDATE &&
			rv == RLT_TERM_OUTDATED) {
		tk_log_warn("ticket outdated (term %d), granted to %s",
				ntohl(msg->ticket.term),
				site_string(leader)
				);
		tk->leader = leader;
		tk->expect_more_rejects = 1;
		become_follower(tk, msg);
		return 0;
	}

	if (tk->state == ST_CANDIDATE &&
			rv == RLT_TERM_STILL_VALID) {
		if (tk->lost_leader == leader) {
			if (tk->election_reason == OR_TKT_LOST) {
				tk_log_warn("%s still has the ticket valid, "
						"we'll backup a bit",
						site_string(sender));
			} else {
				tk_log_warn("%s unexpecetedly rejects elections",
						site_string(sender));
			}
		} else {
			tk_log_warn("ticket was granted to %s "
					"(and we didn't know)",
					site_string(leader));
		}
		tk->leader = leader;
		become_follower(tk, msg);
		tk->expect_more_rejects = 1;
		return 0;
	}

	if (tk->state == ST_CANDIDATE &&
			rv == RLT_YOU_OUTDATED) {
		tk->leader = leader;
		tk->expect_more_rejects = 1;
		if (leader && leader != no_leader) {
			tk_log_warn("our ticket is outdated, granted to %s",
				site_string(leader));
			become_follower(tk, msg);
		} else {
			tk_log_warn("our ticket is outdated and revoked");
			update_ticket_from_msg(tk, msg);
			tk->state = ST_INIT;
		}
		return 0;
	}

	if (!tk->expect_more_rejects) {
		tk_log_warn("from %s: in state %s, got %s (unexpected reject)",
				site_string(sender),
				state_to_string(tk->state),
				state_to_string(rv));
	}

	return 0;
}


static int ticket_seems_ok(struct ticket_config *tk)
{
	int time_left;

	time_left = term_time_left(tk);
	if (!time_left)
		return 0; /* quite sure */
	if (tk->state == ST_CANDIDATE)
		return 0; /* in state of flux */
	if (tk->state == ST_LEADER)
		return 1; /* quite sure */
	if (tk->state == ST_FOLLOWER &&
			time_left >= tk->term_duration/3)
		return 1; /* almost quite sure */
	return 0;
}


static int test_reason(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	int reason;

	reason = ntohl(msg->header.reason);
	if (reason == OR_TKT_LOST) {
		if (tk->state == ST_INIT &&
				tk->leader == no_leader) {
			tk_log_warn("%s claims that the ticket is lost, "
					"but it's in %s state (reject sent)",
					site_string(sender),
					state_to_string(tk->state)
				);
			return RLT_YOU_OUTDATED;
		}
		if (ticket_seems_ok(tk)) {
			tk_log_warn("%s claims that the ticket is lost, "
					"but it is ok here (reject sent)",
					site_string(sender));
			return RLT_TERM_STILL_VALID;
		}
	}
	return 0;
}


/* §5.2 */
static int answer_REQ_VOTE(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	uint32_t term;
	int valid;
	struct boothc_ticket_msg omsg;
	cmd_result_t inappr_reason;

	inappr_reason = test_reason(tk, sender, leader, msg);
	if (inappr_reason)
		return send_reject(sender, tk, inappr_reason);

	term = ntohl(msg->ticket.term);
	/* Important: Ignore duplicated packets! */
	valid = term_time_left(tk);
	if (valid &&
			term == tk->current_term &&
			sender == tk->leader) {
		tk_log_debug("Duplicate OP_VOTE_FOR ignored.");
		return 0;
	}

	/* allow the leader to start new elections on valid tickets */
	if (sender != tk->leader && valid) {
		tk_log_warn("election rejected, term still valid for %ds", valid);
		return send_reject(sender, tk, RLT_TERM_STILL_VALID);
	}

	if (term_too_low(tk, sender, leader, msg))
		return 0;

	/* if it's a newer term or ... */
	if (newer_term(tk, sender, leader, msg, 1)) {
		clear_election(tk);
		goto vote_for_sender;
	}


	/* ... we didn't vote yet, then vote for the sender */
	/* §5.2, §5.4 */
	if (!tk->voted_for) {
vote_for_sender:
		tk->voted_for = sender;
		record_vote(tk, sender, leader);
	}


	init_ticket_msg(&omsg, OP_VOTE_FOR, RLT_SUCCESS, 0, tk);
	omsg.ticket.leader = htonl(get_node_id(tk->voted_for));
	return booth_udp_send(sender, &omsg, sizeof(omsg));
}


int new_election(struct ticket_config *tk,
	struct booth_site *preference, int update_term, cmd_reason_t reason)
{
	struct booth_site *new_leader;
	time_t now;


	time(&now);
	tk_log_debug("start new election?, now=%" PRIi64 ", end %" PRIi64,
			(int64_t)now, (int64_t)(tk->election_end));
	if (now <= tk->election_end)
		return 0;


	/* §5.2 */
	/* If there was _no_ answer, don't keep incrementing the term number
	 * indefinitely. If there was no peer, there'll probably be no one
	 * listening now either. However, we don't know if we were
	 * invoked due to a timeout (caller does).
	 */
	if (update_term)
		tk->current_term++;

	tk->term_expires = 0;
	tk->election_end = now + tk->timeout;

	tk_log_info("starting new election (term=%d)",
			tk->current_term);
	clear_election(tk);

	if(preference)
		new_leader = preference;
	else
		new_leader = (local->type == SITE) ? local : NULL;
	record_vote(tk, local, new_leader);
	tk->voted_for = new_leader;

	tk->state = ST_CANDIDATE;

	/* some callers may want just to repeat on timeout */
	if (reason == OR_AGAIN) {
		reason = tk->election_reason;
	} else {
		tk->election_reason = reason;
	}

	expect_replies(tk, OP_VOTE_FOR);
	ticket_broadcast(tk, OP_REQ_VOTE, RLT_SUCCESS, reason);
	ticket_activate_timeout(tk);
	return 0;
}


int new_round(struct ticket_config *tk, cmd_reason_t reason)
{
	int rv = 0;
	struct timespec delay;

	if (local->type == ARBITRATOR) {
		/* we cannot really do anything, but keep the copy for
		 * somebody else who perhaps can */
		return 0;
	}

	disown_ticket(tk);
	ticket_write(tk);

	/* New vote round; §5.2 */
	/* delay the next election start for up to 200ms */
	delay.tv_sec = 0;
	delay.tv_nsec = 1000000L * (long)cl_rand_from_interval(0, 200);
	nanosleep(&delay, NULL);

	rv = new_election(tk, NULL, 1, reason);

	return rv;
}


/* we were a leader and somebody says that they have a more up
 * to date ticket
 * there was probably connectivity loss
 * tricky
 */
static int leader_handle_newer_ticket(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	update_term_from_msg(tk, msg);
	if (leader != no_leader && leader && leader != local) {
		/* eek, two leaders, split brain */
		/* normally shouldn't happen; run election */
		tk_log_error("from %s: ticket granted to %s! (revoking locally)",
				site_string(sender),
				site_string(leader)
				);
	} else if (term_time_left(tk)) {
		/* eek, two leaders, split brain */
		/* normally shouldn't happen; run election */
		tk_log_error("from %s: ticket granted to %s! (revoking locally)",
				site_string(sender),
				site_string(leader)
				);
	}
	tk->next_state = ST_LEADER;
	return 0;
}

/* reply to STATUS */
static int process_MY_INDEX (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	int i;
	int expired;

	expired = !msg->ticket.term_valid_for;
	i = cmp_msg_ticket(tk, sender, leader, msg);

	if (i > 0) {
		/* let them know about our newer ticket */
		send_msg(OP_MY_INDEX, tk, sender);
		if (tk->state == ST_LEADER) {
			tk_log_info("sending ticket update to %s",
					site_string(sender));
			return send_msg(OP_UPDATE, tk, sender);
		}
	}

	/* we have a newer or equal ticket and theirs is expired,
	 * nothing more to do here */
	if (i >= 0 && expired) {
		return 0;
	}

	if (tk->state == ST_LEADER) {
		/* we're the leader, thread carefully */
		if (expired) {
			/* if their ticket is expired,
			 * nothing more to do */
			return 0;
		}
		if (i < 0) {
			/* they have a newer ticket, trouble if we're already leader
			 * for it */
			tk_log_warn("from %s: more up to date ticket at %s",
					site_string(sender),
					site_string(leader)
					);
			return leader_handle_newer_ticket(tk, sender, leader, msg);
		} else {
			/* we have the ticket and we don't care */
			return 0;
		}
	}

	/* their ticket is either newer or not expired, don't
	 * ignore it */
	update_ticket_from_msg(tk, msg);
	tk->leader = leader;
	update_ticket_state(tk, sender);
	set_ticket_wakeup(tk);
	return 0;
}


int raft_answer(
		struct ticket_config *tk,
		struct booth_site *from,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	int cmd;
	int rv;

	rv = 0;
	cmd = ntohl(msg->header.cmd);

	tk_log_debug("got message %s from %s",
			state_to_string(cmd),
			site_string(from));


	switch (cmd) {
	case OP_REQ_VOTE:
		rv = answer_REQ_VOTE(tk, from, leader, msg);
		break;
	case OP_VOTE_FOR:
		rv = process_VOTE_FOR(tk, from, leader, msg);
		break;
	case OP_HEARTBEAT:
		if (tk->leader == local &&
				tk->state == ST_LEADER)
			rv = process_HEARTBEAT(tk, from, leader, msg);
		else if (tk->leader != local &&
				(tk->state == ST_INIT ||tk->state == ST_FOLLOWER ||
				tk->state == ST_CANDIDATE))
			rv = answer_HEARTBEAT(tk, from, leader, msg);
		else {
			tk_log_warn("unexpected message %s, from %s",
				state_to_string(cmd),
				site_string(from));
			rv = -EINVAL;
		}
		break;
	case OP_UPDATE:
		if (tk->leader != local && tk->state == ST_FOLLOWER) {
			rv = process_UPDATE(tk, from, leader, msg);
		} else {
			tk_log_warn("unexpected message %s, from %s",
				state_to_string(cmd),
				site_string(from));
			rv = -EINVAL;
		}
		break;
	case OP_REJECTED:
		rv = process_REJECTED(tk, from, leader, msg);
		break;
	case OP_REVOKE:
		rv = process_REVOKE(tk, from, leader, msg);
		break;
	case OP_MY_INDEX:
		rv = process_MY_INDEX(tk, from, leader, msg);
		break;
	case OP_STATUS:
		rv = send_msg(OP_MY_INDEX, tk, from);
		break;
	default:
		tk_log_error("unknown message %s, from %s",
			state_to_string(cmd), site_string(from));
		rv = -EINVAL;
	}
	return rv;
}
