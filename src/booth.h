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

#ifndef _BOOTH_H
#define _BOOTH_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <glib.h>
#include "timer.h"


#define BOOTH_RUN_DIR "/var/run/booth/"
#define BOOTH_LOG_DIR "/var/log"
#define BOOTH_LOGFILE_NAME "booth.log"
#define BOOTH_DEFAULT_CONF_DIR "/etc/booth/"
#define BOOTH_DEFAULT_CONF_NAME "booth"
#define BOOTH_DEFAULT_CONF_EXT ".conf"
#define BOOTH_DEFAULT_CONF \
	BOOTH_DEFAULT_CONF_DIR BOOTH_DEFAULT_CONF_NAME BOOTH_DEFAULT_CONF_EXT

#define DAEMON_NAME		"boothd"
#define BOOTH_PATH_LEN		127
#define BOOTH_MAX_KEY_LEN	64
#define BOOTH_MIN_KEY_LEN	8
/* hash size is 160 bits (sha1), but add a bit more space in case
 * stronger hashes are required */
#define BOOTH_MAC_SIZE		24

/* tolerate packets which are not older than 10 minutes */
#define BOOTH_DEFAULT_MAX_TIME_SKEW		600

#define BOOTH_DEFAULT_PORT		9929

#define BOOTHC_MAGIC		0x5F1BA08C
#define BOOTHC_VERSION		0x00010003


/** Timeout value for poll().
 * Determines frequency of periodic jobs, eg. when send-retries are done.
 * See process_tickets(). */
#define POLL_TIMEOUT	100


/** @{ */
/** The on-network data structures and constants. */

#define BOOTH_NAME_LEN		64
#define BOOTH_ATTRVAL_LEN		128

#define CHAR2CONST(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)


/* Says that the ticket shouldn't be active anywhere.
 * NONE wouldn't be specific enough. */
#define NO_ONE ((uint32_t)-1)
/* Says that another one should recover. */
#define TICKET_LOST CHAR2CONST('L', 'O', 'S', 'T')


typedef char boothc_site[BOOTH_NAME_LEN];
typedef char boothc_ticket[BOOTH_NAME_LEN];
typedef char boothc_attr[BOOTH_NAME_LEN];
typedef char boothc_attr_value[BOOTH_ATTRVAL_LEN];

/* message option bits */
enum {
	BOOTH_OPT_AUTH = 1, /* authentication */
	BOOTH_OPT_ATTR = 4, /* attr message type, otherwise ticket */
};

struct boothc_header {
	/** Various options, message type, authentication
	 */
	uint32_t opts;

	/** Generation info (used for authentication)
	 * This is something that would need to be monotone
	 * incremental. CLOCK_MONOTONIC should fit the purpose. On
	 * failover, however, it may happen that the new host has a
	 * clock which is significantly behind the clock of old host.
	 * We'll need to relax a bit for the nodes which are starting
	 * (just accept all OP_STATUS).
	 */
	uint32_t secs;  /* seconds */
	uint32_t usecs; /* microseconds */


	/** BOOTHC_MAGIC */
	uint32_t magic;
	/** BOOTHC_VERSION */
	uint32_t version;

	/** Packet source; site_id. See add_site(). */
	uint32_t from;

	/** Length including header */
	uint32_t length;

	/** The command respectively protocol state. See cmd_request_t. */
	uint32_t cmd;
	/** The matching request (what do we reply to). See cmd_request_t. */
	uint32_t request;
	/** Command options. */
	uint32_t options;
	/** The reason for this RPC. */
	uint32_t reason;
	/** Result of operation. 0 == OK */
	uint32_t result;

	char data[0];
} __attribute__((packed));


struct ticket_msg {
	/** Ticket name. */
	boothc_ticket id;

	/** Current leader. May be NO_ONE. See add_site().
	 * For a OP_REQ_VOTE this is  */
	uint32_t leader;

	/** Current term. */
	uint32_t term;
	uint32_t term_valid_for;

	/* Perhaps we need to send a status along, too - like
	 *  starting, running, stopping, error, ...? */
} __attribute__((packed));

struct attr_msg {
	/** Ticket name. */
	boothc_ticket tkt_id;

	/** Attribute name. */
	boothc_attr name;

	/** The value. */
	boothc_attr_value val;
} __attribute__((packed));

/* GEO attributes
 * attributes should be regularly updated.
 */
struct geo_attr {
	/** Update timestamp. */
	timetype update_ts;

	/** The value. */
	char *val;

	/** Who set it (currently unused)
	struct booth_site *origin;
	*/
} __attribute__((packed));

struct hmac {
	/** hash id, currently set to constant BOOTH_HASH */
	uint32_t hid;

	/** the calculated hash, BOOTH_MAC_SIZE is big enough to
	 * accommodate the hash of type hid */
	unsigned char hash[BOOTH_MAC_SIZE];
} __attribute__((packed));

struct boothc_hdr_msg {
	struct boothc_header header;
	struct hmac hmac;
} __attribute__((packed));

struct boothc_ticket_msg {
	struct boothc_header header;
	struct ticket_msg ticket;
	struct hmac hmac;
} __attribute__((packed));

struct boothc_attr_msg {
	struct boothc_header header;
	struct attr_msg attr;
	struct hmac hmac;
} __attribute__((packed));

typedef enum {
	/* 0x43 = "C"ommands */
	CMD_LIST    = CHAR2CONST('C', 'L', 's', 't'),
	CMD_GRANT   = CHAR2CONST('C', 'G', 'n', 't'),
	CMD_REVOKE  = CHAR2CONST('C', 'R', 'v', 'k'),
	CMD_PEERS   = CHAR2CONST('P', 'e', 'e', 'r'),

	/* Replies */
	CL_RESULT  = CHAR2CONST('R', 's', 'l', 't'),
	CL_LIST    = CHAR2CONST('R', 'L', 's', 't'),
	CL_GRANT   = CHAR2CONST('R', 'G', 'n', 't'),
	CL_REVOKE  = CHAR2CONST('R', 'R', 'v', 'k'),

	/* get status from another server */
	OP_STATUS   = CHAR2CONST('S', 't', 'a', 't'),
	OP_MY_INDEX = CHAR2CONST('M', 'I', 'd', 'x'), /* reply to status */

	/* Raft */
	OP_REQ_VOTE = CHAR2CONST('R', 'V', 'o', 't'), /* start election */
	OP_VOTE_FOR = CHAR2CONST('V', 't', 'F', 'r'), /* reply to REQ_VOTE */
	OP_HEARTBEAT= CHAR2CONST('H', 'r', 't', 'B'), /* Heartbeat */
	OP_ACK      = CHAR2CONST('A', 'c', 'k', '.'), /* Ack for heartbeats and revokes */
	OP_UPDATE   = CHAR2CONST('U', 'p', 'd', 'E'), /* Update ticket */
	OP_REVOKE   = CHAR2CONST('R', 'e', 'v', 'k'), /* Revoke ticket */
	OP_REJECTED = CHAR2CONST('R', 'J', 'C', '!'),

	/* Attributes */
	ATTR_SET     = CHAR2CONST('A', 'S', 'e', 't'),
	ATTR_GET     = CHAR2CONST('A', 'G', 'e', 't'),
	ATTR_DEL     = CHAR2CONST('A', 'D', 'e', 'l'),
	ATTR_LIST    = CHAR2CONST('A', 'L', 's', 't'),
} cmd_request_t;


typedef enum {
	/* for compatibility with other functions */
	RLT_SUCCESS             = 0,
	RLT_ASYNC               = CHAR2CONST('A', 's', 'y', 'n'),
	RLT_MORE                = CHAR2CONST('M', 'o', 'r', 'e'),
	RLT_SYNC_SUCC           = CHAR2CONST('S', 'c', 'c', 's'),
	RLT_SYNC_FAIL           = CHAR2CONST('F', 'a', 'i', 'l'),
	RLT_INVALID_ARG         = CHAR2CONST('I', 'A', 'r', 'g'),
	RLT_NO_SUCH_ATTR        = CHAR2CONST('N', 'A', 't', 'r'),
	RLT_CIB_PENDING         = CHAR2CONST('P', 'e', 'n', 'd'),
	RLT_EXT_FAILED          = CHAR2CONST('X', 'P', 'r', 'g'),
	RLT_ATTR_PREREQ         = CHAR2CONST('A', 'P', 'r', 'q'),
	RLT_TICKET_IDLE         = CHAR2CONST('T', 'i', 'd', 'l'),
	RLT_OVERGRANT           = CHAR2CONST('O', 'v', 'e', 'r'),
	RLT_PROBABLY_SUCCESS    = CHAR2CONST('S', 'u', 'c', '?'),
	RLT_BUSY                = CHAR2CONST('B', 'u', 's', 'y'),
	RLT_AUTH                = CHAR2CONST('A', 'u', 't', 'h'),
	RLT_TERM_OUTDATED       = CHAR2CONST('T', 'O', 'd', 't'),
	RLT_TERM_STILL_VALID    = CHAR2CONST('T', 'V', 'l', 'd'),
	RLT_YOU_OUTDATED        = CHAR2CONST('O', 'u', 't', 'd'),
	RLT_REDIRECT            = CHAR2CONST('R', 'e', 'd', 'r'),
} cmd_result_t;


typedef enum {
	/* for compatibility with other functions */
	OR_JUST_SO              = 0,
	OR_AGAIN                = CHAR2CONST('A', 'a', 'a', 'a'),
	OR_TKT_LOST             = CHAR2CONST('T', 'L', 's', 't'),
	OR_REACQUIRE            = CHAR2CONST('R', 'a', 'c', 'q'),
	OR_ADMIN                = CHAR2CONST('A', 'd', 'm', 'n'),
	OR_LOCAL_FAIL           = CHAR2CONST('L', 'o', 'c', 'F'),
	OR_STEPDOWN             = CHAR2CONST('S', 'p', 'd', 'n'),
	OR_SPLIT                = CHAR2CONST('S', 'p', 'l', 't'),
} cmd_reason_t;

/* bitwise command options
 */
typedef enum {
	OPT_IMMEDIATE = 1, /* immediate grant */
	OPT_WAIT = 2, /* wait for the elections' outcome */
	OPT_WAIT_COMMIT = 4, /* wait for the ticket commit to CIB */
} cmd_options_t;

/** @} */

/** @{ */

struct booth_site {
	/** Calculated ID. See add_site(). */
	int site_id;
	int type;
	int local;

	/** Roles, like ACCEPTOR, PROPOSER, or LEARNER. Not really used ATM. */
	int role;

	boothc_site addr_string;

	int tcp_fd;
	int udp_fd;

	/* 0-based, used for indexing into per-ticket weights */
	int index;
	uint64_t bitmask;

	unsigned short family;
	union {
		struct sockaddr_in  sa4;
		struct sockaddr_in6 sa6;
	};
	int saddrlen;
	int addrlen;

	/** statistics */
	time_t last_recv;
	unsigned int sent_cnt;
	unsigned int sent_err_cnt;
	unsigned int resend_cnt;
	unsigned int recv_cnt;
	unsigned int recv_err_cnt;
	unsigned int sec_cnt;
	unsigned int invalid_cnt;

	/** last timestamp seen from this site */
	uint32_t last_secs;
	uint32_t last_usecs;
} __attribute__((packed));



extern struct booth_site *local;
extern struct booth_site * no_leader;

/** @} */

struct booth_transport;

struct client {
	int fd;
	const struct booth_transport *transport;
	struct boothc_ticket_msg *msg;
	int offset; /* bytes read so far into msg */
	void (*workfn)(int);
	void (*deadfn)(int);
};

extern struct client *clients;
extern struct pollfd *pollfds;


int client_add(int fd, const struct booth_transport *tpt,
		void (*workfn)(int ci), void (*deadfn)(int ci));
int find_client_by_fd(int fd);
void safe_copy(char *dest, char *value, size_t buflen, const char *description);
int update_authkey(void);
void list_peers(int fd);


struct command_line {
	int type;		/* ACT_ */
	int op;			/* OP_ */
	int options;	/* OPT_ */
	char configfile[BOOTH_PATH_LEN];
	char lockfile[BOOTH_PATH_LEN];

	char site[BOOTH_NAME_LEN];
	struct boothc_ticket_msg msg;
	struct boothc_attr_msg attr_msg;
};
extern struct command_line cl;



/* http://gcc.gnu.org/onlinedocs/gcc/Typeof.html */
#define min(a__,b__) \
	({ typeof (a__) _a = (a__); \
	 typeof (b__) _b = (b__); \
	 _a < _b ? _a : _b; })
#define max(a__,b__) \
	({ typeof (a__) _a = (a__); \
	 typeof (b__) _b = (b__); \
	 _a > _b ? _a : _b; })





#endif /* _BOOTH_H */
