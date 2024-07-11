/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013 Philipp Marek <philipp.marek@linbit.com>
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

#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include "b_config.h"
#include "booth.h"

typedef enum {
	TCP = 1,
	UDP,
	SCTP,
	TRANSPORT_ENTRIES,
} transport_layer_t;

typedef enum {
	ARBITRATOR = 0x50,
	SITE,
	CLIENT,
	DAEMON,
	STATUS,
	GEOSTORE,
} action_t;

/* when allocating space for messages
 */
#define MAX_MSG_LEN 1024

struct booth_transport {
	const char *name;
	int (*init) (void *);
	int (*open) (struct booth_site *);
	int (*send) (struct booth_site *, void *, int);
	int (*send_auth) (struct booth_site *, void *, int);
	int (*recv) (struct booth_site *, void *, int);
	int (*recv_auth) (struct booth_site *, void *, int);
	int (*broadcast) (void *, int);
	int (*broadcast_auth) (void *, int);
	int (*close) (struct booth_site *);
	int (*exit) (void);
};

extern const struct booth_transport booth_transport[TRANSPORT_ENTRIES];

/**
 * @internal
 * Attempts to pick identity of self from config-tracked enumeration of sites
 *
 * @param[in,out] conf config object to refer to
 * @param[out] mep when self-discovery successful, site pointer is stored here
 * @param[in] fuzzy_allowed whether it's OK to approximate the match
 *
 * @return 0 on success or negative value (-1 or -errno) on error
 */
int find_myself(struct booth_config *conf, struct booth_site **me,
		int fuzzy_allowed);

int read_client(struct client *req_cl);
int check_boothc_header(struct boothc_header *data, int len_incl_data);

int setup_tcp_listener(int test_only);
int booth_udp_send(struct booth_site *to, void *buf, int len);
int booth_udp_send_auth(struct booth_site *to, void *buf, int len);

int booth_tcp_open(struct booth_site *to);
int booth_tcp_send(struct booth_site *to, void *buf, int len);

/**
 * @internal
 * First stage of incoming datagram handling (authentication)
 *
 * @param[in,out] conf config object to refer to
 * @param[in] msg raw message to act upon
 * @param[in] msglen length of #msg
 *
 * @return 0 on success or negative value (-1 or -errno) on error
 */
int message_recv(struct booth_config *conf, void *msg, int msglen);

inline static void * node_to_addr_pointer(struct booth_site *node) {
	switch (node->family) {
	case AF_INET:  return &node->sa4.sin_addr;
	case AF_INET6: return &node->sa6.sin6_addr;
	}
	return NULL;
}

int send_data(int fd, void *data, int datalen);
int send_header_plus(int fd, struct boothc_hdr_msg *hdr, void *data, int len);
#define send_client_msg(fd, msg) send_data(fd, msg, sendmsglen(msg))

int add_hmac(void *data, int len);
int check_auth(struct booth_site *from, void *buf, int len);

#endif /* _TRANSPORT_H */
