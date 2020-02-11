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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>  /* getnameinfo */
#include <poll.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>  /* getnameinfo */
#include "b_config.h"
#include "config.h"
#include "transport.h"
#include "attr.h"
#include "auth.h"
#include "booth.h"
#include "inline-fn.h"
#include "log.h"
#include "ticket.h"

#define BOOTH_IPADDR_LEN	(sizeof(struct in6_addr))

#define NETLINK_BUFSIZE		16384
#define SOCKET_BUFFER_SIZE	160000
#define FRAME_SIZE_MAX		10000

/* function to be called when handling booth-group-internal messages;
 * it's expected to return 0 to indicate success, negative integer
 * to indicate silent (or possibly already complained about) error,
 * or positive integer to indicate sender's ID that will then be
 * emitted in the error log message together with the real source
 * address if this is available */
static int (*deliver_fn) (void *msg, int msglen);


static void parse_rtattr(struct rtattr *tb[],
			 int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

enum match_type {
	NO_MATCH = 0,
	FUZZY_MATCH,
	EXACT_MATCH,
};

static int find_address(struct booth_config *conf_ptr,
                        unsigned char ipaddr[BOOTH_IPADDR_LEN],
                        int family, int prefixlen, int fuzzy_allowed,
                        struct booth_site **me, int *address_bits_matched)
{
	int i;
	struct booth_site *node;
	int bytes, bits_left, mask;
	unsigned char node_bits, ip_bits;
	uint8_t *n_a;
	int matched;
	enum match_type did_match = NO_MATCH;

	assert(conf_ptr != NULL);

	bytes = prefixlen / 8;
	bits_left = prefixlen % 8;
	/* One bit left to check means ignore 7 lowest bits. */
	mask = ~( (1 << (8 - bits_left)) -1);

	FOREACH_NODE(conf_ptr, i, node) {
		if (family != node->family)
			continue;
		n_a = node_to_addr_pointer(node);

		for(matched = 0; matched < node->addrlen; matched++)
			if (ipaddr[matched] != n_a[matched])
				break;

		if (matched == node->addrlen) {
			*address_bits_matched = matched * 8;
			*me = node;
			did_match = EXACT_MATCH;
			break;
		}

		if (!fuzzy_allowed)
			continue;


		/* Check prefix, whole bytes */
		if (matched < bytes)
			continue;
		if (matched * 8 < *address_bits_matched)
			continue;

		node_bits = n_a[bytes];
		ip_bits = ipaddr[bytes];
		if (((node_bits ^ ip_bits) & mask) == 0) {
			/* _At_least_ prefixlen bits matched. */
			if (did_match < EXACT_MATCH) {
				*address_bits_matched = prefixlen;
				*me = node;
				did_match = FUZZY_MATCH;
			}
		}
	}

	return did_match;
}


static int _find_myself(struct booth_config *conf_ptr, int family,
                        int fuzzy_allowed)
{
	int fd;
	struct sockaddr_nl nladdr;
	struct booth_site *me = NULL;
	unsigned char ipaddr[BOOTH_IPADDR_LEN];
	static char rcvbuf[NETLINK_BUFSIZE];
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	int address_bits_matched;

	assert(conf_ptr != NULL);

	if (conf_ptr->local != NULL)
		goto found;

	address_bits_matched = 0;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		log_error("failed to create netlink socket");
		return 0;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	req.g.rtgen_family = family;

	if (sendto(fd, (void *)&req, sizeof(req), 0,
				(struct sockaddr*)&nladdr, sizeof(nladdr)) < 0)  {
		close(fd);
		log_error("failed to send data to netlink socket");
		return 0;
	}

	while (1) {
		int status;
		struct nlmsghdr *h;
		struct iovec iov = { rcvbuf, sizeof(rcvbuf) };
		struct msghdr msg = {
			(void *)&nladdr, sizeof(nladdr),
			&iov,   1,
			NULL,   0,
			0
		};

		status = recvmsg(fd, &msg, 0);
		if (!status) {
			close(fd);
			log_error("failed to recvmsg from netlink socket");
			return 0;
		}

		h = (struct nlmsghdr *)rcvbuf;
		if (h->nlmsg_type == NLMSG_DONE)
			break;

		if (h->nlmsg_type == NLMSG_ERROR) {
			close(fd);
			log_error("netlink socket recvmsg error");
			return 0;
		}

		while (NLMSG_OK(h, status)) {
			if (h->nlmsg_type == RTM_NEWADDR) {
				struct ifaddrmsg *ifa = NLMSG_DATA(h);
				struct rtattr *tb[IFA_MAX+1];
				int len = h->nlmsg_len 
					- NLMSG_LENGTH(sizeof(*ifa));

				memset(tb, 0, sizeof(tb));
				parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
				memset(ipaddr, 0, BOOTH_IPADDR_LEN);
				/* prefer IFA_LOCAL if it exists, for p-t-p
				 * interfaces, otherwise use IFA_ADDRESS */
				if (tb[IFA_LOCAL]) {
					memcpy(ipaddr, RTA_DATA(tb[IFA_LOCAL]),
							BOOTH_IPADDR_LEN);
				} else {
					memcpy(ipaddr, RTA_DATA(tb[IFA_ADDRESS]),
							BOOTH_IPADDR_LEN);
				}

				/* Try to find the exact address or the address with subnet matching.
				 * The function find_address will be called for each address received
				 * from NLMSG_DATA above.
				 * The exact match will be preferred. If no exact match is found,
				 * the function find_address will try to return another, most similar
				 * address (with the longest possible number of same bytes). */
				if (ifa->ifa_prefixlen > address_bits_matched) {
					find_address(conf_ptr, ipaddr,
					             ifa->ifa_family, ifa->ifa_prefixlen,
					             fuzzy_allowed, &me, &address_bits_matched);

					if (me != NULL) {
						log_debug("found myself at %s (%d bits matched)",
								site_string(me), address_bits_matched);
					}
				}
				/* If the previous NLMSG_DATA calls have already allowed us
				 * to find an address with address_bits_matched matching bits,
				 * then no other better non-exact address can be found.
				 * But we can still try to find an exact match, so let us
				 * call the function find_address with disabled searching of
				 * similar addresses (fuzzy_allowed == 0) */
				else if (ifa->ifa_prefixlen == address_bits_matched) {
					find_address(conf_ptr, ipaddr,
					             ifa->ifa_family, ifa->ifa_prefixlen,
					             0 /* fuzzy_allowed */, &me, &address_bits_matched);

					if (me != NULL) {
						log_debug("found myself at %s (exact match)",
								site_string(me));
					}
				}
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	close(fd);

	if (me == NULL)
		return 0;

	me->local = 1;
	conf_ptr->local = me;
found:
	return 1;
}

int find_myself(struct booth_config *conf_ptr, int fuzzy_allowed)
{
	return _find_myself(conf_ptr, AF_INET6, fuzzy_allowed)
	       || _find_myself(conf_ptr, AF_INET, fuzzy_allowed);
}

/** Checks the header fields for validity.
 * cf. init_header().
 * For @len_incl_data < 0 the length is not checked.
 * Return <0 if error, else bytes read. */
int check_boothc_header(struct boothc_header *h, int len_incl_data)
{
	int l;

	if (h->magic != htonl(BOOTHC_MAGIC)) {
		log_error("magic error %x", ntohl(h->magic));
		return -EINVAL;
	}
	if (h->version != htonl(BOOTHC_VERSION)) {
		log_error("version error %x", ntohl(h->version));
		return -EINVAL;
	}


	l = ntohl(h->length);
	if (l < sizeof(*h)) {
		log_error("length %d out of range", l);
		return -EINVAL;
	}


	if (len_incl_data < 0)
		return 0;

	if (l != len_incl_data) {
		log_error("length error - got %d, wanted %d",
				len_incl_data, l);
		return -EINVAL;
	}

	return len_incl_data;
}

static int do_read(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1 && errno == EWOULDBLOCK)
			break;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return off;
}

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

retry:
	rv = send(fd, (char *)buf + off, count, MSG_NOSIGNAL);
	if (rv == -1 && errno == EINTR)
		goto retry;
	/* If we cannot write _any_ data, we'd be in an (potential) loop. */
	if (rv <= 0) {
		log_error("send failed: %s (%d)", strerror(errno), errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

/* Only used for client requests (tcp) */
static int read_client(struct client *req_cl)
{
	char *msg;
	struct boothc_header *header;
	int rv, fd;
	int len = MAX_MSG_LEN;

	if (!req_cl->msg) {
		msg = malloc(MAX_MSG_LEN);
		if (!msg) {
			log_error("out of memory for client messages");
			return -1;
		}
		req_cl->msg = (void *)msg;
	} else {
		msg = (char *)req_cl->msg;
	}
	header = (struct boothc_header *)msg;

	/* update len if we read enough */
	if (req_cl->offset >= sizeof(*header)) {
		len = min(ntohl(header->length), MAX_MSG_LEN);
	}

	fd = req_cl->fd;
	rv = do_read(fd, msg+req_cl->offset, len-req_cl->offset);
	if (rv < 0) {
		if (errno == ECONNRESET)
			log_debug("client connection reset for fd %d", fd);
		return -1;
	}
	req_cl->offset += rv;

	/* update len if we read enough */
	if (req_cl->offset >= sizeof(*header)) {
		len = min(ntohl(header->length), MAX_MSG_LEN);
	}

	if (req_cl->offset < len) {
		/* client promised to send more */
		return 1;
	}

	if (check_boothc_header(header, len) < 0) {
		return -1;
	}

	return 0;
}

/* Only used for client requests (tcp) */
static void process_connection(struct booth_config *conf_ptr, int ci)
{
	struct client *req_cl;
	void *msg = NULL;
	struct boothc_header *header;
	struct boothc_hdr_msg err_reply;
	cmd_result_t errc;
	void (*deadfn) (int ci);

	req_cl = clients + ci;
	switch (read_client(req_cl)) {
	case -1: /* error */
		goto kill;
	case 1: /* more to read */
		return;
	case 0:
		/* we can process the request now */
		msg = req_cl->msg;
	}

	header = (struct boothc_header *)msg;
	if (check_auth(conf_ptr, NULL, msg, ntohl(header->length))) {
		errc = RLT_AUTH;
		goto send_err;
	}

	/* For CMD_GRANT and CMD_REVOKE:
	 * Don't close connection immediately, but send
	 * result a second later? */
	switch (ntohl(header->cmd)) {
	case CMD_LIST:
		ticket_answer_list(conf_ptr, req_cl->fd);
		goto kill;
	case CMD_PEERS:
		list_peers(conf_ptr, req_cl->fd);
		goto kill;

	case CMD_GRANT:
	case CMD_REVOKE:
		if (process_client_request(conf_ptr, req_cl, msg) == 1)
			goto kill; /* request processed definitely, close connection */
		else
			return;

	case ATTR_LIST:
	case ATTR_GET:
	case ATTR_SET:
	case ATTR_DEL:
		if (process_attr_request(conf_ptr, req_cl, msg) == 1)
			goto kill; /* request processed definitely, close connection */
		else
			return;

	default:
		log_error("connection %d cmd %x unknown",
				ci, ntohl(header->cmd));
		errc = RLT_INVALID_ARG;
		goto send_err;
	}

	assert(0);
	return;

send_err:
	init_header(conf_ptr, &err_reply.header, CL_RESULT, 0, 0, errc, 0,
	            sizeof(err_reply));
	send_client_msg(conf_ptr, req_cl->fd, &err_reply);

kill:
	deadfn = req_cl->deadfn;
	if(deadfn) {
		deadfn(ci);
	}
	return;
}


static void process_tcp_listener(struct booth_config *conf_ptr, int ci)
{
	int fd, i, flags, one = 1;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct sockaddr addr;

	fd = accept(clients[ci].fd, &addr, &addrlen);
	if (fd < 0) {
		log_error("process_tcp_listener: accept error %d %d",
			  fd, errno);
		return;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	i = client_add(fd, clients[ci].transport,
			process_connection, NULL);

	log_debug("client connection %d fd %d", i, fd);
}

int setup_tcp_listener(struct booth_site *local, int test_only)
{
	int s, rv;
	int one = 1;

	assert(local != NULL);

	s = socket(local->family, SOCK_STREAM, 0);
	if (s == -1) {
		log_error("failed to create tcp socket %s", strerror(errno));
		return s;
	}

	rv = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
	if (rv == -1) {
		close(s);
		log_error("failed to set the SO_REUSEADDR option");
		return rv;
	}

	rv = bind(s, &local->sa6, local->saddrlen);
	if (test_only) {
		rv = (rv == -1) ? errno : 0;
		close(s);
		return rv;
	}

	if (rv == -1) {
		close(s);
		log_error("failed to bind socket %s", strerror(errno));
		return rv;
	}

	rv = listen(s, 5);
	if (rv == -1) {
		close(s);
		log_error("failed to listen on socket %s", strerror(errno));
		return rv;
	}

	return s;
}

static int booth_tcp_init(struct booth_config *conf_ptr,
                          void * unused __attribute__((unused)))
{
	int rv;

	assert(conf_ptr != NULL && conf_ptr->transport != NULL);

	if (get_local_id(conf_ptr) < 0)
		return -1;

	rv = setup_tcp_listener(conf_ptr->local, 0);
	if (rv < 0)
		return rv;

	client_add(rv, *conf_ptr->transport + TCP, process_tcp_listener, NULL);

	return 0;
}

static int connect_nonb(int sockfd, const struct sockaddr *saptr,
			socklen_t salen, int sec)
{
	int		flags, n, error;
	socklen_t	len;
	fd_set		rset, wset;
	struct timeval	tval;

	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ( (n = connect(sockfd, saptr, salen)) < 0)
		if (errno != EINPROGRESS)
			return -1;

	if (n == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = sec;
	tval.tv_usec = 0;

	if ((n = select(sockfd + 1, &rset, &wset, NULL,
	    sec ? &tval : NULL)) == 0) {
		/* leave outside function to close */
		/* timeout */
		/* close(sockfd); */	
		errno = ETIMEDOUT;
		return -1;
	}

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;	/* Solaris pending error */
	} else {
		log_error("select error: sockfd not set");
		return -1;
	}

done:
	fcntl(sockfd, F_SETFL, flags);	/* restore file status flags */

	if (error) {
		/* leave outside function to close */
		/* close(sockfd); */	
		errno = error;
		return -1;
	}

	return 0;
}

static int booth_tcp_open(struct booth_site *to)
{
	int s, rv;

	if (to->tcp_fd >= STDERR_FILENO)
		goto found;

	s = socket(to->family, SOCK_STREAM, 0);
	if (s == -1) {
		log_error("cannot create socket of family %d", to->family);
		return -1;
	}


	rv = connect_nonb(s, (struct sockaddr *)&to->sa6, to->saddrlen, 10);
	if (rv == -1) {
		if( errno == ETIMEDOUT)
			log_error("connect to %s got a timeout", site_string(to));
		else 
			log_error("connect to %s got an error: %s", site_string(to),
					strerror(errno));
		goto error;
	}

	to->tcp_fd = s;

found:
	return 1;

error:
	if (s >= 0)
		close(s);
	return -1;
}

/* data + (datalen-sizeof(struct hmac)) points to struct hmac
 * i.e. struct hmac is always tacked on the payload
 */
static int add_hmac(struct booth_config *conf_ptr, void *data, int len)
{
	int rv = 0;
#if HAVE_LIBGCRYPT || HAVE_LIBMHASH
	int payload_len;
	struct hmac *hp;

	assert(conf_ptr != NULL);

	if (!is_auth_req(conf_ptr))
		return 0;

	payload_len = len - sizeof(struct hmac);
	hp = (struct hmac *)((unsigned char *)data + payload_len);
	hp->hid = htonl(BOOTH_HASH);
	memset(hp->hash, 0, BOOTH_MAC_SIZE);
	rv = calc_hmac(data, payload_len, BOOTH_HASH, hp->hash,
	               conf_ptr->authkey, conf_ptr->authkey_len);
	if (rv < 0) {
		log_error("internal error: cannot calculate mac");
	}
#endif
	return rv;
}

static int booth_tcp_send(struct booth_config *conf_ptr,
                          struct booth_site *to, void *buf, int len)
{
	int rv;

	rv = add_hmac(conf_ptr, buf, len);
	if (!rv)
		rv = do_write(to->tcp_fd, buf, len);

	return rv;
}

static int booth_tcp_recv(struct booth_site *from, void *buf, int len)
{
	int got;
	/* Needs timeouts! */
	got = do_read(from->tcp_fd, buf, len);
	if (got < 0) {
		log_error("read failed (%d): %s", errno, strerror(errno));
		return got;
	}
	return got;
}

static int booth_tcp_recv_auth(struct booth_config *conf_ptr,
                               struct booth_site *from, void *buf, int len)
{
	int got, total;
	int payload_len;
	/* Needs timeouts! */

	payload_len = len - sizeof(struct hmac);
	got = booth_tcp_recv(from, buf, payload_len);
	if (got < 0) {
		return got;
	}
	total = got;
	if (is_auth_req(conf_ptr)) {
		got = booth_tcp_recv(from, (unsigned char *)buf+payload_len, sizeof(struct hmac));
		if (got != sizeof(struct hmac)
				|| check_auth(conf_ptr, from, buf, len)) {
			return -1;
		}
		total += got;
	}
	return total;
}

static int booth_tcp_close(struct booth_site *to)
{
	if (to) {
		if (to->tcp_fd > STDERR_FILENO)
			close(to->tcp_fd);
		to->tcp_fd = -1;
	}
	return 0;
}

static int booth_tcp_exit(void)
{
	return 0;
}

static int setup_udp_server(struct booth_site *local)
{
	int rv, fd;
	int one = 1;
	unsigned int recvbuf_size;

	assert(local != NULL);

	fd = socket(local->family, SOCK_DGRAM, 0);
	if (fd == -1) {
		log_error("failed to create UDP socket %s", strerror(errno));
		goto ex;
	}

	rv = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (rv == -1) {
		log_error("failed to set non-blocking operation "
			  "on UDP socket: %s", strerror(errno));
		goto ex;
	}

	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
	if (rv == -1) {
		log_error("failed to set the SO_REUSEADDR option");
		goto ex;
	}

	rv = bind(fd, (struct sockaddr *)&local->sa6, local->saddrlen);

	if (rv == -1) {
		log_error("failed to bind UDP socket to [%s]:%d: %s",
		          site_string(local), site_port(local),
		          strerror(errno));
		goto ex;
	}

	recvbuf_size = SOCKET_BUFFER_SIZE;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
			&recvbuf_size, sizeof(recvbuf_size));
	if (rv == -1) {
		log_error("failed to set recvbuf size");
		goto ex;
	}

	local->udp_fd = fd;
	return 0;

ex:
	if (fd >= 0)
		close(fd);
	return -1;
}


/* Receive/process callback for UDP */
static void process_recv(struct booth_config *conf_ptr, int ci)
{
	struct sockaddr_storage sa;
	int rv;
	socklen_t sa_len;
	/* beware, the buffer needs to be large enough to accept
	 * a packet */
	char buffer[MAX_MSG_LEN];
	/* Used for unit tests */
	struct boothc_ticket_msg *msg;


	sa_len = sizeof(sa);
	msg = (void*)buffer;
	rv = recvfrom(clients[ci].fd,
			buffer, sizeof(buffer),
			MSG_NOSIGNAL | MSG_DONTWAIT,
			(struct sockaddr *)&sa, &sa_len);
	if (rv == -1)
		return;

	rv = deliver_fn((void*)msg, rv);
	if (rv > 0) {
		if (getnameinfo((struct sockaddr *)&sa, sa_len,
				buffer, sizeof(buffer), NULL, 0,
				NI_NUMERICHOST) == 0)
			log_error("unknown sender: %08x (real: %s)", rv, buffer);
		else
			log_error("unknown sender: %08x", rv);
	}
}

static int booth_udp_init(struct booth_config *conf_ptr, void *f)
{
	int rv;

	assert(conf_ptr != NULL && conf_ptr->transport != NULL);
	assert(conf_ptr->local != NULL);

	rv = setup_udp_server(conf_ptr->local);
	if (rv < 0)
		return rv;

	deliver_fn = f;
	client_add(conf_ptr->local->udp_fd, *conf_ptr->transport + UDP,
	           process_recv, NULL);

	return 0;
}

static int booth_udp_send(struct booth_config *conf_ptr, struct booth_site *to,
                          void *buf, int len)
{
	int rv;

	assert(conf_ptr != NULL);
	assert(conf_ptr->local != NULL);

	to->sent_cnt++;
	rv = sendto(conf_ptr->local->udp_fd, buf, len, MSG_NOSIGNAL,
	            (struct sockaddr *)&to->sa6, to->saddrlen);
	if (rv == len) {
		rv = 0;
	} else if (rv < 0) {
		to->sent_err_cnt++;
		log_error("Cannot send to %s: %d %s",
				site_string(to),
				errno,
				strerror(errno));
	} else {
		rv = -1;
		to->sent_err_cnt++;
		log_error("Packet sent to %s got truncated",
				site_string(to));
	}

	return rv;
}

int booth_udp_send_auth(struct booth_config *conf_ptr,
                        struct booth_site *to, void *buf, int len)
{
	int rv;

	rv = add_hmac(conf_ptr, buf, len);
	if (rv < 0)
		return rv;
	return booth_udp_send(conf_ptr, to, buf, len);
}

static int booth_udp_broadcast_auth(struct booth_config *conf_ptr,
                                    void *buf, int len)
{
	int i, rv, rvs;
	struct booth_site *site;

	assert(conf_ptr != NULL);
	assert(conf_ptr->local != NULL);

	if (conf_ptr == NULL || !conf_ptr->site_count)
		return -1;

	rv = add_hmac(conf_ptr, buf, len);
	if (rv < 0)
		return rv;

	rvs = 0;
	FOREACH_NODE(conf_ptr, i, site) {
		if (site != conf_ptr->local) {
			rv = booth_udp_send(conf_ptr, site, buf, len);
			if (!rvs)
				rvs = rv;
		}
	}

	return rvs;
}

static int booth_udp_exit(void)
{
	return 0;
}

/* SCTP transport layer has not been developed yet */
static int booth_sctp_init(struct booth_config *conf_ptr __attribute__((unused)),
                           void *f __attribute__((unused)))
{
	return 0;
}

static int booth_sctp_send(struct booth_config *conf_ptr __attribute__((unused)),
                           struct booth_site * to __attribute__((unused)),
                           void *buf __attribute__((unused)),
                           int len __attribute__((unused)))
{
	return 0;
}

static int booth_sctp_broadcast(void *buf __attribute__((unused)),
				int len __attribute__((unused)))
{
	return 0;
}

static int return_0_booth_site(struct booth_site *v __attribute((unused)))
{
	return 0;
}

static int return_0(void)
{
	return 0;
}

/* semi-hidden, only main.c to have a knowledge about this */
const booth_transport_table_t booth__transport = {
	[TCP] = {
		.name = "TCP",
		.init = booth_tcp_init,
		.open = booth_tcp_open,
		.send = booth_tcp_send,
		.recv = booth_tcp_recv,
		.recv_auth = booth_tcp_recv_auth,
		.close = booth_tcp_close,
		.exit = booth_tcp_exit
	},
	[UDP] = {
		.name = "UDP",
		.init = booth_udp_init,
		.open = return_0_booth_site,
		.send = booth_udp_send,
		.send_auth = booth_udp_send_auth,
		.close = return_0_booth_site,
		.broadcast_auth = booth_udp_broadcast_auth,
		.exit = booth_udp_exit
	},
	[SCTP] = {
		.name = "SCTP",
		.init = booth_sctp_init,
		.open = return_0_booth_site,
		.send = booth_sctp_send,
		.broadcast = booth_sctp_broadcast,
		.exit = return_0,
	}
};

#if HAVE_LIBGCRYPT || HAVE_LIBMHASH

/* TODO: we need some client identification for logging */
#define peer_string(p) (p ? site_string(p) : "client")

/* verify the validity of timestamp from the header
 * the timestamp needs to be either greater than the one already
 * recorded for the site or, and this is checked for clients,
 * not to be older than conf_ptr->maxtimeskew
 * update the timestamp for the site, if this packet is from a
 * site
 */
static int verify_ts(struct booth_config *conf_ptr, struct booth_site *from,
                     void *buf, int len)
{
	struct boothc_header *h;
	struct timeval tv, curr_tv, now;

	assert(conf_ptr != NULL);

	if (len < sizeof(*h)) {
		log_error("%s: packet too short", peer_string(from));
		return -1;
	}

	h = (struct boothc_header *)buf;
	tv.tv_sec = ntohl(h->secs);
	tv.tv_usec = ntohl(h->usecs);
	if (from) {
		curr_tv.tv_sec = from->last_secs;
		curr_tv.tv_usec = from->last_usecs;
		if (timercmp(&tv, &curr_tv, >))
			goto accept;
		log_warn("%s: packet timestamp older than previous one",
			site_string(from));
	}

	gettimeofday(&now, NULL);
	now.tv_sec -= conf_ptr->maxtimeskew;
	if (timercmp(&tv, &now, >))
		goto accept;
	log_error("%s: packet timestamp older than %d seconds",
	          peer_string(from), conf_ptr->maxtimeskew);
	return -1;

accept:
	if (from) {
		from->last_secs = tv.tv_sec;
		from->last_usecs = tv.tv_usec;
	}
	return 0;
}
#endif

int check_auth(struct booth_config *conf_ptr, struct booth_site *from,
               void *buf, int len)
{
	int rv = 0;
#if HAVE_LIBGCRYPT || HAVE_LIBMHASH
	int payload_len;
	struct hmac *hp;

	assert(conf_ptr != NULL);

	if (!is_auth_req(conf_ptr))
		return 0;

	payload_len = len - sizeof(struct hmac);
	if (payload_len < 0) {
		log_error("%s: failed to authenticate, packet too short (size:%d)",
			peer_string(from), len);
		return -1;
	}
	hp = (struct hmac *)((unsigned char *)buf + payload_len);
	rv = verify_hmac(buf, payload_len, ntohl(hp->hid), hp->hash,
	                 conf_ptr->authkey, conf_ptr->authkey_len);
	if (!rv) {
		rv = verify_ts(conf_ptr, from, buf, len);
	}
	if (rv != 0) {
		log_error("%s: failed to authenticate", peer_string(from));
	}
#endif
	return rv;
}

int send_data(struct booth_config *conf_ptr, int fd, void *data, int datalen)
{
	int rv = 0;

	rv = add_hmac(conf_ptr, data, datalen);
	if (!rv)
		rv = do_write(fd, data, datalen);

	return rv;
}

int send_header_plus(struct booth_config *conf_ptr, int fd,
                     struct boothc_hdr_msg *msg, void *data, int len)
{
	int rv;

	rv = send_data(conf_ptr, fd, msg, sendmsglen(msg)-len);

	if (rv >= 0 && len)
		rv = do_write(fd, data, len);

	return rv;
}

/* UDP message receiver (see also deliver_fn declaration's comment) */
int message_recv(struct booth_config *conf_ptr, void *msg, int msglen)
{
	uint32_t from;
	struct boothc_header *header;
	struct booth_site *source;

	header = (struct boothc_header *)msg;

	from = ntohl(header->from);
	if (!find_site_by_id(conf_ptr, from, &source)) {
		/* caller knows the actual source address, pass
		   the (assuredly) positive number and let it report */
		from = from ? from : ~from;  /* avoid 0 (success) */
		return from & (~0U >> 1);  /* avoid negative (error code} */
	}

	time(&source->last_recv);
	source->recv_cnt++;

	if (check_boothc_header(header, msglen) < 0) {
		log_error("message from %s receive error", site_string(source));
		source->recv_err_cnt++;
		return -1;
	}

	if (check_auth(conf_ptr, source, msg, msglen)) {
		log_error("%s failed to authenticate", site_string(source));
		source->sec_cnt++;
		return -1;
	}

	if (ntohl(header->opts) & BOOTH_OPT_ATTR) {
		/* not used, clients send/retrieve attributes directly
		 * from sites
		 */
		return attr_recv(conf_ptr, msg, source);
	} else {
		return ticket_recv(conf_ptr, msg, source);
	}
}
