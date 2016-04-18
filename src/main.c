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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <pacemaker/crm/services.h>
#include <clplumbing/setproctitle.h>
#include <sys/prctl.h>
#include <clplumbing/coredumps.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <error.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "b_config.h"
#include "log.h"
#include "booth.h"
#include "config.h"
#include "transport.h"
#include "inline-fn.h"
#include "pacemaker.h"
#include "ticket.h"
#include "request.h"
#include "attr.h"
#include "handler.h"

#define RELEASE_VERSION		"1.0"
#define RELEASE_STR 	RELEASE_VERSION " (build " BOOTH_BUILD_VERSION ")"

#define CLIENT_NALLOC		32

int daemonize = 0;
int enable_stderr = 0;
timetype start_time;


/** Structure for "clients".
 * Filehandles with incoming data get registered here (and in pollfds),
 * along with their callbacks.
 * Because these can be reallocated with every new fd, addressing
 * happens _only_ by their numeric index. */
struct client *clients = NULL;
struct pollfd *pollfds = NULL;
static int client_maxi;
static int client_size = 0;


static const struct booth_site _no_leader = {
	.addr_string = "none",
	.site_id = NO_ONE,
};
struct booth_site *no_leader = (struct booth_site*)& _no_leader;

typedef enum
{
	BOOTHD_STARTED=0,
	BOOTHD_STARTING
} BOOTH_DAEMON_STATE;

int poll_timeout;



struct booth_config *booth_conf;
struct command_line cl;

static void client_alloc(void)
{
	int i;

	if (!clients) {
		clients = malloc(CLIENT_NALLOC * sizeof(struct client));
		pollfds = malloc(CLIENT_NALLOC * sizeof(struct pollfd));
	} else {
		clients = realloc(clients, (client_size + CLIENT_NALLOC) *
					sizeof(struct client));
		pollfds = realloc(pollfds, (client_size + CLIENT_NALLOC) *
					sizeof(struct pollfd));
	}
	if (!clients || !pollfds) {
		log_error("can't alloc for client array");
		exit(1);
	}

	for (i = client_size; i < client_size + CLIENT_NALLOC; i++) {
		clients[i].workfn = NULL;
		clients[i].deadfn = NULL;
		clients[i].fd = -1;
		pollfds[i].fd = -1;
		pollfds[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

static void client_dead(int ci)
{
	struct client *c = clients + ci;

	if (c->fd != -1) {
		log_debug("removing client %d", c->fd);
		close(c->fd);
	}

	c->fd = -1;
	c->workfn = NULL;

	if (c->msg) {
		free(c->msg);
		c->msg = NULL;
		c->offset = 0;
	}

	pollfds[ci].fd = -1;
}

int client_add(int fd, const struct booth_transport *tpt,
		void (*workfn)(int ci),
		void (*deadfn)(int ci))
{
	int i;
	struct client *c;


	if (client_size - 1 <= client_maxi ) {
		client_alloc();
	}

	for (i = 0; i < client_size; i++) {
		c = clients + i;
		if (c->fd != -1)
			continue;

		c->workfn = workfn;
		if (deadfn)
			c->deadfn = deadfn;
		else
			c->deadfn = client_dead;

		c->transport = tpt;
		c->fd = fd;
		c->msg = NULL;
		c->offset = 0;

		pollfds[i].fd = fd;
		pollfds[i].events = POLLIN;
		if (i > client_maxi)
			client_maxi = i;

		return i;
	}

	assert(!"no client");
}

int find_client_by_fd(int fd)
{
	int i;

	if (fd < 0)
		return -1;

	for (i = 0; i <= client_maxi; i++) {
		if (clients[i].fd == fd)
			return i;
	}
	return -1;
}

static int format_peers(char **pdata, unsigned int *len)
{
	struct booth_site *s;
	char *data, *cp;
	char time_str[64];
	int i, alloc;

	*pdata = NULL;
	*len = 0;

	alloc = booth_conf->site_count * (BOOTH_NAME_LEN + 256);
	data = malloc(alloc);
	if (!data)
		return -ENOMEM;

	cp = data;
	foreach_node(i, s) {
		if (s == local)
			continue;
		strftime(time_str, sizeof(time_str), "%F %T",
			localtime(&s->last_recv));
		cp += snprintf(cp,
				alloc - (cp - data),
				"%-12s %s, last recv: %s\n",
				type_to_string(s->type),
				s->addr_string,
				time_str);
		cp += snprintf(cp,
				alloc - (cp - data),
				"\tSent pkts:%u error:%u resends:%u\n",
				s->sent_cnt,
				s->sent_err_cnt,
				s->resend_cnt);
		cp += snprintf(cp,
				alloc - (cp - data),
				"\tRecv pkts:%u error:%u authfail:%u invalid:%u\n\n",
				s->recv_cnt,
				s->recv_err_cnt,
				s->sec_cnt,
				s->invalid_cnt);
		if (alloc - (cp - data) <= 0)
			return -ENOMEM;
	}

	*pdata = data;
	*len = cp - data;

	return 0;
}


void list_peers(int fd)
{
	char *data;
	unsigned int olen;
	struct boothc_hdr_msg hdr;

	if (format_peers(&data, &olen) < 0)
		goto out;

	init_header(&hdr.header, CL_LIST, 0, 0, RLT_SUCCESS, 0, sizeof(hdr) + olen);
	(void)send_header_plus(fd, &hdr, data, olen);

out:
	if (data)
		free(data);
}

/* trim trailing spaces if the key is ascii
 */
static void trim_key()
{
	char *p;
	int i;

	for (i=0, p=booth_conf->authkey; i < booth_conf->authkey_len; i++, p++)
		if (!isascii(*p))
			return;

	p = booth_conf->authkey;
	while (booth_conf->authkey_len > 0 && isspace(*p)) {
		p++;
		booth_conf->authkey_len--;
	}
	memmove(booth_conf->authkey, p, booth_conf->authkey_len);

	p = booth_conf->authkey + booth_conf->authkey_len - 1;
	while (booth_conf->authkey_len > 0 && isspace(*p)) {
		booth_conf->authkey_len--;
		p--;
	}
}

static int read_authkey()
{
	int fd;

	booth_conf->authkey[0] = '\0';
	if (stat(booth_conf->authfile, &booth_conf->authstat) < 0) {
		log_error("cannot stat authentication file %s: %s",
			booth_conf->authfile, strerror(errno));
		return -1;
	}
	if (booth_conf->authstat.st_mode & (S_IRGRP | S_IROTH)) {
		log_error("%s: file can be readable only for the owner", booth_conf->authfile);
		return -1;
	}
	fd = open(booth_conf->authfile, O_RDONLY);
	if (fd < 0) {
		log_error("cannot open %s: %s",
			booth_conf->authfile, strerror(errno));
		return -1;
	}
	booth_conf->authkey_len = read(fd, booth_conf->authkey, BOOTH_MAX_KEY_LEN);
	close(fd);
	trim_key();
	log_debug("read key of size %d in authfile %s",
		booth_conf->authkey_len, booth_conf->authfile);
	/* make sure that the key is of minimum length */
	return (booth_conf->authkey_len >= BOOTH_MIN_KEY_LEN) ? 0 : -1;
}

int update_authkey()
{
	struct stat statbuf;

	if (stat(booth_conf->authfile, &statbuf) < 0) {
		log_error("cannot stat authentication file %s: %s",
			booth_conf->authfile, strerror(errno));
		return -1;
	}
	if (statbuf.st_mtime > booth_conf->authstat.st_mtime) {
		return read_authkey();
	}
	return 0;
}

static int setup_config(int type)
{
	int rv;

	rv = read_config(cl.configfile, type);
	if (rv < 0)
		goto out;

	if (booth_conf->authfile[0] != '\0') {
		rv = read_authkey();
		if (rv < 0)
			goto out;
	}

	/* Set "local" pointer, ignoring errors. */
	if (cl.type == DAEMON && cl.site[0]) {
		if (!find_site_by_name(cl.site, &local, 1)) {
			log_error("Cannot find \"%s\" in the configuration.",
					cl.site);
			return -EINVAL;
		}
		local->local = 1;
	} else
		find_myself(NULL, type == CLIENT || type == GEOSTORE);


	rv = check_config(type);
	if (rv < 0)
		goto out;


	/* Per default the PID file name is derived from the
	 * configuration name. */
	if (!cl.lockfile[0]) {
		snprintf(cl.lockfile, sizeof(cl.lockfile)-1,
				"%s/%s.pid", BOOTH_RUN_DIR, booth_conf->name);
	}

out:
	return rv;
}

static int setup_transport(void)
{
	int rv;

	rv = transport()->init(message_recv);
	if (rv < 0) {
		log_error("failed to init booth_transport %s", transport()->name);
		goto out;
	}

	rv = booth_transport[TCP].init(NULL);
	if (rv < 0) {
		log_error("failed to init booth_transport[TCP]");
		goto out;
	}

out:
	return rv;
}


static int write_daemon_state(int fd, int state)
{
	char buffer[1024];
	int rv, size;

	size = sizeof(buffer) - 1;
	rv = snprintf(buffer, size,
			"booth_pid=%d "
			"booth_state=%s "
			"booth_type=%s "
			"booth_cfg_name='%s' "
			"booth_id=%d "
			"booth_addr_string='%s' "
			"booth_port=%d\n",
		getpid(), 
		( state == BOOTHD_STARTED  ? "started"  : 
		  state == BOOTHD_STARTING ? "starting" : 
		  "invalid"), 
		type_to_string(local->type),
		booth_conf->name,
		local->site_id,
		local->addr_string,
		booth_conf->port);

	if (rv < 0 || rv == size) {
		log_error("Buffer filled up in write_daemon_state().");
		return -1;
	}
	size = rv;


	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error("lockfile %s truncate error %d: %s",
				cl.lockfile, errno, strerror(errno));
		return rv;
	}


	rv = lseek(fd, 0, SEEK_SET);
	if (rv < 0) {
		log_error("lseek set fd(%d) offset to 0 error, return(%d), message(%s)",
			fd, rv, strerror(errno));
		rv = -1;
		return rv;
	} 


	rv = write(fd, buffer, size);

	if (rv != size) {
		log_error("write to fd(%d, %d) returned %d, errno %d, message(%s)",
                      fd, size,
		      rv, errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int loop(int fd)
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	int rv, i;

	rv = setup_transport();
	if (rv < 0)
		goto fail;

	rv = setup_ticket();
	if (rv < 0)
		goto fail;

	rv = write_daemon_state(fd, BOOTHD_STARTED);
	if (rv != 0) {
		log_error("write daemon state %d to lockfile error %s: %s",
                      BOOTHD_STARTED, cl.lockfile, strerror(errno));
		goto fail;
	}

	log_info("BOOTH %s daemon started, node id is 0x%08X (%d).",
		type_to_string(local->type),
			local->site_id, local->site_id);

	while (1) {
		rv = poll(pollfds, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			log_error("poll failed: %s (%d)", strerror(errno), errno);
			goto fail;
		}

		for (i = 0; i <= client_maxi; i++) {
			if (clients[i].fd < 0)
				continue;

			if (pollfds[i].revents & POLLIN) {
				workfn = clients[i].workfn;
				if (workfn)
					workfn(i);
			}
			if (pollfds[i].revents &
					(POLLERR | POLLHUP | POLLNVAL)) {
				deadfn = clients[i].deadfn;
				if (deadfn)
					deadfn(i);
			}
		}

		process_tickets();
	}

	return 0;

fail:
	return -1;
}


static int test_reply(cmd_result_t reply_code, cmd_request_t cmd)
{
	int rv = 0;
	const char *op_str = "";

	if (cmd == CMD_GRANT)
		op_str = "grant";
	else if (cmd == CMD_REVOKE)
		op_str = "revoke";
	else if (cmd == CMD_LIST)
		op_str = "list";
	else if (cmd == CMD_PEERS)
		op_str = "peers";
	else {
		log_error("internal error reading reply result!");
		return -1;
	}

	switch (reply_code) {
	case RLT_OVERGRANT:
		log_info("You're granting a granted ticket. "
			 "If you wanted to migrate a ticket, "
			 "use revoke first, then use grant.");
		rv = -1;
		break;

	case RLT_TICKET_IDLE:
		log_info("ticket is not owned");
		rv = 0;
		break;

	case RLT_ASYNC:
		log_info("%s command sent, result will be returned "
			 "asynchronously. Please use \"booth list\" to "
			 "see the outcome.", op_str);
		rv = 0;
		break;

	case RLT_CIB_PENDING:
		log_info("%s succeeded (CIB commit pending)", op_str);
		/* wait for the CIB commit? */
		rv = (cl.options & OPT_WAIT_COMMIT) ? 3 : 0;
		break;

	case RLT_MORE:
		rv = 2;
		break;

	case RLT_SYNC_SUCC:
	case RLT_SUCCESS:
		if (cmd != CMD_LIST && cmd != CMD_PEERS)
			log_info("%s succeeded!", op_str);
		rv = 0;
		break;

	case RLT_SYNC_FAIL:
		log_info("%s failed!", op_str);
		rv = -1;
		break;

	case RLT_INVALID_ARG:
		log_error("ticket \"%s\" does not exist",
				cl.msg.ticket.id);
		rv = -1;
		break;

	case RLT_AUTH:
		log_error("authentication error");
		rv = -1;
		break;

	case RLT_EXT_FAILED:
		log_error("before-acquire-handler for ticket \"%s\" failed, grant denied",
				cl.msg.ticket.id);
		rv = -1;
		break;

	case RLT_ATTR_PREREQ:
		log_error("attr-prereq for ticket \"%s\" failed, grant denied",
				cl.msg.ticket.id);
		rv = -1;
		break;

	case RLT_REDIRECT:
		/* talk to another site */
		rv = 1;
		break;

	default:
		log_error("got an error code: %x", rv);
		rv = -1;
	}
	return rv;
}

static int query_get_string_answer(cmd_request_t cmd)
{
	struct booth_site *site;
	struct boothc_hdr_msg reply;
	struct boothc_header *header;
	char *data;
	int data_len;
	int rv;
	struct booth_transport const *tpt;
	int (*test_reply_f) (cmd_result_t reply_code, cmd_request_t cmd);
	size_t msg_size;
	void *request;

	if (cl.type == GEOSTORE) {
		test_reply_f = test_attr_reply;
		msg_size = sizeof(cl.attr_msg);
		request = &cl.attr_msg;
	} else {
		test_reply_f = test_reply;
		msg_size = sizeof(cl.msg);
		request = &cl.msg;
	}
	header = (struct boothc_header *)request;
	data = NULL;

	init_header(header, cmd, 0, cl.options, 0, 0, msg_size);

	if (!*cl.site)
		site = local;
	else if (!find_site_by_name(cl.site, &site, 1)) {
		log_error("cannot find site \"%s\"", cl.site);
		rv = ENOENT;
		goto out;
	}

	tpt = booth_transport + TCP;
	rv = tpt->open(site);
	if (rv < 0)
		goto out_close;

	rv = tpt->send(site, request, msg_size);
	if (rv < 0)
		goto out_close;

	rv = tpt->recv_auth(site, &reply, sizeof(reply));
	if (rv < 0)
		goto out_close;

	data_len = ntohl(reply.header.length) - rv;

	/* no attribute, or no ticket found */
	if (!data_len) {
		goto out_test_reply;
	}

	data = malloc(data_len+1);
	if (!data) {
		rv = -ENOMEM;
		goto out_close;
	}
	rv = tpt->recv(site, data, data_len);
	if (rv < 0)
		goto out_close;
	*(data+data_len) = '\0';

	*(data + data_len) = '\0';
	(void)fputs(data, stdout);
	fflush(stdout);
	rv = 0;

out_test_reply:
	rv = test_reply_f(ntohl(reply.header.result), cmd);
out_close:
	tpt->close(site);
out:
	if (data)
		free(data);
	return rv;
}


static int do_command(cmd_request_t cmd)
{
	struct booth_site *site;
	struct boothc_ticket_msg reply;
	struct booth_transport const *tpt;
	uint32_t leader_id;
	int rv;
	int reply_cnt = 0, msg_logged = 0;
	const char *op_str = "";

	if (cmd == CMD_GRANT)
		op_str = "grant";
	else if (cmd == CMD_REVOKE)
		op_str = "revoke";

	rv = 0;
	site = NULL;

	/* Always use TCP for client - at least for now. */
	tpt = booth_transport + TCP;

	if (!*cl.site)
		site = local;
	else {
		if (!find_site_by_name(cl.site, &site, 1)) {
			log_error("Site \"%s\" not configured.", cl.site);
			goto out_close;
		}
	}

	if (site->type == ARBITRATOR) {
		if (site == local) {
			log_error("We're just an arbitrator, cannot grant/revoke tickets here.");
		} else {
			log_error("%s is just an arbitrator, cannot grant/revoke tickets there.", cl.site);
		}
		goto out_close;
	}

	assert(site->type == SITE);

	/* We don't check for existence of ticket, so that asking can be
	 * done without local configuration, too.
	 * Although, that means that the UDP port has to be specified, too. */
	if (!cl.msg.ticket.id[0]) {
		/* If the loaded configuration has only a single ticket defined, use that. */
		if (booth_conf->ticket_count == 1) {
			strncpy(cl.msg.ticket.id, booth_conf->ticket[0].name,
				sizeof(cl.msg.ticket.id));
		} else {
			log_error("No ticket given.");
			goto out_close;
		}
	}

redirect:
	init_header(&cl.msg.header, cmd, 0, cl.options, 0, 0, sizeof(cl.msg));

	rv = tpt->open(site);
	if (rv < 0)
		goto out_close;

	rv = tpt->send(site, &cl.msg, sendmsglen(&cl.msg));
	if (rv < 0)
		goto out_close;

read_more:
	rv = tpt->recv_auth(site, &reply, sizeof(reply));
	if (rv < 0) {
		/* print any errors depending on the code sent by the
		 * server */
		(void)test_reply(ntohl(reply.header.result), cmd);
		goto out_close;
	}

	rv = test_reply(ntohl(reply.header.result), cmd);
	if (rv == 1) {
		tpt->close(site);
		leader_id = ntohl(reply.ticket.leader);
		if (!find_site_by_id(leader_id, &site)) {
			log_error("Message with unknown redirect site %x received", leader_id);
			rv = -1;
			goto out_close;
		}
		goto redirect;
	} else if (rv == 2 || rv == 3) {
		/* the server has more to say */
		/* don't wait too long */
		if (reply_cnt > 1 && !(cl.options & OPT_WAIT)) {
			rv = 0;
			log_info("Giving up on waiting for the definite result. "
				 "Please use \"booth list\" later to "
				 "see the outcome.");
			goto out_close;
		}
		if (reply_cnt == 0) {
			log_info("%s request sent, "
				"waiting for the result ...", op_str);
			msg_logged++;
		} else if (rv == 3 && msg_logged < 2) {
			log_info("waiting for the CIB commit ...");
			msg_logged++;
		}
		reply_cnt++;
		goto read_more;
	}

out_close:
	if (site)
		tpt->close(site);
	return rv;
}



static int _lockfile(int mode, int *fdp, pid_t *locked_by)
{
	struct flock lock;
	int fd, rv;


	/* After reboot the directory may not yet exist.
	 * Try to create it, but ignore errors. */
	if (strncmp(cl.lockfile, BOOTH_RUN_DIR,
				strlen(BOOTH_RUN_DIR)) == 0)
		mkdir(BOOTH_RUN_DIR, 0775);


	if (locked_by)
		*locked_by = 0;

	*fdp = -1;
	fd = open(cl.lockfile, mode, 0664);
	if (fd < 0)
		return errno;

	*fdp = fd;

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;
	lock.l_pid = 0;


	if (fcntl(fd, F_SETLK, &lock) == 0)
		return 0;

	rv = errno;

	if (locked_by)
		if (fcntl(fd, F_GETLK, &lock) == 0)
			*locked_by = lock.l_pid;

	return rv;
}


static inline int is_root(void)
{
	return geteuid() == 0;
}


static int create_lockfile(void)
{
	int rv, fd;

	fd = -1;
	rv = _lockfile(O_CREAT | O_WRONLY, &fd, NULL);

	if (fd == -1) {
		log_error("lockfile %s open error %d: %s",
				cl.lockfile, rv, strerror(rv));
		return -1;
	}

	if (rv < 0) {
		log_error("lockfile %s setlk error %d: %s",
				cl.lockfile, rv, strerror(rv));
		goto fail;
	}

	rv = write_daemon_state(fd, BOOTHD_STARTING);
	if (rv != 0) {
		log_error("write daemon state %d to lockfile error %s: %s",
				BOOTHD_STARTING, cl.lockfile, strerror(errno));
		goto fail;
	}

	if (is_root()) {
		if (fchown(fd, booth_conf->uid, booth_conf->gid) < 0)
			log_error("fchown() on lockfile said %d: %s",
					errno, strerror(errno));
	}

	return fd;

fail:
	close(fd);
	return -1;
}

static void unlink_lockfile(int fd)
{
	unlink(cl.lockfile);
	close(fd);
}

static void print_usage(void)
{
	printf(
	"Usage:\n"
	"  booth list [options]\n"
	"  booth {grant|revoke} [options] <ticket>\n"
	"  booth status [options]\n"
	"\n"
	"  list:	     List all tickets\n"
	"  grant:        Grant ticket to site\n"
	"  revoke:       Revoke ticket\n"
	"\n"
	"Options:\n"
	"  -c FILE       Specify config file [default " BOOTH_DEFAULT_CONF "]\n"
	"                Can be a path or just a name without \".conf\" suffix\n"
	"  -s <site>     Connect/grant to a different site\n"
	"  -F            Try to grant the ticket immediately\n"
	"                even if not all sites are reachable\n"
	"  -w            Wait forever for the outcome of the request\n"
	"  -C            Wait until the ticket is committed to the CIB (grant only)\n"
	"  -h            Print this help\n"
	"\n"
	"Examples:\n"
	"\n"
	"  # booth list (list tickets)\n"
	"  # booth grant ticket-A (grant ticket here)\n"
	"  # booth grant -s 10.121.8.183 ticket-A (grant ticket to site 10.121.8.183)\n"
	"  # booth revoke ticket-A (revoke ticket)\n"
	"\n"
	"See the booth(8) man page for more details.\n"
	);
}

#define OPTION_STRING		"c:Dl:t:s:FhSwC"
#define ATTR_OPTION_STRING		"c:Dt:s:h"

void safe_copy(char *dest, char *value, size_t buflen, const char *description) {
	int content_len = buflen - 1;

	if (strlen(value) >= content_len) {
		fprintf(stderr, "'%s' exceeds maximum %s length of %d\n",
			value, description, content_len);
		exit(EXIT_FAILURE);
	}
	strncpy(dest, value, content_len);
	dest[content_len] = 0;
}

static int host_convert(char *hostname, char *ip_str, size_t ip_size)
{
	struct addrinfo *result = NULL, hints = {0};
	int re = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	re = getaddrinfo(hostname, NULL, &hints, &result);

	if (re == 0) {
		struct in_addr addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
		const char *re_ntop = inet_ntop(AF_INET, &addr, ip_str, ip_size);
		if (re_ntop == NULL) {
			re = -1;
		}
	}

	freeaddrinfo(result);
	return re;
}

#define cparg(dest, descr) do { \
	if (optind >= argc) \
		goto missingarg; \
	safe_copy(dest, argv[optind], sizeof(dest), descr); \
	optind++; \
} while(0)

static int read_arguments(int argc, char **argv)
{
	int optchar;
	char *arg1 = argv[1];
	char *op = NULL;
	char *cp;
	const char *opt_string = OPTION_STRING;
	char site_arg[INET_ADDRSTRLEN] = {0};
	int left;

	cl.type = 0;
	if ((cp = strstr(argv[0], ATTR_PROG)) &&
			!strcmp(cp, ATTR_PROG)) {
		cl.type = GEOSTORE;
		op = argv[1];
		optind = 2;
		opt_string = ATTR_OPTION_STRING;
	} else if (argc > 1 && (strcmp(arg1, "arbitrator") == 0 ||
			strcmp(arg1, "site") == 0 ||
			strcmp(arg1, "start") == 0 ||
			strcmp(arg1, "daemon") == 0)) {
		cl.type = DAEMON;
		optind = 2;
	} else if (argc > 1 && (strcmp(arg1, "status") == 0)) {
		cl.type = STATUS;
		optind = 2;
	} else if (argc > 1 && (strcmp(arg1, "client") == 0)) {
		cl.type = CLIENT;
		if (argc < 3) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		op = argv[2];
		optind = 3;
	}
	if (!cl.type) {
		cl.type = CLIENT;
		op = argv[1];
		optind = 2;
    }

	if (argc < 2 || !strcmp(arg1, "help") || !strcmp(arg1, "--help") ||
			!strcmp(arg1, "-h")) {
		if (cl.type == GEOSTORE)
			print_geostore_usage();
		else
			print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version") || !strcmp(arg1, "--version") ||
			!strcmp(arg1, "-V")) {
		printf("%s %s\n", argv[0], RELEASE_STR);
		exit(EXIT_SUCCESS);
	}

    if (cl.type == CLIENT) {
		if (!strcmp(op, "list"))
			cl.op = CMD_LIST;
		else if (!strcmp(op, "grant"))
			cl.op = CMD_GRANT;
		else if (!strcmp(op, "revoke"))
			cl.op = CMD_REVOKE;
		else if (!strcmp(op, "peers"))
			cl.op = CMD_PEERS;
		else {
			fprintf(stderr, "client operation \"%s\" is unknown\n",
					op);
			exit(EXIT_FAILURE);
		}
	} else if (cl.type == GEOSTORE) {
		if (!strcmp(op, "list"))
			cl.op = ATTR_LIST;
		else if (!strcmp(op, "set"))
			cl.op = ATTR_SET;
		else if (!strcmp(op, "get"))
			cl.op = ATTR_GET;
		else if (!strcmp(op, "delete"))
			cl.op = ATTR_DEL;
		else {
			fprintf(stderr, "attribute operation \"%s\" is unknown\n",
					op);
			exit(EXIT_FAILURE);
		}
	}

	while (optind < argc) {
		optchar = getopt(argc, argv, opt_string);

		switch (optchar) {
		case 'c':
			if (strchr(optarg, '/')) {
				safe_copy(cl.configfile, optarg,
						sizeof(cl.configfile), "config file");
			} else {
				/* If no "/" in there, use with default directory. */
				strcpy(cl.configfile, BOOTH_DEFAULT_CONF_DIR);
				cp = cl.configfile + strlen(BOOTH_DEFAULT_CONF_DIR);
				assert(cp > cl.configfile);
				assert(*(cp-1) == '/');

				/* Write at the \0, ie. after the "/" */
				safe_copy(cp, optarg,
						(sizeof(cl.configfile) -
						 (cp -  cl.configfile) -
						 strlen(BOOTH_DEFAULT_CONF_EXT)),
						"config name");

				/* If no extension, append ".conf".
				 * Space is available, see -strlen() above. */
				if (!strchr(cp, '.'))
					strcat(cp, BOOTH_DEFAULT_CONF_EXT);
			}
			break;
		case 'D':
			debug_level++;
			enable_stderr = 1;
			/* Fall through */
		case 'S':
			daemonize = 1;
			break;

		case 'l':
			safe_copy(cl.lockfile, optarg, sizeof(cl.lockfile), "lock file");
			break;
		case 't':
			if (cl.op == CMD_GRANT || cl.op == CMD_REVOKE) {
				safe_copy(cl.msg.ticket.id, optarg,
						sizeof(cl.msg.ticket.id), "ticket name");
			} else if (cl.type == GEOSTORE) {
				safe_copy(cl.attr_msg.attr.tkt_id, optarg,
						sizeof(cl.attr_msg.attr.tkt_id), "ticket name");
			} else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			/* For testing and debugging: allow "-s site" also for
			 * daemon start, so that the address that should be used
			 * can be set manually.
			 * This makes it easier to start multiple processes
			 * on one machine. */
			if (cl.type == CLIENT || cl.type == GEOSTORE ||
					(cl.type == DAEMON && debug_level)) {
				if (strcmp(optarg, OTHER_SITE) &&
						host_convert(optarg, site_arg, INET_ADDRSTRLEN) == 0) {
					safe_copy(cl.site, site_arg, sizeof(cl.site), "site name");
				} else {
					safe_copy(cl.site, optarg, sizeof(cl.site), "site name");
				}
			} else {
				log_error("\"-s\" not allowed in daemon mode.");
				exit(EXIT_FAILURE);
			}
			break;

		case 'F':
			if (cl.type != CLIENT || cl.op != CMD_GRANT) {
				log_error("use \"-F\" only for client grant");
				exit(EXIT_FAILURE);
			}
			cl.options |= OPT_IMMEDIATE;
			break;

		case 'w':
			if (cl.type != CLIENT ||
					(cl.op != CMD_GRANT && cl.op != CMD_REVOKE)) {
				log_error("use \"-w\" only for grant and revoke");
				exit(EXIT_FAILURE);
			}
			cl.options |= OPT_WAIT;
			break;

		case 'C':
			if (cl.type != CLIENT || cl.op != CMD_GRANT) {
				log_error("use \"-C\" only for grant");
				exit(EXIT_FAILURE);
			}
			cl.options |= OPT_WAIT | OPT_WAIT_COMMIT;
			break;

		case 'h':
			if (cl.type == GEOSTORE)
				print_geostore_usage();
			else
				print_usage();
			exit(EXIT_SUCCESS);
			break;

		case ':':
		case '?':
			fprintf(stderr, "Please use '-h' for usage.\n");
			exit(EXIT_FAILURE);
			break;

		case -1:
			/* No more parameters on cmdline, only arguments. */
			goto extra_args;

		default:
			goto unknown;
		};
	}

	return 0;

extra_args:
	if (cl.type == CLIENT && !cl.msg.ticket.id[0]) {
		cparg(cl.msg.ticket.id, "ticket name");
	} else if (cl.type == GEOSTORE) {
		if (cl.op != ATTR_LIST) {
			cparg(cl.attr_msg.attr.name, "attribute name");
		}
		if (cl.op == ATTR_SET) {
			cparg(cl.attr_msg.attr.val, "attribute value");
		}
	}

	if (optind == argc)
		return 0;


	left = argc - optind;
	fprintf(stderr, "Superfluous argument%s: %s%s\n",
			left == 1 ? "" : "s",
			argv[optind],
			left == 1 ? "" : "...");
	exit(EXIT_FAILURE);

unknown:
	fprintf(stderr, "unknown option: %s\n", argv[optind]);
	exit(EXIT_FAILURE);

missingarg:
	fprintf(stderr, "not enough arguments\n");
	exit(EXIT_FAILURE);
}


static void set_scheduler(void)
{
	struct sched_param sched_param;
	struct rlimit rlimit;
	int rv;

	rlimit.rlim_cur = RLIM_INFINITY;
	rlimit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_MEMLOCK, &rlimit);
	rv = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rv < 0) {
		log_error("mlockall failed");
	}

	rv = sched_get_priority_max(SCHED_RR);
	if (rv != -1) {
		sched_param.sched_priority = rv;
		rv = sched_setscheduler(0, SCHED_RR, &sched_param);
		if (rv == -1)
			log_error("could not set SCHED_RR priority %d: %s (%d)",
					sched_param.sched_priority,
					strerror(errno), errno);
	} else {
		log_error("could not get maximum scheduler priority err %d",
				errno);
	}
}

static int set_procfs_val(const char *path, const char *val)
{
	int rc = -1;
	FILE *fp = fopen(path, "w");

	if (fp) {
		if (fprintf(fp, "%s", val) > 0)
			rc = 0;
		fclose(fp);
	}
	return rc;
}

static int do_status(int type)
{
	pid_t pid;
	int rv, lock_fd, ret;
	const char *reason = NULL;
	char lockfile_data[1024], *cp;


	ret = PCMK_OCF_NOT_RUNNING;

	rv = setup_config(type);
	if (rv) {
		reason = "Error reading configuration.";
		ret = PCMK_OCF_UNKNOWN_ERROR;
		goto quit;
	}


	if (!local) {
		reason = "No Service IP active here.";
		goto quit;
	}


	rv = _lockfile(O_RDWR, &lock_fd, &pid);
	if (rv == 0) {
		reason = "PID file not locked.";
		goto quit;
	}
	if (lock_fd == -1) {
		reason = "No PID file.";
		goto quit;
	}

	if (pid) {
		fprintf(stdout, "booth_lockpid=%d ", pid);
		fflush(stdout);
	}


	rv = read(lock_fd, lockfile_data, sizeof(lockfile_data) - 1);
	if (rv < 4) {
		reason = "Cannot read lockfile data.";
		ret = PCMK_LSB_UNKNOWN_ERROR;
		goto quit;

	}
	lockfile_data[rv] = 0;

	if (lock_fd != -1)
		close(lock_fd);


	/* Make sure it's only a single line */
	cp = strchr(lockfile_data, '\r');
	if (cp)
		*cp = 0;
	cp = strchr(lockfile_data, '\n');
	if (cp)
		*cp = 0;



	rv = setup_tcp_listener(1);
	if (rv == 0) {
		reason = "TCP port not in use.";
		goto quit;
	}


	fprintf(stdout, "booth_lockfile='%s' %s\n",
			cl.lockfile, lockfile_data);
	if (daemonize)
		fprintf(stderr, "Booth at %s port %d seems to be running.\n",
				local->addr_string, booth_conf->port);
	return 0;


quit:
	log_debug("not running: %s", reason);
	/* Ie. "DEBUG" */
	if (daemonize)
		fprintf(stderr, "not running: %s\n", reason);
	return ret;
}


static int limit_this_process(void)
{
	int rv;
	if (!is_root())
		return 0;

	if (setregid(booth_conf->gid, booth_conf->gid) < 0) {
		rv = errno;
		log_error("setregid() didn't work: %s", strerror(rv));
		return rv;
	}

	if (setreuid(booth_conf->uid, booth_conf->uid) < 0) {
		rv = errno;
		log_error("setreuid() didn't work: %s", strerror(rv));
		return rv;
	}

	return 0;
}

static int lock_fd = -1;

static void server_exit(void)
{
	int rv;

	if (lock_fd >= 0) {
		/* We might not be able to delete it, but at least
		 * make it empty. */
		rv = ftruncate(lock_fd, 0);
		(void)rv;
		unlink_lockfile(lock_fd);
	}
	log_info("exiting");
}

static void sig_exit_handler(int sig)
{
	log_info("caught signal %d", sig);
	exit(0);
}

static int do_server(int type)
{
	int rv = -1;
	static char log_ent[128] = DAEMON_NAME "-";

	rv = setup_config(type);
	if (rv < 0)
		return rv;

	if (!local) {
		log_error("Cannot find myself in the configuration.");
		exit(EXIT_FAILURE);
	}

	if (!daemonize) {
		if (daemon(0, 0) < 0) {
			perror("daemon error");
			exit(EXIT_FAILURE);
		}
	}

	/* The lockfile must be written to _after_ the call to daemon(), so
	 * that the lockfile contains the pid of the daemon, not the parent. */
	lock_fd = create_lockfile();
	if (lock_fd < 0)
		return lock_fd;

	atexit(server_exit);

	strcat(log_ent, type_to_string(local->type));
	cl_log_set_entity(log_ent);
	cl_log_enable_stderr(enable_stderr ? TRUE : FALSE);
	cl_log_set_facility(HA_LOG_FACILITY);
	cl_inherit_logging_environment(0);

	log_info("BOOTH %s %s daemon is starting",
			type_to_string(local->type), RELEASE_STR);

	signal(SIGUSR1, (__sighandler_t)tickets_log_info);
	signal(SIGTERM, (__sighandler_t)sig_exit_handler);
	signal(SIGINT, (__sighandler_t)sig_exit_handler);
	/* we'll handle errors there and then */
	signal(SIGPIPE, SIG_IGN);

	set_scheduler();
	/* we don't want to be killed by the OOM-killer */
	if (set_procfs_val("/proc/self/oom_score_adj", "-999"))
		(void)set_procfs_val("/proc/self/oom_adj", "-16");
	set_proc_title("%s %s %s for [%s]:%d",
			DAEMON_NAME,
			cl.configfile,
			type_to_string(local->type),
			local->addr_string,
			booth_conf->port);

	rv = limit_this_process();
	if (rv)
		return rv;

	if (cl_enable_coredumps(TRUE) < 0){
		log_error("enabling core dump failed");
	}
	cl_cdtocoredir();
	prctl(PR_SET_DUMPABLE, (unsigned long)TRUE, 0UL, 0UL, 0UL);

	signal(SIGCHLD, (__sighandler_t)wait_child);
	rv = loop(lock_fd);

	return rv;
}

static int do_client(void)
{
	int rv;

	rv = setup_config(CLIENT);
	if (rv < 0) {
		log_error("cannot read config");
		goto out;
	}

	switch (cl.op) {
	case CMD_LIST:
	case CMD_PEERS:
		rv = query_get_string_answer(cl.op);
		break;

	case CMD_GRANT:
	case CMD_REVOKE:
		rv = do_command(cl.op);
		break;
	}

out:
	return rv;
}

static int do_attr(void)
{
	int rv = -1;

	rv = setup_config(GEOSTORE);
	if (rv < 0) {
		log_error("cannot read config");
		goto out;
	}

	/* We don't check for existence of ticket, so that asking can be
	 * done without local configuration, too.
	 * Although, that means that the UDP port has to be specified, too. */
	if (!cl.attr_msg.attr.tkt_id[0]) {
		/* If the loaded configuration has only a single ticket defined, use that. */
		if (booth_conf->ticket_count == 1) {
			strncpy(cl.attr_msg.attr.tkt_id, booth_conf->ticket[0].name,
				sizeof(cl.attr_msg.attr.tkt_id));
		} else {
			rv = 1;
			log_error("No ticket given.");
			goto out;
		}
	}

	switch (cl.op) {
	case ATTR_LIST:
	case ATTR_GET:
		rv = query_get_string_answer(cl.op);
		break;

	case ATTR_SET:
	case ATTR_DEL:
		rv = do_attr_command(cl.op);
		break;
	}

out:
	return rv;
}

int main(int argc, char *argv[], char *envp[])
{
	int rv;
	const char *cp;

	init_set_proc_title(argc, argv, envp);
	get_time(&start_time);

	memset(&cl, 0, sizeof(cl));
	strncpy(cl.configfile,
			BOOTH_DEFAULT_CONF, BOOTH_PATH_LEN - 1);
	cl.lockfile[0] = 0;
	debug_level = 0;

	cl_log_set_entity(
		(cp = strstr(argv[0], ATTR_PROG)) && !strcmp(cp, ATTR_PROG)
		? ATTR_PROG
		: "booth"
		);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(0);


	rv = read_arguments(argc, argv);
	if (rv < 0)
		goto out;


	switch (cl.type) {
	case STATUS:
		rv = do_status(cl.type);
		break;

	case ARBITRATOR:
	case DAEMON:
	case SITE:
		rv = do_server(cl.type);
		break;

	case CLIENT:
		rv = do_client();
		break;

	case GEOSTORE:
		rv = do_attr();
		break;
	}

out:
	/* Normalize values. 0x100 would be seen as "OK" by waitpid(). */
	return (rv >= 0 && rv < 0x70) ? rv : 1;
}
