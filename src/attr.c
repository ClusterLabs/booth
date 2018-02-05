/*
 * Copyright (C) 2015 Dejan Muhamedagic <dejan@hello-penguin.com>
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "attr.h"
#include "booth.h"
#include "ticket.h"
#include "pacemaker.h"

void print_geostore_usage(void)
{
	printf(
	"Usage:\n"
	"  geostore {list|set|get|delete} [-t ticket] [options] attr [value]\n"
	"\n"
	"  list:	     List all attributes\n"
	"  set:          Set attribute to a value\n"
	"  get:          Get attribute's value\n"
	"  delete:       Delete attribute\n"
	"\n"
	"  -t <ticket>   Ticket where attribute resides\n"
	"                (required, if more than one ticket is configured)\n"
	"\n"
	"Options:\n"
	"  -c FILE       Specify config file [default " BOOTH_DEFAULT_CONF "]\n"
	"                Can be a path or just a name without \".conf\" suffix\n"
	"  -s <site>     Connect to a different site\n"
	"  -h            Print this help\n"
	"\n"
	"Examples:\n"
	"\n"
	"  # geostore list -t ticket-A -s 10.121.8.183\n"
	"  # geostore set -s 10.121.8.183 sr_status ACTIVE\n"
	"  # geostore get -t ticket-A -s 10.121.8.183 sr_status\n"
	"  # geostore delete -s 10.121.8.183 sr_status\n"
	"\n"
	"See the geostore(8) man page for more details.\n"
	);
}

/*
 * the client side
 */

/* cl has all the input parameters:
 * ticket, attr name, attr value
 */

int test_attr_reply(cmd_result_t reply_code, cmd_request_t cmd)
{
	int rv = 0;
	const char *op_str = "";

	switch (cmd) {
	case ATTR_SET:	op_str = "set";		break;
	case ATTR_GET:	op_str = "get";		break;
	case ATTR_LIST:	op_str = "list";	break;
	case ATTR_DEL:	op_str = "delete";	break;
	default:
		log_error("internal error reading reply result!");
		return -1;
	}

	switch (reply_code) {
	case RLT_ASYNC:
		log_info("%s command sent, result will be returned "
			 "asynchronously.", op_str);
		rv = 0;
		break;

	case RLT_SYNC_SUCC:
	case RLT_SUCCESS:
		if (cmd == ATTR_SET)
			log_info("%s succeeded!", op_str);
		rv = 0;
		break;

	case RLT_SYNC_FAIL:
		log_info("%s failed!", op_str);
		rv = -1;
		break;

	case RLT_INVALID_ARG:
		log_error("ticket \"%s\" does not exist",
				cl.attr_msg.attr.tkt_id);
		rv = 1;
		break;

	case RLT_NO_SUCH_ATTR:
		log_error("attribute \"%s\" not set",
				cl.attr_msg.attr.name);
		rv = 1;
		break;

	case RLT_AUTH:
		log_error("authentication error");
		rv = -1;
		break;

	default:
		log_error("got an error code: %x", rv);
		rv = -1;
	}
	return rv;
}

/* read the server's reply
 * need to first get the header which contains the length of the
 * reply
 * return codes:
 *   -2: header not received
 *   -1: header received, but message too short
 *   >=0: success
 */
static int read_server_reply(
		struct booth_transport const *tpt, struct booth_site *site,
		char *msg)
{
	struct boothc_header *header;
	int rv;
	int len;

	header = (struct boothc_header *)msg;
	rv = tpt->recv(site, header, sizeof(*header));
	if (rv < 0) {
		return -2;
	}
	len = ntohl(header->length);
	rv = tpt->recv(site, msg+len, len-sizeof(*header));
	if (rv < 0) {
		return -1;
	}
	return rv;
}

int do_attr_command(cmd_request_t cmd, struct booth_site *site)
{
	struct boothc_header *header;
	struct booth_transport const *tpt;
	int len, rv = -1;
	char *msg = NULL;

	if (site->type == ARBITRATOR) {
		if (site == local) {
			log_error("We're just an arbitrator, no attributes here.");
		} else {
			log_error("%s is just an arbitrator, no attributes there.", cl.site);
		}
		goto out_close;
	}

	tpt = booth_transport + TCP;

	init_header(&cl.attr_msg.header, cmd, 0, cl.options, 0, 0,
		sizeof(cl.attr_msg));

	rv = tpt->open(site);
	if (rv < 0)
		goto out_close;

	rv = tpt->send(site, &cl.attr_msg, sendmsglen(&cl.attr_msg));
	if (rv < 0)
		goto out_close;

	msg = malloc(MAX_MSG_LEN);
	if (!msg) {
		log_error("out of memory");
		rv = -1;
		goto out_close;
	}

	rv = read_server_reply(tpt, site, msg);
	header = (struct boothc_header *)msg;
	if (rv < 0) {
		if (rv == -1)
			(void)test_attr_reply(ntohl(header->result), cmd);
		goto out_close;
	}
	len = ntohl(header->length);

	if (check_boothc_header(header, len) < 0) {
		log_error("message from %s receive error", site_string(site));
		rv = -1;
		goto out_close;
	}

	if (check_auth(site, msg, len)) {
		log_error("%s failed to authenticate", site_string(site));
		rv = -1;
		goto out_close;
	}
	rv = test_attr_reply(ntohl(header->result), cmd);

out_close:
	tpt->close(site);
	if (msg)
		free(msg);
	return rv;
}

/*
 * the server side
 */

/* need to invert gboolean, our success is 0
 */
#define gbool2rlt(i) (i ? RLT_SUCCESS : RLT_SYNC_FAIL)

static void free_geo_attr(gpointer data)
{
	struct geo_attr *a = (struct geo_attr *)data;

	if (!a)
		return;
	g_free(a->val);
	g_free(a);
}

int store_geo_attr(struct ticket_config *tk, const char *name,
		   const char *val, int notime)
{
	struct geo_attr *a;
	GDestroyNotify free_geo_attr_notify = free_geo_attr;

	if (!tk)
		return -1;
	/*
	 * allocate new, if attr doesn't already exist
	 * copy the attribute value
	 * send status
	 */
	if (!tk->attr)
		tk->attr = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, free_geo_attr_notify);
	if (!tk->attr) {
		log_error("out of memory");
		return -1;
	}

	if (strnlen(name, BOOTH_NAME_LEN) == BOOTH_NAME_LEN)
		tk_log_warn("name of the attribute too long (%d+ bytes), skipped",
			 BOOTH_NAME_LEN);
	else if (strnlen(val, BOOTH_ATTRVAL_LEN) == BOOTH_ATTRVAL_LEN)
		tk_log_warn("value of the attribute too long (%d+ bytes), skipped",
			 BOOTH_ATTRVAL_LEN);
	else {
		a = (struct geo_attr *)calloc(1, sizeof(struct geo_attr));
		if (!a) {
			log_error("out of memory");
			return -1;
		}

		a->val = g_strdup(val);
		if (!notime)
			get_time(&a->update_ts);

		g_hash_table_insert(tk->attr,
			g_strdup(name), a);
	}

	return 0;
}

static cmd_result_t attr_set(struct ticket_config *tk, struct boothc_attr_msg *msg)
{
	int rc;

	rc = store_geo_attr(tk, msg->attr.name, msg->attr.val, 0);
	if (rc) {
		return RLT_SYNC_FAIL;
	}
	(void)pcmk_handler.set_attr(tk, msg->attr.name, msg->attr.val);
	return RLT_SUCCESS;
}

static cmd_result_t attr_del(struct ticket_config *tk, struct boothc_attr_msg *msg)
{
	gboolean rv;
	gpointer orig_key, value;

	/*
	 * lookup attr
	 * deallocate, if found
	 * send status
	 */
	if (!tk->attr)
		return RLT_NO_SUCH_ATTR;

	rv = g_hash_table_lookup_extended(tk->attr, msg->attr.name,
			&orig_key, &value);
	if (!rv)
		return RLT_NO_SUCH_ATTR;

	rv = g_hash_table_remove(tk->attr, msg->attr.name);

	(void)pcmk_handler.del_attr(tk, msg->attr.name);

	return gbool2rlt(rv);
}

static void
append_attr(gpointer key, gpointer value, gpointer user_data)
{
	char *attr_name = (char *)key;
	struct geo_attr *a = (struct geo_attr *)value;
	GString *data = (GString *)user_data;
	char time_str[64];
	time_t ts;

	if (is_time_set(&a->update_ts)) {
		ts = wall_ts(&a->update_ts);
		strftime(time_str, sizeof(time_str), "%F %T",
				localtime(&ts));
	} else {
		time_str[0] = '\0';
	}
	g_string_append_printf(data, "%s %s %s\n",
		attr_name, a->val, time_str);
}


static cmd_result_t attr_get(struct ticket_config *tk, int fd, struct boothc_attr_msg *msg)
{
	cmd_result_t rv = RLT_SUCCESS;
	struct boothc_hdr_msg hdr;
	struct geo_attr *a;
	GString *attr_val;

	/*
	 * lookup attr
	 * send value
	 */

	a = (struct geo_attr *)g_hash_table_lookup(tk->attr, msg->attr.name);
	if (!a)
		return RLT_NO_SUCH_ATTR;
	attr_val = g_string_new(NULL);
	if (!attr_val) {
		log_error("out of memory");
		return RLT_SYNC_FAIL;
	}
	g_string_printf(attr_val, "%s\n", a->val);
	init_header(&hdr.header, ATTR_GET, 0, 0, RLT_SUCCESS, 0,
		sizeof(hdr) + attr_val->len);
	if (send_header_plus(fd, &hdr, attr_val->str, attr_val->len))
		rv = RLT_SYNC_FAIL;
	if (attr_val)
		g_string_free(attr_val, FALSE);
	return rv;
}

static cmd_result_t attr_list(struct ticket_config *tk, int fd, struct boothc_attr_msg *msg)
{
	GString *data;
	cmd_result_t rv;
	struct boothc_hdr_msg hdr;

	/*
	 * list all attributes for the ticket
	 * send the list
	 */
	data = g_string_sized_new(512);
	if (!data) {
		log_error("out of memory");
		return RLT_SYNC_FAIL;
	}
	g_hash_table_foreach(tk->attr, append_attr, data);

	init_header(&hdr.header, ATTR_LIST, 0, 0, RLT_SUCCESS, 0,
		sizeof(hdr) + data->len);
	rv = send_header_plus(fd, &hdr, data->str, data->len);

	if (data)
		g_string_free(data, FALSE);
	return rv;
}

int process_attr_request(struct client *req_client, void *buf)
{
	cmd_result_t rv = RLT_SYNC_FAIL;
	struct ticket_config *tk;
	int cmd;
	struct boothc_attr_msg *msg;
	struct boothc_hdr_msg hdr;

	msg = (struct boothc_attr_msg *)buf;
	cmd = ntohl(msg->header.cmd);
	if (!check_ticket(msg->attr.tkt_id, &tk)) {
		log_warn("client referenced unknown ticket %s",
				msg->attr.tkt_id);
		rv = RLT_INVALID_ARG;
		goto reply_now;
	}

	switch (cmd) {
	case ATTR_LIST:
		rv = attr_list(tk, req_client->fd, msg);
		if (rv)
			goto reply_now;
		return 1;
	case ATTR_GET:
		rv = attr_get(tk, req_client->fd, msg);
		if (rv)
			goto reply_now;
		return 1;
	case ATTR_SET:
		rv = attr_set(tk, msg);
		break;
	case ATTR_DEL:
		rv = attr_del(tk, msg);
		break;
	}

reply_now:
	init_header(&hdr.header, CL_RESULT, 0, 0, rv, 0, sizeof(hdr));
	send_header_plus(req_client->fd, &hdr, NULL, 0);
	return 1;
}

/* read attr message from another site */

/* this is a NOOP and it should never be invoked
 * only clients retrieve/manage attributes and they connect
 * directly to the target site
 */
int attr_recv(void *buf, struct booth_site *source)
{
	struct boothc_attr_msg *msg;
	struct ticket_config *tk;

	msg = (struct boothc_attr_msg *)buf;

	log_warn("unexpected attribute message from %s",
			site_string(source));

	if (!check_ticket(msg->attr.tkt_id, &tk)) {
		log_warn("got invalid ticket name %s from %s",
				msg->attr.tkt_id, site_string(source));
		source->invalid_cnt++;
		return -1;
	}

	return 0;
}
