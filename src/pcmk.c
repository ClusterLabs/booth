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
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "ticket.h"
#include "log.h"
#include "attr.h"
#include "pcmk.h"
#include "inline-fn.h"


#define COMMAND_MAX	2048

const char * interpret_rv(int rv)
{
	static char text[64];

	if (rv == 0)
		return "0";

	if (WIFSIGNALED(rv))
		sprintf(text, "got signal %d", WTERMSIG(rv));
	else
		sprintf(text, "exit code %d", WEXITSTATUS(rv));

	return text;
}


static int pcmk_write_ticket_atomic(struct ticket_config *tk, int grant)
{
	char cmd[COMMAND_MAX];
	int rv;

	/* The long format (--attr-value=) for attribute value is used instead of "-v",
	* so that NO_ONE (which is -1) isn't seen as another option. */
	rv = snprintf(cmd, COMMAND_MAX,
			"crm_ticket -t '%s' "
			"%s --force "
			"-S owner --attr-value=%" PRIi32 " "
			"-S expires --attr-value=%" PRIi64 " "
			"-S term --attr-value=%" PRIi64 " "
			"-S booth-cfg-name --attr-value=%s",
			tk->name,
			(grant > 0 ? "-g" :
			 grant < 0 ? "-r" :
			 ""),
			(int32_t)get_node_id(tk->leader),
			(int64_t)wall_ts(&tk->term_expires),
			(int64_t)tk->current_term,
			booth_conf->name);

	if (rv < 0 || rv >= COMMAND_MAX) {
		log_error("pcmk_write_ticket_atomic: cannot format crm_ticket cmdline (probably too long)");
		return -1;
	}

	rv = system(cmd);
	log_debug("command: '%s' was executed", cmd);
	if (rv != 0)
		log_error("\"%s\" failed, %s", cmd, interpret_rv(rv));

	return rv;
}


static int pcmk_grant_ticket(struct ticket_config *tk)
{

	return pcmk_write_ticket_atomic(tk, +1);
}


static int pcmk_revoke_ticket(struct ticket_config *tk)
{

	return pcmk_write_ticket_atomic(tk, -1);
}


static int _run_crm_ticket(char *cmd)
{
	int i, rv;

	/* If there are errors, there's not much we can do but retry ... */
	for (i=0; i<3 &&
			(rv = system(cmd));
			i++) ;

	log_debug("'%s' gave result %s", cmd, interpret_rv(rv));

	return rv;
}

static int pcmk_set_attr(struct ticket_config *tk, const char *attr, const char *val)
{
	char cmd[COMMAND_MAX];
	int rv;

	rv = snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t '%s' -S '%s' --attr-value='%s'",
		 tk->name, attr, val);

	if (rv < 0 || rv >= COMMAND_MAX) {
		log_error("pcmk_set_attr: cannot format crm_ticket cmdline (probably too long)");
		return -1;
	}

	return _run_crm_ticket(cmd);
}

static int pcmk_del_attr(struct ticket_config *tk, const char *attr)
{
	char cmd[COMMAND_MAX];
	int rv;

	rv = snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t '%s' -D '%s'",
		 tk->name, attr);

	if (rv < 0 || rv >= COMMAND_MAX) {
		log_error("pcmk_del_attr: cannot format crm_ticket cmdline (probably too long)");
		return -1;
	}

	return _run_crm_ticket(cmd);
}


typedef int (*attr_f)(struct booth_config *conf, struct ticket_config *tk,
		      const char *name, const char *val);

struct attr_tab
{
	const char *name;
	attr_f handling_f;
};

static int save_expires(struct booth_config *conf, struct ticket_config *tk,
			const char *name, const char *val)
{
	secs2tv(unwall_ts(atol(val)), &tk->term_expires);
	return 0;
}

static int save_term(struct booth_config *conf, struct ticket_config *tk,
		     const char *name, const char *val)
{
	tk->current_term = atol(val);
	return 0;
}

static int parse_boolean(const char *val)
{
	long v;

	if (!strncmp(val, "false", 5)) {
		v = 0;
	} else if (!strncmp(val, "true", 4)) {
		v = 1;
	} else {
		v = atol(val);
	}
	return v;
}

static int save_granted(struct booth_config *conf, struct ticket_config *tk,
			const char *name, const char *val)
{
	tk->is_granted = parse_boolean(val);
	return 0;
}

static int save_owner(struct booth_config *conf, struct ticket_config *tk,
		      const char *name, const char *val)
{
	/* No check, node could have been deconfigured. */
	tk->leader = NULL;
	return !find_site_by_id(conf, atol(val), &tk->leader);
}

static int ignore_attr(struct booth_config *conf, struct ticket_config *tk,
		       const char *name, const char *val)
{
	return 0;
}

static int save_attr(struct ticket_config *tk, const char *name,
		     const char *val)
{
	/* tell store_geo_attr not to store time, we don't have that
	 * information available
	 */
	return store_geo_attr(tk, name, val, 1);
}

struct attr_tab attr_handlers[] = {
	{ "expires", save_expires},
	{ "term", save_term},
	{ "granted", save_granted},
	{ "owner", save_owner},
	{ "id", ignore_attr},
	{ "last-granted", ignore_attr},
	{ "booth-cfg-name", ignore_attr},
	{ NULL, 0},
};


/* get_attr is currently not used and has not been tested
 */
static int pcmk_get_attr(struct ticket_config *tk, const char *attr, const char **vp)
{
	char cmd[COMMAND_MAX];
	char line[BOOTH_ATTRVAL_LEN+1];
	int rv = 0, pipe_rv;
	int res;
	FILE *p;


	*vp = NULL;
	res = snprintf(cmd, COMMAND_MAX,
			"crm_ticket -t '%s' -G '%s' --quiet",
			tk->name, attr);
	if (res < 0 || res >= COMMAND_MAX) {
		log_error("pcmk_get_attr: cannot format crm_ticket cmdline (probably too long)");
		return -1;
	}

	p = popen(cmd, "r");
	if (p == NULL) {
		pipe_rv = errno;
		log_error("popen error %d (%s) for \"%s\"",
				pipe_rv, strerror(pipe_rv), cmd);
		return (pipe_rv != 0 ? pipe_rv : EINVAL);
	}
	if (fgets(line, BOOTH_ATTRVAL_LEN, p) == NULL) {
		rv = ENODATA;
		goto out;
	}

	*vp = g_strdup(line);

out:
	pipe_rv = pclose(p);
	if (!pipe_rv) {
		log_debug("command \"%s\"", cmd);
	} else if (WEXITSTATUS(pipe_rv) == 6) {
		log_info("command \"%s\", ticket not found", cmd);
	} else {
		log_error("command \"%s\" %s", cmd, interpret_rv(pipe_rv));
	}
	return rv | pipe_rv;
}

static int save_attributes(struct booth_config *conf, struct ticket_config *tk,
			   xmlDocPtr doc)
{
	int rv = 0, rc;
	xmlNodePtr n;
	xmlAttrPtr attr;
	xmlChar *v;
	struct attr_tab *atp;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		tk_log_error("crm_ticket xml output empty");
		return -EINVAL;
	}
	if (xmlStrcmp(n->name, (const xmlChar *)"ticket_state")) {
		tk_log_error("crm_ticket xml root element not ticket_state");
		return -EINVAL;
	}
	for (attr = n->properties; attr; attr = attr->next) {
		v = xmlGetProp(n, attr->name);
		for (atp = attr_handlers; atp->name; atp++) {
			if (!strcmp(atp->name, (const char *) attr->name)) {
				rc = atp->handling_f(conf, tk,
						     (const char *) attr->name,
						     (const char *) v);
				break;
			}
		}
		if (!atp->name) {
			rc = save_attr(tk, (const char *) attr->name,
				       (const char *) v);
		}
		if (rc) {
			tk_log_error("error storing attribute %s", attr->name);
			rv |= rc;
		}
		xmlFree(v);
	}
	return rv;
}


#define CHUNK_SIZE 256

static int parse_ticket_state(struct booth_config *conf, struct ticket_config *tk,
			      FILE *p)
{
	int rv = 0;
	GString *input = NULL;
	char line[CHUNK_SIZE];
	xmlDocPtr doc = NULL;
	int opts = XML_PARSE_COMPACT | XML_PARSE_NONET;

	/* skip first two lines of output */
	if (fgets(line, CHUNK_SIZE-1, p) == NULL || fgets(line, CHUNK_SIZE-1, p) == NULL) {
		tk_log_error("crm_ticket xml output empty");
		rv = ENODATA;
		goto out;
	}
	input = g_string_sized_new(CHUNK_SIZE);
	if (!input) {
		log_error("out of memory");
		rv = -1;
		goto out;
	}
	while (fgets(line, CHUNK_SIZE-1, p) != NULL) {
		if (!g_string_append(input, line)) {
			log_error("out of memory");
			rv = -1;
			goto out;
		}
	}

	doc = xmlReadDoc((const xmlChar *) input->str, NULL, NULL, opts);
	if (doc == NULL) {
		const xmlError *errptr = xmlGetLastError();
		if (errptr) {
			tk_log_error("crm_ticket xml parse failed (domain=%d, level=%d, code=%d): %s",
					errptr->domain, errptr->level,
					errptr->code, errptr->message);
		} else {
			tk_log_error("crm_ticket xml parse failed");
		}
		rv = -EINVAL;
		goto out;
	}
	rv = save_attributes(conf, tk, doc);

out:
	if (doc)
		xmlFreeDoc(doc);
	if (input)
		g_string_free(input, TRUE);
	return rv;
}

static int pcmk_load_ticket(struct booth_config *conf, struct ticket_config *tk)
{
	char cmd[COMMAND_MAX];
	int rv = 0, pipe_rv;
	int res;
	FILE *p;

	res = snprintf(cmd, COMMAND_MAX,
			"crm_ticket -t '%s' -q",
			tk->name);

	if (res < 0 || res >= COMMAND_MAX) {
		log_error("pcmk_load_ticket: cannot format crm_ticket cmdline (probably too long)");
		return -1;
	}

	p = popen(cmd, "r");
	if (p == NULL) {
		pipe_rv = errno;
		log_error("popen error %d (%s) for \"%s\"",
				pipe_rv, strerror(pipe_rv), cmd);
		return (pipe_rv != 0 ? pipe_rv : EINVAL);
	}

	rv = parse_ticket_state(conf, tk, p);

	if (!tk->leader) {
		/* Hmm, no site found for the ticket we have in the
		 * CIB!?
		 * Assume that the ticket belonged to us if it was
		 * granted here!
		 */
		log_warn("%s: no site matches; site got reconfigured?",
			tk->name);
		if (tk->is_granted) {
			log_warn("%s: granted here, assume it belonged to us",
				tk->name);
			set_leader(tk, local);
		}
	}

	pipe_rv = pclose(p);
	if (!pipe_rv) {
		log_debug("command \"%s\"", cmd);
	} else if (WEXITSTATUS(pipe_rv) == 6) {
		log_info("command \"%s\", ticket not found", cmd);
	} else {
		log_error("command \"%s\" %s", cmd, interpret_rv(pipe_rv));
	}
	return rv | pipe_rv;
}


struct ticket_handler pcmk_handler = {
	.grant_ticket   = pcmk_grant_ticket,
	.revoke_ticket  = pcmk_revoke_ticket,
	.load_ticket    = pcmk_load_ticket,
	.set_attr    = pcmk_set_attr,
	.get_attr    = pcmk_get_attr,
	.del_attr    = pcmk_del_attr,
};
