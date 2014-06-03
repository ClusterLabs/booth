/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <zlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include "booth.h"
#include "config.h"
#include "raft.h"
#include "ticket.h"
#include "log.h"

static int ticket_size = 0;

static int ticket_realloc(void)
{
	const int added = 5;
	int had, want;
	void *p;

	had = booth_conf->ticket_allocated;
	want = had + added;

	p = realloc(booth_conf->ticket,
			sizeof(struct ticket_config) * want);
	if (!p) {
		log_error("can't alloc more tickets");
		return -ENOMEM;
	}

	booth_conf->ticket = p;
	memset(booth_conf->ticket + had, 0,
			sizeof(struct ticket_config) * added);
	booth_conf->ticket_allocated = want;

	return 0;
}


static int exclude_site_realloc(struct ticket_config *tk)
{
	const int added = 2;
	int had, want;
	void *p;

	had = tk->exclude_site_allocated;
	want = had + added;

	p = realloc(tk->exclude_site,
			sizeof(struct exclude_site_config) * want);
	if (!p) {
		log_error("can't alloc more exclude sites");
		return -ENOMEM;
	}

	tk->exclude_site = p;
	memset(tk->exclude_site + had, 0,
			sizeof(struct exclude_site_config) * added);
	tk->exclude_site_allocated = want;

	return 0;
}


int add_site(char *address, int type);
int add_site(char *addr_string, int type)
{
	int rv;
	struct booth_site *site;
	uLong nid;
	uint32_t mask;
	int i;


	rv = 1;
	if (booth_conf->site_count == MAX_NODES) {
		log_error("too many nodes");
		goto out;
	}
	if (strlen(addr_string)+1 >= sizeof(booth_conf->site[0].addr_string)) {
		log_error("site address \"%s\" too long", addr_string);
		goto out;
	}

	site = booth_conf->site + booth_conf->site_count;

	site->family = BOOTH_PROTO_FAMILY;
	site->type = type;
	/* Make site_id start at a non-zero point.
	 * Perhaps use hash over string or address? */
	strcpy(site->addr_string, addr_string);


	site->index = booth_conf->site_count;
	site->bitmask = 1 << booth_conf->site_count;
	/* Catch site overflow */
	assert(site->bitmask);
	booth_conf->all_bits |= site->bitmask;
	if (type == SITE)
		booth_conf->sites_bits |= site->bitmask;

	site->tcp_fd = -1;

	booth_conf->site_count++;

	rv = 0;
	memset(&site->sa6, 0, sizeof(site->sa6));

	nid = crc32(0L, NULL, 0);
	/* Using the ASCII representation in site->addr_string (both sizeof()
	 * and strlen()) gives quite a lot of collisions; a brute-force run
	 * from 0.0.0.0 to 24.0.0.0 gives ~4% collisions, and this tends to
	 * increase even more.
	 * Whether there'll be a collision in real-life, with 3 or 5 nodes, is
	 * another question ... but for now get the ID from the binary
	 * representation - that had *no* collisions up to 32.0.0.0. */
	if (inet_pton(AF_INET,
				site->addr_string,
				&site->sa4.sin_addr) > 0) {

		site->family = AF_INET;
		site->sa4.sin_family = site->family;
		site->sa4.sin_port = htons(booth_conf->port);
		site->saddrlen = sizeof(site->sa4);
		site->addrlen = sizeof(site->sa4.sin_addr);
		site->site_id = crc32(nid, (void*)&site->sa4.sin_addr, site->addrlen);

	} else if (inet_pton(AF_INET6,
				site->addr_string,
				&site->sa6.sin6_addr) > 0) {

		site->family = AF_INET6;
		site->sa6.sin6_family = site->family;
		site->sa6.sin6_flowinfo = 0;
		site->sa6.sin6_port = htons(booth_conf->port);
		site->saddrlen = sizeof(site->sa6);
		site->addrlen = sizeof(site->sa6.sin6_addr);
		site->site_id = crc32(nid, (void*)&site->sa6.sin6_addr, site->addrlen);

	} else {
		log_error("Address string \"%s\" is bad", site->addr_string);
		rv = EINVAL;
	}

	/* Make sure we will never collide with NO_ONE,
	 * or be negative (to get "get_local_id() < 0" working). */
	mask = 1 << (sizeof(site->site_id)*8 -1);
	assert(NO_ONE & mask);
	site->site_id &= ~mask;


	/* Test for collisions with other sites */
	for(i=0; i<site->index; i++)
		if (booth_conf->site[i].site_id == site->site_id) {
			log_error("Got a site-ID collision. Please file a bug on https://github.com/ClusterLabs/booth/issues/new, attaching the configuration file.");
			exit(1);
		}

	log_debug("configured %s: %s, id=%d",
		(site->type == ARBITRATOR ? "arbitrator" : "site"),
		site->addr_string, site->site_id);

out:
	return rv;
}


inline static char *skip_while_in(const char *cp, int (*fn)(int), const char *allowed)
{
	/* strchr() returns a pointer to the terminator if *cp == 0. */
	while (*cp &&
			(fn(*cp) ||
			 strchr(allowed, *cp)))
		cp++;
	/* discard "const" qualifier */
	return (char*)cp;
}


inline static char *skip_while(char *cp, int (*fn)(int))
{
	while (fn(*cp))
		cp++;
	return cp;
}

inline static char *skip_until(char *cp, char expected)
{
	while (*cp && *cp != expected)
		cp++;
	return cp;
}


static inline int is_end_of_line(char *cp)
{
	char c = *cp;
	return c == '\n' || c == 0 || c == '#';
}


static int add_ticket(const char *name, struct ticket_config **tkp,
		const struct ticket_config *def)
{
	int rv;
	struct ticket_config *tk;


	if (booth_conf->ticket_count == booth_conf->ticket_allocated) {
		rv = ticket_realloc();
		if (rv < 0)
			return rv;
	}


	tk = booth_conf->ticket + booth_conf->ticket_count;
	booth_conf->ticket_count++;


	if (!check_max_len_valid(name, sizeof(tk->name))) {
		log_error("ticket name \"%s\" too long.", name);
		return -EINVAL;
	}

	if (find_ticket_by_name(name, NULL)) {
		log_error("ticket name \"%s\" used again.", name);
		return -EINVAL;
	}

	if (* skip_while_in(name, isalnum, "-/")) {
		log_error("ticket name \"%s\" invalid; only alphanumeric names.", name);
		return -EINVAL;
	}

	strcpy(tk->name, name);
	tk->timeout = def->timeout;
	tk->term_duration = def->term_duration;
	tk->retries = def->retries;
	memcpy(tk->weight, def->weight, sizeof(tk->weight));

	if (tkp)
		*tkp = tk;
	return 0;
}


/* returns number of weights, or -1 on bad input. */
static int parse_weights(const char *input, int weights[MAX_NODES])
{
	int i, v;
	char *cp;

	for(i=0; i<MAX_NODES; i++) {
		/* End of input? */
		if (*input == 0)
			break;

		v = strtol(input, &cp, 0);
		if (input == cp) {
			log_error("No integer weight value at \"%s\"", input);
			return -1;
		}

		weights[i] = v;

		while (*cp) {
			/* Separator characters */
			if (isspace(*cp) ||
					strchr(",;:-+", *cp))
				cp++;
			/* Next weight */
			else if (isdigit(*cp))
				break;
			/* Rest */
			else {
				log_error("Invalid character at \"%s\"", cp);
				return -1;
			}
		}

		input = cp;
	}


	/* Fill rest of vector. */
	for(v=i; v<MAX_NODES; v++) {
		weights[v] = 0;
	}

	return i;
}


static int set_exclude_siteid(void)
{
	int i, j, k;
	struct ticket_config *t;
	struct exclude_site_config *e;
	struct booth_site *s;

	for (i = 0; i < booth_conf->ticket_count; i++) {
		t = &booth_conf->ticket[i];
		for (j = 0; j < t->exclude_site_count; j++) {
			e = &t->exclude_site[j];
			for (k = 0; k < booth_conf->site_count; k++) {
				s = &booth_conf->site[k];
				if (strcmp(e->addr, s->addr_string) == 0) {
					e->id = s->site_id;
					break;
				}
			}
		}
	}
	return 0;
}


int read_config(const char *path, int type)
{
	char line[1024];
	FILE *fp;
	char *s, *key, *val, *end_of_key;
	const char *cp, *error;
	int i;
	int lineno = 0;
	int got_transport = 0;
	struct ticket_config defaults = { { 0 } };
	struct ticket_config *last_ticket = NULL;


	fp = fopen(path, "r");
	if (!fp) {
		log_error("failed to open %s: %s", path, strerror(errno));
		return -1;
	}

	booth_conf = malloc(sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	if (!booth_conf) {
		log_error("failed to alloc memory for booth config");
		return -ENOMEM;
	}
	memset(booth_conf, 0, sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	ticket_size = TICKET_ALLOC;


	booth_conf->proto = UDP;
	booth_conf->port = BOOTH_DEFAULT_PORT;


	/* Provide safe defaults. -1 is reserved, though. */
	booth_conf->uid = -2;
	booth_conf->gid = -2;
	strcpy(booth_conf->site_user,  "hacluster");
	strcpy(booth_conf->site_group, "haclient");
	strcpy(booth_conf->arb_user,   "nobody");
	strcpy(booth_conf->arb_group,  "nobody");

	parse_weights("", defaults.weight);
	defaults.ext_verifier  = NULL;
	defaults.term_duration        = DEFAULT_TICKET_EXPIRY;
	defaults.timeout       = DEFAULT_TICKET_TIMEOUT;
	defaults.retries       = DEFAULT_RETRIES;
	defaults.acquire_after = 0;

	error = "";

	log_debug("reading config file %s", path);
	while (fgets(line, sizeof(line), fp)) {
		lineno++;

		s = skip_while(line, isspace);
		if (is_end_of_line(s))
			continue;
		key = s;


		/* Key */
		end_of_key = skip_while_in(key, isalnum, "-_");
		if (end_of_key == key) {
			error = "No key";
			goto err;
		}

		if (!*end_of_key)
			goto exp_equal;


		/* whitespace, and something else but nothing more? */
		s = skip_while(end_of_key, isspace);


		if (*s != '=') {
exp_equal:
			error = "Expected '=' after key";
			goto err;
		}
		s++;

		/* It's my buffer, and I terminate if I want to. */
		/* But not earlier than that, because we had to check for = */
		*end_of_key = 0;


		/* Value tokenizing */
		s = skip_while(s, isspace);
		switch (*s) {
			case '"':
			case '\'':
				val = s+1;
				s = skip_until(val, *s);
				/* Terminate value */
				if (!*s) {
					error = "Unterminated quoted string";
					goto err;
				}

				/* Remove and skip quote */
				*s = 0;
				s++;
				if (* skip_while(s, isspace)) {
					error = "Surplus data after value";
					goto err;
				}

				*s = 0;

				break;

			case 0:
no_value:
				error = "No value";
				goto err;
				break;

			default:
				val = s;
				/* Rest of line. */
				i = strlen(s);
				/* i > 0 because of "case 0" above. */
				while (i > 0 && isspace(s[i-1]))
					i--;
				s += i;
				*s = 0;
		}

		if (val == s)
			goto no_value;


		if (strlen(key) > BOOTH_NAME_LEN
				|| strlen(val) > BOOTH_NAME_LEN) {
			error = "key/value too long";
			goto err;
		}

		if (strcmp(key, "transport") == 0) {
			if (got_transport) {
				error = "config file has multiple transport lines";
				goto err;
			}

			if (strcasecmp(val, "UDP") == 0)
				booth_conf->proto = UDP;
			else if (strcasecmp(val, "SCTP") == 0)
				booth_conf->proto = SCTP;
			else {
				error = "invalid transport protocol";
				goto err;
			}
			got_transport = 1;
			continue;
		}

		if (strcmp(key, "port") == 0) {
			booth_conf->port = atoi(val);
			continue;
		}

		if (strcmp(key, "name") == 0) {
			safe_copy(booth_conf->name, 
					val, BOOTH_NAME_LEN,
					"name");
			continue;
		}

		if (strcmp(key, "site") == 0) {
			if (add_site(val, SITE))
				goto out;
			continue;
		}

		if (strcmp(key, "arbitrator") == 0) {
			if (add_site(val, ARBITRATOR))
				goto out;
			continue;
		}

		if (strcmp(key, "debug") == 0) {
			if (type != CLIENT)
				debug_level = max(debug_level, atoi(val));
			continue;
		}

		if (strcmp(key, "ticket") == 0) {
			if (add_ticket(val, &last_ticket, &defaults))
				goto out;

			/* last_ticket is valid until another one is needed -
			 * and then it already has the new address and
			 * is valid again. */
			continue;
		}

		if (strcmp(key, "expire") == 0) {
			defaults.term_duration = strtol(val, &s, 0);
			if (*s || s == val || defaults.term_duration<10) {
				error = "Expected plain integer value >=10 for expire";
				goto err;
			}

			if (last_ticket)
				last_ticket->term_duration = defaults.term_duration;
			continue;
		}

		if (strcmp(key, "site-user") == 0) {
			safe_copy(booth_conf->site_user, optarg, BOOTH_NAME_LEN,
					"site-user");
			continue;
		}
		if (strcmp(key, "site-group") == 0) {
			safe_copy(booth_conf->site_group, optarg, BOOTH_NAME_LEN,
					"site-group");
			continue;
		}
		if (strcmp(key, "arbitrator-user") == 0) {
			safe_copy(booth_conf->arb_user, optarg, BOOTH_NAME_LEN,
					"arbitrator-user");
			continue;
		}
		if (strcmp(key, "arbitrator-group") == 0) {
			safe_copy(booth_conf->arb_group, optarg, BOOTH_NAME_LEN,
					"arbitrator-group");
			continue;
		}


		if (strcmp(key, "timeout") == 0) {
			defaults.timeout = strtol(val, &s, 0);
			if (*s || s == val || defaults.timeout<1) {
				error = "Expected plain integer value >=1 for timeout";
				goto err;
			}

			if (last_ticket)
				last_ticket->timeout = defaults.timeout;
			continue;
		}

		if (strcmp(key, "retries") == 0) {
			defaults.retries = strtol(val, &s, 0);
			if (*s || s == val || defaults.retries<3 || defaults.retries > 100) {
				error = "Expected plain integer value in the range [3, 100] for retries";
				goto err;
			}

			if (last_ticket)
				last_ticket->retries = defaults.retries;
			continue;
		}

		if (strcmp(key, "acquire-after") == 0) {
			defaults.acquire_after = strtol(val, &s, 0);
			if (*s || s == val || defaults.acquire_after<0) {
				error = "Expected plain integer value >=1 for acquire-after";
				goto err;
			}

			if (last_ticket)
				last_ticket->acquire_after = defaults.acquire_after;
			continue;
		}

		if (strcmp(key, "before-acquire-handler") == 0) {
			defaults.ext_verifier = strdup(val);
			if (*s || s == val || defaults.timeout<1) {
				error = "Expected plain integer value >=1 for timeout";
				goto err;
			}

			if (last_ticket)
				last_ticket->ext_verifier = defaults.ext_verifier;
			continue;
		}


		if (strcmp(key, "weights") == 0) {
			if (parse_weights(val, defaults.weight) < 0)
				goto out;

			if (last_ticket)
				memcpy(last_ticket->weight, defaults.weight,
						sizeof(last_ticket->weight));
			continue;
		}

		if (strcmp(key, "exclude_site") == 0 && last_ticket) {
			i = last_ticket->exclude_site_count;
			if (i == last_ticket->exclude_site_allocated) {
				if (exclude_site_realloc(last_ticket) < 0)
					goto out;
			}
			last_ticket->exclude_site[i].id = -1;
			strcpy(last_ticket->exclude_site[i].addr, val);
			last_ticket->exclude_site_count++;
			continue;
		}


		error = "Unknown item";
		goto out;
	}

	if ((booth_conf->site_count % 2) == 0) {
		log_warn("An odd number of nodes is strongly recommended!");
	}

	/* Default: make config name match config filename. */
	if (!booth_conf->name[0]) {
		cp = strrchr(path, '/');
		if (!cp)
			cp = path;

		/* TODO: locale? */
		/* NUL-termination by memset. */
		for(i=0; i<BOOTH_NAME_LEN-1 && isalnum(*cp); i++)
			booth_conf->name[i] = *(cp++);

		/* Last resort. */
		if (!booth_conf->name[0])
			strcpy(booth_conf->name, "booth");
	}

	if (set_exclude_siteid() < 0)
		goto out;

	return 0;


err:
out:
	log_error("%s in config file line %d",
			error, lineno);

	free(booth_conf);
	booth_conf = NULL;
	return -1;
}


int check_config(int type)
{
	struct passwd *pw;
	struct group *gr;
	char *cp, *input;

	if (!booth_conf)
		return -1;


	input = (type == ARBITRATOR)
		? booth_conf->arb_user
		: booth_conf->site_user;
	if (!*input)
		goto u_inval;
	if (isdigit(input[0])) {
		booth_conf->uid = strtol(input, &cp, 0);
		if (*cp != 0) {
u_inval:
			log_error("User \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	}
	else {
		pw = getpwnam(input);
		if (!pw)
			goto u_inval;
		booth_conf->uid = pw->pw_uid;
	}


	input = (type == ARBITRATOR)
		? booth_conf->arb_group
		: booth_conf->site_group;
	if (!*input)
		goto g_inval;
	if (isdigit(input[0])) {
		booth_conf->gid = strtol(input, &cp, 0);
		if (*cp != 0) {
g_inval:
			log_error("Group \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	}
	else {
		gr = getgrnam(input);
		if (!gr)
			goto g_inval;
		booth_conf->gid = gr->gr_gid;
	}


	/* TODO: check whether uid or gid is 0 again?
	 * The admin may shoot himself in the foot, though. */

	return 0;
}


int find_site_by_name(unsigned char *site, struct booth_site **node, int any_type)
{
	struct booth_site *n;
	int i;

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->site_count; i++) {
		n = booth_conf->site + i;
		if ((n->type == SITE || any_type) &&
		    strcmp(n->addr_string, site) == 0) {
			*node = n;
			return 1;
		}
	}

	return 0;
}

int find_site_by_id(uint32_t site_id, struct booth_site **node)
{
	struct booth_site *n;
	int i;

	if (site_id == NO_ONE) {
		*node = no_leader;
		return 1;
	}

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->site_count; i++) {
		n = booth_conf->site + i;
		if (n->site_id == site_id) {
			*node = n;
			return 1;
		}
	}

	return 0;
}



const char *type_to_string(int type)
{
	switch (type)
	{
		case ARBITRATOR: return "arbitrator";
		case SITE:       return "site";
		case CLIENT:     return "client";
	}
	return "??invalid-type??";
}
