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
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <zlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include "b_config.h"
#include "booth.h"
#include "config.h"
#include "log.h"
#include "raft.h"
#include "ticket.h"
#include "utils.h"

static int ticket_size = 0;

static const struct booth_site _no_leader = {
	.addr_string = "none",
	.site_id = NO_ONE,
	.index = -1,
};
struct booth_site *const no_leader = (struct booth_site*) &_no_leader;


static int ticket_realloc(struct booth_config *conf_ptr)
{
	const int added = 5;
	int had, want;
	void *p;

	assert(conf_ptr != NULL);

	had = conf_ptr->ticket_allocated;
	want = had + added;

	p = realloc(conf_ptr->ticket, sizeof(struct ticket_config) * want);
	if (!p) {
		log_error("can't alloc more tickets");
		return -ENOMEM;
	}

	conf_ptr->ticket = p;
	memset(conf_ptr->ticket + had, 0,
	       sizeof(struct ticket_config) * added);
	conf_ptr->ticket_allocated = want;

	return 0;
}

static void hostname_to_ip(char * hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(hostname)) == NULL) {
		log_error("can't find IP for the host \"%s\"", hostname);
		return;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	/* Return the first found address */
	if (addr_list[0] != NULL) {
		strncpy(hostname, inet_ntoa(*addr_list[0]), BOOTH_NAME_LEN - 1);
		/* buffer overflow will not happen (IPv6 notation < 63 chars),
		   but suppress the warnings */
		hostname[BOOTH_NAME_LEN - 1] = '\0';
	}
	else {
		log_error("no IP addresses found for the host \"%s\"", hostname);
	}
}

static int add_site(struct booth_config *conf_ptr, char *addr_string, int type)
{
	int rv;
	struct booth_site *site;
	uLong nid;
	uint32_t mask;
	int i;

	assert(conf_ptr != NULL);

	rv = 1;
	if (conf_ptr->site_count == MAX_NODES) {
		log_error("too many nodes");
		goto out;
	}
	if (strnlen(addr_string, sizeof(conf_ptr->site[0].addr_string))
			>= sizeof(conf_ptr->site[0].addr_string)) {
		log_error("site address \"%s\" too long", addr_string);
		goto out;
	}

	site = conf_ptr->site + conf_ptr->site_count;

	site->family = AF_INET;
	site->type = type;

	/* buffer overflow will not hapen (we've already checked that
	   addr_string will fit incl. terminating '\0' above), but
	   suppress the warnings with copying everything but the boundary
	   byte, which is valid as-is, since this last byte will be safely
	   pre-zeroed from the struct booth_config initialization */
	strncpy(site->addr_string, addr_string, sizeof(site->addr_string) - 1);

	if (!(inet_pton(AF_INET, site->addr_string, &site->sa4.sin_addr) > 0) &&
        !(inet_pton(AF_INET6, site->addr_string, &site->sa6.sin6_addr) > 0)) {

		/* Not a valid address, so let us try to convert it into an IP address */
		hostname_to_ip(site->addr_string);
	}

	site->index = conf_ptr->site_count;
	site->bitmask = 1 << conf_ptr->site_count;
	/* Catch site overflow */
	assert(site->bitmask);
	conf_ptr->all_bits |= site->bitmask;
	if (type == SITE)
		conf_ptr->sites_bits |= site->bitmask;

	site->tcp_fd = -1;

	conf_ptr->site_count++;

	rv = 0;
	memset(&site->sa6, 0, sizeof(site->sa6));

	nid = crc32(0L, NULL, 0);
	/* Using the ASCII representation in site->addr_string (both sizeof()
	 * and strlen()) gives quite a lot of collisions; a brute-force run
	 * from 0.0.0.0 to 24.0.0.0 gives ~4% collisions, and this tends to
	 * increase even more.
	 * Whether there'll be a collision in real-life, with 3 or 5 nodes, is
	 * another question ... but for now get the ID from the binary
	 * representation - that had *no* collisions up to 32.0.0.0.
	 * Note that POSIX mandates inet_pton to arange the address pointed
	 * to by "dst" in network byte order, assuring little/big-endianess
	 * mutual compatibility. */
	if (inet_pton(AF_INET,
				site->addr_string,
				&site->sa4.sin_addr) > 0) {

		site->family = AF_INET;
		site->sa4.sin_family = site->family;
		site->sa4.sin_port = htons(conf_ptr->port);
		site->saddrlen = sizeof(site->sa4);
		site->addrlen = sizeof(site->sa4.sin_addr);
		site->site_id = crc32(nid, (void*)&site->sa4.sin_addr, site->addrlen);

	} else if (inet_pton(AF_INET6,
				site->addr_string,
				&site->sa6.sin6_addr) > 0) {

		site->family = AF_INET6;
		site->sa6.sin6_family = site->family;
		site->sa6.sin6_flowinfo = 0;
		site->sa6.sin6_port = htons(conf_ptr->port);
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
		if (conf_ptr->site[i].site_id == site->site_id) {
			log_error("Got a site-ID collision. Please file a bug on https://github.com/ClusterLabs/booth/issues/new, attaching the configuration file.");
			exit(1);
		}

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


static int add_ticket(struct booth_config *conf_ptr, const char *name,
                      struct ticket_config **tkp, const struct ticket_config *def)
{
	int rv;
	struct ticket_config *tk;

	assert(conf_ptr != NULL);

	if (conf_ptr->ticket_count == conf_ptr->ticket_allocated) {
		rv = ticket_realloc(conf_ptr);
		if (rv < 0)
			return rv;
	}


	tk = conf_ptr->ticket + conf_ptr->ticket_count;
	conf_ptr->ticket_count++;

	if (!check_max_len_valid(name, sizeof(tk->name))) {
		log_error("ticket name \"%s\" too long.", name);
		return -EINVAL;
	}

	if (find_ticket_by_name(conf_ptr, name, NULL)) {
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
	tk->mode = def->mode;

	if (tkp)
		*tkp = tk;
	return 0;
}

static int postproc_ticket(struct ticket_config *tk)
{
	if (!tk)
		return 1;

	if (!tk->renewal_freq) {
		tk->renewal_freq = tk->term_duration/2;
	}

	if (tk->timeout*(tk->retries+1) >= tk->renewal_freq) {
		log_error("%s: total amount of time to "
			"retry sending packets cannot exceed "
			"renewal frequency "
			"(%d*(%d+1) >= %d)",
			tk->name, tk->timeout, tk->retries, tk->renewal_freq);
		return 0;
	}
	return 1;
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

/* returns TICKET_MODE_AUTO if failed to parse the ticket mode. */
static ticket_mode_e retrieve_ticket_mode(const char *input)
{
	if (strcasecmp(input, "manual") == 0) {
		return TICKET_MODE_MANUAL;
	}

	return TICKET_MODE_AUTO;
}

/* scan val for time; time is [0-9]+(ms)?, i.e. either in seconds
 * or milliseconds
 * returns -1 on failure, otherwise time in ms
 */
static long read_time(char *val)
{
	long t;
	char *ep;

	t = strtol(val, &ep, 10);
	if (ep == val) { /* matched none */
		t = -1L;
	} else if (*ep == '\0') { /* matched all */
		t = t*1000L; /* in seconds, convert to ms */
	} else if (strcmp(ep, "ms")) { /* ms not exactly matched */
		t = -1L;
	} /* otherwise, time in ms */
	/* if second fractions configured, send finer resolution
	 * times (i.e. term_valid_for) */
	if (t % 1000L) {
		TIME_MULT = 1000;
	}
	return t;
}

/* make arguments for execv(2)
 * tk_test.path points to the path
 * tk_test.argv is argument vector (starts with the prog)
 * (strtok pokes holes in the configuration parameter value, i.e.
 * we don't need to allocate memory for arguments)
 */
static int parse_extprog(char *val, struct ticket_config *tk)
{
	char *p;
	int i = 0;

	if (tk_test.path) {
		free(tk_test.path);
	}
	if (!(tk_test.path = strdup(val))) {
		log_error("out of memory");
		return -1;
	}

	p = strtok(tk_test.path, " \t");
	tk_test.argv[i++] = p;
	do {
		p = strtok(NULL, " \t");
		if (i >= MAX_ARGS) {
			log_error("too many arguments for the acquire-handler");
			free(tk_test.path);
			return -1;
		}
		tk_test.argv[i++] = p;
	} while (p);

	return 0;
}

struct toktab grant_type[] = {
	{ "auto", GRANT_AUTO},
	{ "manual", GRANT_MANUAL},
	{ NULL, 0},
};

struct toktab attr_op[] = {
	{"eq", ATTR_OP_EQ},
	{"ne", ATTR_OP_NE},
	{NULL, 0},
};

static int lookup_tokval(char *key, struct toktab *tab)
{
	struct toktab *tp;

	for (tp = tab; tp->str; tp++) {
		if (!strcmp(tp->str, key))
			return tp->val;
	}
	return 0;
}

/* attribute prerequisite
 */
static int parse_attr_prereq(char *val, struct ticket_config *tk)
{
	struct attr_prereq *ap = NULL;
	char *p;

	ap = (struct attr_prereq *)calloc(1, sizeof(struct attr_prereq));
	if (!ap) {
		log_error("out of memory");
		return -1;
	}

	p = strtok(val, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	ap->grant_type = lookup_tokval(p, grant_type);
	if (!ap->grant_type) {
		log_error("%s is not a grant type", p);
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	if (!(ap->attr_name = strdup(p))) {
		log_error("out of memory");
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	ap->op = lookup_tokval(p, attr_op);
	if (!ap->op) {
		log_error("%s is not an attribute operation", p);
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	if (!(ap->attr_val = strdup(p))) {
		log_error("out of memory");
		goto err_out;
	}

	tk->attr_prereqs = g_list_append(tk->attr_prereqs, ap);
	if (!tk->attr_prereqs) {
		log_error("out of memory");
		goto err_out;
	}

	return 0;

err_out:
	if (ap) {
		if (ap->attr_val)
			free(ap->attr_val);
		if (ap->attr_name)
			free(ap->attr_name);
		free(ap);
	}
	return -1;
}

int read_config(struct booth_config **conf_pptr,
                const booth_transport_table_t *transport,
                const struct ticket_handler *ticket_handler,
                const char *path, int type)
{
	char line[1024];
	FILE *fp;
	char *s, *key, *val, *end_of_key;
	const char *error;
	char *cp, *cp2;
	int i;
	int lineno = 0;
	int got_transport = 0;
	int min_timeout = 0;
	struct ticket_config defaults = { { 0 } };
	struct ticket_config *current_tk = NULL;

	assert(conf_pptr != NULL);
	config_free(*conf_pptr);

	fp = fopen(path, "r");
	if (!fp) {
		log_error("failed to open %s: %s", path, strerror(errno));
		*conf_pptr = NULL;
		return -1;
	}

	*conf_pptr = malloc(sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	if (*conf_pptr == NULL) {
		fclose(fp);
		log_error("failed to alloc memory for booth config");
		return -ENOMEM;
	}
	memset(*conf_pptr, 0, sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	ticket_size = TICKET_ALLOC;
	(*conf_pptr)->transport = transport;
	(*conf_pptr)->ticket_handler = ticket_handler;

	(*conf_pptr)->proto = UDP;
	(*conf_pptr)->port = BOOTH_DEFAULT_PORT;
	(*conf_pptr)->maxtimeskew = BOOTH_DEFAULT_MAX_TIME_SKEW;
	(*conf_pptr)->authkey[0] = '\0';

	/* Provide safe defaults. -1 is reserved, though. */
	(*conf_pptr)->uid = -2;
	(*conf_pptr)->gid = -2;
	strcpy((*conf_pptr)->site_user,  "hacluster");
	strcpy((*conf_pptr)->site_group, "haclient");
	strcpy((*conf_pptr)->arb_user,   "nobody");
	strcpy((*conf_pptr)->arb_group,  "nobody");

	parse_weights("", defaults.weight);
	defaults.clu_test.path  = NULL;
	defaults.clu_test.pid  = 0;
	defaults.clu_test.status  = 0;
	defaults.clu_test.progstate  = EXTPROG_IDLE;
	defaults.term_duration        = DEFAULT_TICKET_EXPIRY;
	defaults.timeout       = DEFAULT_TICKET_TIMEOUT;
	defaults.retries       = DEFAULT_RETRIES;
	defaults.acquire_after = 0;
	defaults.mode          = TICKET_MODE_AUTO;

	error = "";

	log_debug("reading config file %s", path);
	while (fgets(line, sizeof(line), fp)) {
		lineno++;

		s = skip_while(line, isspace);
		if (is_end_of_line(s) || *s == '#')
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
				if (*(s = skip_while(s, isspace)) && *s != '#') {
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
				(*conf_pptr)->proto = UDP;
			else if (strcasecmp(val, "SCTP") == 0)
				(*conf_pptr)->proto = SCTP;
			else {
				error = "invalid transport protocol";
				goto err;
			}
			got_transport = 1;
			continue;
		}

		if (strcmp(key, "port") == 0) {
			(*conf_pptr)->port = atoi(val);
			continue;
		}

		if (strcmp(key, "name") == 0) {
			safe_copy((*conf_pptr)->name,
					val, BOOTH_NAME_LEN,
					"name");
			continue;
		}

#if HAVE_LIBGCRYPT || HAVE_LIBMHASH
		if (strcmp(key, "authfile") == 0) {
			safe_copy((*conf_pptr)->authfile,
					val, BOOTH_PATH_LEN,
					"authfile");
			continue;
		}

		if (strcmp(key, "maxtimeskew") == 0) {
			(*conf_pptr)->maxtimeskew = atoi(val);
			continue;
		}
#endif

		if (strcmp(key, "site") == 0) {
			if (add_site(*conf_pptr, val, SITE))
				goto err;
			continue;
		}

		if (strcmp(key, "arbitrator") == 0) {
			if (add_site(*conf_pptr, val, ARBITRATOR))
				goto err;
			continue;
		}

		if (strcmp(key, "site-user") == 0) {
			safe_copy((*conf_pptr)->site_user, optarg, BOOTH_NAME_LEN,
			          "site-user");
			continue;
		}
		if (strcmp(key, "site-group") == 0) {
			safe_copy((*conf_pptr)->site_group, optarg, BOOTH_NAME_LEN,
			          "site-group");
			continue;
		}
		if (strcmp(key, "arbitrator-user") == 0) {
			safe_copy((*conf_pptr)->arb_user, optarg, BOOTH_NAME_LEN,
			          "arbitrator-user");
			continue;
		}
		if (strcmp(key, "arbitrator-group") == 0) {
			safe_copy((*conf_pptr)->arb_group, optarg, BOOTH_NAME_LEN,
			          "arbitrator-group");
			continue;
		}

		if (strcmp(key, "debug") == 0) {
			if (type != CLIENT && type != GEOSTORE)
				debug_level = max(debug_level, atoi(val));
			continue;
		}

		if (strcmp(key, "ticket") == 0) {
			if (current_tk && strcmp(current_tk->name, "__defaults__")) {
				if (!postproc_ticket(current_tk)) {
					goto err;
				}
			}
			if (!strcmp(val, "__defaults__")) {
				current_tk = &defaults;
			} else if (add_ticket(*conf_pptr, val, &current_tk,
			                      &defaults)) {
				goto err;
			}
			continue;
		}

		/* current_tk must be allocated at this point, otherwise
		 * we don't know to which ticket the key refers
		 */
		if (!current_tk) {
			error = "Unexpected keyword";
			goto err;
		}

		if (strcmp(key, "expire") == 0) {
			current_tk->term_duration = read_time(val);
			if (current_tk->term_duration <= 0) {
				error = "Expected time >0 for expire";
				goto err;
			}
			continue;
		}

		if (strcmp(key, "timeout") == 0) {
			current_tk->timeout = read_time(val);
			if (current_tk->timeout <= 0) {
				error = "Expected time >0 for timeout";
				goto err;
			}
			if (!min_timeout) {
				min_timeout = current_tk->timeout;
			} else {
				min_timeout = min(min_timeout, current_tk->timeout);
			}
			continue;
		}

		if (strcmp(key, "retries") == 0) {
			current_tk->retries = strtol(val, &s, 0);
			if (*s || s == val ||
					current_tk->retries<3 || current_tk->retries > 100) {
				error = "Expected plain integer value in the range [3, 100] for retries";
				goto err;
			}
			continue;
		}

		if (strcmp(key, "renewal-freq") == 0) {
			current_tk->renewal_freq = read_time(val);
			if (current_tk->renewal_freq <= 0) {
				error = "Expected time >0 for renewal-freq";
				goto err;
			}
			continue;
		}

		if (strcmp(key, "acquire-after") == 0) {
			current_tk->acquire_after = read_time(val);
			if (current_tk->acquire_after < 0) {
				error = "Expected time >=0 for acquire-after";
				goto err;
			}
			continue;
		}

		if (strcmp(key, "before-acquire-handler") == 0) {
			if (parse_extprog(val, current_tk)) {
				goto err;
			}
			continue;
		}

		if (strcmp(key, "attr-prereq") == 0) {
			if (parse_attr_prereq(val, current_tk)) {
				goto err;
			}
			continue;
		}

		if (strcmp(key, "mode") == 0) {
			current_tk->mode = retrieve_ticket_mode(val);
			continue;
		}

		if (strcmp(key, "weights") == 0) {
			if (parse_weights(val, current_tk->weight) < 0)
				goto err;
			continue;
		}

		error = "Unknown keyword";
		goto err;
	}
	fclose(fp);

	if (((*conf_pptr)->site_count % 2) == 0) {
		log_warn("Odd number of nodes is strongly recommended!");
	}

	/* Default: make config name match config filename. */
	if (!(*conf_pptr)->name[0]) {
		cp = strrchr(path, '/');
		cp = cp ? cp+1 : (char *)path;
		cp2 = strrchr(cp, '.');
		if (!cp2)
			cp2 = cp + strlen(cp);
		if (cp2-cp >= BOOTH_NAME_LEN) {
			log_error("booth config file name too long");
			goto out;
		}
		strncpy((*conf_pptr)->name, cp, cp2-cp);
		*((*conf_pptr)->name+(cp2-cp)) = '\0';
	}

	if (!postproc_ticket(current_tk)) {
		goto out;
	}

	safe_copy((*conf_pptr)->path_to_self, path,
	          sizeof((*conf_pptr)->path_to_self),
	          "path to config file itself");

	(*conf_pptr)->poll_timeout = min(POLL_TIMEOUT, min_timeout/10);
	if ((*conf_pptr)->poll_timeout == 0)
		(*conf_pptr)->poll_timeout = POLL_TIMEOUT;

	return 0;


err:
	fclose(fp);
out:
	log_error("%s in config file line %d",
			error, lineno);

	config_free(*conf_pptr);
	*conf_pptr = NULL;
	return -1;
}

void config_free(struct booth_config *conf_ptr)
{
	if (conf_ptr != NULL) {
		free(conf_ptr->ticket);
	}
	free(conf_ptr);
}

int check_config(struct booth_config *conf_ptr, int type)
{
	struct passwd *pw;
	struct group *gr;
	char *cp, *input;

	if (conf_ptr == NULL)
		return -1;

	input = (type == ARBITRATOR)
		? conf_ptr->arb_user
		: conf_ptr->site_user;
	if (!*input)
		goto u_inval;
	if (isdigit(input[0])) {
		conf_ptr->uid = strtol(input, &cp, 0);
		if (*cp != 0) {
u_inval:
			log_error("User \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	} else {
		pw = getpwnam(input);
		if (!pw)
			goto u_inval;
		conf_ptr->uid = pw->pw_uid;
	}


	input = (type == ARBITRATOR)
		? conf_ptr->arb_group
		: conf_ptr->site_group;
	if (!*input)
		goto g_inval;
	if (isdigit(input[0])) {
		conf_ptr->gid = strtol(input, &cp, 0);
		if (*cp != 0) {
g_inval:
			log_error("Group \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	} else {
		gr = getgrnam(input);
		if (!gr)
			goto g_inval;
		conf_ptr->gid = gr->gr_gid;
	}

	return 0;
}

static int get_other_site(struct booth_config *conf_ptr,
                          struct booth_site **node)
{
	struct booth_site *n;
	int i;

	*node = NULL;
	if (conf_ptr == NULL)
		return 0;

	assert(conf_ptr->local != NULL);

	FOREACH_NODE(conf_ptr, i, n) {
		if (n != conf_ptr->local && n->type == SITE) {
			if (!*node) {
				*node = n;
			} else {
				return 0;
			}
		}
	}

	return !*node ? 0 : 1;
}

int find_site_by_name(struct booth_config *conf_ptr, const char *site,
                      struct booth_site **node, int any_type)
{
	struct booth_site *n;
	int i;

	if (conf_ptr == NULL)
		return 0;

	if (!strcmp(site, OTHER_SITE))
		return get_other_site(conf_ptr, node);

	FOREACH_NODE(conf_ptr, i, n) {
		if ((n->type == SITE || any_type) &&
		    strncmp(n->addr_string, site, sizeof(n->addr_string)) == 0) {
			*node = n;
			return 1;
		}
	}

	return 0;
}

int find_site_by_id(struct booth_config *conf_ptr, uint32_t site_id,
                    struct booth_site **node)
{
	struct booth_site *n;
	int i;

	if (site_id == NO_ONE) {
		*node = no_leader;
		return 1;
	}

	if (conf_ptr == NULL)
		return 0;

	FOREACH_NODE(conf_ptr, i, n) {
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
		case GEOSTORE:   return "attr";
	}
	return "??invalid-type??";
}

int find_ticket_by_name(struct booth_config *conf_ptr,
                        const char *ticket, struct ticket_config **found)
{
	struct ticket_config *tk;
	int i;

	assert(conf_ptr != NULL);

	if (found)
		*found = NULL;

	FOREACH_TICKET(conf_ptr, i, tk) {
		if (!strncmp(tk->name, ticket, sizeof(tk->name))) {
			if (found)
				*found = tk;
			return 1;
		}
	}

	return 0;
}
