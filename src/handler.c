/* 
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
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
#include <signal.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <dirent.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "ticket.h"
#include "config.h"
#include "inline-fn.h"
#include "log.h"
#include "pacemaker.h"
#include "booth.h"
#include "handler.h"

static int set_booth_env(struct booth_config *conf_ptr,
                         struct ticket_config *tk)
{
	int rv;
	char expires[16];

	assert(conf_ptr != NULL);
	assert(conf_ptr->local != NULL);

	sprintf(expires, "%" PRId64, (int64_t)wall_ts(&tk->term_expires));
	rv = setenv("BOOTH_TICKET", tk->name, 1) ||
		setenv("BOOTH_LOCAL", conf_ptr->local->addr_string, 1) ||
		setenv("BOOTH_CONF_NAME", conf_ptr->name, 1) ||
		setenv("BOOTH_CONF_PATH", conf_ptr->path_to_self, 1) ||
		setenv("BOOTH_TICKET_EXPIRES", expires, 1);

	if (rv) {
		log_error("Cannot set environment: %s", strerror(errno));
	}
	return rv;
}

static void
closefiles(void)
{
	int fd;

	/* close all descriptors except stdin/out/err */
	for (fd = getdtablesize() - 1; fd > STDERR_FILENO; fd--) {
		close(fd);
	}
}

static void
run_ext_prog(struct booth_config *conf_ptr, struct ticket_config *tk,
             char *prog)
{
	if (set_booth_env(conf_ptr, tk)) {
		_exit(1);
	}
	closefiles(); /* don't leak open files */
	tk_log_debug("running handler %s", prog);
	execv(prog, tk_test.argv);
	tk_log_error("%s: execv failed (%s)", prog, strerror(errno));
	_exit(1);
}

static int
prog_filter(const struct dirent *dp)
{
	return (*dp->d_name != '.');
}

static pid_t curr_pid;
static int ignore_status;

static int
test_exit_status(struct ticket_config *tk, char *prog, int status, int log_msg)
{
	int rv = -1;

	if (WIFEXITED(status)) {
		rv = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		rv = 128 + WTERMSIG(status);
	}
	if (rv) {
		if (log_msg) {
			tk_log_warn("handler \"%s\" failed: %s",
				prog, interpret_rv(status));
			tk_log_warn("we are not allowed to acquire ticket");
		}
	} else {
		tk_log_debug("handler \"%s\" exited with success",
			prog);
	}
	return rv;
}

static void
reset_test_state(struct ticket_config *tk)
{
	tk_test.pid = 0;
	set_progstate(tk, EXTPROG_IDLE);
}

int tk_test_exit_status(struct ticket_config *tk)
{
	int rv;

	rv = test_exit_status(tk, tk_test.path, tk_test.status, !tk_test.is_dir);
	reset_test_state(tk);
	return rv;
}

void wait_child(struct booth_config *conf_ptr)
{
	int i, status;
	struct ticket_config *tk;

	/* use waitpid(2) and not wait(2) in order not to interfere
	 * with popen(2)/pclose(2) and system(2) used in pacemaker.c
	 */
	FOREACH_TICKET(conf_ptr, i, tk) {
		if (tk_test.path && tk_test.pid > 0 &&
				(tk_test.progstate == EXTPROG_RUNNING ||
				tk_test.progstate == EXTPROG_IGNORE) &&
				waitpid(tk_test.pid, &status, WNOHANG) == tk_test.pid) {
			if (tk_test.progstate == EXTPROG_IGNORE) {
				/* not interested in the outcome */
				reset_test_state(tk);
			} else {
				tk_test.status = status;
				set_progstate(tk, EXTPROG_EXITED);
			}
		}
	}
}

/* the parent may want to have us stop processing scripts, say
 * when the ticket gets revoked
 */
static void ignore_rest(int sig)
{
	signal(SIGTERM, SIG_IGN);
	log_info("external programs handler caught TERM, ignoring status of external test programs");
	ignore_status = 1;
	if (curr_pid > 0) {
		(void)kill(curr_pid, SIGTERM);
	}
}

void ext_prog_timeout(struct ticket_config *tk)
{
	tk_log_warn("handler timed out");
}

int is_ext_prog_running(struct ticket_config *tk)
{
	if (!tk_test.path)
		return 0;
	return (tk_test.pid > 0 && tk_test.progstate == EXTPROG_RUNNING);
}

void ignore_ext_test(struct ticket_config *tk)
{
	if (is_ext_prog_running(tk)) {
		(void)kill(tk_test.pid, SIGTERM);
		set_progstate(tk, EXTPROG_IGNORE);
	} else if (tk_test.progstate == EXTPROG_EXITED) {
		/* external prog exited, but the status not yet examined;
		 * we're not interested in checking the status anymore */
		reset_test_state(tk);
	}
}

static void
process_ext_dir(struct booth_config *conf_ptr, struct ticket_config *tk)
{
	char prog[FILENAME_MAX+1];
	int rv, n_progs, i, status;
	struct dirent **proglist, *dp;

	signal(SIGTERM, (__sighandler_t)ignore_rest);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	tk_log_debug("running programs in directory %s", tk_test.path);
	n_progs = scandir(tk_test.path, &proglist, prog_filter, alphasort);
	if (n_progs == -1) {
		tk_log_error("%s: scandir failed (%s)", tk_test.path, strerror(errno));
		_exit(1);
	}
	for (i = 0; i < n_progs; i++) {
		if (ignore_status)
			break;
		dp = proglist[i];
		if (strlen(dp->d_name) + strlen(tk_test.path) + 1 > FILENAME_MAX) {
			tk_log_error("%s: name exceeds max length (%s)",
				tk_test.path, dp->d_name);
			_exit(1);
		}
		strcpy(prog, tk_test.path);
		strcat(prog, "/");
		strcat(prog, dp->d_name);
		switch(curr_pid=fork()) {
		case -1:
			log_error("fork: %s", strerror(errno));
			_exit(1);
		case 0: /* child */
			run_ext_prog(conf_ptr, tk, prog);
			break;  /* run_ext_prog effectively noreturn */
		default: /* parent */
			while (waitpid(curr_pid, &status, 0) != curr_pid)
				;
			curr_pid = 0;
			if (!ignore_status) {
				rv = test_exit_status(tk, prog, status, 1);
				if (rv)
					_exit(rv);
			}
		}
	}
	_exit(0);
}

/* run some external program
 * return codes:
 * RUNCMD_ERR: executing program failed (or some other failure)
 * RUNCMD_MORE: program forked, results later
 */
int run_handler(struct booth_config *conf_ptr, struct ticket_config *tk)
{
	int rv = 0;
	pid_t pid;
	struct stat stbuf;

	if (!tk_test.path)
		return 0;

	if (stat(tk_test.path, &stbuf)) {
		tk_log_error("%s: stat failed (%s)", tk_test.path, strerror(errno));
		return RUNCMD_ERR;
	}
	tk_test.is_dir = (stbuf.st_mode & S_IFDIR);

	switch(pid=fork()) {
	case -1:
		log_error("fork: %s", strerror(errno));
		return RUNCMD_ERR;
	case 0: /* child */
		if (tk_test.is_dir) {
			process_ext_dir(conf_ptr, tk);
		} else {
			run_ext_prog(conf_ptr, tk, tk_test.path);
		}
	default: /* parent */
		tk_test.pid = pid;
		set_progstate(tk, EXTPROG_RUNNING);
		rv = RUNCMD_MORE; /* program runs */
	}

	return rv;
}
