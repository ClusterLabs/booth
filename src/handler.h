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

#ifndef _HANDLER_H
#define _HANDLER_H

enum {
	RUNCMD_ERR = -1,
	RUNCMD_MORE = -2,
};

int run_handler(const struct booth_config *conf, struct ticket_config *tk);
int tk_test_exit_status(struct ticket_config *tk);
void ignore_ext_test(struct ticket_config *tk);
int is_ext_prog_running(struct ticket_config *tk);
void ext_prog_timeout(struct ticket_config *tk);
void wait_child(int sig);

#define set_progstate(tk, newst) do { \
	if (!(newst)) tk_log_debug("progstate reset"); \
	else tk_log_debug("progstate set to %d", newst); \
	tk->clu_test.progstate = newst; \
} while(0)

#endif
