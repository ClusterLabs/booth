/*
 * Copyright (C) 2016 Jan Pokorny <jpokorny@redhat.com>
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

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include <systemd/sd-daemon.h>

#include "nametag_libsystemd.h"
#include "booth.h"
#include "log.h"
#include "transport.h"

/* assume first argument after "fmt" is for DAEMON_NAME, that is
   really not of interest in our "nametag" function based on
   sd_notify (that very data point is provided implicitly) */
void sd_notify_wrapper(const char *fmt, ...)
{
	/* assume that first %s in fmt is intended for DAEMON_NAME,
	   i.e., for first argument following fmt in original
	   set_proc_title invocation, which has already been dropped
	   before it boils down here (using the wrapping macro trick);
	   we now simply append the reset after that first %s
	   (with whitespace stripped) to the "Running: " prefix */
	int rv;
	char buffer[255];
	char *fmt_iter;
	char *suffix = NULL;
	va_list ap, copy;

	/* this code undoes the type_to_string mapping */
	va_start(ap, fmt);
	va_copy(copy, ap);
	for (int i = 0; i < 3; i++) {
		fmt_iter = va_arg(copy, char *);
	}
	/* see config.c:type_to_string */
	if (strcmp(fmt_iter, "arbitrator") && strcmp(fmt_iter, "attr")) {
		return;  /* not expected to be run as system service */
	}

	fmt_iter = strchr(fmt, '%');
	while (fmt_iter) {
		switch (*++fmt_iter) {
			case 's': suffix = fmt_iter;
				  /* fall through */
			default: fmt_iter = NULL;
		}
	}
	if (!suffix) {
		log_warn("%s:%d: invalid format: %s", __FILE__, __LINE__, fmt);
		return;
	}
	while (isspace(*++suffix)) /* noop */ ;

	fmt_iter = va_arg(ap, char *);  /* just shift by one */
	assert(!strcmp(fmt_iter, DAEMON_NAME));
	rv = vsnprintf(buffer, sizeof(buffer), suffix, ap);
	va_end(ap);

	rv = sd_notifyf(0, "READY=1\n"
			"STATUS=Running: %s",
			buffer);
	if (rv < 0)
		log_warn("%s:%d: sd_notifyf fail", __FILE__, __LINE__);
}
