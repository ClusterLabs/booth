/*
 * Copyright (C) 2014 Dejan Muhamedagic <dejan@suse.de>
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

#include "timer.h"

/* which time resolution makes most sense?
 * the factors are clock resolution and network latency
 */
int TIME_RES = 1000;
int TIME_MULT = 1;

int
time_sub_int(timetype *a, timetype *b)
{
	timetype res;

	time_sub(a, b, &res);
	return res.tv_sec*TIME_RES + res.SUBSEC/TIME_FAC;
}

/* interval (b) is in ms (1/TIME_RES) */
void
interval_add(timetype *a, int b, timetype *res)
{
	/* need this to allow interval_add(a, b, a); */
	long tmp_subsec = a->SUBSEC + (long)b*TIME_FAC;

	res->SUBSEC = tmp_subsec%NSECS;
	res->tv_sec = a->tv_sec + tmp_subsec/NSECS;
}

int
is_time_set(timetype *p)
{
	return (p->tv_sec != 0) || (p->SUBSEC != 0);
}

int
is_past(timetype *p)
{
	timetype now;

	/*if (!is_time_set(p))
		return 1;*/
	assert(p->tv_sec || p->SUBSEC);
	get_time(&now);
	return time_cmp(&now, p, >);
}

void
secs2tv(time_t secs, timetype *p)
{
	memset(p, 0, sizeof(timetype));
	p->tv_sec = secs;
}

int
time_left(timetype *p)
{
	timetype now;

	assert(p->tv_sec || p->SUBSEC);
	get_time(&now);
	return time_sub_int(p, &now);
}

void
set_future_time(timetype *a, int b)
{
	timetype now;

	get_time(&now);
	interval_add(&now, b, a);
}

void
time_reset(timetype *p)
{
	memset(p, 0, sizeof(timetype));
}

void
copy_time(timetype *src, timetype *dst)
{
	dst->SUBSEC = src->SUBSEC;
	dst->tv_sec = src->tv_sec;
}

#if _POSIX_TIMERS > 0

void
time_sub(struct timespec *a, struct timespec *b, struct timespec *res)
{
	if (a->tv_nsec < b->tv_nsec) {
		res->tv_sec = a->tv_sec - b->tv_sec - 1L;
		res->tv_nsec = a->tv_nsec + (NSECS - b->tv_nsec);
	} else {
		res->tv_sec = a->tv_sec - b->tv_sec;
		res->tv_nsec = a->tv_nsec - b->tv_nsec;
	}
}

void
time_add(struct timespec *a, struct timespec *b, struct timespec *res)
{
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	res->tv_sec = a->tv_sec + b->tv_sec;
	if (res->tv_nsec >= NSECS) {
		res->tv_sec++;
		res->tv_nsec %= NSECS;
	}
}

time_t
get_secs(struct timespec *p)
{
	if (p) {
		get_time(p);
		return p->tv_sec;
	} else {
		struct timespec tv;
		get_time(&tv);
		return tv.tv_sec;
	}
}

/* time booth_clk_t is a time since boot or similar, convert that
 * to time since epoch (Jan 1, 1970)
 */
static void
clock2epochtime(struct timespec *booth_clk_t, struct timespec *res)
{
	struct timespec booth_clk_now, now_tv;
	struct timeval now;

	get_time(&booth_clk_now);
	gettimeofday(&now, NULL);
	TIMEVAL_TO_TIMESPEC(&now, &now_tv);
	time_sub(&now_tv, &booth_clk_now, res);
	time_add(booth_clk_t, res, res);
}

/* time booth_clk_t is a time since boot or similar, return
 * something humans can understand (rounded seconds only) */
time_t
wall_ts(struct timespec *booth_clk_t)
{
	struct timespec res;

	clock2epochtime(booth_clk_t, &res);
	return round2secs(&res);
}

/* time booth_clk_t is a time since boot or similar, get here
 * seconds since epoch
 */
time_t
secs_since_epoch(struct timespec *booth_clk_t)
{
	struct timespec res;

	clock2epochtime(booth_clk_t, &res);
	return res.tv_sec;
}

/* time t is wall clock time, convert to time compatible
 * with our clock_gettime clock */
time_t
unwall_ts(time_t t)
{
	struct timespec booth_clk_now, now_tv, res;
	struct timeval now;

	get_time(&booth_clk_now);
	gettimeofday(&now, NULL);
	TIMEVAL_TO_TIMESPEC(&now, &now_tv);
	time_sub(&now_tv, &booth_clk_now, &res);
	return t - res.tv_sec;
}

#endif
