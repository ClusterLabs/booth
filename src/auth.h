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

#include "b_config.h"
#include "log.h"
#include <sys/types.h>

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

#define BOOTH_HASH GCRY_MD_SHA1

int calc_hmac(const void *data, size_t datalen,
	int hid, unsigned char *result, char *key, unsigned int keylen);
int verify_hmac(const void *data, size_t datalen,
	int hid, unsigned char *hmac, char *key, int keylen);
#endif

#if HAVE_LIBMHASH

#include <mhash.h>

#define BOOTH_HASH MHASH_SHA1

int calc_hmac(const void *data, size_t datalen,
	hashid hid, unsigned char *result, char *key, int keylen);
int verify_hmac(const void *data, size_t datalen,
	hashid hid, unsigned char *hmac, char *key, int keylen);
#endif
