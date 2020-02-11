/*
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdlib.h>  /* size_t */

/**
 * @internal
 * Like strncpy, but with explicit protection and better diagnostics
 *
 * @param[out] dest where to copy the string to
 * @param[in] value where to copy the string from
 * @param[in] buflen nmaximum size of #dest (incl. trailing '\0', or sizeof)
 * @param[in] description how to refer to the target as
 *
 * @return number of clients tracked (incl. this one)
 */
void safe_copy(char *dest, const char *value, size_t buflen,
               const char *description);
