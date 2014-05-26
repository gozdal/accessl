/*
    This file is part of AcceSSL.

    Copyright 2011-2014 Marcin Gozdalik <gozdal@gmail.com>

    AcceSSL is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    AcceSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with AcceSSL; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _ACCESSL_STAT_H
#define _ACCESSL_STAT_H

#include <time.h>

#define NANOSEC_IN_SEC 1000000000

typedef long long stat_val_t;

struct stat_t {
    stat_val_t val;
};

int stat_init(void);
void stat_destroy(void);

void stat_inc(struct stat_t *s);
void stat_dec(struct stat_t *s);
void stat_add(struct stat_t *s, stat_val_t a);
void stat_sub(struct stat_t *s, stat_val_t a);

void stat_write(struct stat_t *s, stat_val_t a);
stat_val_t stat_read(struct stat_t *s);
stat_val_t stat_diff(struct stat_t *cur, struct stat_t *prev);

void stat_store_time(struct timespec *t);
void stat_difftime(const struct timespec *t1, const struct timespec *t0, struct timespec *difft);
void stat_addtime(struct timespec *tbase, const struct timespec *tadded);

#endif // _ACCESSL_STAT_H
