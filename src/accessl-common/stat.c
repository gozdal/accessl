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

#include <common/compiler.h>

#include "stat.h"

#ifdef __APPLE__

#include <mach/clock.h>
#include <mach/mach.h>

int clock_gettime(int type UNUSED, struct timespec *ts) {
    clock_serv_t cclock;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, (mach_timespec_t *)ts);
    mach_port_deallocate(mach_task_self(), cclock);

    return 0;
}

#define CLOCK_MONOTONIC 0

#endif

#ifdef __GNUC__

#if !defined(CLOCK_MONOTONIC_COARSE)
#define CLOCK_MONOTONIC_COARSE 6
#endif

#endif

static int stat_clock_id = CLOCK_MONOTONIC;

int stat_init(void)
{
    struct timespec ts;

    int ret = clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    if (ret == 0)
        stat_clock_id = CLOCK_MONOTONIC_COARSE;

    return 1;
}

void stat_destroy(void)
{
}

void stat_inc(struct stat_t *s)
{
    s->val += 1;
}

void stat_dec(struct stat_t *s)
{
    s->val -= 1;
}

void stat_add(struct stat_t *s, stat_val_t a)
{
    s->val += a;
}

void stat_sub(struct stat_t *s, stat_val_t a)
{
    s->val -= a;
}

stat_val_t stat_diff(struct stat_t *cur, struct stat_t *prev)
{
    return cur->val - prev->val;
}

void stat_difftime(const struct timespec *t1, const struct timespec *t0, struct timespec *difft)
{
    difft->tv_sec = t1->tv_sec - t0->tv_sec;
    difft->tv_nsec = t1->tv_nsec - t0->tv_nsec;
    if (difft->tv_nsec < 0)
    {
        --difft->tv_sec;
        difft->tv_nsec += NANOSEC_IN_SEC;
    }
}

void stat_addtime(struct timespec *tbase, const struct timespec *tadded)
{
    tbase->tv_sec += tadded->tv_sec;
    tbase->tv_nsec += tadded->tv_nsec;

    if (tbase->tv_nsec > NANOSEC_IN_SEC)
    {
        tbase->tv_nsec -= NANOSEC_IN_SEC;
        tbase->tv_sec += 1;
    }
}

void stat_store_time(struct timespec *t)
{
    if (likely(t->tv_sec == 0))
        clock_gettime(stat_clock_id, t);
}

void stat_write(struct stat_t *s, stat_val_t val)
{
    s->val = val;
}

stat_val_t stat_read(struct stat_t *s)
{
    return s->val;
}
