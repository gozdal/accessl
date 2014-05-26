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

#ifndef _ACCELERATORS_H_
#define _ACCELERATORS_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int accel_init(void);
void accel_destroy(void);

void *accel_add_key(int type, unsigned long len, const unsigned char *data);
void accel_destroy_key(int type, void *key);
size_t accel_result_max_len(void *key, int op);
int accel_perform(void *key, int op, size_t len, const unsigned char *data, unsigned char *result);

#ifdef __cplusplus
};
#endif

#endif // _ACCELERATORS_H_
