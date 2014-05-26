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

#ifndef _ACCELERATOR_BASE_H_
#define _ACCELERATOR_BASE_H_

#include <stdlib.h>

struct accel_method_t {
    const char *(*get_name)(void *accel_priv);

    void (*free_priv)(void *accel_priv);

    void (*destroy_key)(void *accel_priv, int type, void *key);
    void *(*add_key)(void *accel_priv, int type, size_t len, const unsigned char *data);

    size_t (*result_max_len)(void *accel_priv, void *key, int op);
    int (*rsa_priv_dec)(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result);
    int (*rsa_pub_dec)(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result);
    int (*rsa_priv_enc)(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result);
    int (*rsa_pub_enc)(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result);
};
typedef struct accel_method_t accel_method;

struct accelerator_t {
    accel_method *method;
    void *priv;
};
typedef struct accelerator_t accelerator;

void accelerator_done(accelerator *accel);
const char *accelerator_name(accelerator *accel);
void *accelerator_add_key(accelerator *accel, int type, size_t len, const unsigned char *data);
void accelerator_destroy_key(accelerator *accel, int type, void *key);
size_t accelerator_result_max_len(accelerator *accel, void *key, int op);
int accelerator_rsa_priv_dec(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result);
int accelerator_rsa_pub_dec(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result);
int accelerator_rsa_priv_enc(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result);
int accelerator_rsa_pub_enc(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result);

#endif // _ACCELERATOR_GMP_H_
