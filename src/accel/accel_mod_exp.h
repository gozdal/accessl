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

#ifndef _ACCEL_MOD_EXP_H_
#define _ACCEL_MOD_EXP_H_

#include <openssl/bn.h>

#include "accel_base.h"

#define ACCEL_MOD_EXP_RSA_N  1
#define ACCEL_MOD_EXP_RSA_E  2
#define ACCEL_MOD_EXP_RSA_D  3
#define ACCEL_MOD_EXP_RSA_P  4
#define ACCEL_MOD_EXP_RSA_Q  5
#define ACCEL_MOD_EXP_RSA_DMP1  6
#define ACCEL_MOD_EXP_RSA_DMQ1  7
#define ACCEL_MOD_EXP_RSA_IQMP  8

struct mod_exp_method_t {
    const char *(*get_name)(void);

    void *(*alloc_priv)(void);
    void (*free_priv)(void *mod_exp_priv);

    int (*decode_elem)(void *mod_exp_priv, int mod_exp_elem, unsigned char *data, size_t len);
    int (*mod_exp)(void *mod_exp_priv, BIGNUM *r0, const BIGNUM *I0);
};
typedef struct mod_exp_method_t mod_exp_method;

int accel_mod_exp_init(void);
void accel_mod_exp_destroy(void);

accelerator *accel_mod_exp_method(mod_exp_method *mod_exp);

#endif // _ACCEL_MOD_EXP_H_
