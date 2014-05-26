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

#include <string.h>
#include <stdlib.h>

#include <tfm.h>

#include <common/compiler.h>

#include <accessl-common/cmd.h>

#include "accel_tfm.h"

struct tfm_rsa_key_t {
    fp_int n;
    fp_int d;
    fp_int e;
    fp_int p;
    fp_int q;
    fp_int dmp1;
    fp_int dmq1;
    fp_int iqmp;
};
typedef struct tfm_rsa_key_t tfm_rsa_key;

static const char *accel_tfm_get_name(void)
{
    return "tfm";
}

static void accel_tfm_rsa_key_destroy(void *k)
{
    free(k);
}

static void *accel_tfm_rsa_key_alloc(void)
{
    tfm_rsa_key *k = calloc(1, sizeof(tfm_rsa_key));
    if (unlikely(!k))
        return NULL;

    return k;
}

static void bn2fp(const BIGNUM *bn, fp_int *fp)
{
    bn_check_top(bn);
    memcpy(&fp->dp[0], &bn->d[0], bn->top * sizeof(bn->d[0]));
    fp->used = bn->top;
    fp->sign = bn->neg;
}

static void fp2bn(fp_int *fp, BIGNUM *bn)
{
    BN_zero(bn);
    bn_expand2(bn, fp->used);
    bn->top = fp->used;
    memcpy(&bn->d[0], &fp->dp[0], fp->used * sizeof(bn->d[0]));
    bn_correct_top(bn);
    bn->neg = fp->sign;
}

static int accel_tfm_rsa_key_decode_elem(void *k, int mod_exp_elem, unsigned char *data, size_t len)
{
    tfm_rsa_key *key = (tfm_rsa_key *)k;
    fp_int *g;

    switch (mod_exp_elem) {
        case ACCEL_MOD_EXP_RSA_N:
            g = &key->n;
            break;
        case ACCEL_MOD_EXP_RSA_E:
            g = &key->e;
            break;
        case ACCEL_MOD_EXP_RSA_D:
            g = &key->d;
            break;
        case ACCEL_MOD_EXP_RSA_P:
            g = &key->p;
            break;
        case ACCEL_MOD_EXP_RSA_Q:
            g = &key->q;
            break;
        case ACCEL_MOD_EXP_RSA_DMP1:
            g = &key->dmp1;
            break;
        case ACCEL_MOD_EXP_RSA_DMQ1:
            g = &key->dmq1;
            break;
        case ACCEL_MOD_EXP_RSA_IQMP:
            g = &key->iqmp;
            break;
        default:
            return -1;
    }

    fp_read_unsigned_bin(g, data, len);

    return 1;
}

static void accel_tfm_mod_exp(tfm_rsa_key *key, fp_int *r0, fp_int *I0)
{
    fp_int r1, m1;

    fp_init(&r1);
    fp_init(&m1);

    fp_mod(I0, &key->q, &r1); // r1 = I0 mod q
    fp_exptmod(&r1, &key->dmq1, &key->q, &m1); // m1 = r1^dmq1 (mod q)

    fp_mod(I0, &key->p, &r1); // r1 = I0 mod p
    fp_exptmod(&r1, &key->dmp1, &key->p, r0); // r0 = r1^dmp1 (mod p)

    fp_sub(r0, &m1, r0); // r0 = r0-m1

    // if (r0 < 0) r0 += p
    if(r0->sign == FP_NEG)
        fp_add(r0, &key->p, r0);
    fp_mul(r0, &key->iqmp, &r1); // r1 = r0*iqmp
    fp_mod(&r1, &key->p, r0); // r0 = r1 mod p

    // if (r0 < 0) r0 += p
    if(r0->sign == FP_NEG)
        fp_add(r0, &key->p, r0);
    fp_mul(r0, &key->q, &r1); // r1 = r0*q
    fp_add(&r1, &m1, r0); // r0 = r1+m1
}

static int accel_tfm_rsa_mod_exp(void *k, BIGNUM *r0, const BIGNUM *I0)
{
    fp_int fp_r0, fp_I0;
    tfm_rsa_key *key = (tfm_rsa_key *)k;

    bn2fp(I0, &fp_I0);
    fp_init(&fp_r0);
    accel_tfm_mod_exp(key, &fp_r0, &fp_I0);
    fp2bn(&fp_r0, r0);

    return 1;
}

static mod_exp_method tfm = {
    .get_name = accel_tfm_get_name,
    .alloc_priv = accel_tfm_rsa_key_alloc,
    .free_priv = accel_tfm_rsa_key_destroy,
    .decode_elem = accel_tfm_rsa_key_decode_elem,
    .mod_exp = accel_tfm_rsa_mod_exp,
};

mod_exp_method *accel_tfm_method()
{
    return &tfm;
}
