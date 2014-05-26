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

#include <gmp.h>

#include <common/compiler.h>

#include <accessl-common/cmd.h>

#include "accel_gmp.h"

struct gmp_rsa_key_t {
    mpz_t n;
    mpz_t d;
    mpz_t e;
    mpz_t p;
    mpz_t q;
    mpz_t dmp1;
    mpz_t dmq1;
    mpz_t iqmp;
};
typedef struct gmp_rsa_key_t gmp_rsa_key;

static const char *accel_gmp_get_name(void)
{
    return "GMP";
}

static void bn2gmp(const BIGNUM *bn, mpz_t g)
{
    bn_check_top(bn);
    if(((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) && (BN_BITS2 == GMP_NUMB_BITS)) 
    {
        /* The common case */
        if(!_mpz_realloc (g, bn->top))
            return;
        memcpy(&g->_mp_d[0], &bn->d[0], bn->top * sizeof(bn->d[0]));
        g->_mp_size = bn->top;
        if(bn->neg)
            g->_mp_size = -g->_mp_size;
    }
    else
    {
        int count = BN_num_bytes(bn);
        unsigned char buf[count];

        BN_bn2bin(bn, buf);
        mpz_import(g, count, 1, 1, 0, 0, buf);
    }
}

static void gmp2bn(mpz_t g, BIGNUM *bn)
{
    if(((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) &&
            (BN_BITS2 == GMP_NUMB_BITS))
    {
        /* The common case */
        int s = (g->_mp_size >= 0) ? g->_mp_size : -g->_mp_size;
        BN_zero(bn);
        bn_expand2(bn, s);
        bn->top = s;
        memcpy(&bn->d[0], &g->_mp_d[0], s * sizeof(bn->d[0]));
        bn_correct_top(bn);
        bn->neg = g->_mp_size >= 0 ? 0 : 1;
    }
    else
    {
        int count = (mpz_sizeinbase(g, 2) + 7) / 8;
        unsigned char buf[count];

        mpz_export(buf, NULL, 1, 1, 0, 0, g);
        BN_bin2bn(buf, count, bn);
    }
}

static int accel_gmp_rsa_key_decode_elem(void *k, int mod_exp_elem, unsigned char *data, size_t len)
{
    gmp_rsa_key *key = (gmp_rsa_key *)k;
    mpz_t *g;

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

    mpz_import(*g, len, 1, 1, 0, 0, data);

    return 1;
}

static void accel_gmp_rsa_key_destroy(void *k)
{
    gmp_rsa_key *key = (gmp_rsa_key *)k;

    mpz_clear(key->n);
    mpz_clear(key->e);
    mpz_clear(key->d);
    mpz_clear(key->p);
    mpz_clear(key->q);
    mpz_clear(key->dmp1);
    mpz_clear(key->dmq1);
    mpz_clear(key->iqmp);

    free(k);
}

static void *accel_gmp_rsa_key_alloc(void)
{
    gmp_rsa_key *k = calloc(1, sizeof(gmp_rsa_key));
    if (unlikely(!k))
        return NULL;

    return k;
}

static void accel_gmp_mod_exp(gmp_rsa_key *key, mpz_t r0, mpz_t I0)
{
    mpz_t r1, m1;

    mpz_init(r1);
    mpz_init(m1);

    mpz_mod(r1, I0, key->q);
    mpz_powm(m1, r1, key->dmq1, key->q);

    mpz_mod(r1, I0, key->p);
    mpz_powm(r0, r1, key->dmp1, key->p);

    mpz_sub(r0, r0, m1);

    if(mpz_sgn(r0) < 0)
        mpz_add(r0, r0, key->p);
    mpz_mul(r1, r0, key->iqmp);
    mpz_mod(r0, r1, key->p);

    if(mpz_sgn(r0) < 0)
        mpz_add(r0, r0, key->p);
    mpz_mul(r1, r0, key->q);
    mpz_add(r0, r1, m1);

    mpz_clear(r1);
    mpz_clear(m1);
}

static int accel_gmp_rsa_mod_exp(void *k, BIGNUM *r0, const BIGNUM *I0)
{
    mpz_t gmp_r0, gmp_I0;
    gmp_rsa_key *key = (gmp_rsa_key *)k;

    mpz_init(gmp_r0);
    mpz_init(gmp_I0);
    bn2gmp(I0, gmp_I0);
    accel_gmp_mod_exp(key, gmp_r0, gmp_I0);
    gmp2bn(gmp_r0, r0);
    mpz_clear(gmp_r0);
    mpz_clear(gmp_I0);

    return 1;
}

static mod_exp_method gmp = {
    .get_name = accel_gmp_get_name,
    .alloc_priv = accel_gmp_rsa_key_alloc,
    .free_priv = accel_gmp_rsa_key_destroy,
    .decode_elem = accel_gmp_rsa_key_decode_elem,
    .mod_exp = accel_gmp_rsa_mod_exp,
};

mod_exp_method *accel_gmp_method()
{
    return &gmp;
}

