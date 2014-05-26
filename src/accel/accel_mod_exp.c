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

#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>

#include <string.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <common/compiler.h>

#include <accessl-common/cmd.h>
#include <accessl-common/log.h>

#include "accel_mod_exp.h"

LOG_MODULE_DEFINE;

struct mod_exp_rsa_key_t {
    RSA *rsa_key;

    mod_exp_method *method;

    void *priv;
};
typedef struct mod_exp_rsa_key_t mod_exp_rsa_key;

struct mod_exp_priv_t {
    mod_exp_method *method;
};
typedef struct mod_exp_priv_t mod_exp_priv;

static int data_idx = -1;
static RSA_METHOD rsa_method;

static int accel_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);

int accel_mod_exp_init(void)
{
    ERR_load_crypto_strings();
    // TODO - currently Linux only
    if (RAND_load_file("/dev/urandom", 1024) < 1024)
        return -1;

    data_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (data_idx == -1)
        return -1;

    LOG_MODULE_INIT("accessl.accel_mod_exp");

    memset(&rsa_method, 0, sizeof(rsa_method));

    const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
    rsa_method.rsa_pub_enc = meth->rsa_pub_enc;
    rsa_method.rsa_pub_dec = meth->rsa_pub_dec;
    rsa_method.rsa_priv_enc = meth->rsa_priv_enc;
    rsa_method.rsa_priv_dec = meth->rsa_priv_dec;
    rsa_method.bn_mod_exp = meth->bn_mod_exp;
    rsa_method.rsa_mod_exp = accel_rsa_mod_exp;
    rsa_method.flags = RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;

    return 1;
}

void accel_mod_exp_destroy(void)
{
    LOG_TRACE("[%d] accel_mod_exp_destroy()", getpid());

    ERR_free_strings();
    EVP_cleanup();
}

static void *accel_mod_exp_alloc_priv(mod_exp_method *method)
{
    mod_exp_priv *ret = malloc(sizeof(mod_exp_priv));

    ret->method = method;

    LOG_TRACE("[%d] accel_mod_exp_alloc_priv() return 0x%p", getpid(), ret);

    return ret;
}

static void accel_mod_exp_free_priv(void *accel_priv)
{
    LOG_TRACE("[%d] accel_mod_exp_free_priv(0x%p)", getpid(), accel_priv);
    free(accel_priv);
}

static const char *accel_mod_exp_get_name(void *accel_priv)
{
    mod_exp_priv *priv = (mod_exp_priv *)accel_priv;
    return priv->method->get_name();
}

static int accel_rsa_key_decode_elem(mod_exp_rsa_key *k, int mod_exp_elem, const unsigned char **data, size_t *len)
{
    vli *v = (vli *)*data;
    size_t vlen = ntohl(v->len);
    BIGNUM **bn;

    if (unlikely(*len < vlen))
        return -1;

    switch (mod_exp_elem) {
    case ACCEL_MOD_EXP_RSA_N:
        bn = &k->rsa_key->n;
        break;
    case ACCEL_MOD_EXP_RSA_E:
        bn = &k->rsa_key->e;
        break;
    case ACCEL_MOD_EXP_RSA_D:
        bn = &k->rsa_key->d;
        break;
    case ACCEL_MOD_EXP_RSA_P:
        bn = &k->rsa_key->p;
        break;
    case ACCEL_MOD_EXP_RSA_Q:
        bn = &k->rsa_key->q;
        break;
    case ACCEL_MOD_EXP_RSA_DMP1:
        bn = &k->rsa_key->dmp1;
        break;
    case ACCEL_MOD_EXP_RSA_DMQ1:
        bn = &k->rsa_key->dmq1;
        break;
    case ACCEL_MOD_EXP_RSA_IQMP:
        bn = &k->rsa_key->iqmp;
        break;
    default:
        return -1;
    }

    *bn = BN_bin2bn(v->data, vlen, *bn);

    if (k->method->decode_elem(k->priv, mod_exp_elem, v->data, vlen) < 0)
        return -1;

    *data += vlen + sizeof(unsigned int);
    *len -= vlen + sizeof(unsigned int);

    return 1;
}

static int accel_rsa_key_decode(mod_exp_rsa_key *k, size_t len, const unsigned char *data)
{
    int ret = 1;

    // TODO handle public only key

    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_N, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_E, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_D, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_P, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_Q, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_DMP1, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_DMQ1, &data, &len);
    if (likely(ret > 0)) ret = accel_rsa_key_decode_elem(k, ACCEL_MOD_EXP_RSA_IQMP, &data, &len);

    return ret;
}

static void accel_mod_exp_rsa_key_destroy(void *key)
{
    mod_exp_rsa_key *k = (mod_exp_rsa_key *)key;

    k->method->free_priv(k->priv);
    RSA_free(k->rsa_key);
    free(k);
}

static mod_exp_rsa_key *accel_mod_exp_rsa_key_alloc(mod_exp_priv *priv, size_t len, const unsigned char *data)
{
    mod_exp_rsa_key *k = calloc(1, sizeof(mod_exp_rsa_key));
    if (unlikely(!k))
        return NULL;

    k->rsa_key = RSA_new();
    if (unlikely(!k->rsa_key))
    {
        accel_mod_exp_rsa_key_destroy(k);
        return NULL;
    }

    RSA_set_ex_data(k->rsa_key, data_idx, k);
    RSA_set_method(k->rsa_key, &rsa_method);

    k->method = priv->method;
    k->priv = k->method->alloc_priv();

    if (unlikely(!k->priv))
    {
        accel_mod_exp_rsa_key_destroy(k);
        return NULL;
    }

    if (accel_rsa_key_decode(k, len, data) < 0)
    {
        accel_mod_exp_rsa_key_destroy(k);
        return NULL;
    }

    return k;
}

static void *accel_mod_exp_add_key(void *accel_priv, int type, size_t len, const unsigned char *data)
{
    mod_exp_priv *priv = (mod_exp_priv *)accel_priv;

    switch (type)
    {
    case CMD_KEY_RSA:
        {
            mod_exp_rsa_key *k = accel_mod_exp_rsa_key_alloc(priv, len, data);

            if (unlikely(!k))
                return NULL;

            return k;
        }
    default:
        return NULL;
    }
}

static void accel_mod_exp_destroy_key(void *accel_priv UNUSED, int type, void *key)
{
    switch (type)
    {
    case CMD_KEY_RSA:
        accel_mod_exp_rsa_key_destroy(key);
    default:
        return;
    }
}

static size_t accel_mod_exp_result_max_len(void *accel_priv UNUSED, void *key, int op)
{
    switch (op) {
    case CMD_OP_RSA_PRIV_DEC:
    case CMD_OP_RSA_PRIV_ENC:
    case CMD_OP_RSA_PUB_DEC:
    case CMD_OP_RSA_PUB_ENC:
        {
            mod_exp_rsa_key *gkey = (mod_exp_rsa_key *)key;
            return RSA_size(gkey->rsa_key);
        }
    default:
        return -1;
    }
}

static int accel_mod_exp_rsa_priv_dec(void *accel_priv UNUSED, void *key, size_t len UNUSED, const unsigned char *data, unsigned char *result)
{
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    mod_exp_rsa_key *mod_exp_key = (mod_exp_rsa_key *)key;
    return RSA_private_decrypt(ntohl(op->len), op->data, result, mod_exp_key->rsa_key, ntohl(op->pad));
}

static int accel_mod_exp_rsa_pub_dec(void *accel_priv UNUSED, void *key, size_t len UNUSED, const unsigned char *data, unsigned char *result)
{
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    mod_exp_rsa_key *mod_exp_key = (mod_exp_rsa_key *)key;
    return RSA_public_decrypt(ntohl(op->len), op->data, result, mod_exp_key->rsa_key, ntohl(op->pad));
}

static int accel_mod_exp_rsa_priv_enc(void *accel_priv UNUSED, void *key, size_t len UNUSED, const unsigned char *data, unsigned char *result)
{
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    mod_exp_rsa_key *mod_exp_key = (mod_exp_rsa_key *)key;
    return RSA_private_encrypt(ntohl(op->len), op->data, result, mod_exp_key->rsa_key, ntohl(op->pad));
}

static int accel_mod_exp_rsa_pub_enc(void *accel_priv UNUSED, void *key, size_t len UNUSED, const unsigned char *data, unsigned char *result)
{
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    mod_exp_rsa_key *mod_exp_key = (mod_exp_rsa_key *)key;
    return RSA_public_encrypt(ntohl(op->len), op->data, result, mod_exp_key->rsa_key, ntohl(op->pad));
}

static int accel_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    mod_exp_rsa_key *key = (mod_exp_rsa_key *)RSA_get_ex_data(rsa, data_idx);

    if (likely(key && key->method->mod_exp))
        return key->method->mod_exp(key->priv, r0, I);
    else
        return RSA_PKCS1_SSLeay()->rsa_mod_exp(r0, I, rsa, ctx);
}

static accel_method mod_exp_accel_method = {
    .free_priv = accel_mod_exp_free_priv,
    .get_name = accel_mod_exp_get_name,
    .add_key = accel_mod_exp_add_key,
    .destroy_key = accel_mod_exp_destroy_key,
    .result_max_len = accel_mod_exp_result_max_len,
    .rsa_priv_dec = accel_mod_exp_rsa_priv_dec,
    .rsa_pub_dec = accel_mod_exp_rsa_pub_dec,
    .rsa_priv_enc = accel_mod_exp_rsa_priv_enc,
    .rsa_pub_enc = accel_mod_exp_rsa_pub_enc
};

accelerator *accel_mod_exp_method(mod_exp_method *mod_exp)
{
    accelerator *accel = malloc(sizeof(accelerator));
    if (!accel)
        return NULL;

    LOG_TRACE("accel_mod_exp_method(0x%p): returning 0x%p", mod_exp, accel);

    accel->method = &mod_exp_accel_method;
    accel->priv = accel_mod_exp_alloc_priv(mod_exp);

    return accel;
}

