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

#include "accel_ipp.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <ippcore.h>
#include <ippcp.h>

#include <accessl-common/cmd.h>
#include <accessl-common/compiler.h>
#include <accessl-common/log.h>

#define MAX(a,b)  (((a)>(b))?(a):(b))
#define IPP_BN_LEN(bn)  (((bn)->top)*BN_BYTES/sizeof(Ipp32u))

#define ACCEL_IPP_RSA_N    1
#define ACCEL_IPP_RSA_E    2
#define ACCEL_IPP_RSA_D    3
#define ACCEL_IPP_RSA_P    4
#define ACCEL_IPP_RSA_Q    5

LOG_MODULE_DEFINE;

struct ipp_rsa_key_t {
    int max_len;
    int ipp_bn_len;

    IppsBigNumState *n;
    IppsBigNumState *d;
    IppsBigNumState *e;
    IppsBigNumState *p;
    IppsBigNumState *q;

    IppsRSAState *rsa;
};
typedef struct ipp_rsa_key_t ipp_rsa_key;

int accel_ipp_init()
{
    LOG_MODULE_INIT("accessl.accel_ipp");

    ippSetNumThreads(1);

    return 1;
}

void accel_ipp_destroy()
{
}

static const char *accel_ipp_get_name()
{
    return "IPP";
}

static void accel_ipp_free_priv(void *priv)
{
}

static int accel_rsa_key_decode_elem(ipp_rsa_key *k, int key_elem, BIGNUM *bn)
{
    IppsBigNumState **ipp_bn;
    IppRSAKeyTag tag;
    int len, size;

    switch (key_elem) {
    case ACCEL_IPP_RSA_N:
        ipp_bn = &k->n;
        tag = IppRSAkeyN;
        break;
    case ACCEL_IPP_RSA_E:
        ipp_bn = &k->e;
        tag = IppRSAkeyE;
        break;
    case ACCEL_IPP_RSA_D:
        ipp_bn = &k->d;
        tag = IppRSAkeyD;
        break;
    case ACCEL_IPP_RSA_P:
        ipp_bn = &k->p;
        tag = IppRSAkeyP;
        break;
    case ACCEL_IPP_RSA_Q:
        ipp_bn = &k->q;
        tag = IppRSAkeyQ;
        break;
    default:
        return -1;
    }

    len = IPP_BN_LEN(bn);
    if (ippsBigNumGetSize(len, &size) != ippStsNoErr)
        return -1;

    *ipp_bn = malloc(size);
    if (! (*ipp_bn))
        return -1;

    if (ippsBigNumInit(len, *ipp_bn) != ippStsNoErr)
        return -1;

    if (ippsSet_BN(IppsBigNumPOS, len, (const Ipp32u *)bn->d, *ipp_bn) != ippStsNoErr)
        return -1;
    if (ippsRSASetKey(*ipp_bn, tag, k->rsa) != ippStsNoErr)
        return -1;

    return 1;
}

static int accel_rsa_key_bn(BIGNUM **bn, const unsigned char **data, size_t *len)
{
    vli *v = (vli *)*data;
    size_t vlen = ntohl(v->len);

    if (unlikely(*len < vlen))
        return -1;

    *bn = BN_bin2bn(v->data, vlen, *bn);

    *data += vlen + sizeof(unsigned int);
    *len -= vlen + sizeof(unsigned int);

    return 1;
}

static int accel_rsa_key_decode(ipp_rsa_key *k, size_t len, const unsigned char *data)
{
    int ret = 1;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    int n_bit_size, p_bit_size, q_bit_size, p_bit_max, size;

    // TODO handle public only key

    if (ret > 0) ret = accel_rsa_key_bn(&n, &data, &len);
    if (ret > 0) ret = accel_rsa_key_bn(&e, &data, &len);
    if (ret > 0) ret = accel_rsa_key_bn(&d, &data, &len);
    if (ret > 0) ret = accel_rsa_key_bn(&p, &data, &len);
    if (ret > 0) ret = accel_rsa_key_bn(&q, &data, &len);

    if (ret > 0) {
        k->max_len = BN_num_bytes(n);
        k->ipp_bn_len = IPP_BN_LEN(n);

        n_bit_size = BN_num_bits(n);
        p_bit_size = BN_num_bits(p);
        q_bit_size = BN_num_bits(q);
        p_bit_max = MAX((n_bit_size + 1) / 2, MAX(p_bit_size, q_bit_size));

        if (ippsRSAGetSize(n_bit_size, 0, IppRSAprivate, &size) != ippStsNoErr)
            ret = -1;

        if (ret > 0) 
            k->rsa = malloc(size);

        if (!k->rsa)
            ret = -1;

        if (ret > 0 && ippsRSAInit(n_bit_size, p_bit_max, IppRSAprivate, k->rsa) != ippStsNoErr)
            ret = -1;
    }

    if (ret > 0) ret = accel_rsa_key_decode_elem(k, ACCEL_IPP_RSA_N, n);
    if (ret > 0) ret = accel_rsa_key_decode_elem(k, ACCEL_IPP_RSA_E, e);
    if (ret > 0) ret = accel_rsa_key_decode_elem(k, ACCEL_IPP_RSA_D, d);
    if (ret > 0) ret = accel_rsa_key_decode_elem(k, ACCEL_IPP_RSA_P, p);
    if (ret > 0) ret = accel_rsa_key_decode_elem(k, ACCEL_IPP_RSA_Q, q);

    if (n) BN_clear_free(n);
    if (e) BN_clear_free(e);
    if (d) BN_clear_free(d);
    if (p) BN_clear_free(p);
    if (q) BN_clear_free(q);

    return ret;
}

static void accel_ipp_rsa_key_destroy(void *key)
{
    ipp_rsa_key *k = (ipp_rsa_key *)key;

    free(k->n);
    free(k->d);
    free(k->e);
    free(k->p);
    free(k->q);

    free(k->rsa);

    free(k);
}

static void accel_ipp_destroy_key(void *accel_priv, int type, void *key)
{
    switch (type)
    {
    case CMD_KEY_RSA:
        accel_ipp_rsa_key_destroy(key);
    default:
        return;
    }
}

static ipp_rsa_key *accel_ipp_rsa_key_alloc(void *priv, size_t len, const unsigned char *data)
{
    ipp_rsa_key *k = calloc(1, sizeof(ipp_rsa_key));
    if (unlikely(!k))
        return NULL;

    if (accel_rsa_key_decode(k, len, data) < 0)
    {
        accel_ipp_rsa_key_destroy(k);
        return NULL;
    }

    return k;
}

static void *accel_ipp_add_key(void *priv, int type, size_t len, const unsigned char *data)
{
    switch (type)
    {
    case CMD_KEY_RSA:
        {
            ipp_rsa_key *k = accel_ipp_rsa_key_alloc(priv, len, data);

            if (unlikely(!k))
                return NULL;

            return k;
        }
    default:
        return NULL;
    }
}

static size_t accel_ipp_result_max_len(void *accel_priv, void *key, int op)
{
    switch (op) {
    case CMD_OP_RSA_PRIV_DEC:
    case CMD_OP_RSA_PRIV_ENC:
    case CMD_OP_RSA_PUB_DEC:
    case CMD_OP_RSA_PUB_ENC:
        {
            ipp_rsa_key *gkey = (ipp_rsa_key *)key;
            return gkey->max_len;
        }
    default:
        return -1;
    }
}

static int accel_ipp_rsa_priv_dec(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    ipp_rsa_key *k = (ipp_rsa_key *)key;
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    long oplen = ntohl(op->len);
    long oppad = ntohl(op->pad);
    int ret = -1;
    int size;
    IppsBigNumState *tmp, *output;
    Ipp8u *buf;

    buf = malloc(k->max_len);

    ippsBigNumGetSize(k->ipp_bn_len, &size);
    tmp = malloc(size);
    output = malloc(size);

    if (unlikely(!buf || !tmp || !output))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, tmp) != ippStsNoErr))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, output) != ippStsNoErr))
        goto end;

    if (unlikely(ippsSetOctString_BN(op->data, oplen, tmp) != ippStsNoErr))
        goto end;

    ippsCmp_BN(tmp, k->n, (Ipp32u*)&size);
    if (unlikely(IS_ZERO == size || GREATER_THAN_ZERO == size))
        goto end;

    if (unlikely(ippsRSADecrypt(tmp, output, k->rsa) != ippStsNoErr))
        goto end;

    ippsExtGet_BN(0, &size, 0, output);
    size = (size+7)/8;
    ippsGetOctString_BN(buf, size, output);

    switch (oppad) {
    case RSA_PKCS1_PADDING:
        ret = RSA_padding_check_PKCS1_type_2(result, k->max_len, buf,size, k->max_len);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        ret = RSA_padding_check_PKCS1_OAEP(result,k->max_len, buf,size, k->max_len,NULL,0);
        break;
    case RSA_SSLV23_PADDING:
        ret = RSA_padding_check_SSLv23(result,k->max_len, buf,size, k->max_len);
        break;
    case RSA_NO_PADDING:
        ret = RSA_padding_check_none(result,k->max_len, buf,size, k->max_len);
        break;
    default:
        goto end;
    }

end:
    free(buf);
    free(tmp);
    free(output);
    return ret;
}

static int accel_ipp_rsa_pub_dec(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    ipp_rsa_key *k = (ipp_rsa_key *)key;
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    long oplen = ntohl(op->len);
    long oppad = ntohl(op->pad);
    int ret = -1;
    int size;
    IppsBigNumState *tmp, *output;
    Ipp8u *buf;

    buf = malloc(k->max_len);

    ippsBigNumGetSize(k->ipp_bn_len, &size);
    tmp = malloc(size);
    output = malloc(size);

    if (unlikely(!buf || !tmp || !output))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, tmp) != ippStsNoErr))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, output) != ippStsNoErr))
        goto end;

    if (unlikely(ippsSetOctString_BN(op->data, oplen, tmp) != ippStsNoErr))
        goto end;

    ippsCmp_BN(tmp, k->n, (Ipp32u*)&size);
    if (unlikely(IS_ZERO == size || GREATER_THAN_ZERO == size))
        goto end;

    if (unlikely(ippsRSAEncrypt(tmp, output, k->rsa) != ippStsNoErr))
        goto end;

    ippsExtGet_BN(0, &size, (Ipp32u *)buf, output);
    if ((oppad == RSA_X931_PADDING) && ((((Ipp32u*)buf)[0] & 0xf) != 12))
        ippsSub_BN(k->n, output, output);

    ippsExtGet_BN(0, &size, 0, output);
    size = (size+7)/8;
    ippsGetOctString_BN(buf, size, output);

    switch (oppad) {
    case RSA_PKCS1_PADDING:
        ret = RSA_padding_check_PKCS1_type_1(result, k->max_len, buf, size, k->max_len);
        break;
    case RSA_X931_PADDING:
        ret = RSA_padding_check_X931(result, k->max_len, buf,size, k->max_len);
        break;
    case RSA_NO_PADDING:
        ret = RSA_padding_check_none(result, k->max_len, buf,size, k->max_len);
        break;
    default:
        ret = -1;
        goto end;
    }

end:
    free(buf);
    free(tmp);
    free(output);
    return ret;
}

static int accel_ipp_rsa_priv_enc(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    ipp_rsa_key *k = (ipp_rsa_key *)key;
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    long oplen = ntohl(op->len);
    long oppad = ntohl(op->pad);
    int ret = -1;
    int size;
    IppsBigNumState *tmp, *output;
    Ipp8u *buf;

    buf = malloc(k->max_len);

    ippsBigNumGetSize(k->ipp_bn_len, &size);
    tmp = malloc(size);
    output = malloc(size);

    if (unlikely(!buf || !tmp || !output))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, tmp) != ippStsNoErr))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, output) != ippStsNoErr))
        goto end;

    switch (oppad) {
    case RSA_PKCS1_PADDING:
        ret = RSA_padding_add_PKCS1_type_1(buf, k->max_len, op->data, oplen);
        break;
    case RSA_X931_PADDING:
        ret = RSA_padding_add_X931(buf, k->max_len, op->data, oplen);
        break;
    case RSA_NO_PADDING:
        ret = RSA_padding_add_none(buf, k->max_len, op->data, oplen);
        break;
    default:
        ret = -1;
        goto end;
    }

    if (unlikely(ret < 0))
        goto end;

    if (unlikely(ippsSetOctString_BN(buf, k->max_len, tmp) != ippStsNoErr))
        goto end;

    ippsCmp_BN(tmp, k->n, (Ipp32u*)&size);
    if (unlikely(IS_ZERO == size || GREATER_THAN_ZERO == size))
        goto end;

    if (unlikely(ippsRSADecrypt(tmp, output, k->rsa) != ippStsNoErr))
        goto end;

    if (unlikely(ippsGetOctString_BN(result, k->max_len, output) != ippStsNoErr))
        goto end;

    ret = k->max_len;

end:
    free(buf);
    free(tmp);
    free(output);
    return ret;
}

static int accel_ipp_rsa_pub_enc(void *accel_priv, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    ipp_rsa_key *k = (ipp_rsa_key *)key;
    cmd_op_rsa *op = (cmd_op_rsa *)data;
    long oplen = ntohl(op->len);
    long oppad = ntohl(op->pad);
    int ret = -1;
    int size;
    IppsBigNumState *tmp, *output;
    Ipp8u *buf;

    buf = malloc(k->max_len);

    ippsBigNumGetSize(k->ipp_bn_len, &size);
    tmp = malloc(size);
    output = malloc(size);

    if (unlikely(!buf || !tmp || !output))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, tmp) != ippStsNoErr))
        goto end;

    if (unlikely(ippsBigNumInit(k->ipp_bn_len, output) != ippStsNoErr))
        goto end;

    switch (oppad) {
    case RSA_PKCS1_PADDING:
        ret = RSA_padding_add_PKCS1_type_2(buf, k->max_len, op->data, oplen);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        ret = RSA_padding_add_PKCS1_OAEP(buf, k->max_len, op->data, oplen, NULL, 0);
        break;
    case RSA_SSLV23_PADDING:
        ret = RSA_padding_add_SSLv23(buf, k->max_len, op->data, oplen);
        break;
    case RSA_NO_PADDING:
        ret = RSA_padding_add_none(buf, k->max_len, op->data, oplen);
        break;
    default:
        ret = -1;
        goto end;
    }

    if (unlikely(ret < 0))
        goto end;

    ret = -1;

    if (unlikely(ippsSetOctString_BN(buf, k->max_len, tmp) != ippStsNoErr))
        goto end;

    ippsCmp_BN(tmp, k->n, (Ipp32u*)&size);
    if (unlikely(IS_ZERO == size || GREATER_THAN_ZERO == size))
        goto end;

    if (unlikely(ippsRSAEncrypt(tmp, output, k->rsa) != ippStsNoErr))
        goto end;

    if (unlikely(ippsGetOctString_BN(result, k->max_len, output) != ippStsNoErr))
        goto end;

    ret = k->max_len;

end:
    free(buf);
    free(tmp);
    free(output);
    return ret;
}

static accel_method ipp_accel_method = {
    .free_priv = accel_ipp_free_priv,
    .get_name = accel_ipp_get_name,
    .add_key = accel_ipp_add_key,
    .destroy_key = accel_ipp_destroy_key,
    .result_max_len = accel_ipp_result_max_len,
    .rsa_priv_dec = accel_ipp_rsa_priv_dec,
    .rsa_pub_dec = accel_ipp_rsa_pub_dec,
    .rsa_priv_enc = accel_ipp_rsa_priv_enc,
    .rsa_pub_enc = accel_ipp_rsa_pub_enc
};

accelerator *accel_ipp_method()
{
    accelerator *ret = malloc(sizeof(accelerator));
    if (!ret)
        return ret;

    ret->method = &ipp_accel_method;
    ret->priv = NULL;

    return ret;
}
