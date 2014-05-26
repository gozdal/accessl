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

/* crypto/engine/e_accessl.c */
/* Written by Marcin Gozdalik <gozdal@gmail.com>.
 */

/*
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

#include <arpa/inet.h>

#include <accessl-common/accessl_key.h>

#define UNUSED __attribute__((unused))

// #ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_ACCESSL

#define E_ACCESSL_LIB_NAME "AcceSSL engine"
#include "e_accessl_err.c"

static int e_accessl_destroy(ENGINE *e);
static int e_accessl_init(ENGINE *e);
static int e_accessl_finish(ENGINE *e);
static int e_accessl_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

#ifndef OPENSSL_NO_RSA
/* RSA stuff */
static int e_accessl_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int e_accessl_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int e_accessl_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int e_accessl_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int e_accessl_rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
static int e_accessl_rsa_verify(int dtype, const unsigned char *m, unsigned int m_length, unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
static int e_accessl_rsa_init(RSA *r);
static int e_accessl_rsa_finish(RSA *r);
#endif

#define ACCESSL_CMD_SO_PATH    ENGINE_CMD_BASE

static const ENGINE_CMD_DEFN e_accessl_cmd_defns[] = {
    {ACCESSL_CMD_SO_PATH,
        "SO_PATH",
        "Specifies the path to the 'accessl-engine' shared library",
        ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

#ifndef OPENSSL_NO_RSA
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD e_accessl_rsa =
{
    "AcceSSL",
    e_accessl_rsa_pub_enc,
    e_accessl_rsa_pub_dec,
    e_accessl_rsa_priv_enc,
    e_accessl_rsa_priv_dec,
    NULL,
    NULL,
    e_accessl_rsa_init,
    e_accessl_rsa_finish,
    RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE|RSA_METHOD_FLAG_NO_CHECK|RSA_FLAG_EXT_PKEY,
    NULL,
    NULL, //e_accessl_rsa_sign,
    NULL, //e_accessl_rsa_verify,
    NULL
};

static RSA_METHOD e_accessl_rsa_sign_verify UNUSED =
{
    "AcceSSLerator",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    e_accessl_rsa_init,
    e_accessl_rsa_finish,
    RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE|RSA_FLAG_SIGN_VER|RSA_METHOD_FLAG_NO_CHECK|RSA_FLAG_EXT_PKEY,
    NULL,
    e_accessl_rsa_sign,
    e_accessl_rsa_verify,
    NULL
};

#endif

#ifndef OPENSSL_NO_RSA
/* Used to attach key fingerprint an RSA structure */
static int accessl_data_idx = -1;

typedef int AcceSSL_Init_t(void);
typedef void AcceSSL_Finish_t(void);
typedef int AcceSSL_RSA_Verify_t(accessl_key *, int, const unsigned char *, unsigned int, unsigned char *, unsigned int);
typedef int AcceSSL_RSA_Sign_t(accessl_key *, int, const unsigned char *, unsigned int, int, unsigned char *, unsigned int *);
typedef int AcceSSL_RSA_Priv_Dec_t(accessl_key *, int, const unsigned char *, int, unsigned char *, int);
typedef int AcceSSL_RSA_Priv_Enc_t(accessl_key *, int, const unsigned char *, int, unsigned char *, int);
typedef int AcceSSL_RSA_Pub_Dec_t(accessl_key *, int, const unsigned char *, int, unsigned char *, int);
typedef int AcceSSL_RSA_Pub_Enc_t(accessl_key *, int, const unsigned char *, int, unsigned char *, int);

static AcceSSL_Init_t *accessl_init = NULL;
static AcceSSL_Finish_t *accessl_finish = NULL;
static AcceSSL_RSA_Verify_t *accessl_rsa_verify = NULL;
static AcceSSL_RSA_Sign_t *accessl_rsa_sign = NULL;
static AcceSSL_RSA_Pub_Enc_t *accessl_rsa_pub_enc = NULL;
static AcceSSL_RSA_Pub_Dec_t *accessl_rsa_pub_dec = NULL;
static AcceSSL_RSA_Priv_Enc_t *accessl_rsa_priv_enc = NULL;
static AcceSSL_RSA_Priv_Dec_t *accessl_rsa_priv_dec = NULL;

#endif

static DSO *accessl_dso = NULL;

/* Constants used when creating the ENGINE */
static const char *engine_e_accessl_id = "accessl";
static const char *engine_e_accessl_name = "AcceSSL engine support";

/* This internal function is used by ENGINE_accessl() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
#ifndef OPENSSL_NO_RSA
    const RSA_METHOD *meth1;
#endif
    if(!ENGINE_set_id(e, engine_e_accessl_id) ||
            !ENGINE_set_name(e, engine_e_accessl_name) ||
#ifndef OPENSSL_NO_RSA
            !ENGINE_set_RSA(e, &e_accessl_rsa) ||
#endif
            !ENGINE_set_destroy_function(e, e_accessl_destroy) ||
            !ENGINE_set_init_function(e, e_accessl_init) ||
            !ENGINE_set_finish_function(e, e_accessl_finish) ||
            !ENGINE_set_ctrl_function(e, e_accessl_ctrl) ||
            !ENGINE_set_cmd_defns(e, e_accessl_cmd_defns))
        return 0;

#ifndef OPENSSL_NO_RSA
    meth1 = RSA_PKCS1_SSLeay();
    e_accessl_rsa.bn_mod_exp = meth1->bn_mod_exp;
#endif

    /* Ensure the e_accessl error handling is set up */
    ERR_load_accessl_strings();
    return 1;
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_fn(ENGINE *e, const char *id)
{
    if(id && (strcmp(id, engine_e_accessl_id) != 0))
        return 0;
    if(!bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */


#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_accessl(void)
{
    ENGINE *ret = ENGINE_new();
    if(!ret)
        return NULL;
    if(!bind_helper(ret))
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_accessl(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_accessl();
    if(!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif

static int e_accessl_destroy(ENGINE *e UNUSED)
{
    ERR_unload_accessl_strings();
    return 1;
}

static const char *AcceSSL_libname = NULL;

static const char *get_AcceSSL_libname(void)
{
    if (AcceSSL_libname)
        return AcceSSL_libname;
    return "accessl-openssl";
}

static void free_AcceSSL_libname(void)
{
    if (AcceSSL_libname)
        OPENSSL_free((void *)AcceSSL_libname);
    AcceSSL_libname = NULL;
}

static int set_AcceSSL_libname(const char *name)
{
    free_AcceSSL_libname();
    return (((AcceSSL_libname = BUF_strdup(name)) != NULL) ? 1 : 0);
}

/* (de)initialisation functions. */
static int e_accessl_init(ENGINE *e UNUSED)
{
    AcceSSL_Init_t *p1 = NULL;
    AcceSSL_Finish_t *p2 = NULL;
    AcceSSL_RSA_Verify_t *p9 = NULL;
    AcceSSL_RSA_Sign_t *p10 = NULL;
    AcceSSL_RSA_Pub_Dec_t *p11 = NULL;
    AcceSSL_RSA_Pub_Enc_t *p12 = NULL;
    AcceSSL_RSA_Priv_Dec_t *p13 = NULL;
    AcceSSL_RSA_Priv_Enc_t *p14 = NULL;

    if(accessl_dso != NULL)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_INIT, ACCESSL_R_ALREADY_LOADED);
        return 0;
    }
    accessl_dso = DSO_load(NULL, get_AcceSSL_libname(), NULL, 0);

    if (accessl_dso == NULL)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_INIT, ACCESSL_R_DSO_FAILURE);
        return 0;
    }

#ifndef OPENSSL_NO_RSA
    if (accessl_data_idx == -1)
        accessl_data_idx = RSA_get_ex_new_index(0,
                "AcceSSL private data handle",
                NULL, NULL, NULL);
    if (accessl_data_idx == -1)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_INIT, ACCESSL_R_RSA_GET_NEW_INDEX_FAILURE);
        return 0;
    }
#endif

    p1 = (AcceSSL_Init_t *)DSO_bind_func(accessl_dso, "accessl_init");
    p2 = (AcceSSL_Finish_t *)DSO_bind_func(accessl_dso, "accessl_finish");
    p9 = (AcceSSL_RSA_Verify_t *)DSO_bind_func(accessl_dso, "accessl_rsa_verify");
    p10 = (AcceSSL_RSA_Sign_t *)DSO_bind_func(accessl_dso, "accessl_rsa_sign");
    p11 = (AcceSSL_RSA_Pub_Dec_t *)DSO_bind_func(accessl_dso, "accessl_rsa_pub_dec");
    p12 = (AcceSSL_RSA_Pub_Enc_t *)DSO_bind_func(accessl_dso, "accessl_rsa_pub_enc");
    p13 = (AcceSSL_RSA_Priv_Dec_t *)DSO_bind_func(accessl_dso, "accessl_rsa_priv_dec");
    p14 = (AcceSSL_RSA_Priv_Enc_t *)DSO_bind_func(accessl_dso, "accessl_rsa_priv_enc");

    if (!p1 || !p2 || !p9 || !p10 || !p11 || !p12 || !p13 || !p14)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_INIT, ACCESSL_R_DSO_FAILURE);
        return 0;
    }

    accessl_init = p1;
    accessl_finish = p2;
    accessl_rsa_verify = p9;
    accessl_rsa_sign = p10;
    accessl_rsa_pub_dec = p11;
    accessl_rsa_pub_enc = p12;
    accessl_rsa_priv_dec = p13;
    accessl_rsa_priv_enc = p14;

    return accessl_init();
}

static int e_accessl_finish(ENGINE *e UNUSED)
{
    accessl_finish();
    return 1;
}

static int e_accessl_ctrl(ENGINE *e UNUSED, int cmd, long i UNUSED, void *p, void (*f)(void) UNUSED)
{
    int to_return = 1;
    int initialised = ((accessl_dso == NULL) ? 0 : 1);

    switch(cmd)
    {
    case ACCESSL_CMD_SO_PATH:
        if (!p)
        {
            ACCESSLerr(ACCESSL_F_E_ACCESSL_CTRL, ACCESSL_R_PASSED_NULL_PARAM);
            return 0;
        }
        if (initialised)
        {
            ACCESSLerr(ACCESSL_F_E_ACCESSL_CTRL, ACCESSL_R_ALREADY_LOADED);
            return 0;
        }
        to_return = set_AcceSSL_libname((const char *)p);
        break;
    default:
        ACCESSLerr(ACCESSL_F_E_ACCESSL_CTRL, ACCESSL_R_CTRL_COMMAND_NOT_IMPLEMENTED);
        to_return = 0;
        break;
    }

    return to_return;
}

static void e_accessl_free_accessl_key(accessl_key *key UNUSED)
{
    // no-op
}

static int e_accessl_convert_rsa_key(const RSA *rsa, accessl_key *a_key)
{
    int ret = 0;
    MD5_CTX md5_ctx;
    unsigned char *n_bin = NULL; int n_len;
    unsigned char *e_bin = NULL; int e_len;

    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_CONVERT_RSA_KEY, ACCESSL_R_NO_KEY_CONTEXT);
        return 0;
    }

    n_len = BN_num_bytes(rsa->n); n_bin = OPENSSL_malloc(n_len);
    e_len = BN_num_bytes(rsa->e); e_bin = OPENSSL_malloc(e_len);

    if (!n_bin || !e_bin)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_CONVERT_RSA_KEY, ACCESSL_R_MEMORY_ALLOC);
        goto err;
    }

    memset(n_bin, 0, n_len);
    BN_bn2bin(rsa->n, n_bin);
    memset(e_bin, 0, e_len);
    BN_bn2bin(rsa->e, e_bin);

    if (!MD5_Init(&md5_ctx) ||
        !MD5_Update(&md5_ctx, n_bin, n_len) ||
        !MD5_Update(&md5_ctx, e_bin, e_len) ||
        !MD5_Final(a_key->fingerprint, &md5_ctx))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_CONVERT_RSA_KEY, ACCESSL_R_MD5_FAILURE);
        goto err;
    }

    a_key->type = 1;
    a_key->key_converted = 1;

    ret = 1;
err:
    OPENSSL_free(n_bin);
    OPENSSL_free(e_bin);
    return ret;
}

static int e_accessl_rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_SIGN, ACCESSL_R_NO_KEY_CONTEXT);
        goto err;
    }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        goto err;
    }

    ret = accessl_rsa_sign(a_key, type, m, m_len, RSA_size(rsa), sigret, siglen);

    if (!ret)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_SIGN, ACCESSL_R_ACCESSL_FAILURE);
        goto err;
    }

    ret = 1;
err:
    return ret;
}

static int e_accessl_rsa_verify(int dtype, const unsigned char *m, unsigned int m_length, unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_VERIFY, ACCESSL_R_NO_KEY_CONTEXT);
        goto err; }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        goto err;
    }

    ret = accessl_rsa_verify(a_key, dtype, m, m_length, sigbuf, siglen);

    if (!ret)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_VERIFY, ACCESSL_R_ACCESSL_FAILURE);
        goto err;
    }

    ret = 1;
err:
    return ret;
}

static int e_accessl_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    ret = accessl_rsa_priv_enc(a_key, flen, from, RSA_size(rsa), to, padding);

    if (ret == -1)
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_ACCESSL_FAILURE);

    return ret;
}

static int e_accessl_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_DEC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_DEC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    ret = accessl_rsa_priv_dec(a_key, flen, from, RSA_size(rsa), to, padding);

    if (ret == -1)
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_ACCESSL_FAILURE);

    return ret;
}

static int e_accessl_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PUB_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PUB_ENC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    ret = accessl_rsa_pub_enc(a_key, flen, from, RSA_size(rsa), to, padding);

    if (ret == -1)
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_ACCESSL_FAILURE);

    return ret;
}

static int e_accessl_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;

    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PUB_DEC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    if (!a_key->key_converted && !e_accessl_convert_rsa_key(rsa, a_key))
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PUB_DEC, ACCESSL_R_NO_KEY_CONTEXT);
        return -1;
    }

    ret = accessl_rsa_pub_dec(a_key, flen, from, RSA_size(rsa), to, padding);

    if (ret == -1)
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_PRIV_ENC, ACCESSL_R_ACCESSL_FAILURE);

    return ret;
}

static int e_accessl_rsa_init(RSA *rsa)
{
    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_INIT, ACCESSL_R_KEY_CONTEXT);
        return 0;
    }
    a_key = OPENSSL_malloc(sizeof(accessl_key));
    if (!a_key)
    {
        ACCESSLerr(ACCESSL_F_E_ACCESSL_RSA_INIT, ACCESSL_R_MEMORY_ALLOC);
        return 0;
    }
    memset(a_key, 0, sizeof(accessl_key));

    RSA_set_ex_data(rsa, accessl_data_idx, a_key);

    return 1;
}

static int e_accessl_rsa_finish(RSA *rsa)
{
    accessl_key *a_key = RSA_get_ex_data(rsa, accessl_data_idx);
    if (!a_key)
        return 1;

    e_accessl_free_accessl_key(a_key);
    OPENSSL_free(a_key);

    return 1;
}

#endif /* !OPENSSL_NO_HW_ACCESSL */
// #endif /* !OPENSSL_NO_HW */

