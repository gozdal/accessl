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

#include "accel.h"

#include <arpa/inet.h>
#include <string.h>
#include <limits.h>

#include <openssl/rsa.h>

#include <common/compiler.h>

#include <accessl-common/cmd.h>
#include <accessl-common/log.h>
#include <accessl-common/stat.h>
#include <accessl-common/test_keys.h>

#include "accel_base.h"
#include "accel_mod_exp.h"
#include "accel_gmp.h"
#include "accel_tfm.h"
#include "accel_bn.h"
#include "accel_ipp.h"

LOG_MODULE_DEFINE;

accelerator *rsa_accel = NULL;

static void *setup_test_key(accelerator *method)
{
    void *key = accelerator_add_key(method, CMD_KEY_RSA, sizeof(test_key_rsa1024), test_key_rsa1024);

    return key;
}

static int benchmark(accelerator *accel)
{
    const int iterations = 1000;

    int ret, i;
    struct timespec t1, t2, total;
    uint64_t speed = INT_MAX;

    memset(&t1, 0, sizeof(struct timespec));
    memset(&t2, 0, sizeof(struct timespec));
    memset(&total, 0, sizeof(struct timespec));

    unsigned char plain[] = {1,2,3,4,5};
    int plain_len = sizeof(plain);
    const unsigned char *p = test_key_openssl_rsa1024;
    RSA *rsa_key = d2i_RSAPrivateKey(NULL, &p, sizeof(test_key_openssl_rsa1024));
    unsigned char cipher[RSA_size(rsa_key)];
    unsigned char result[RSA_size(rsa_key)];

    int len = RSA_public_encrypt(plain_len, plain, cipher, rsa_key, RSA_PKCS1_PADDING);

    void *key = NULL;
    cmd_op_rsa *op = NULL;

    if (len < 0)
    {
        LOG_ERROR("RSA_public_encrypt failed");
        goto ret;
    }

    key = setup_test_key(accel);
    op = malloc(sizeof(cmd_op_rsa) + accelerator_result_max_len(accel, key, CMD_OP_RSA_PRIV_DEC));

    if (!op)
    {
        goto ret;
    }

    op->len = htonl(len);
    op->pad = htonl(RSA_PKCS1_PADDING);
    memcpy(&op->data[0], cipher, len);

    if (!key)
    {
        LOG_ERROR("%s failed in setup_test_key", accelerator_name(accel));
        goto ret;
    }


    ret = accelerator_rsa_priv_dec(accel, key, len, (const unsigned char *)op, result);
    if (ret != plain_len || memcmp(result, plain, ret) != 0)
    {
        LOG_ERROR("%s failed in accelerator_rsa_priv_dec", accelerator_name(accel));
        goto ret;
    }

    stat_store_time(&t1);
    for (i = 0; i < iterations; ++i)
    {
        if (unlikely(accelerator_rsa_priv_dec(accel, key, len, (const unsigned char *)op, result) != plain_len))
        {
            LOG_ERROR("%s failed in RSA_priv_dec", accelerator_name(accel));
            goto ret;
        }
    }
    stat_store_time(&t2);

    stat_difftime(&t2, &t1, &total);
    speed = ((uint64_t)total.tv_sec * (uint64_t)NANOSEC_IN_SEC + (uint64_t)total.tv_nsec) / (uint64_t)iterations;

    LOG_INFO("%s RSA 1024 private decrypt: %lld ns", accelerator_name(accel), speed);

ret:
    RSA_free(rsa_key);
    free(op);
    accelerator_destroy_key(accel, CMD_KEY_RSA, key);
    return speed;
}

static accelerator *accel_rsa_choose_best(void)
{
    accelerator *methods[] = {
        //accel_ipp_method(),
        accel_mod_exp_method(accel_gmp_method()),
        //accel_mod_exp_method(accel_tfm_method()),
        accel_mod_exp_method(accel_bn_method()),
    };
    int method_count = (int)(sizeof(methods) / sizeof(mod_exp_method *));
    int method_times[method_count];
    int best_time = INT_MAX;

    int i;
    int best = -1;

    for (i = 0; i < method_count; ++i)
    {
        setup_test_key(methods[i]);
        method_times[i] = benchmark(methods[i]);

        if (method_times[i] < best_time)
        {
            best_time = method_times[i];
            best = i;
        }
    }

    for (i = 0; i < method_count; ++i)
    {
        if (i != best)
            accelerator_done(methods[i]);
    }

    if (best == -1)
        return NULL;

    return methods[best];
}

int accel_init()
{
    LOG_MODULE_INIT("accessl.accel");

    if (accel_mod_exp_init() < 0)
        return -1;

    //if (accel_ipp_init() < 0)
    //  return -1;

    rsa_accel = accel_rsa_choose_best();

    if (!rsa_accel)
        return -1;
    return 1;
}

void accel_destroy()
{
    accelerator_done(rsa_accel);

    //accel_ipp_destroy();
    accel_mod_exp_destroy();
}

void *accel_add_key(int type, size_t len, const unsigned char *data)
{
    switch (type) {
    case CMD_KEY_RSA:
        return accelerator_add_key(rsa_accel, type, len, data);
    default:
        return NULL;
    }
}

void accel_destroy_key(int type, void *key)
{
    switch (type) {
    case CMD_KEY_RSA:
        accelerator_destroy_key(rsa_accel, type, key);
    default:
        return;
    }
}

size_t accel_result_max_len(void *key, int op)
{
    switch (op) {
    case CMD_OP_RSA_PRIV_DEC:
    case CMD_OP_RSA_PRIV_ENC:
    case CMD_OP_RSA_PUB_DEC:
    case CMD_OP_RSA_PUB_ENC:
        return accelerator_result_max_len(rsa_accel, key, op);
    default:
        return -1;
    }
}

int accel_perform(void *key, int op, size_t len, const unsigned char *data, unsigned char *result)
{
    switch (op) {
    case CMD_OP_RSA_PRIV_DEC:
        return accelerator_rsa_priv_dec(rsa_accel, key, len, data, result);
    case CMD_OP_RSA_PRIV_ENC:
        return accelerator_rsa_priv_enc(rsa_accel, key, len, data, result);
    case CMD_OP_RSA_PUB_DEC:
        return accelerator_rsa_pub_dec(rsa_accel, key, len, data, result);
    case CMD_OP_RSA_PUB_ENC:
        return accelerator_rsa_pub_enc(rsa_accel, key, len, data, result);
    default:
        return -1;
    }
}

