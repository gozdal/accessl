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

#include <pthread.h>

#include <common/compiler.h>

#include <accessl-common/accessl_key.h>
#include <accessl-common/cmd.h>

#include <boost/scoped_ptr.hpp>

#include "engine.hpp"

extern "C" int accessl_init(void);
extern "C" void accessl_finish(void);

extern "C" int accessl_rsa_sign(accessl_key *key, int type, const unsigned char *m, unsigned int m_len, int retlen, unsigned char *sigret, unsigned int *siglen);
extern "C" int accessl_rsa_verify(accessl_key *key, int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int siglen);
extern "C" int accessl_rsa_pub_enc(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding);
extern "C" int accessl_rsa_pub_dec(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding);
extern "C" int accessl_rsa_priv_enc(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding);
extern "C" int accessl_rsa_priv_dec(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding);

namespace accessl {

    struct rsa_ctx
    {
        boost::scoped_ptr<engine> e;

        rsa_ctx(const string & _socket) :
            e(new engine(_socket))
        { }
    };

    static pthread_key_t rsa_ctx_key;

    static void rsa_ctx_destroy(void *buf)
    {
        rsa_ctx *ctx = reinterpret_cast<rsa_ctx *>(buf);
        delete ctx;
    }

    static rsa_ctx *get_rsa_ctx(void)
    {
        rsa_ctx *ret = reinterpret_cast<rsa_ctx *>(pthread_getspecific(rsa_ctx_key));

        if (unlikely(!ret))
        {
            // TODO
            // how to pass the socket name?
            ret = new rsa_ctx("ipc:///tmp/accessld.0mq");
            if (!ret)
                return NULL;

            pthread_setspecific(rsa_ctx_key, ret);

            return ret;
        }

        return ret;
    }

    static int rsa_init(void)
    {
        int ret = 1;

        if (pthread_key_create(&rsa_ctx_key, rsa_ctx_destroy) < 0)
            ret = 0;

        return ret;
    }

    void rsa_finish(void)
    {
    }

}

int accessl_init(void)
{
    int ret = 1;

    if (ret > 0) ret = accessl::rsa_init();

    return ret;
}

void accessl_finish(void)
{
    accessl::rsa_finish();

    accessl::rsa_ctx *ctx = accessl::get_rsa_ctx();

    delete ctx;
}

int accessl_rsa_sign(accessl_key *key UNUSED, int type UNUSED,
    const unsigned char *m UNUSED, unsigned int m_len UNUSED,
    int retlen UNUSED, unsigned char *sigret UNUSED, unsigned int *siglen UNUSED)
{
    return -1;
}

int accessl_rsa_verify(accessl_key *key UNUSED, int type UNUSED,
    const unsigned char *m UNUSED, unsigned int m_len UNUSED,
    unsigned char *sigret UNUSED, unsigned int siglen UNUSED)
{
    return -1;
}

int accessl_rsa_pub_enc(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    accessl::rsa_ctx *ctx = accessl::get_rsa_ctx();

    if (likely(ctx))
        return ctx->e->rsa_op(key, CMD_OP_RSA_PUB_ENC, flen, from, tlen, to, padding);
    else
        return -1;
}

int accessl_rsa_pub_dec(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    accessl::rsa_ctx *ctx = accessl::get_rsa_ctx();

    if (likely(ctx))
        return ctx->e->rsa_op(key, CMD_OP_RSA_PUB_DEC, flen, from, tlen, to, padding);
    else
        return -1;
}

int accessl_rsa_priv_enc(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    accessl::rsa_ctx *ctx = accessl::get_rsa_ctx();

    if (likely(ctx))
        return ctx->e->rsa_op(key, CMD_OP_RSA_PRIV_ENC, flen, from, tlen, to, padding);
    else
        return -1;
}

int accessl_rsa_priv_dec(accessl_key *key, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    accessl::rsa_ctx *ctx = accessl::get_rsa_ctx();

    if (likely(ctx))
        return ctx->e->rsa_op(key, CMD_OP_RSA_PRIV_DEC, flen, from, tlen, to, padding);
    else
        return -1;
}
