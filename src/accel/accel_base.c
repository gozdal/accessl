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

#include "accel_base.h"

const char *accelerator_name(accelerator *accel)
{
    return accel->method->get_name(accel->priv);
}

void accelerator_done(accelerator *accel)
{
    if (accel)
    {
        accel->method->free_priv(accel->priv);
        free(accel);
    }
}

void accelerator_destroy_key(accelerator *accel, int type, void *key)
{
    accel->method->destroy_key(accel->priv, type, key);
}

void *accelerator_add_key(accelerator *accel, int type, size_t len, const unsigned char *data)
{
    return accel->method->add_key(accel->priv, type, len, data);
}

size_t accelerator_result_max_len(accelerator *accel, void *key, int op)
{
    return accel->method->result_max_len(accel->priv, key, op);
}

int accelerator_rsa_priv_dec(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    return accel->method->rsa_priv_dec(accel->priv, key, len, data, result);
}

int accelerator_rsa_pub_dec(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    return accel->method->rsa_pub_dec(accel->priv, key, len, data, result);
}

int accelerator_rsa_priv_enc(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    return accel->method->rsa_priv_enc(accel->priv, key, len, data, result);
}

int accelerator_rsa_pub_enc(accelerator *accel, void *key, size_t len, const unsigned char *data, unsigned char *result)
{
    return accel->method->rsa_pub_enc(accel->priv, key, len, data, result);
}
