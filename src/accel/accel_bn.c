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

#include <common/compiler.h>

#include <accessl-common/cmd.h>

#include "accel_bn.h"

static const char *accel_bn_get_name(void)
{
    return "BIGNUM";
}

static void accel_bn_rsa_key_destroy(void *k)
{
    free(k);
}

static void *accel_bn_rsa_key_alloc(void)
{
    // dummy, returning NULL is interpreted as a failure
    return malloc(1);
}

static int accel_bn_rsa_key_decode_elem(void *k UNUSED, int mod_exp_elem UNUSED, unsigned char *data UNUSED, size_t len UNUSED)
{
    return 1;
}

static mod_exp_method bn = {
    .get_name = accel_bn_get_name,
    .alloc_priv = accel_bn_rsa_key_alloc,
    .free_priv = accel_bn_rsa_key_destroy,
    .decode_elem = accel_bn_rsa_key_decode_elem,
    .mod_exp = NULL,
};

mod_exp_method *accel_bn_method()
{
    return &bn;
}
