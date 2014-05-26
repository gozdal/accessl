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

#include "log.h"

#define MAX_HEX_LEN 4096

static char buf[MAX_HEX_LEN+1];

int log_init()
{
    log4c_init();
    return 1;
}

void log_destroy()
{
    log4c_fini();
}

static inline char hex_digit(char c)
{
    if (c <= 9)
        return c+'0';
    else
        return c-10+'a';
}

const char *log_hex(int len, const unsigned char *data)
{
    int i;

    if (len*2 > MAX_HEX_LEN)
        return NULL;

    for (i = 0; i < len; ++i)
    {
        buf[i*2] = hex_digit((data[i] & 0xf0) >> 4);
        buf[i*2+1] = hex_digit(data[i] & 0x0f);
    }

    buf[len*2] = 0;

    return buf;
}
