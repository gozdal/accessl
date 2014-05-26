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

#include <stdlib.h>
#include <time.h>

#include <cassert>

#include "op.hpp"

using namespace accessl;

int main()
{
    unsigned char fingerprint[KEY_FINGERPRINT_SIZE];
    int op;
    size_t data_len;
    unsigned char *data;
    int padding;
    size_t i;

    srand(time(NULL));

    for (i = 0; i < KEY_FINGERPRINT_SIZE; i++)
        fingerprint[i] = rand();
    op = rand();
    data_len = rand() % 128;
    data = new unsigned char[data_len];
    for (i = 0; i < data_len; i++)
        data[i] = rand();
    padding = rand();

    req r1(fingerprint, op, data_len, data, padding);
    req r2(r1.get_buf(), r1.get_buf_len());

    assert(memcmp(r1.get_fingerprint(), r2.get_fingerprint(), KEY_FINGERPRINT_SIZE) == 0);
    assert(r1.get_fingerprint() != r2.get_fingerprint());
    assert(r1.get_op() == r2.get_op());
    assert(r1.get_data_len() == r2.get_data_len());
    assert(memcmp(r1.get_data(), r2.get_data(), r1.get_data_len()) == 0);
    assert(r1.get_data() != r2.get_data());
    assert(r1.get_padding() == r2.get_padding());

    delete [] data;
}
