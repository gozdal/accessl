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

#ifndef _ACCESSL_KEY_H_
#define _ACCESSL_KEY_H_

#ifdef  __cplusplus
extern "C" {
#endif

// MD5 is 128 bit length
#define KEY_FINGERPRINT_SIZE 16

struct accessl_key_t {
    int type; // for now only RSA_KEY == 1
    int key_converted;
    unsigned char fingerprint[KEY_FINGERPRINT_SIZE];
};
typedef struct accessl_key_t accessl_key;

#ifdef  __cplusplus
}
#endif

#endif // _ACCESSL_KEY_H_

