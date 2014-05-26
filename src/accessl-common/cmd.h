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

#ifndef _CMD_H_
#define _CMD_H_

#include <stdint.h>

#include <sys/ipc.h>

#include <accessl-common/accessl_key.h>

// TODO just guessing, enough for 4096 bit RSA?
#define CMD_MAX_LEN  2048

#define CMD_OP    2

#define CMD_KEY_RSA  1

#define CMD_OP_RSA_PRIV_DEC  1
#define CMD_OP_RSA_PRIV_ENC  2
#define CMD_OP_RSA_PUB_DEC  3
#define CMD_OP_RSA_PUB_ENC  4

struct cmd_op_t {
    uint32_t op;
    unsigned char key_fingerprint[KEY_FINGERPRINT_SIZE];
    uint32_t len; // length in bytes of data which follows
    unsigned char data[0]; // op specific
} __attribute__((packed));
typedef struct cmd_op_t cmd_op;

struct cmd_t {
    uint32_t tag;
    uint32_t cmd;
    cmd_op op;
} __attribute__((packed));
typedef struct cmd_t cmd;

struct vli_t {
    uint32_t len;
    unsigned char data[0];
} __attribute__((packed));
typedef struct vli_t vli;

struct cmd_op_rsa_t {
    uint32_t len;
    uint32_t pad;
    unsigned char data[0];
};
typedef struct cmd_op_rsa_t cmd_op_rsa;

#endif // _CMD_H_
