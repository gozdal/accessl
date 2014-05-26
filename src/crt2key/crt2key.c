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

#include <stdio.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

int main(int argc, char **argv)
{
    RSA *rsa = RSA_new();
    FILE *f;

    if (argc < 3)
    {
        printf("Usage: %s [pubkey] [output]\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "rb");
    rsa = PEM_read_RSA_PUBKEY(f, &rsa, NULL, NULL);
    fclose(f);

    BN_dec2bn(&rsa->d, "0");
    BN_dec2bn(&rsa->p, "0");
    BN_dec2bn(&rsa->q, "0");
    BN_dec2bn(&rsa->dmp1, "0");
    BN_dec2bn(&rsa->dmq1, "0");
    BN_dec2bn(&rsa->iqmp, "0");

    f = fopen(argv[2], "wb");
    int ret = PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    if (ret) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}
