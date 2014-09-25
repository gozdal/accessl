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
    X509 *x509 = X509_new();
    EVP_PKEY *pkey;
    RSA *rsa;
    FILE *f;

    if (argc < 3)
    {
        printf("Usage: %s [pubkey] [output]\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "rb");
    x509 = PEM_read_X509(f, &x509, NULL, NULL);
    if (x509 == NULL) {
        printf("Error loading certificate\n");
        return 1;
    }
    pkey = X509_get_pubkey(x509);
    if (pkey->type != EVP_PKEY_RSA) {
        printf("Not an RSA key\n");
        return 1;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
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
