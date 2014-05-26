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

#ifndef _CRYPTO_HPP_
#define _CRYPTO_HPP_

#include <openssl/engine.h>
#include <openssl/pem.h>

#include <stdexcept>
#include <string>

namespace accessl {
namespace openssl {

class crypto_error : public std::runtime_error {
public:
    crypto_error(const std::string& reason) :
        std::runtime_error(reason)
    {}
};

namespace locking {

    class lock;

    extern "C" {
        void static_lock(int mode, int n, const char *file, int line);
        unsigned long static_id();
        lock *dynamic_create(char *file, int line);
        void dynamic_lock(int mode, lock *l, const char *file, int line);
        void dynamic_destroy(lock *l, const char *file, int line);
    };

    void setup();
    void destroy();
};

class crypto_t {
public:
    crypto_t(bool setup_locking = false) throw ();
    ~crypto_t() throw ();

    ENGINE *engine_load(const char *name);
    void engine_setup(ENGINE *engine);
    void engine_ctrl(ENGINE *e, const char *name, const char *arg, int cmd_optional);

    static size_t MAX_ERROR_LEN;

    static std::string extract_errors();
    static RSA *rsa_private_key_from_pem(const std::string& filename);

private:
    bool setup_locking;
};

} // namespace openssl
} // namespace accessl

#endif // _CRYPTO_HPP_
