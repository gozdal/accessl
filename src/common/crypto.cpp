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

#include <vector>
#include <string>
#include <sstream>

#include <glog/logging.h>

#include <common/compiler.h>

#include <boost/thread.hpp>

#include "crypto.hpp"

using namespace std;

namespace accessl {
namespace openssl {
namespace locking {

class lock {
public:
    lock(const char *file = "static", int line = -1) :
        m_file_create(file),
        m_line_create(line),
        m_file_lock(NULL),
        m_line_lock(-1)
    {
    }

    lock(const lock& other)
    {
        // dummy, just not to copy m_mutex
        if (&other == this)
            return;
        rewrite(other);
    }

    ~lock()
    {
    }

    lock& operator= (const lock& other)
    {
        // dummy, just not to copy m_mutex
        if (&other == this)
            return *this;
        rewrite(other);
        return *this;
    }

    void do_lock(const char *file, int line)
    {
        m_file_lock = file;
        m_line_lock = line;
        m_mutex.lock();
    }

    void unlock()
    {
        m_file_lock = NULL;
        m_line_lock = -1;
        m_mutex.unlock();
    }
private:
    void rewrite(const lock& other)
    {
        m_file_create = other.m_file_create;
        m_line_create = other.m_line_create;
        m_file_lock = other.m_file_lock;
        m_line_lock = other.m_line_lock;
    }

private:
    boost::mutex m_mutex;
    const char *m_file_create;
    int m_line_create;
    const char *m_file_lock;
    int m_line_lock;
};

vector<lock> locks;

extern "C" {

    void static_lock(int mode, int n, const char *file, int line)
    {
        VLOG(2) << "static_lock(" << mode << "," << n << "," << file << ":" << line << ")";

        if (mode & CRYPTO_LOCK)
            locks[n].do_lock(file, line);
        else
            locks[n].unlock();
    }

    unsigned long static_id()
    {
        // FIXME - should be portable to Win32 also
        return (unsigned long)pthread_self();
    }

    lock *dynamic_create(char *file, int line)
    {
        return new lock(file, line);
    }

    void dynamic_lock(int mode, lock *l, const char *file, int line)
    {
        VLOG(2) << "dynamic_lock(" << mode << "," << file << ":" << line << ")";

        if (mode & CRYPTO_LOCK)
            l->do_lock(file, line);
        else
            l->unlock();
    }

    void dynamic_destroy(lock *l, const char *file UNUSED, int line UNUSED)
    {
        delete l;
    }
};

void setup()
{
    locks.resize(CRYPTO_num_locks());

    CRYPTO_set_locking_callback(&static_lock);
    CRYPTO_set_id_callback(&static_id);

    CRYPTO_set_dynlock_create_callback(reinterpret_cast<struct CRYPTO_dynlock_value *(*)(const char *file, int line)>(&dynamic_create));
    CRYPTO_set_dynlock_lock_callback(reinterpret_cast<void (*)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)>(&dynamic_lock));
    CRYPTO_set_dynlock_destroy_callback(reinterpret_cast<void (*)(struct CRYPTO_dynlock_value *l, const char *file, int line)>(&dynamic_destroy));
}

void destroy()
{
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
}

} // namespace locking

size_t crypto_t::MAX_ERROR_LEN = 120;

crypto_t::crypto_t(bool setup_locking) throw ()
{
    this->setup_locking = setup_locking;

    ERR_load_crypto_strings();
    ENGINE_load_builtin_engines();
    // FIXME - Linux only
    RAND_load_file("/dev/urandom", 1024);

    if (setup_locking)
        locking::setup();
}

crypto_t::~crypto_t() throw ()
{
    if (setup_locking)
        locking::destroy();

    ENGINE_cleanup();
    ERR_free_strings();
    EVP_cleanup();
}

ENGINE *crypto_t::engine_load(const char *name)
{
    // TODO: don't know if it's of any use
    if(strcmp(name, "auto") == 0)
    {
        ENGINE_register_all_complete();
        return NULL;
    }

    ENGINE *ret = ENGINE_by_id(name);
    if (ret == NULL)
    {
        ret = ENGINE_by_id("dynamic");
        if (ret)
        {
            if (!ENGINE_ctrl_cmd_string(ret, "SO_PATH", name, 0) ||
                    !ENGINE_ctrl_cmd_string(ret, "LOAD", NULL, 0))
            {
                ENGINE_free(ret);
                ret = NULL;
            }
        }
    }
    if (ret == NULL)
    {
        stringstream what;

        what << "Invalid engine '" << name << "'" << endl;
        what << extract_errors();
        throw crypto_error(what.str());
    }
    return ret;
}

void crypto_t::engine_setup(ENGINE *engine)
{
    if (engine)
    {
        if (!ENGINE_init(engine) || !ENGINE_set_default(engine, ENGINE_METHOD_ALL))
        {
            stringstream what;

            what << "Couldn't use engine " << engine << endl;
            what << extract_errors();
            ENGINE_free(engine);
            throw crypto_error(what.str());
        }

        /* Free our "structural" reference. */
        ENGINE_free(engine);
    }
}

void crypto_t::engine_ctrl(ENGINE *e, const char *name, const char *arg, int cmd_optional)
{
    if (!ENGINE_ctrl_cmd_string(e, name, arg, cmd_optional))
    {
        stringstream what;

        what << "Ctrl command " << name << " " << arg << " failed" << endl;
        what << extract_errors();
        ENGINE_free(e);
        throw crypto_error(what.str());
    }
}

string crypto_t::extract_errors()
{
    BIO *mem = BIO_new(BIO_s_mem());
    char *data;

    if (!mem)
        return "";
    (void)BIO_set_close(mem, BIO_CLOSE);
    ERR_print_errors(mem);
    BIO_get_mem_data(mem, &data);

    string ret;
    if (data)
        ret = data;

    BIO_free(mem);
    return ret;
}

RSA *crypto_t::rsa_private_key_from_pem(const std::string& filename)
{
    RSA *rsa = NULL;
    FILE *fp = fopen(filename.c_str(), "rb");
    if (!fp)
        throw crypto_error("could not open " + filename + ": " + strerror(errno));
    rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        stringstream what;

        what << "could not load key from " << filename << endl;
        what << extract_errors();
        throw crypto_error(what.str());
    }

    return rsa;
}

} // namespace openssl
} // namespace accessl
