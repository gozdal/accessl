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

#ifndef _KEYS_HPP_
#define _KEYS_HPP_

#include <string.h>

#include <exception>
#include <algorithm>

#include <boost/unordered_map.hpp>

#include <accessl-common/cmd.h>

namespace accessl {

class fingerprint {
public:
    fingerprint(const unsigned char *f)
    {
        memcpy(fingerprint_, f, KEY_FINGERPRINT_SIZE);
    }

    fingerprint(const fingerprint& o)
    {
        memcpy(fingerprint_, o.fingerprint_, KEY_FINGERPRINT_SIZE);
    }

    bool operator==(const fingerprint& other) const {
        return (memcmp(fingerprint_, other.fingerprint_, KEY_FINGERPRINT_SIZE) == 0);
    }

private:
    union {
        unsigned char fingerprint_[KEY_FINGERPRINT_SIZE];
        size_t hash_;
    };

    friend class fingerprint_hash;
};

class fingerprint_hash {
public:
    size_t operator()(const fingerprint& f) const 
    {
        return f.hash_;
    }
};

class key {
public:
    key() :
        len_(0),
        data_(NULL)
    { }

    key(const unsigned char *data, size_t len, void *priv) :
        len_(len),
        data_(new unsigned char[len_]),
        priv_(priv)
    {
        memcpy(data_, data, len);
    }

    key(const key& o) :
        len_(o.len_),
        data_(new unsigned char[len_]),
        priv_(o.priv_)
    {
        memcpy(data_, o.data_, o.len_);
    }

    ~key()
    {
        delete [] data_;
    }

    key& operator=(key& o)
    {
        key tmp(o);
        std::swap(data_, tmp.data_);
        std::swap(len_, tmp.len_);
        std::swap(priv_, tmp.priv_);

        return *this;
    }

    unsigned char *get_data() const {
        return data_;
    }

    size_t get_len() const {
        return len_;
    }

    void set_priv(void *priv)
    {
        priv_ = priv;
    }

    void *get_priv() const {
        return priv_;
    }

private:
    size_t len_;
    unsigned char *data_;
    void *priv_;
};

class keys {
private:
    typedef boost::unordered_map<fingerprint, key, fingerprint_hash> map_t;
    map_t map;

public:
    class not_found: public std::exception
    {
        virtual const char* what() const throw()
        {
            return "key not found";
        }
    };

    key& find(const unsigned char *fingerprint)
    {
        map_t::iterator i = map.find(fingerprint);
        if (i != map.end())
            return i->second;
        else
            throw not_found();
    }

    void add(const unsigned char *fingerprint, const unsigned char *data, size_t len, void *priv)
    {
        map.insert(std::make_pair(fingerprint, key(data, len, priv)));
    }
};

};

#endif // _KEYS_HPP_
