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

#ifndef _OP_HPP_
#define _OP_HPP_

#include <string.h>

#include <arpa/inet.h>

#include <accessl-common/cmd.h>

#include <boost/scoped_array.hpp>
#include <boost/noncopyable.hpp>

namespace accessl {

using namespace boost;

const int OP_MAX_BUF = 1500;

class req : public noncopyable {
private:
    unsigned char key_fingerprint_[KEY_FINGERPRINT_SIZE];
    uint32_t op_;
    uint32_t padding_;
    uint32_t data_len_;
    const unsigned char *data_;

    uint32_t buf_len_;
    scoped_array<unsigned char> buf_;

    size_t count_buf_len() const {
        return
            sizeof(cmd_op) +
            sizeof(cmd_op_rsa) +
            data_len_;
    }

    void serialize()
    {
        unsigned char *ptr = buf_.get();
        int *intptr;

        intptr = reinterpret_cast<int *>(ptr);
        *intptr = htonl(op_);
        ptr += sizeof(op_);

        memcpy(ptr, key_fingerprint_, KEY_FINGERPRINT_SIZE);
        ptr += KEY_FINGERPRINT_SIZE;

        intptr = reinterpret_cast<int *>(ptr);
        *intptr = htonl(sizeof(cmd_op_rsa) + data_len_);
        ptr += sizeof(uint32_t);

        intptr = reinterpret_cast<int *>(ptr);
        *intptr = htonl(data_len_);
        ptr += sizeof(data_len_);

        intptr = reinterpret_cast<int *>(ptr);
        *intptr = htonl(padding_);
        ptr += sizeof(padding_);

        memcpy(ptr, data_, data_len_);

        data_ = ptr;
    }

    void deserialize()
    {
        unsigned char *ptr = buf_.get();
        int *intptr;

        intptr = reinterpret_cast<int *>(ptr);
        op_ = ntohl(*intptr);
        ptr += sizeof(op_);

        memcpy(key_fingerprint_, ptr, KEY_FINGERPRINT_SIZE);
        ptr += KEY_FINGERPRINT_SIZE;

        // ignore len of cmd_op_rsa as it is known from the next field
        ptr += sizeof(uint32_t);

        intptr = reinterpret_cast<int *>(ptr);
        data_len_ = ntohl(*intptr);
        ptr += sizeof(data_len_);

        intptr = reinterpret_cast<int *>(ptr);
        padding_ = ntohl(*intptr);
        ptr += sizeof(padding_);

        data_ = reinterpret_cast<unsigned char *>(ptr);
    }

public:
    req(const unsigned char *fingerprint, int op, uint32_t data_len, const unsigned char *data, int padding) :
        op_(op),
        padding_(padding),
        data_len_(data_len),
        data_(data),
        buf_len_(count_buf_len()),
        buf_(new unsigned char[buf_len_])
    {
        memcpy(key_fingerprint_, fingerprint, KEY_FINGERPRINT_SIZE);
        serialize();
    }

    req(const unsigned char *buf, size_t len) :
        buf_len_(len),
        buf_(new unsigned char[buf_len_])
    {
        memcpy(buf_.get(), buf, len);
        deserialize();
    }

    req(const char *buf, size_t len) :
        buf_len_(len),
        buf_(new unsigned char[buf_len_])
    {
        memcpy(buf_.get(), buf, len);
        deserialize();
    }

    size_t get_buf_len() const {
        return buf_len_;
    }

    const unsigned char *get_buf() const {
        return buf_.get();
    }

    const unsigned char *get_fingerprint() const {
        return key_fingerprint_;
    }

    int get_op() const {
        return op_;
    }

    int get_padding() const {
        return padding_;
    }

    size_t get_data_len() const {
        return data_len_;
    }

    const unsigned char *get_data() const {
        return data_;
    }
};

class resp : public boost::noncopyable {
private:
    unsigned char *data_;
    size_t len_;

public:
    resp(const unsigned char *data, size_t len) :
        len_(len)
    {
        data_ = new unsigned char[len];
        memcpy(data_, data, len);
    }

    ~resp()
    {
        delete data_;
    }

    unsigned char *get_data() const {
        return data_;
    }

    size_t get_len() const {
        return len_;
    }
};

};

#endif // _OP_HPP_
