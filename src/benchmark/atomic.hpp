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

#ifndef _ATOMIC_HPP_
#define _ATOMIC_HPP_

namespace atomic {

class Int {
public:
    Int(int val = 0) :
        m_val(val)
    {}

    int add(int val)
    {
        return __sync_add_and_fetch(&m_val, val);
    }

    int inc()
    {
        return add(1);
    }

    int sub(int val)
    {
        return __sync_sub_and_fetch(&m_val, val);
    }

    int dec()
    {
        return sub(1);
    }

    int val()
    {
        return __sync_add_and_fetch(&m_val, 0);
    }

private:
    volatile int m_val;
};

};

#endif // _ATOMIC_HPP_
