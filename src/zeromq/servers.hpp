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

#ifndef _SERVERS_HPP_
#define _SERVERS_HPP_

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <common/compiler.h>

#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <algorithm>

#include <boost/noncopyable.hpp>
#include <boost/random.hpp>
#include <boost/nondet_random.hpp>
#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/unordered_map.hpp>

#include "idgen.hpp"
#include "counted_tree.hpp"

namespace accessl {

using namespace std;

class server {
public:
    typedef int id_t;

private:
    in_addr addr_;
    int port_;
    id_t id_;

    int compare_addr(const server& other) const {
        return memcmp(&addr_, &other.addr_, sizeof(addr_));
    }

    int compare_port(const server& other) const {
        return get_port() - other.get_port();
    }

public:
    server()
    {
        memset(&addr_, 0, sizeof(addr_));
        port_ = 0;
        id_ = -1;
    }

    server(in_addr _addr, int _port, id_t _id) :
        addr_(_addr),
        port_(_port),
        id_(_id)
    { }

    server(const server& other) :
        addr_(other.addr_),
        port_(other.port_),
        id_(other.id_)
    { }

    virtual ~server()
    { }

    string as_string() const {
        stringstream out;
        out << inet_ntoa(addr_) << ":" << port_;
        return out.str();
    }

    operator string() const {
        return as_string();
    }

    id_t get_id() const {
        return id_;
    }

    in_addr get_addr() const {
        return addr_;
    }

    int get_port() const {
        return port_;
    }

    bool operator==(const server& other) const {
        return compare_addr(other) == 0 && compare_port(other) == 0;
    }

    bool operator<(const server& other) const {
        return compare_addr(other) < 0 ||
            (compare_addr(other) == 0 && compare_port(other) < 0);
    }

    bool operator<=(const server& other) const {
        return operator<(other) || operator==(other);
    }
};

class speed_estimator_t {
public:
    typedef boost::shared_ptr<speed_estimator_t> shptr;
    typedef boost::shared_ptr<const speed_estimator_t> cshptr;

private:
    int64_t srtt;
    int64_t mdev;
    int64_t mdev_max;
    int64_t rttvar;
    int64_t reqs_sec;
    int64_t rto;

public:
    speed_estimator_t() :
        srtt(0),
        mdev(0),
        mdev_max(0),
        rttvar(0),
        // 100k reqs/sec is a huge number wich will lead to selecting this server
        // after that we will update its response time
        reqs_sec(100000),
        rto((boost::posix_time::milliseconds(200)).total_microseconds())
    { }

    void update_rtt(int64_t last_rtt)
    {
        if (srtt == 0)
        {
            srtt = last_rtt;
            mdev = last_rtt/2;

            // (200ms in microseconds)/4

            // the reason to case to int64_t is that in gcc
            // long long int is not int64_t and std::max does not work
            // it works in LLVM though

            mdev_max = max(last_rtt/2, (int64_t)(200LL*1000LL/4LL));
            rttvar = mdev_max;
        }
        else
        {
            int64_t new_srtt = srtt + (last_rtt-srtt)/8;
            int64_t new_mdev = mdev;
            int64_t new_rttvar = rttvar;

            if (last_rtt < srtt-mdev)
                new_mdev = (31*mdev + abs(last_rtt-srtt)) / 32;
            else
                new_mdev = (3*mdev + abs(last_rtt-srtt)) / 4;
            if (new_mdev > mdev_max)
            {
                mdev_max = new_mdev;
                if (mdev_max > rttvar)
                    new_rttvar = mdev_max;
            }

            srtt = new_srtt;
            mdev = new_mdev;
            rttvar = new_rttvar;

            rto = srtt + 4*rttvar;
        }

        reqs_sec = 1000*1000 / srtt;
    }

    void update_timeout()
    {
        // if the server failed to respond we quite rapidly decrease our estimate of how many
        // requests per second it is capable of
        reqs_sec /= 4;
    }

    int64_t get_rto() const
    {
        return rto;
    }

    int64_t get_reqs_sec() const
    {
        return reqs_sec;
    }
};

class server_times {
private:
    typedef boost::unordered_map<server::id_t, speed_estimator_t::shptr> server_speed_container;
    server_speed_container speed;

    speed_estimator_t::shptr& server_find(server::id_t id)
    {
        server_speed_container::iterator i = speed.find(id);
        if (i != speed.end())
            return i->second;
        else
        {
            speed_estimator_t::shptr server_speed(new speed_estimator_t());
            pair<server_speed_container::iterator, bool> ret = speed.insert(server_speed_container::value_type(id, server_speed));
            return ret.first->second;
        }
    }

    speed_estimator_t::shptr& server_find(const server& w)
    {
        return server_find(w.get_id());
    }

public:
    server_times()
    { }

    void update_resp_time(const server& w, uint32_t microsecs)
    {
        server_find(w)->update_rtt(microsecs);
    }

    void update_resp_time(server::id_t server_id, uint32_t microsecs)
    {
        server_find(server_id)->update_rtt(microsecs);
    }

    void update_resp_timeout(server::id_t server_id)
    {
        server_find(server_id)->update_timeout();
    }

    uint32_t req_timeout(const server& w)
    {
        speed_estimator_t::cshptr server_speed = server_find(w);
        return server_speed->get_rto();
    }

    uint32_t reqs_sec(const server& w)
    {
        speed_estimator_t::cshptr server_speed = server_find(w);
        return server_speed->get_reqs_sec();
    }

};

class servers_chooser {
private:
    typedef boost::unordered_map<server::id_t, counted_tree<server>::const_iterator> server_tree_iter_map;

    counted_tree<server> servers_;
    server_tree_iter_map servers_map_;
    server_times server_times_;
    boost::mt19937 rng_;

    void update_server(const server& s, uint32_t new_reqs_sec)
    {
        server_tree_iter_map::const_iterator it = servers_map_.find(s.get_id());
        if (it != servers_map_.end())
        {
            servers_.change_count(it->second, new_reqs_sec);
        }
    }

    void update_servers_map()
    {
        for (counted_tree<server>::const_iterator it = servers_.begin(); it != servers_.end(); it++)
            servers_map_[it->get_id()] = it;
    }

public:
    typedef boost::optional<server> optional_server;

    servers_chooser()
    {
        boost::random_device dev;
        rng_.seed(dev());
    }

    void push_back(const server& s, uint32_t reqs_sec)
    {
        servers_.push_back(s, reqs_sec);
        update_servers_map();
    }

    optional_server choose()
    {
        size_t reqs_total = servers_.total_count();

        if (unlikely(reqs_total == 0))
            return optional_server();

        boost::uniform_int<uint32_t> dist(0, reqs_total-1);
        boost::variate_generator<boost::mt19937&, boost::uniform_int<uint32_t> > gen(rng_, dist);

        uint32_t req_random = gen();

        DLOG(INFO) << "server_choose: reqs_total " << reqs_total << " random " << req_random;

        return optional_server(*(servers_.find_by_count(req_random)));
    }

    void report_time(const server& s, boost::posix_time::time_duration time)
    {
        server_times_.update_resp_time(s.get_id(), time.total_microseconds());
        uint32_t new_reqs_sec = server_times_.reqs_sec(s);

        update_server(s, new_reqs_sec);
    }

    void report_timeout(const server& s)
    {
        server_times_.update_resp_timeout(s.get_id());
        uint32_t new_reqs_sec = server_times_.reqs_sec(s);

        update_server(s, new_reqs_sec);
    }

    boost::posix_time::time_duration get_timeout(const server& s)
    {
        return boost::posix_time::microseconds(server_times_.req_timeout(s));
    }
};

};

#endif // _SERVERS_HPP_
