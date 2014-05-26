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

#include <glog/logging.h>

#include <iostream>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <boost/random.hpp>

#include "servers.hpp"

using namespace std;
using namespace accessl;

namespace po = boost::program_options;
namespace pt = boost::posix_time;

struct config_t {
    uint64_t loops;
    int servers;
};

void benchmark_chooser(const config_t& config)
{
    int sum = 0;

    servers_chooser chooser;

    for (int i = 0; i < config.servers; i++) {
        in_addr addr;
        addr.s_addr = INADDR_ANY;
        server s(addr, i, i);
        chooser.push_back(s, 1000);
    }

    for (uint64_t i = 0; i < config.loops; i++) {
        boost::optional<server> os = chooser.choose();
        if (os)
            sum += os->get_port();
    }
    cout << sum << endl;
}

bool analyze_options(int argc, char *argv[], config_t & config)
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("loops,l", po::value< uint64_t >(&config.loops)->default_value(1000000), "number of loops of benchmark")
        ("servers,s", po::value< int >(&config.servers)->default_value(100), "number of servers")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return true;
    }

    return false;
}

void show_results(const config_t& config, const pt::ptime& start_time, const pt::ptime& stop_time) {
    pt::time_duration total_time = stop_time - start_time;

    long total_microsecs = total_time.total_microseconds();

    uint64_t loops_per_sec = config.loops * 1000000 / total_microsecs;

    cout << "Loops per sec: " << loops_per_sec << endl;
}

int main(int argc, char *argv[])
{
    config_t config;

    google::InitGoogleLogging(argv[0]);

    if (analyze_options(argc, argv, config))
        return 0;

    pt::ptime start_time = pt::microsec_clock::local_time();
    benchmark_chooser(config);
    pt::ptime stop_time = pt::microsec_clock::local_time();

    show_results(config, start_time, stop_time);
}
