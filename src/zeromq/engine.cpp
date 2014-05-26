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

#include <iostream>

#include <boost/program_options.hpp>

#include <glog/logging.h>

#include "engine.hpp"
#include "servers.hpp"

using namespace std;
using namespace boost;

namespace accessl {
namespace accessld {

namespace po = boost::program_options;

struct config_t {
    string socket;
};

bool analyze_options(int argc, char *argv[], config_t & config)
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("socket,s", po::value< string >(&config.socket)->default_value("ipc:///tmp/accessld.0mq"), "communication socket")
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

} // namespace accessld
} // namespace accessl

using namespace accessl;
using namespace accessl::accessld;

int main(int argc, char *argv[])
{
    google::InitGoogleLogging(argv[0]);

    config_t config;

    try {
        if (analyze_options(argc, argv, config))
        {
            return 0;
        }

        engine e(config.socket);

        while (1)
        {
            e.rsa_op(NULL, 1, 10, NULL, 10, NULL, 10);
        }

        return 0;
    } catch (po::error& e) {
        cerr << "Invalid option: " << e.what();
        return 1;
    } catch (std::exception& e) {
        cerr << "Error: " << e.what();
        return 2;
    }

    return 0;
}
