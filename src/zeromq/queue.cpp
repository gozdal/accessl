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

#include <string.h>
#include <signal.h>
#include <glog/logging.h>

#include <iostream>

#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>

#include <common/zmq.hpp>

using namespace std;
using namespace boost;

namespace zeromq {
namespace queue {

namespace po = boost::program_options;

int thread_count;
int port;
string interface;

bool analyze_options(int argc, char *argv[])
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,?", "help message")
        ("interface,i", po::value<string>(&interface)->default_value("lo"), "interface or TCP address to listen for workers")
        ("port,p", po::value<int>(&port)->default_value(5555), "TCP port to listen on for workers")
        ("threads,t", po::value<int>(&thread_count)->default_value(4), "number of worker threads")
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

} // namespace queue
} // namespace zeromq

using namespace zeromq::queue;

int main(int argc, char *argv[])
{
    try {
        if (analyze_options(argc, argv))
        {
            return 0;
        }

        zmq::context_t ctx (thread_count);

        //  Create an endpoint for worker threads to connect to.
        //  We are using XREQ socket so that processing of one request
        //  won't block other requests.
        zmq::socket_t workers (ctx, ZMQ_XREQ);
        string bind_addr = string("tcp://")+interface+string(":")+boost::lexical_cast<string>(port);
        workers.bind (bind_addr.c_str());

        //  Create an endpoint for client applications to connect to.
        //  We are usign XREP socket so that processing of one request
        //  won't block other requests.
        zmq::socket_t clients (ctx, ZMQ_XREP);
        clients.bind ("ipc://queue");

        //  Use queue device as a dispatcher of messages from clients to worker
        //  threads.
        zmq::device (ZMQ_QUEUE, clients, workers);

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
