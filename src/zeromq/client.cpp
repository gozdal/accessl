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
#include <pthread.h>

#include <iostream>

#include <boost/thread/thread.hpp>
#include <boost/program_options.hpp>

#include <common/zmq.hpp>

using namespace std;
using namespace boost;

namespace zeromq {
namespace client {

namespace po = boost::program_options;
namespace pt = boost::posix_time;

boost::thread_group client_threads;
int stop_clients;
int req_size;
int thread_count;

void client_thread (zmq::context_t *ctx)
{
    //  This client is a requester.
    zmq::socket_t s (*ctx, ZMQ_REQ);

    //  Connect to the server.
    s.connect ("ipc://queue");

    while (!stop_clients) {
        //  Send the request. No point in filling the content in as server
        //  is a dummy and won't use it anyway.
        zmq::message_t request (req_size);
        memset (request.data (), 0, request.size ());
        s.send (request);

        //  Get the reply. 
        zmq::message_t reply;
        s.recv (&reply);
    }
}

bool analyze_options(int argc, char *argv[])
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("size,s", po::value<int>(&req_size)->default_value(132), "request size in bytes")
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

void stop(int sig)
{
    ++stop_clients;;
}

} // namespace client
} // namespace zeromq

using namespace zeromq::client;

int main(int argc, char *argv[])
{
    try {
        if (analyze_options(argc, argv))
        {
            return 0;
        }

        // Wait for signal indicating time to shut down.
        signal(SIGINT, stop);
        signal(SIGQUIT, stop);
        signal(SIGTERM, stop);

        zmq::context_t ctx (thread_count);

        // Block all signals for background threads
        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        for (int i = 0; i < thread_count; i++) {
            client_threads.create_thread(boost::bind(client_thread, &ctx));
        }

        // Restore previous signals.
        pthread_sigmask(SIG_SETMASK, &old_mask, 0);

        while(!stop_clients)
            pause();

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
