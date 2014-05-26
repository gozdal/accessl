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
#include <glog/logging.h>

#include <iostream>

#include <boost/thread/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>

#include <common/zmq.hpp>

using namespace std;
using namespace boost;

namespace zeromq {
namespace server {

namespace po = boost::program_options;
namespace pt = boost::posix_time;

boost::thread_group worker_threads;
int thread_count, reqs_sec;
int port, resp_size;
int stop_workers;
string host;

void worker_thread (zmq::context_t *ctx)
{
    zmq::socket_t s (*ctx, ZMQ_REP);

    s.connect ("inproc://workers");

    pt::time_duration td = pt::microsec(1000000/reqs_sec);

    while (!stop_workers) {

        //  Get a request from the dispatcher.
        zmq::message_t request;
        s.recv (&request);

        //  Our server does no real processing. So let's sleep for a while
        //  to simulate actual processing.
        this_thread::sleep (td);

        //  Send the reply. No point in filling the data in as the client
        //  is a dummy and won't check it anyway.
        zmq::message_t reply (resp_size);
        memset (reply.data (), 0, reply.size ());
        s.send (reply);
    }
}

bool analyze_options(int argc, char *argv[])
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,?", "help message")
        ("host,h", po::value<string>(&host)->default_value("localhost"), "hostname or TCP address to connect to queue")
        ("port,p", po::value<int>(&port)->default_value(5555), "TCP port to connect to queue")
        ("reqs,r", po::value<int>(&reqs_sec)->default_value(1500), "how many reqs/s to simulate per thread")
        ("size,s", po::value<int>(&resp_size)->default_value(160), "response size in bytes")
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
    ++stop_workers;
}

} // namespace server
} // namespace zeromq

using namespace zeromq::server;

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

        //  Create an endpoint for worker threads to connect to.
        //  We are using XREQ socket so that processing of one request
        //  won't block other requests.
        zmq::socket_t workers (ctx, ZMQ_XREQ);
        workers.bind ("inproc://workers");

        //  Connect to queue
        //  We are usign XREP socket so that processing of one request
        //  won't block other requests.
        zmq::socket_t clients (ctx, ZMQ_XREP);
        string connect_addr = string("tcp://")+host+string(":")+boost::lexical_cast<string>(port);
        clients.connect (connect_addr.c_str());

        // Block all signals for background threads
        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        for (int i = 0; i < thread_count; i++) {
            worker_threads.create_thread(boost::bind(worker_thread, &ctx));
        }

        // Restore previous signals.
        pthread_sigmask(SIG_SETMASK, &old_mask, 0);

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
