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
#include <glog/logging.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include <common/zmq.hpp>

#include "servers.hpp"

using namespace std;
using namespace boost;

namespace accessl {
namespace accessld {

namespace po = boost::program_options;

struct config_t {
    string socket;
    vector<string> workers;
    string worker_file;
};

bool analyze_options(int argc, char *argv[], config_t & config)
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,?", "help message")
        ("socket,s", po::value< string >(&config.socket)->default_value("ipc:///tmp/accessld.0mq"), "communication socket")
        ("worker,w", po::value< vector<string> >(&config.workers), "list of workers (host:port)")
        ("worker-file,f", po::value< string >(&config.worker_file), "list of workers read from file")
        ;

    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(desc).run(), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return true;
    }

    if (vm.count("worker-file")) {
        // Load the file and tokenize it
        ifstream ifs(vm["worker-file"].as<string>().c_str());
        if (!ifs) {
            cerr << "Could not open file with worker list\n";
            return false;
        }
        // Read the whole file into a string
        stringstream ss;
        ss << ifs.rdbuf();
        // Split the file content
        char_separator<char> sep(" \n\r,");
        string sstr = ss.str();
        tokenizer<char_separator<char> > tok(sstr, sep);
        copy(tok.begin(), tok.end(), back_inserter(config.workers));
    }

    return false;
}

void setup_servers(config_t & config, vector<server> & s, id_generator<id_t> & gen)
{
    vector<string>::iterator i;
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

#ifndef NDEBUG
    DLOG(INFO) << "setup_servers: ";
    std::copy(config.workers.begin(), config.workers.end(), std::ostream_iterator<string>(DLOG(INFO), ","));
#endif

    for (i = config.workers.begin(); i != config.workers.end(); i++)
    {
        DLOG(INFO) << "setup_server: " << *i;

        string::size_type colon = i->find(':');
        if (colon == string::npos)
        {
            LOG(WARNING) << "worker " << *i << " skipped - not in fomat host:port";
            continue;
        }

        string host(*i, 0, colon), port(*i, colon+1);

        int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
        if (ret != 0) {
            LOG(WARNING) << "could not resolve " << *i << ": " << gai_strerror(ret);
            continue;
        }

        struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;
        DLOG(INFO) << "setup_server: resolved " << *i << " to " << inet_ntoa(addr_in->sin_addr) << ":" << ntohs(addr_in->sin_port);

        s.push_back(server(addr_in->sin_addr, ntohs(addr_in->sin_port), gen()));
    }
}

void run_server(config_t & config)
{
    vector<server> live;
    id_generator<id_t> id_generator;

    setup_servers(config, live, id_generator);

    zmq::context_t ctx(1);

    zmq::socket_t s(ctx, ZMQ_REP);
    s.bind(config.socket.c_str());

    while(1) {
        zmq::message_t request;
        s.recv(&request);

        string reqstr(static_cast<const char *>(request.data()), request.size());

        DLOG(INFO) << "request: " << reqstr;

        if (reqstr == "GET") {
            stringstream allstream;

            for (vector<server>::const_iterator iter = live.begin(); iter != live.end(); iter++)
                allstream << iter->as_string() << ",";

            string all = allstream.str();

            DLOG(INFO) << "reply: " << all;

            zmq::message_t resp(all.size());
            memcpy(resp.data(), all.data(), all.size());
            s.send(resp);
        } else {
            LOG(ERROR) << "Unknown message " << reqstr;
        }
    }
}

} // namespace accessld
} // namespace accessl

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

        run_server(config);

        return 0;
    } catch (po::error& e) {
        LOG(ERROR) << "Invalid option: " << e.what();
        return 1;
    } catch (std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 2;
    }

    return 0;
}
