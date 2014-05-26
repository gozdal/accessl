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

#ifndef _ENGINE_HPP_
#define _ENGINE_HPP_

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#include <string>
#include <vector>

#include <boost/tokenizer.hpp>
#include <boost/optional.hpp>
#include <boost/bind.hpp>

#include <common/zmq.hpp>
#include <common/compiler.h>

// TODO
// we should get rid of logging here
#include <glog/logging.h>

#include <accessl-common/accessl_key.h>
#include <accessl-common/cmd.h>

#include "servers.hpp"

namespace accessl {

using namespace std;
using namespace boost;

class engine {
private:
    zmq::context_t zmq_ctx;

    int sock;

    servers_chooser chooser_;
    id_generator<id_t> generator_;

    posix_time::ptime req_time;

    vector<string> get_initial_servers(const string & socket)
    {
        zmq::socket_t zmq_sock(zmq_ctx, ZMQ_REQ);
        zmq_sock.connect(socket.c_str());
        string getmsg("GET");

        zmq::message_t req(getmsg.size());
        memcpy(req.data(), getmsg.data(), getmsg.size());
        if (!zmq_sock.send(req))
            throw runtime_error(string("zmq::socket_t.send: ") + strerror(errno));

        zmq::message_t resp;
        if (!zmq_sock.recv(&resp))
            throw runtime_error(string("zmq::socket_t.recv: ") + strerror(errno));

        string respstr(reinterpret_cast<const char *>(resp.data()), resp.size());
        typedef tokenizer<char_separator<char> > tok_t;
        char_separator<char> sep(",");
        tok_t tok(respstr, sep);

        vector<string> ret;

        for(tok_t::iterator i = tok.begin(); i != tok.end(); ++i){
            ret.push_back(*i);
        }

        return ret;
    }

    void setup_servers(vector<string> server_addrs)
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
        std::copy(server_addrs.begin(), server_addrs.end(), ostream_iterator<string>(DLOG(INFO), ","));
#endif

        for (i = server_addrs.begin(); i != server_addrs.end(); i++)
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
            // 1000 should be good enough as a ballpark for start - it will be updated after first request
            chooser_.push_back(server(addr_in->sin_addr, ntohs(addr_in->sin_port), generator_()), 1000);

            freeaddrinfo(result);
        }
    }

    bool create_socket() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);

        return (sock != -1);
    }

    void create_socket_throw() {
        if (!create_socket())
            throw runtime_error(string("could not create UDP socket: ") + strerror(errno));
    }

public:
    engine(const string & _socket) :
        zmq_ctx(1),
        generator_()
    {
        create_socket_throw();

        vector<string> server_addrs = get_initial_servers(_socket);

        setup_servers(server_addrs);
    }

    virtual ~engine()
    {
        close(sock);
    }

    int rsa_op(accessl_key *key, int op, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
    {
        size_t req_len = 2*sizeof(uint32_t) + sizeof(cmd_op) + sizeof(cmd_op_rsa) + flen;
        unsigned char req[req_len];
        cmd *c = reinterpret_cast<cmd *>(req);
        cmd_op *cop = reinterpret_cast<cmd_op *>(&c->op);
        cmd_op_rsa *rsa_op = reinterpret_cast<cmd_op_rsa *>(&cop->data);

        c->tag = 0;
        c->cmd = htonl(CMD_OP);

        memcpy(cop->key_fingerprint, key->fingerprint, KEY_FINGERPRINT_SIZE);
        cop->op = htonl(op);
        cop->len = htonl(sizeof(cmd_op_rsa) + flen);

        rsa_op->len = htonl(flen);
        rsa_op->pad = htonl(padding);
        memcpy(rsa_op->data, from, flen);

        try {
            do {
                optional<server> os = chooser_.choose();

                if (!os)
                {
                    LOG(WARNING) << "no servers available";
                    return -1;
                }
                server s = os.get();

                posix_time::time_duration timeout = chooser_.get_timeout(s);

                struct sockaddr_in addr;

                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(s.get_port());
                addr.sin_addr = s.get_addr();

                req_time = posix_time::microsec_clock::local_time();

                size_t sent = sendto(sock, req, req_len, 0, (const sockaddr *)&addr, sizeof(addr));

                /*
                 * After each failed server/request we recreate local socket.
                 * Thus if any response returns, it returns to the old socket and is silently 
                 * discarded by the kernel.
                 */

                if (sent != req_len)
                {
                    LOG(WARNING) << "could not send request to " << inet_ntoa(addr.sin_addr) << ":" << s.get_port();
                    create_socket_throw();
                    continue;
                }

                struct pollfd fds;

                fds.fd = sock;
                fds.events = POLLIN | POLLERR;

                long poll_timeout = timeout.total_milliseconds();;

                do {
                    DLOG(INFO) << "waiting for server " <<
                        inet_ntoa(s.get_addr()) << ":" << s.get_port() <<
                        ", timeout " << poll_timeout << "ms";

                    // TODO
                    // record time and retry with decreased timeout if the do {} while loop is continued
                    int ret = poll(&fds, 1, poll_timeout);

                    if (likely(ret == 1)) {
                        if (unlikely(fds.revents & POLLERR)) {
                            // unfortunately there is no errno available here - we only get POLLERR flag and no details
                            LOG(WARNING) << "server " << inet_ntoa(s.get_addr()) << ":" << s.get_port() << " error";
                            create_socket_throw();
                            break;
                        }

                        struct sockaddr_in src_addr;
                        socklen_t src_addrlen = sizeof(src_addr);

                        ssize_t ret = recvfrom(sock, to, tlen, 0, (struct sockaddr *)&src_addr, &src_addrlen);

                        in_addr serv_addr_in = s.get_addr();

                        if (unlikely(ntohs(src_addr.sin_port) != s.get_port() ||
                                src_addr.sin_addr.s_addr != serv_addr_in.s_addr))
                        {
                            LOG(WARNING) << "received packet from strange source " <<
                                inet_ntoa(src_addr.sin_addr) << ":" << ntohs(src_addr.sin_port) <<
                                ", expected " <<
                                inet_ntoa(serv_addr_in) << ":" << s.get_port() << endl;
                            create_socket_throw();
                            continue;
                        }

                        if (likely(ret > 0)) {
                            posix_time::time_duration elapsed = posix_time::microsec_clock::local_time() - req_time;
                            DLOG(INFO) << "elapsed " << elapsed;
                            chooser_.report_time(s, elapsed);
                            return ret;
                        }

                        PLOG(WARNING) << "server " << inet_ntoa(s.get_addr()) << ":" << s.get_port() << " error";
                        chooser_.report_timeout(s);
                        create_socket_throw();
                        break;

                    } else if (ret == 0) {
                        LOG(WARNING) << "server " << inet_ntoa(s.get_addr()) << ":" << s.get_port() << " timeout";
                        chooser_.report_timeout(s);
                        create_socket_throw();
                        break;
                    } else { // ret < 0
                        if (errno == EINTR) {
                            DLOG(INFO) << "poll was interrupted by signal, restarting";
                            continue;
                        }
                        PLOG(WARNING) << "server " << inet_ntoa(s.get_addr()) << ":" << s.get_port() << " poll error";
                        create_socket_throw();
                        break;
                    }
                } while (1);

            } while (1);
        } catch (std::exception& e) {
            LOG(ERROR) << e.what();
            return -1;
        }
    }
};

};

#endif // _ENGINE_HPP_
