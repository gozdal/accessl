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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/bn.h>

#include <iostream>
#include <exception>
#include <vector>

#include <boost/program_options.hpp>

#include <glog/logging.h>

#include <common/compiler.h>

#include <accessl-common/testrsa.h>
#include <accessl-common/cmd.h>

#include <accel/accel.h>

#include <common/crypto.hpp>

#include "keys.hpp"

using namespace std;
using namespace boost;

namespace accessl {
namespace worker {

keys worker_keys;

namespace po = program_options;

class key_loading_error : public runtime_error {
public:
    key_loading_error(const string& what) :
        runtime_error(what)
    {}
};

struct config_t {
    string host;
    int port;
    int count;
    vector<string> keys;
};

bool analyze_options(int argc, char *argv[], config_t & config)
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("host,o", po::value< string >(&config.host)->default_value("0.0.0.0"), "host address to bind to")
        ("port,p", po::value< int >(&config.port)->default_value(10000), "UDP port to bind to")
        ("key,k", po::value< vector<string> >(&config.keys), "key to load (may be specified more than once)")
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

static void serialize_bn(const BIGNUM *bn, unsigned char **ptr)
{
    unsigned int *len = (unsigned int *)*ptr;
    *len = htonl(BN_num_bytes(bn));
    *ptr += sizeof(unsigned int);
    BN_bn2bin(bn, *ptr);
    *ptr += BN_num_bytes(bn);
}


void convert_rsa_key(const RSA *rsa)
{
    MD5_CTX md5_ctx;
    int n_len = BN_num_bytes(rsa->n);
    int e_len = BN_num_bytes(rsa->e);
    unsigned char n_bin[n_len];
    unsigned char e_bin[e_len];

    size_t key_len;
    unsigned char f[KEY_FINGERPRINT_SIZE];

    key ret;

    memset(n_bin, 0, n_len); BN_bn2bin(rsa->n, n_bin);
    memset(e_bin, 0, e_len); BN_bn2bin(rsa->e, e_bin);

    if (!MD5_Init(&md5_ctx) ||
        !MD5_Update(&md5_ctx, n_bin, n_len) ||
        !MD5_Update(&md5_ctx, e_bin, e_len) ||
        !MD5_Final(f, &md5_ctx))
    {
        throw accessl::openssl::crypto_error("MD5 failure");
    }

    key_len =
        BN_num_bytes(rsa->n) +
        BN_num_bytes(rsa->e) +
        2 * sizeof(unsigned int);

    if(!rsa->p || !rsa->q || !rsa->d || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp)
    {
        throw accessl::openssl::crypto_error("Need public and private key, only public given");
    } else {
        key_len +=
            BN_num_bytes(rsa->p) +
            BN_num_bytes(rsa->q) +
            BN_num_bytes(rsa->d) +
            BN_num_bytes(rsa->dmp1) +
            BN_num_bytes(rsa->dmq1) +
            BN_num_bytes(rsa->iqmp) +
            6 * sizeof(unsigned int);
    }

    unsigned char data[key_len];

    unsigned char *ptr = data;
    serialize_bn(rsa->n, &ptr);
    serialize_bn(rsa->e, &ptr);
    serialize_bn(rsa->d, &ptr);
    serialize_bn(rsa->p, &ptr);
    serialize_bn(rsa->q, &ptr);
    serialize_bn(rsa->dmp1, &ptr);
    serialize_bn(rsa->dmq1, &ptr);
    serialize_bn(rsa->iqmp, &ptr);

    void *priv = accel_add_key(CMD_KEY_RSA, key_len, data);

    worker_keys.add(f, data, key_len, priv);
}

string get_openssl_error(const string& msg)
{
    stringstream sstr;

    sstr << msg << endl;
    sstr << accessl::openssl::crypto_t::extract_errors();
    return sstr.str();
}

void setup_default_keys()
{
    unsigned char *rsa_data[] = {test512,test1024,test2048,test4096};
    const int rsa_count = sizeof(rsa_data) / sizeof(rsa_data[0]);
    RSA *rsa_key[rsa_count];
    int rsa_data_length[rsa_count]= {
        sizeof(test512),sizeof(test1024),
        sizeof(test2048),sizeof(test4096)
    };

    memset(rsa_key, 0, sizeof(rsa_key));

    for (int i = 0; i < rsa_count; i++)
        rsa_key[i] = NULL;

    for (int i = 0; i < rsa_count; i++)
    {
        const unsigned char *p;

        p = rsa_data[i];
        rsa_key[i] = d2i_RSAPrivateKey(NULL, &p, rsa_data_length[i]);
        if (rsa_key[i] == NULL)
            throw key_loading_error(get_openssl_error("Internal error loading RSA keys"));

        convert_rsa_key(rsa_key[i]);
    }

}

void load_key(const string& filename)
{
    RSA *rsa = accessl::openssl::crypto_t::rsa_private_key_from_pem(filename);
    convert_rsa_key(rsa);
}

void load_keys(const vector<string>& filenames)
{
    for (vector<string>::const_iterator it = filenames.begin(); it != filenames.end(); it++)
        load_key(*it);
} 

int process_req(const unsigned char *req, unsigned char *resp)
{
    try {
        const cmd *c = reinterpret_cast<const cmd *>(req);
        if (ntohl(c->cmd) != CMD_OP)
            return -1;

        int opcode = ntohl(c->op.op);
        int cmd_len = ntohl(c->op.len);

        key& k = worker_keys.find(c->op.key_fingerprint);

        DLOG(INFO) << "req " << opcode << " for buf of " << cmd_len << " bytes";

        return accel_perform(k.get_priv(), opcode, cmd_len, c->op.data, resp);
    } catch (keys::not_found& e) {
        LOG(ERROR) << "key not found";
        return -1;
    }
}

int processor(int port)
{
    DLOG(INFO) << "processor starting at port " << port;

    struct sockaddr_in sin;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1)
    {
        LOG(ERROR) << "processor could not create UDP socket: " << strerror(errno);
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        LOG(ERROR) << "processor could not bind to UDP port " << port << ": " << strerror(errno);
        close(s);
        return 1;
    }

    while(1)
    {
        unsigned char req[CMD_MAX_LEN], resp[CMD_MAX_LEN];
        struct sockaddr_in src;
        socklen_t addrlen = sizeof(src);
        ssize_t ret = recvfrom(s, req, sizeof(req), 0, (struct sockaddr *)&src, &addrlen);

        if (unlikely(ret == -1))
        {
            LOG(ERROR) << "processor got error on recvfrom: " << strerror(errno);
            break;
        }

        DLOG(INFO) << "got packet from " << inet_ntoa(src.sin_addr) << ":" << ntohs(src.sin_port);

        int resp_len = process_req(req, resp);
        if (resp_len < 0)
            continue;

        addrlen = sizeof(src);

        DLOG(INFO) << "returning " << resp_len << " bytes";

        ret = sendto(s, resp, resp_len, 0, (const sockaddr *)&src, addrlen);

        if (unlikely(ret == -1))
        {
            LOG(ERROR) << "processor got error on sendto: " << strerror(errno);
            break;
        }
    }

    close(s);

    return 0;
}

} // namespace worker
} // namespace accessl

using namespace accessl;
using namespace accessl::worker;

int main(int argc, char *argv[])
{
    int ret = 0;

    google::InitGoogleLogging(argv[0]);

    config_t config;

    try {
        if (analyze_options(argc, argv, config))
        {
            return 0;
        }

        accel_init();
        setup_default_keys();
        load_keys(config.keys);

        ret = processor(config.port);
    } catch (po::error& e) {
        cerr << "Invalid option: " << e.what() << endl;
        ret = 1;
    } catch (std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        ret = 2;
    }

    accel_destroy();

    return ret;
}
