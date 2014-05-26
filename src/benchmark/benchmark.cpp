#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

#include <glog/logging.h>

#include <common/compiler.h>

#include <boost/thread/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/detail/atomic_count.hpp>
#include <boost/array.hpp>

#include <common/crypto.hpp>

#include <accessl-common/testrsa.h>

using namespace std;
using namespace boost;
using namespace boost::posix_time;

namespace accessl {
namespace benchmark {

detail::atomic_count sign_count(0), error_count(0), stop_benchmark(0);

static const int RSA_NUM = 4;
static const int BUFSIZE = 1024*8+1;

namespace po = boost::program_options;

boost::thread_group benchmark_threads;
int thread_count;
string engine_name;
int interval;
int bits;
bool quiet;

class benchmark_error : public std::runtime_error
{
public:
    benchmark_error(const string& reason) :
        std::runtime_error(reason)
    { }
};

void rsa_benchmark()
{
    int i;
    int j;

    RSA *rsa_key[RSA_NUM];
    unsigned char *rsa_data[RSA_NUM] = {test512,test1024,test2048,test4096};
    int rsa_data_length[RSA_NUM]= {
        sizeof(test512),sizeof(test1024),
        sizeof(test2048),sizeof(test4096)
    };

    if (bits == 512)
        j = 0;
    else if (bits == 1024)
        j = 1;
    else if (bits == 2048)
        j = 2;
    else if (bits == 4096)
        j = 3;
    else
        j = 1;

    memset(rsa_key, 0, sizeof(rsa_key));

    for (i = 0; i < RSA_NUM; i++)
        rsa_key[i] = NULL;

    for (i = 0; i < RSA_NUM; i++)
    {
        const unsigned char *p;

        p = rsa_data[i];
        rsa_key[i] = d2i_RSAPrivateKey(NULL, &p, rsa_data_length[i]);
        if (rsa_key[i] == NULL)
        {
            LOG(ERROR) << "Internal error loading RSA keys";
            return;
        }
    }

    boost::array<unsigned char, BUFSIZE> plain, cipher, check;

    memset(plain.c_array(), 0, BUFSIZE);
    memset(cipher.c_array(), 0, BUFSIZE);
    memset(check.c_array(), 0, BUFSIZE);

    int plain_size, cipher_size, check_size;

    plain_size = RSA_size(rsa_key[j])-RSA_PKCS1_PADDING_SIZE;
    cipher_size = RSA_public_encrypt(plain_size, plain.c_array(), cipher.c_array(), rsa_key[j], RSA_PKCS1_PADDING);
    if (cipher_size < 0)
    {
        LOG(ERROR) << "Could not encrypt using public key, cannot benchmark";
        return;
    }

    while (!stop_benchmark)
    {
        check_size = RSA_private_decrypt(cipher_size, cipher.c_array(), check.c_array(), rsa_key[j], RSA_PKCS1_PADDING);
        if (check_size <= 0)
        {
            ++error_count;
        } else {
            ++sign_count;
        }
    }

    for (i=0; i<RSA_NUM; i++)
        if (rsa_key[i] != NULL)
            RSA_free(rsa_key[i]);
}

void stop(int sig UNUSED)
{
    ++stop_benchmark;
}

bool analyze_options(int argc, char *argv[])
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("threads,t", po::value<int>(&thread_count)->default_value(4), "number of worker threads")
        ("engine-name,e", po::value<string>(&engine_name)->default_value("accessl"), "engine to benchmark")
        ("interval,i", po::value<int>(&interval)->default_value(1), "interval in seconds to report req/s")
        ("bits,b", po::value<int>(&bits)->default_value(1024), "length of RSA key to benchmark (512,1024,2048,4096)")
        ("quiet,q", "suppress output")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return true;
    }

    if (vm.count("quiet"))
        quiet = true;
    else
        quiet = false;

    return false;
}

void setup_engine(accessl::openssl::crypto_t &crypto)
{
    ENGINE *e = crypto.engine_load(engine_name.data());

    crypto.engine_setup(e);
}

void create_benchmark_threads()
{
    if (thread_count < 1)
    {
        throw benchmark_error("invalid thread count");
    }


    for(int i = 0; i < thread_count; ++i)
    {
        benchmark_threads.create_thread(rsa_benchmark);
    }
}

void benchmark()
{
    int last_sign_count = sign_count;
    int last_error_count = error_count;

    ptime last_time = microsec_clock::local_time();

    while (!stop_benchmark)
    {
        sleep(interval);

        if (!quiet)
        {
            int cur_sign_count = sign_count;
            int cur_error_count = error_count;
            ptime cur_time = microsec_clock::local_time();

            uint64_t elapsed = (cur_time - last_time).total_microseconds();
            int signs = cur_sign_count - last_sign_count;
            int errors = cur_error_count - last_error_count;

            double sign_rate = (signs * 1000000.0) / (double)elapsed;

            cout << "Current rate: " << sign_rate << " private decrypts/s";
            if (errors > 0)
            {
                double error_rate = (errors * 1000000.0) / (double)elapsed;
                cout << " " << error_rate << " errors/s";
            }
            cout << endl;

            last_sign_count = cur_sign_count;
            last_error_count = cur_error_count;
            last_time = cur_time;
        }
    }
    benchmark_threads.join_all();
}

} // namespace benchmark
} // namespace accessl

using namespace accessl::benchmark;

int main(int argc, char *argv[])
{
    google::InitGoogleLogging(argv[0]);
    accessl::openssl::crypto_t crypto;

    try {
        if (analyze_options(argc, argv))
        {
            return 0;
        }
        setup_engine(crypto);

        // Block all signals for background threads
        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        create_benchmark_threads();
        //
        // Restore previous signals.
        pthread_sigmask(SIG_SETMASK, &old_mask, 0);

        // Wait for signal indicating time to shut down.
        signal(SIGINT, stop);
        signal(SIGQUIT, stop);
        signal(SIGTERM, stop);

        benchmark();

    } catch (po::error& e) {
        LOG(ERROR) << "Invalid option: " << e.what();
        return 1;
    } catch (accessl::benchmark::benchmark_error& e) {
        LOG(ERROR) << "Benchmark error: " << e.what();
        return 2;
    } catch (std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 3;
    }


    return 0;
}
