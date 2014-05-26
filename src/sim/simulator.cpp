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

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <deque>
#include <vector>
#include <iostream>

#include <glog/logging.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/random.hpp>
#include <boost/random/normal_distribution.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/unordered_map.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

#define UNUSED __attribute__ ((unused))

namespace accessl {
namespace simulator {

using namespace std;

namespace po = boost::program_options;
namespace pt = boost::posix_time;
namespace mi = boost::multi_index;

struct config_t {
    int engine_count;
    int worker_count;
    vector<int> req_sec;
    int req_sec_stddev;
    int duration;
    int interval;
    int rtt_us_mean;
    int rtt_us_sigma;
};

class stat_t {
public:
    typedef uint64_t stat_val;

    pt::time_duration dur_;

    void set_duration(pt::time_duration dur)
    {
        dur_ = dur;
    }

    void show_value(ostream& out, stat_val val) const
    {
        out << val * pt::seconds(1).total_milliseconds() / dur_.total_milliseconds();
    }
};

class engine_stat_t : public stat_t {
public:
    stat_val req;
    stat_val resp;
    stat_val timeout;

    engine_stat_t() :
        req(0),
        resp(0),
        timeout(0)
    { }
};

class worker_stat_t : public stat_t {
public:
    stat_val req;
    stat_val resp;
    stat_val no_reqs_queued;
    stat_val reqs_queued;
    stat_val reqs_queued_used;

    worker_stat_t() :
        req(0),
        resp(0),
        no_reqs_queued(0),
        reqs_queued(0),
        reqs_queued_used(0)
    { }

};

engine_stat_t operator- (const engine_stat_t& s1, const engine_stat_t& s2)
{
    engine_stat_t ret;

    ret.req = s1.req - s2.req;
    ret.resp = s1.resp - s2.resp;
    ret.timeout = s1.timeout - s2.timeout;

    return ret;
}

engine_stat_t operator+ (const engine_stat_t& s1, const engine_stat_t& s2)
{
    engine_stat_t ret;

    ret.req = s1.req + s2.req;
    ret.resp = s1.resp + s2.resp;
    ret.timeout = s1.timeout + s2.timeout;

    return ret;
}

worker_stat_t operator- (const worker_stat_t& s1, const worker_stat_t& s2)
{
    worker_stat_t ret;

    ret.req = s1.req - s2.req;
    ret.resp = s1.resp - s2.resp;
    ret.no_reqs_queued = s1.no_reqs_queued - s2.no_reqs_queued;
    ret.reqs_queued = s1.reqs_queued - s2.reqs_queued;
    ret.reqs_queued_used = s1.reqs_queued_used - s2.reqs_queued_used;

    return ret;
}


worker_stat_t operator+ (const worker_stat_t& s1, const worker_stat_t& s2)
{
    worker_stat_t ret;

    ret.req = s1.req + s2.req;
    ret.resp = s1.resp + s2.resp;
    ret.no_reqs_queued = s1.no_reqs_queued + s2.no_reqs_queued;
    ret.reqs_queued = s1.reqs_queued + s2.reqs_queued;
    ret.reqs_queued_used = s1.reqs_queued_used + s2.reqs_queued_used;

    return ret;
}

ostream& operator<< (ostream& out, const engine_stat_t& s)
{
    s.show_value(out, s.req);
    out << "\t";
    s.show_value(out, s.resp);
    out << "\t";
    s.show_value(out, s.timeout);

    return out;
}

ostream& operator<< (ostream& out, const worker_stat_t& s)
{
    s.show_value(out, s.req);
    out << "\t";
    s.show_value(out, s.resp);
    out << "\t";
    s.show_value(out, s.no_reqs_queued);
    out << "\t";
    s.show_value(out, s.reqs_queued);
    out << "\t";
    s.show_value(out, s.reqs_queued_used);

    return out;
}

enum msg_t {
    REQ,
    RESP,
    TIMEOUT,
    CANCEL,
};

enum state_t {
    INIT,
    WAIT_RESP,
    WORK,
};

class event_t;

class process_t {
public:
    typedef boost::shared_ptr<process_t> shptr;
    typedef int id_t;

    state_t state;
    id_t id;

    process_t(id_t _id) :
        state(INIT),
        id(_id)
    { }

    virtual void move(pt::time_duration time, boost::shared_ptr<event_t> e) = 0;
};

class timings_t {
private:
    const config_t &config_;
    boost::mt19937 &rng_;
    boost::normal_distribution<> dist;
    boost::variate_generator<boost::mt19937&, boost::normal_distribution<> > gen;

public:
    timings_t(const config_t& _config, boost::mt19937 & _rng) :
        config_(_config),
        rng_(_rng),
        dist(config_.rtt_us_mean, config_.rtt_us_sigma),
        gen(rng_, dist)
    {
    }

    pt::time_duration host_distance(process_t::shptr e1 UNUSED, process_t::shptr e2 UNUSED)
    {
        return pt::microseconds(static_cast<int>(gen() / 2));
    }

};

class event_t {
public:
    typedef boost::shared_ptr<event_t> shptr;
    typedef int id_t;

    id_t id, related_id;
    pt::time_duration send_time;
    pt::time_duration recv_time;
    process_t::shptr sender;
    process_t::shptr receiver;
    msg_t msg;
};

class events_t {
private:
    typedef boost::multi_index_container<
        event_t::shptr,
        mi::indexed_by<
            mi::sequenced<>,
        mi::ordered_non_unique< mi::member<event_t, pt::time_duration, &event_t::recv_time> >,
        mi::ordered_unique< mi::member<event_t, event_t::id_t, &event_t::id> >
            >
            > container;

    container events;
    event_t::id_t id;
public:
    events_t() :
        id(0)
    {}

    event_t::shptr send(id_t related_id, pt::time_duration send_time, pt::time_duration recv_time,
            process_t::shptr sender, process_t::shptr receiver,
            msg_t msg)
    {
        event_t::shptr e = event_t::shptr(new event_t());
        e->id = id++;
        e->related_id = related_id;
        e->send_time = send_time;
        e->recv_time = recv_time;
        e->sender = sender;
        e->receiver = receiver;
        e->msg = msg;

        events.push_back(e);

        return e;
    }

    void cancel(event_t::shptr e)
    {
        container::nth_index<2>::type& uniq_index=events.get<2>();
        uniq_index.erase(e->id);
    }

    event_t::shptr front()
    {
        container::nth_index<1>::type& sorted_index=events.get<1>();
        event_t::shptr ret = *sorted_index.begin();

        sorted_index.erase(sorted_index.begin());
        return ret;
    }
};

class worker_t : public process_t, public boost::enable_shared_from_this<worker_t> {
private:
    typedef deque<event_t::shptr> reqs_t;
    reqs_t reqs;
    event_t::shptr req_event;

    events_t & events_;
    timings_t & timings_;
    config_t & config_;
    boost::mt19937 &rng_;
    pt::time_duration req_time;
    boost::normal_distribution<> dist;
    boost::variate_generator<boost::mt19937&, boost::normal_distribution<> > gen;

    worker_stat_t stats, prev_stats;

    pt::time_duration get_req_time()
    {
        double rand = gen();
        return pt::microseconds(static_cast<int>(rand));
    }

    process_t::shptr shared_process_t_from_this()
    {
        return boost::dynamic_pointer_cast<process_t>(shared_from_this());
    }

    void process_req(pt::time_duration time, event_t::shptr e)
    {
        pt::time_duration timeout_time = time + get_req_time();

        req_event = e;

        DLOG(INFO) << time << " worker " << id << " sending TIMEOUT to self to be received at " << timeout_time;
        events_.send(e->id, time, timeout_time, shared_process_t_from_this(), shared_process_t_from_this(), TIMEOUT);
        state = WORK;
    }
public:
    typedef boost::shared_ptr<worker_t> shptr;

    worker_t(id_t id, boost::mt19937 & _rng, events_t & _events, config_t & _config, timings_t & _timings) :
        process_t(id),
        events_(_events),
        timings_(_timings),
        config_(_config),
        rng_(_rng),
        req_time(pt::seconds(1) / config_.req_sec[id % config_.req_sec.size()]),
        dist(req_time.total_microseconds(), config_.req_sec_stddev * req_time.total_microseconds() / 100),
        gen(rng_, dist)
    {
    }

    void move(pt::time_duration time, event_t::shptr e)
    {
        // regardless of the state if we get CANCEL we search for the message in reqs
        // and delete it from there
        if (e->msg == CANCEL)
        {
            DLOG(INFO) << time << " worker " << id << " received CANCEL for REQ " << e->related_id;

            for (reqs_t::iterator i = reqs.begin(); i != reqs.end(); i++)
            {
                if ((*i)->id == e->related_id)
                {
                    DLOG(INFO) << time << " worker " << id << " cancelled REQ " << e->related_id;
                    reqs.erase(i);
                    break;
                }
            }

            return;
        }

        switch(state) {

        case INIT:

            if (e->msg == REQ)
            {
                DLOG(INFO) << time << " worker " << id << " received REQ " << e->id << " from engine " << e->sender->id;
                process_req(time, e);

                stats.req++;
            }
            else
            {
                LOG(ERROR) << "unknown event in INIT";
            }

            break;

        case WORK:
            if (e->msg == TIMEOUT)
            {
                DLOG(INFO) << time << " worker " << id << " got TIMEOUT " << e->id << ", sending RESP to REQ " << req_event->id
                    << " to engine " << req_event->sender->id;

                events_.send(req_event->id, time, time + timings_.host_distance(shared_process_t_from_this(), req_event->sender),
                        shared_process_t_from_this(), req_event->sender, RESP);
                stats.resp++;
                req_event.reset();

                if (reqs.empty())
                {
                    DLOG(INFO) << time << " worker " << id << " no reqs, going to INIT";
                    stats.no_reqs_queued++;
                    state = INIT;
                }
                else
                {
                    event_t::shptr r = reqs.front();

                    DLOG(INFO) << time << " worker " << id << ", " << reqs.size() << " reqs queued, processing first from engine " << r->sender->id;
                    stats.reqs_queued_used++;

                    reqs.pop_front();
                    process_req(time, r);
                }
            }
            else if (e->msg == REQ)
            {
                DLOG(INFO) << time << " worker " << id << " got REQ " << e->id << " from engine " << e->sender->id << " while busy, queueing";
                stats.req++;
                stats.reqs_queued++;
                reqs.push_back(e);
            }
            else
            {
                LOG(ERROR)<< "unknown event in WORK";
            }
            break;

        default:
            LOG(ERROR) << "unknown state";
        }
    }

    worker_stat_t get_stats_diff(pt::time_duration dur)
    {
        worker_stat_t ret = stats-prev_stats;
        ret.set_duration(dur);
        prev_stats = stats;
        return ret;
    }
};

typedef vector<worker_t::shptr> workers_t;

class speed_estimator_t {
private:
    int64_t srtt;
    int64_t mdev;
    int64_t mdev_max;
    int64_t rttvar;
    int64_t reqs_sec;
    int64_t rto;

    static int64_t max(int64_t a, int64_t b)
    {
        if (a > b)
            return a;
        else
            return b;
    }

    static int64_t abs(int64_t a)
    {
        if (a >= 0)
            return a;
        else
            return -a;
    }

public:
    typedef boost::shared_ptr<speed_estimator_t> shptr;

    speed_estimator_t() :
        srtt(0),
        mdev(0),
        mdev_max(0),
        rttvar(0),
        // 100k reqs/sec is a huge number wich will lead to selecting this worker
        // after that we will update its response time
        reqs_sec(100000),
        rto((pt::milliseconds(200)).total_microseconds())
    { }

    void update_rtt(int64_t last_rtt)
    {
        if (srtt == 0)
        {
            srtt = last_rtt;
            mdev = last_rtt/2;
            // (200ms in microseconds)/4
            mdev_max = max(last_rtt/2, 200*1000/4);
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
        // if the worker failed to respond we quite rapidly decrease our estimate of how many
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

class worker_times_t {
private:
    typedef boost::unordered_map<process_t::id_t, speed_estimator_t::shptr> worker_speed_container;
    worker_speed_container speed;

    speed_estimator_t::shptr worker_find(process_t::id_t id)
    {
        worker_speed_container::iterator i = speed.find(id);
        if (i != speed.end())
            return i->second;
        else
        {
            speed_estimator_t::shptr worker_speed(new speed_estimator_t());
            speed.insert(worker_speed_container::value_type(id, worker_speed));
            return worker_speed;
        }
    }

    speed_estimator_t::shptr worker_find(worker_t::shptr w)
    {
        return worker_find(w->id);
    }

public:
    worker_times_t()
    { }

    void update_resp_time(worker_t::shptr w, uint64_t microsecs)
    {
        worker_find(w)->update_rtt(microsecs);
    }

    void update_resp_time(worker_t::id_t worker_id, uint64_t microsecs)
    {
        worker_find(worker_id)->update_rtt(microsecs);
    }

    void update_resp_timeout(worker_t::id_t worker_id)
    {
        worker_find(worker_id)->update_timeout();
    }

    uint64_t req_timeout(worker_t::shptr w)
    {
        speed_estimator_t::shptr worker_speed = worker_find(w);
        return worker_speed->get_rto();
    }

    uint64_t reqs_sec(worker_t::shptr w)
    {
        speed_estimator_t::shptr worker_speed = worker_find(w);
        return worker_speed->get_reqs_sec();
    }

};

class engine_t : public process_t, public boost::enable_shared_from_this<engine_t> {
private:
    boost::mt19937 & rng_;
    workers_t & workers_;
    events_t & events_;
    config_t & config_;
    timings_t & timings_;

    worker_times_t worker_times;
    engine_stat_t stats, prev_stats;

    event_t::shptr req_event, timeout_event;

    process_t::shptr shared_process_t_from_this()
    {
        return boost::dynamic_pointer_cast<process_t>(shared_from_this());
    }

    worker_t::shptr worker_choose()
    {
        vector< pair<uint64_t, worker_t::shptr> > reqs_sec;
        uint64_t reqs_total = 0;

        reqs_sec.reserve(workers_.size());
        for (workers_t::iterator i = workers_.begin(); i != workers_.end(); i++)
        {
            reqs_total += worker_times.reqs_sec(*i);
            reqs_sec.push_back( pair<uint64_t, worker_t::shptr>(reqs_total, *i) );
        }

        boost::uniform_int<uint64_t> dist(0, reqs_total-1);
        boost::variate_generator<boost::mt19937&, boost::uniform_int<uint64_t> > gen(rng_, dist);

        uint64_t req_random = gen();

        vector< pair<uint64_t, worker_t::shptr> >::iterator ret_iter = upper_bound(reqs_sec.begin(), reqs_sec.end(), pair<uint64_t, worker_t::shptr>(req_random, *workers_.begin()));

        DLOG(INFO) << "worker_choose: reqs_total " << reqs_total << " random " << req_random;

        if (ret_iter == reqs_sec.end())
            DLOG(INFO) << "worker_choose: upper_bound returned end";
        else
            DLOG(INFO) << "worker_choose: upper_bound returned worker " << ret_iter->second->id;

        return ret_iter->second;
    }

    pt::time_duration worker_timeout(worker_t::shptr w)
    {
        uint64_t microsecs = worker_times.req_timeout(w);

        DLOG(INFO) << "engine " << id << " worker_timeout for worker " << w->id << " is " << microsecs;

        return pt::microseconds(microsecs);
    }

public:
    typedef boost::shared_ptr<engine_t> shptr;

    engine_t(id_t id, boost::mt19937 & _rng, workers_t & _workers, events_t & _events, config_t & _config, timings_t & _timings) :
        process_t(id),
        rng_(_rng),
        workers_(_workers),
        events_(_events),
        config_(_config),
        timings_(_timings),
        worker_times()
    {
    }

    void send_req(pt::time_duration time, bool requeue = false)
    {
        worker_t::shptr w;
        pt::time_duration recv_time, timeout_time;

        w = worker_choose();

        recv_time = time + timings_.host_distance(shared_from_this(), w);
        req_event = events_.send(0, time, recv_time, shared_from_this(), w, REQ);

        timeout_time = time + worker_timeout(w);
        timeout_event = events_.send(0, time, timeout_time, shared_from_this(), shared_from_this(), TIMEOUT);

        DLOG(INFO) << time << " engine " << id << " sending REQ " << req_event->id
            << " to worker " << w->id << " to be received at " << recv_time;
        DLOG(INFO) << time << " engine " << id << " sending TIMEOUT " << timeout_event->id
            << " to self to be received at " << timeout_time;

        state = WAIT_RESP;

        if (!requeue)
            stats.req++;
    }

    void move(pt::time_duration time, event_t::shptr e)
    {
        switch(state) {

            case INIT:
                LOG(ERROR) << time << " engine " << id << " received event in INIT, should not happen";
                break;

            case WAIT_RESP:
                if (e->msg == TIMEOUT)
                {
                    DLOG(INFO) << time << " engine " << id << " TIMEOUT " << e->id
                        << " received for worker " << req_event->receiver->id
                        << " sending CANCEL for REQ " << req_event->id;

                    stats.timeout++;
                    worker_times.update_resp_timeout(req_event->receiver->id);

                    // send info to worker to forget about this request
                    events_.send(req_event->id, time, time+timings_.host_distance(shared_from_this(), req_event->receiver),
                            shared_from_this(), req_event->receiver, CANCEL);

                    // reschedule the request
                    send_req(time, true);
                }
                else if (e->msg == RESP)
                {
                    if (e->related_id != req_event->id)
                    {
                        DLOG(INFO) << time << " engine " << id << " received stale RESP for REQ " << e->related_id << ", ignoring";
                        break;
                    }

                    DLOG(INFO) << time << " engine " << id << " received RESP for REQ " << e->related_id
                        << " from worker " << e->sender->id;

                    events_.cancel(timeout_event);
                    stats.resp++;
                    worker_times.update_resp_time(e->sender->id, (e->recv_time - req_event->send_time).total_microseconds());

                    // just after receiving reponse for previous request send another request
                    // simulates a very busy server
                    // we could simulate a timeout here
                    // TODO: should we?
                    send_req(time);
                }
                else
                {
                    LOG(ERROR) << time << " engine " << id << " received unknown event";
                    send_req(time);
                }
                break;

            default:
                LOG(ERROR) << "unknown state";
        }
    }

    engine_stat_t get_stats_diff(pt::time_duration dur)
    {
        engine_stat_t ret = stats-prev_stats;
        ret.set_duration(dur);
        prev_stats = stats;
        return ret;
    }
};

bool analyze_options(int argc, char *argv[], config_t &config)
{
    po::options_description desc("Usage");
    desc.add_options()
        ("help,h", "help message")
        ("interval,i", po::value<int>(&config.interval)->default_value(1), "interval in seconds to report req/s")
        ("engines,e", po::value<int>(&config.engine_count)->default_value(32), "number of engines")
        ("workers,w", po::value<int>(&config.worker_count)->default_value(16), "number of workers")
        ("duration,d", po::value<int>(&config.duration)->default_value(1), "length of simulation")
        ("reqs-sec,r", po::value< vector<int> >(&config.req_sec), "number of requests per second per worker")
        ("reqs-stddev", po::value< int >(&config.req_sec_stddev)->default_value(5), "stddev of number of requests per second per worker in %")
        ("rtt-mean,t", po::value< int >(&config.rtt_us_mean)->default_value(600), "mean RTT between 2 hosts (in microseconds)")
        ("rtt-sigma,s", po::value< int >(&config.rtt_us_sigma)->default_value(100), "standard deviation of RTT between 2 hosts (in microseconds)")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (!vm.count("reqs-sec"))
        config.req_sec.push_back(1500);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return true;
    }

    return false;
}

void simulate(config_t & config)
{
    typedef vector<engine_t::shptr> engines_t;

    engines_t engines;
    workers_t workers;
    events_t events;

    boost::mt19937 rng;
    rng.seed(time(NULL));

    timings_t timings(config, rng);

    pt::time_duration cur_time;
    pt::time_duration end_time;
    pt::time_duration last_show_time;
    pt::time_duration interval_time = pt::seconds(config.interval);

    cur_time = pt::seconds(0);
    last_show_time = pt::seconds(0);

    for (int i = 0; i < config.worker_count; i++)
    {
        worker_t::shptr w = worker_t::shptr(new worker_t(i, rng, events, config, timings));
        workers.push_back(w);
    }

    for (int i = 0; i < config.engine_count; i++)
    {
        engine_t::shptr e = engine_t::shptr(new engine_t(i, rng, workers, events, config, timings));
        engines.push_back(e);
    }

    for (vector<engine_t::shptr>::iterator i = engines.begin(); i != engines.end(); i++)
    {
        (*i)->send_req(cur_time);
    }

    end_time = pt::seconds(config.duration);

    while (cur_time < end_time)
    {
        event_t::shptr e = events.front();

        DLOG(INFO) << e->recv_time << " simulate event sent at " << e->send_time;

        cur_time = e->recv_time;
        e->receiver->move(cur_time, e);

        pt::time_duration diff_time = cur_time - last_show_time;
        if (diff_time > interval_time)
        {
            engine_stat_t engine_total;
            worker_stat_t worker_total;

            cout << "\t\treq\tresp\ttout" << endl;
            for(engines_t::iterator i = engines.begin(); i != engines.end(); i++)
            {
                engine_stat_t stat = (*i)->get_stats_diff(diff_time);
                engine_total = engine_total + stat;
                cout << "engine " << (*i)->id << "\t" << stat << endl;
            }

            engine_total.set_duration(diff_time);
            cout << "engine total\t" << engine_total << endl;

            cout << "\t\treq\tresp\tnoq\tqued\tqused" << endl;
            for(workers_t::iterator i = workers.begin(); i != workers.end(); i++)
            {
                worker_stat_t stat = (*i)->get_stats_diff(diff_time);
                worker_total = worker_total + stat;
                cout << "worker " << (*i)->id << "\t" << stat << endl;
            }

            worker_total.set_duration(diff_time);
            cout << "worker total\t" << worker_total << endl;

            last_show_time = cur_time;
        }
    }

}

} // namespace simulator
} // namespace accessl

using namespace accessl::simulator;

int main(int argc, char *argv[])
{
    google::InitGoogleLogging(argv[0]);

    config_t config;

    try {
        if (analyze_options(argc, argv, config))
        {
            return 0;
        }

        simulate(config);

    } catch (po::error& e) {
        LOG(ERROR) << "Invalid option: " << e.what();
        return 1;
    } catch (std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 4;
    }

    return 0;
}
