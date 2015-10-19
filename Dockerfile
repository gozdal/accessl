FROM debian:jessie

ADD . /accessl
RUN apt-get -q update && \
    apt-get -qy install \
        gcc g++ cmake liblog4c-dev libevent-dev libssl-dev m4 libboost-dev libboost-thread-dev libboost-program-options-dev \
        libboost-system-dev uuid-dev libzmq3-dev libgoogle-glog-dev libboost-random-dev libgmp3-dev \
        liblog4c3 libgoogle-glog0 libboost-thread1.55.0 libboost-program-options1.55.0 libboost-random1.55.0 libzmq3 && \
    cd /accessl && \
    ./scripts/build-prepare.sh && \
    make -C Build/Release -j$(awk '/^processor/{n+=1}END{print n}' /proc/cpuinfo) && \
    make -C Build/Release install && \
    cd .. && \
    rm -rf accessl && \
    apt-get -qy purge --auto-remove \
        gcc g++ cmake liblog4c-dev libevent-dev libssl-dev m4 libboost-dev libboost-thread-dev libboost-program-options-dev \
        libboost-system-dev uuid-dev libzmq3-dev libgoogle-glog-dev libboost-random-dev libgmp3-dev && \
    apt-get -q clean && \
    rm -rf /var/lib/apt/lists/*

USER nobody

EXPOSE 10000/udp

ENTRYPOINT ["/usr/bin/worker", "-p", "10000"]
