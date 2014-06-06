Building
========

Instructions for Ubuntu 14.04.

```
sudo apt-get install git-core gcc g++ cmake liblog4c-dev libevent-dev libssl-dev m4 libboost-dev libboost-thread-dev libboost-program-options-dev libboost-system-dev uuid-dev libzmq3-dev libgoogle-glog-dev libboost-random-dev libgmp3-dev
./scripts/build-prepare.sh
make -C Build/Debug -j8
make -C Build/Release -j8
```
