#!/bin/bash

TARGET=deb
PACKAGE_NAME=accessl
PACKAGE_VERSION=0.1
BUILD_DIR=Build/Release
PKG_ROOT=${BUILD_DIR}/pkg-root
LICENSE=GPLv3
VENDOR="Marcin Gozdalik <gozdal@gmail.com>"
URL="https://github.com/gozdal/accessl"

DEPS="libboost-program-options1.54.0 libboost-random1.54.0 libboost-system1.54.0 libboost-thread1.54.0 libc6 libexpat1 libgcc1 libgflags2 libgmp10 libgoogle-glog0 liblog4c3 liblzma5 libpgm-5.1-0 libssl1.0.0 libstdc++6 libunwind8 libzmq3"

DEPS_ARG=""
for DEP in ${DEPS}; do
    DEPS_ARG="${DEPS_ARG} -d ${DEP}"
done

make DESTDIR=pkg-root -C ${BUILD_DIR} install
rm -f ${PACKAGE_NAME}-${PACKAGE_VERSION}*deb
fpm -s dir -t ${TARGET} \
    ${DEPS_ARG} \
    -n "${PACKAGE_NAME}" -v "${PACKAGE_VERSION}" \
    --license "${LICENSE}" --vendor "${VENDOR}" \
    --maintainer "${VENDOR}" --url "${URL}" \
    -C ${PKG_ROOT} $(ls ${PKG_ROOT})
