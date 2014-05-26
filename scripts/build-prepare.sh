#!/bin/sh

CC=gcc
CXX=g++

prepare()
{
  mkdir $1
  cd $1 && cmake -D CMAKE_BUILD_TYPE=$1 -D CMAKE_C_COMPILER=$CC -D CMAKE_CXX_COMPILER=$CXX ../..
  cd ..
}

mkdir Build
cd Build

prepare Debug
prepare Release
prepare RelWithDebInfo
