#!/bin/sh

# This script is intended to be run inside docker container

cd crypto3

mkdir -p build && cd build

cmake -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=FALSE \
    -DBUILD_TESTS=TRUE \
    -DZK_PLACEHOLDER_PROFILING=TRUE \
    ..

test_targets="crypto3_zk_commitment_fold_polynomial_test \
    crypto3_zk_commitment_fri_test crypto3_zk_commitment_lpc_test"

for t in $test_targets ; do
    cmake --build . -t $t
done

