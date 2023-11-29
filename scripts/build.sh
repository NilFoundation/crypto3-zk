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
    crypto3_zk_commitment_fri_test \
    crypto3_zk_commitment_lpc_test \
    crypto3_zk_commitment_kzg_test \
    crypto3_zk_systems_plonk_placeholder_placeholder_test \
    crypto3_zk_commitment_powers_of_tau_test \
    crypto3_zk_commitment_proof_of_knowledge_test \
    crypto3_zk_commitment_r1cs_gg_ppzksnark_mpc_test \
    crypto3_zk_math_expression_test \
    crypto3_zk_systems_plonk_plonk_constraint_test \
    crypto3_zk_commitment_proof_of_knowledge_test \
    crypto3_zk_transcript_transcript_test"

for t in $test_targets ; do
    cmake --build . -t $t
done

for t in $test_targets ; do
    echo "\033[1;32m$t..\033[0m"
    libs/zk/test/$t
done
