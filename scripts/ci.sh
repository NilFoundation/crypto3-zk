#!/bin/sh

set -vxe

rm -rf suite
mkdir -p suite && cd suite

SUITE_REPO=https://github.com/NilFoundation/crypto3

git clone --depth=1 --recursive ${SUITE_REPO}

pushd suite/crypto3/libs/zk
git switch ${GIT_BRANCH}
popd
