#!/bin/sh

set -vxe

docker build -t crypto3-zk-test libs/zk/scripts/docker

# Build tests
docker run --rm --volume ${PWD}:/home:Z -w /home \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    crypto3-zk-test ./build.sh

