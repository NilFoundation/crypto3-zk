# Test environment for crypto3-zk

FROM ubuntu:22.04

WORKDIR /home

ENV DEBIAN_FRONTEND=noninteractive

RUN useradd --system ${uid:+--uid "$uid"} --user-group --shell /sbin/nologin --create-home --home-dir /home test

RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        curl \
        gnupg \
        ca-certificates

RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        build-essential \
        cmake \
        git \
        clang-14 pkg-config libc-ares-dev liblz4-dev libgnutls28-dev \
        libprotobuf-dev libyaml-cpp-dev lksctp-tools libsctp-dev ragel \
        spd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && curl -L -O https://launchpadlibrarian.net/466750967/libfmt-dev_6.1.2+ds-2_amd64.deb \
    && apt install /tmp/libfmt-dev_6.1.2+ds-2_amd64.deb

RUN cd /tmp && curl -L -O https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2 
#RUN cd /tmp && curl -O http://192.168.123.11:8000/boost_1_76_0.tar.bz2

RUN cd /tmp && tar jxf boost_1_76_0.tar.bz2 \
    && cd boost_1_76_0 && ./bootstrap.sh && ./b2 install

RUN cd /tmp && rm -rf boost* libfmt*

RUN chown test:test /home

USER test

