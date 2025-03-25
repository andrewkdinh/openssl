FROM ubuntu:24.04

ENV LD_LIBRARY_PATH=/usr/lib64:/usr/lib:/usr/lib/x86_64-linux-gnu:/usr/local/lib
ENV PATH=/root/go/bin:$PATH
# TODO: Change this for each test so that each heap profile can be associated with specific tests
ENV HEAPPROFILE=/tmp/heapprof
ENV DO_MPROFILE=1

# The version of openssl to clone
ARG OPENSSL_URL=https://github.com/andrewkdinh/openssl.git
ARG OPENSSL_BRANCH=master

RUN apt-get update && \
    apt-get install -y \
        git make gcc perl cmake build-essential \
        autoconf libtool pkg-config libpsl-dev \
        zip graphviz golang

WORKDIR /app

# Download and build gperftools
RUN git clone --depth 1 https://github.com/gperftools/gperftools.git && \
    cd gperftools && \
    ./autogen.sh && \
    ./configure && \
    make -j $(nproc) && \
    make -j $(nproc) install

# download and build openssl
RUN git clone --depth 1 --branch ${OPENSSL_BRANCH} ${OPENSSL_URL} && \
    cd openssl && \
    ./Configure disable-docs -ltcmalloc && \
    make -j $(nproc)

# download and install pprof
RUN go install github.com/google/pprof@latest

# docker build -t gperftools . && docker run --rm -it --name gperftools gperftools bash
# $ TESTS=test_quic_multistream make test
# $ pprof --png /app/openssl/test/quic_multistream_test /tmp/heapprof.0001.heap
