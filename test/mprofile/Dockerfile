FROM ubuntu:24.04

# Set the environment variable LD_LIBRARY_PATH to ensure we get the right libraries
ENV LD_LIBRARY_PATH=/usr/lib64:/usr/lib:/usr/lib/x86_64-linux-gnu
ENV DO_MPROFILE=1

# The version of openssl to clone
ARG OPENSSL_URL=https://github.com/andrewkdinh/openssl.git
ARG OPENSSL_BRANCH=mprofile

RUN apt-get update && \
    apt-get install -y \
        git make gcc perl cmake build-essential \
        autoconf libtool pkg-config libpsl-dev

WORKDIR /app

# download and build openssl
RUN git clone --depth 1 --branch ${OPENSSL_BRANCH} ${OPENSSL_URL}
RUN cd openssl && \
    ./Configure enable-sslkeylog enable-fips disable-docs --prefix=/usr --openssldir=/etc/pki/tls && \
    make -j $(nproc)
RUN make -j $(nproc) test
