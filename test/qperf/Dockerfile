FROM ubuntu:24.04

# Set the environment variable LD_LIBRARY_PATH to ensure we get the right libraries
ENV LD_LIBRARY_PATH=/usr/lib64:/usr/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

# The version of openssl to clone
ARG OPENSSL_URL=https://github.com/andrewkdinh/openssl.git
ARG OPENSSL_BRANCH=qperf

# The version of qperf to clone
ARG QPERF_URL=https://github.com/andrewkdinh/qperf.git
ARG QPERF_BRANCH=openssl

RUN apt-get update && \
    apt-get install -y git cmake libssl-dev libev-dev g++ && \
    apt-get clean

WORKDIR /app

# download and build qperf
RUN git clone --recurse-submodules --branch ${QPERF_BRANCH} ${QPERF_URL} && \
    mkdir build-qperf && \
    cd build-qperf && \
    cmake ../qperf && \
    make -j $(nproc) && \
    cp ./qperf /app/qperf-cli && \
    rm -rf /app/qperf /app/build-qperf && \
    cd .. && \
    mv qperf-cli qperf

# download and build openssl
RUN git clone --depth 1 --branch ${OPENSSL_BRANCH} ${OPENSSL_URL}
RUN cd openssl && \
    ./Configure enable-sslkeylog enable-fips enable-demos disable-docs --prefix=/usr --openssldir=/etc/pki/tls && \
    make -j $(nproc) && \
    make -j $(nproc) install && \
    cp demos/guide/quic-server-non-block /app/quic-server && \
    rm -rf /app/openssl && \
    chmod u+x /app/quic-server

RUN openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

ENTRYPOINT [ "./quic-server", "18080", "./server.crt", "./server.key" ]

