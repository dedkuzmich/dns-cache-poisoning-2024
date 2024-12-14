# FORWARDER
FROM debian:bookworm-slim AS base

RUN apt-get update && apt-get install -y nano net-tools tcpdump iputils-ping dnsutils
RUN apt-get install -y procps checksec


# BUILD STAGE
FROM base AS build

WORKDIR /build
ARG DNSMASQ_VERSION

RUN apt-get install -y gcc make
ADD http://www.thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz .
RUN tar zxvf dnsmasq-${DNSMASQ_VERSION}.tar.gz
RUN cd dnsmasq-${DNSMASQ_VERSION} && \
    sed -ie 's/TIMEOUT 10/TIMEOUT 1800/' src/config.h && \
    make CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3" LDFLAGS="-Wl,-z,now -Wl,-z,relro" && \
    make install


# FINAL STAGE
FROM base AS final

WORKDIR /app
ARG PORT

COPY --from=build /usr/local/sbin/dnsmasq /usr/local/sbin/dnsmasq
COPY service/forwarder/dnsmasq.conf /etc/dnsmasq.conf
EXPOSE $PORT/tcp $PORT/udp
ENTRYPOINT ["dnsmasq", "-k", "--log-facility=-"]