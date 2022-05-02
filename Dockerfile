FROM golang:alpine as build
WORKDIR /app

# install build dependencies
RUN apk add --no-cache \
    build-base \
    automake \
    autoconf \
    pkgconfig \
    libtool \
    bison \
    libressl-dev \
    git

# install YARA
RUN git clone --depth 1 https://github.com/virustotal/yara.git \
    && cd yara \
    && sh ./build.sh \
    && make install \
    && cd ..

# copy and build PMF
COPY . .
RUN make

FROM golang:alpine
LABEL org.opencontainers.image.source="https://github.com/jvoisin/php-malware-finder"
WORKDIR /app

# install dependencies
RUN apk add --no-cache libressl

# copy files from build container
COPY --from=build /usr/local/lib /usr/lib
COPY --from=build /app/php-malware-finder /app

ENTRYPOINT ["/app/php-malware-finder", "-v", "-a", "-c", "/data"]
