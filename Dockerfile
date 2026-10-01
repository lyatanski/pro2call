FROM alpine:edge AS build

# Build dependencies, as the root Dockerfile groups them:
#
#   build-base cmake ninja pkgconf   core C toolchain + build system
#   openssl-dev                      net module (OpenSSL::SSL)
#   go                               gtp/gen + diam/gen code generators
#   clang libbpf-dev bpftool         gtp/u eBPF datapath (BpfCompile.cmake)
#   linux-headers                    kernel UAPI headers for the BPF object
#   swig lua5.1-dev                  the Lua bindings the scripts are written in
#
# Without clang/bpftool/libbpf the gtp/u configure step fails outright
# (BpfCompile.cmake's check_bpf_toolchain), so they are not optional here.
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    pkgconf \
    linux-headers \
    openssl-dev \
    go \
    clang \
    swig \
    lua5.1-dev \
    libbpf-dev \
    bpftool

ENV GOPATH=/tmp/go
ENV GOCACHE=/tmp/go/cache

# go depends on gcc/binutils/musl-dev (its own apk dependency, pulled in
# regardless of what we ask for), so gcc ends up installed either way. Pin
# the compiler to clang explicitly rather than letting cmake's default
# search pick up gcc's `cc`.
ENV CC=clang
ENV CXX=clang++

WORKDIR /src
COPY . .
RUN cmake -B out -G Ninja \
 && cmake --build out --target \
    gtp_lua net_lua sip_lua sdp_lua sms_lua rtp_lua ipsec diam_lua json_lua


FROM alpine:edge

# Runtime deps of the modules: liblua5.1 (lua5.1 pulls lua5.1-libs) plus
# libstdc++/libgcc for the SWIG C++ facades, libcrypto for Milenage and MD5,
# and libbpf for the datapath.
RUN apk add --no-cache lua5.1 libstdc++ libcrypto3 libbpf

# /usr/lib/lua/5.1 is already on Lua's default package.cpath, so `require "gtp"`
# resolves with no LUA_CPATH in the environment.
COPY --from=build /src/out/bindings/lua/*.so /usr/lib/lua/5.1/
COPY --from=build /src/bindings/examples/ /opt/

WORKDIR /opt
ENTRYPOINT ["lua"]
CMD ["ims_test_s5.lua"]
