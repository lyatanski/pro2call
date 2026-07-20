FROM alpine:edge

# Build dependencies, grouped by what needs them:
#
#   build-base cmake ninja pkgconf   core C toolchain + build system
#   openssl-dev                      net module (OpenSSL::SSL)
#   go                               gtp/gen + diam/gen code generators (build-time)
#   clang libbpf-dev bpftool         gtp/u eBPF datapath (BpfCompile.cmake)
#   clang-extra-tools                clang-format/clang-tidy for the
#                                    format/format-check/tidy targets
#   linux-headers                    kernel UAPI headers for the BPF object
#
# The eBPF datapath is optional: without clang/bpftool/libbpf, gtp/u still
# builds with the datapath stubbed out (GTPU_EBPF_DISABLED). DWARF
# stripping (llvm-strip) is likewise optional and left out here.
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    pkgconf \
    linux-headers \
    openssl-dev \
    go \
    clang \
    clang-extra-tools \
    swig \
    lua5.1-dev \
    libbpf-dev \
    bpftool

ENV GOPATH=/tmp/go
ENV GOCACHE=/tmp/go/cache
WORKDIR /src
