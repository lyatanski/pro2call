# mobile-core protocol toolkit

Zero-copy C codecs and a eBPF datapath for the mobile-core
signalling and media protocols (GTP, Diameter, SIP, SDP, RTP, IPsec),
an epoll transport layer to run them, code generators for the spec-driven
layers, and Python/Lua bindings. Each module builds standalone as a CMake
subdirectory; the deeper per-module READMEs carry the usage detail.

## Modules

| Module | Description |
| ------ | ----------- |
| [`task/`](task) | Foundation library shared by every codec: generic zero-copy TLV codec, FSM engine, big-endian helpers, logging and test macros. |
| [`net/`](net) | Transport layer — non-blocking UDP/TCP/SCTP sockets, epoll event loop, async DNS resolver, TLS/DTLS over OpenSSL. |
| [`gtp/`](gtp) | GTP protocol family: GTPv1-C (`v1`), GTPv2-C (`v2`) and the GTP-U eBPF datapath (`u`). See [`gtp/README.md`](gtp/README.md). |
| [`diam/`](diam) | Diameter base codec plus a generated dictionary for the 3GPP Cx / Rx / Ro / Rf interfaces, and the RFC 6733 session state machines. |
| [`sip/`](sip) | SIP message codec — zero-copy parse, buffer-writing encode, enum-resolved methods and headers — plus the RFC 3261 transaction state machines. |
| [`sdp/`](sdp) | SDP session-description codec — zero-copy single-pass parse, enum-resolved attributes. |
| [`rtp/`](rtp) | RTP/RTCP codec with the RFC 3550 receiver-side source tracker (sequence validation, loss, jitter). |
| [`nlmsg/`](netlink) | Kernel configuration over netlink: IPsec SA/policy management (`xfrm`, NETLINK_XFRM) and interface address add/del (`rtnl`, RTNETLINK `RTM_*ADDR`). |
| [`bindings/`](bindings) | SWIG bindings (Lua) over C++ facades of the C libraries. |

## Specifications

### task
- common reusable code.

### net
- RFC 1035 — DNS message format (with EDNS0, RFC 6891); A/AAAA/SRV (RFC 2782)/NAPTR (RFC 3403).
- RFC 8446 / RFC 6347 — TLS and DTLS (via OpenSSL).

### gtp
- 3GPP TS 29.060 — GTPv1-C, 2G/3G control plane (`gtp/v1`).
- 3GPP TS 29.274 — GTPv2-C, EPC control plane (`gtp/v2`).
- 3GPP TS 29.281 — GTP-U, user-plane tunnelling (`gtp/u`).

### diam
- RFC 6733 — Diameter base protocol.
- RFC 4006 — Diameter Credit-Control application (Ro).
- 3GPP TS 29.229 — Cx interface (IMS HSS).
- 3GPP TS 29.214 — Rx interface (policy/media authorization).
- 3GPP TS 32.299 — Diameter charging applications (Ro/Rf).

### sip
- RFC 3261 — SIP: Session Initiation Protocol (plus standard method/header extensions).

### sdp
- RFC 8866 — SDP: Session Description Protocol (plus RTP/AVP, ICE, DTLS-SRTP attributes).

### rtp
- RFC 3550 — RTP: transport for real-time applications (SR/RR/SDES/BYE, source tracker).
- RFC 3551 — RTP profile for audio/video (payload-type constants).

### netlink
- RFC 4301 — Security Architecture for the Internet Protocol (IPsec) (`xfrm`).
- RFC 3549 — Linux netlink as an IP services protocol (XFRM and RTNETLINK wire layout).

### bindings
- Follows the specs of whichever module is wrapped (GTP, SIP, Diameter, IPsec).

## Build

```sh
cmake -B build && cmake --build build
ctest --test-dir build
```

The generated codec layers (`gtp/v?/gen`, `diam/gen`) are committed, so a
normal build needs no Go toolchain; the SWIG bindings and the GTP-U eBPF
datapath are auto-detected and skipped cleanly when their toolchains
(SWIG/Python, clang/libbpf) are absent.

### Lint and format

When clang-format/clang-tidy are installed, the build offers (see
`cmake/ClangTools.cmake`; generated code is excluded throughout):

```sh
cmake --build build --target format        # re-format in place
cmake --build build --target format-check  # verify, fail on drift
cmake --build build --target tidy          # clang-tidy over the whole tree
```

Configuring with `-DENABLE_CLANG_TIDY=ON` additionally runs clang-tidy
on every translation unit as it compiles.
