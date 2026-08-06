# mobile-core protocol toolkit

Zero-copy C codecs and a eBPF datapath for the mobile-core
signalling and media protocols (GTP, Diameter, SIP, SDP, RTP, SMS, IPsec),
an epoll transport layer to run them, code generators for the spec-driven
layers, and Python/Lua bindings. Each module builds standalone as a CMake
subdirectory; the deeper per-module READMEs carry the usage detail.

## Modules

| Module | Description |
| ------ | ----------- |
| [`task/`](task) | Foundation library shared by every codec: generic zero-copy TLV codec, FSM engine, IP address pool with reuse, big-endian helpers, logging and test macros. |
| [`net/`](net) | Transport layer — non-blocking UDP/TCP/SCTP sockets, epoll event loop with batched loop-driven output (`sendmmsg`), async DNS resolver, TLS/DTLS over OpenSSL. |
| [`gtp/`](gtp) | GTP protocol family: GTPv1-C (`v1`), GTPv2-C (`v2`) and the GTP-U eBPF datapath (`u`). See [`gtp/README.md`](gtp/README.md). |
| [`diam/`](diam) | Diameter base codec plus a generated dictionary for the 3GPP Cx / Gx / Rx / Ro / Rf interfaces, and the RFC 6733 session state machines. |
| [`sip/`](sip) | SIP message codec — zero-copy parse, buffer-writing encode, enum-resolved methods and headers — plus the RFC 3261 transaction state machines. |
| [`sdp/`](sdp) | SDP session-description codec — zero-copy single-pass parse, enum-resolved attributes. |
| [`sms/`](sms) | SMS codec for SMS over IMS: TS 23.040 TPDUs, the TS 24.011 relay layer, and the TS 23.038 alphabets and data coding schemes. See [`sms/README.md`](sms/README.md). |
| [`json/`](json) | JSON codec — zero-copy parse into a caller-owned node pool, JSON Pointer lookup, and a writer that owns the punctuation. The text payload layer: 5G SBI bodies, and the configuration and results the tools themselves read and write. |
| [`rtp/`](rtp) | RTP/RTCP codec with the RFC 3550 receiver-side source tracker (sequence validation, loss, jitter). |
| [`nlmsg/`](netlink) | Kernel configuration over netlink: IPsec SA/policy management (`xfrm`, NETLINK_XFRM) and interface address add/del (`rtnl`, RTNETLINK `RTM_*ADDR`). |
| [`bindings/`](bindings) | SWIG bindings (Lua) over C++ facades of the C libraries. |

## Specifications

### task
- common reusable code (TLV codec, FSM engine, IP address pool, logging).

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
- RFC 7155 — Diameter NAS application (the AA command and access AVPs Rx reuses).
- 3GPP TS 29.229 — Cx interface (IMS HSS).
- 3GPP TS 29.212 — Gx interface (PCEF/PCRF policy and charging control).
- 3GPP TS 29.214 — Rx interface (policy/media authorization).
- 3GPP TS 32.299 — Diameter charging applications (Ro/Rf).
- 3GPP TS 29.328 / 29.329 — Sh interface (application server / HSS).
- 3GPP TS 29.338 — SGd / S6c interfaces (SMS over Diameter).

### sip
- RFC 3261 — SIP: Session Initiation Protocol (plus standard method/header extensions).

### sdp
- RFC 8866 — SDP: Session Description Protocol (plus RTP/AVP, ICE, DTLS-SRTP attributes).

### sms
- 3GPP TS 23.040 — realization of SMS: the six TPDU types, address fields,
  timestamps, validity periods, the user data header and concatenation.
- 3GPP TS 23.038 — SMS data coding schemes, the GSM 7-bit default alphabet
  and its extension table.
- 3GPP TS 24.011 — point-to-point SMS support: the RP layer (RP-DATA,
  RP-ACK, RP-ERROR, RP-SMMA) and its cause values.
- 3GPP TS 24.341 — SMS over IP: the `+g.3gpp.smsip` feature tag, the
  `application/vnd.3gpp.sms` body, and the MO/MT procedures over SIP MESSAGE.
- 3GPP TS 23.204 — architecture for SMS over generic IP (the IP-SM-GW).

### json
- RFC 8259 — JSON: the interchange format (strict: no trailing commas,
  comments, unquoted names, NaN or Infinity).
- RFC 6901 — JSON Pointer, the member path syntax `json_ptr()` resolves
  and RFC 6902 (JSON Patch) bodies carry.
- RFC 3629 — UTF-8, for the `\uXXXX` escapes and surrogate pairs of
  RFC 8259 §7 and the encoding validator.
- 3GPP TS 29.500 — 5G SBI: JSON over HTTP/2 is the payload of every
  service operation (the reason this codec is here).

### rtp
- RFC 3550 — RTP: transport for real-time applications (SR/RR/SDES/BYE, source tracker).
- RFC 3551 — RTP profile for audio/video (payload-type constants).

### netlink
- RFC 4301 — Security Architecture for the Internet Protocol (IPsec) (`xfrm`).
- RFC 3549 — Linux netlink as an IP services protocol (XFRM and RTNETLINK wire layout).

### bindings
- Follows the specs of whichever module is wrapped (GTP, SIP, SDP, SMS,
  Diameter, RTP, IPsec).

## Build

```sh
cmake -B build && cmake --build build
ctest --test-dir build
```

The generated codec layers (`gtp/gen`, `diam/gen`) are produced at build
time from the specifications pinned beside them and exist only in the
build tree, so a build needs a Go toolchain; the SWIG bindings and the
GTP-U eBPF datapath are auto-detected and skipped cleanly when their
toolchains (SWIG/Python, clang/libbpf) are absent.

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
