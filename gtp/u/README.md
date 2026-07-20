# gtpu

GTP-U eBPF TC datapath — 3GPP TS 29.281

Two `BPF_PROG_TYPE_SCHED_CLS` programs on the clsact qdisc do the
per-packet work in the kernel, copy-free (`bpf_skb_adjust_room` +
`bpf_skb_store_bytes`, no clone helpers):

- **`gtpu_decap`** (ingress, GTP-U-facing interface): parses outer
  Eth + IPv4/IPv6 + UDP:2152 + GTP-U including the extension-header
  chain, looks the TEID up in `teid_rx_map`, strips the outer headers
  in-place and redirects the inner packet (`bpf_redirect`) or hands it
  to the local stack. Unknown TEIDs, End Markers and malformed inners
  are reported to userspace through a ring buffer; Echo and Error
  Indication fall through to the userspace socket untouched.
- **`gtpu_encap`** (egress, inner-traffic-facing interface): classifies
  the inner packet onto a bearer, grows headroom, writes the outer
  Eth + IP + UDP + GTP-U headers in-place and redirects to the uplink.
  Packets matching no tunnel pass through unmodified.

## Dedicated bearers / TEID

Each bearer is a TEID pair. RX side, dedicated bearers are just more
`teid_rx_map` entries. TX side, classification runs in two stages:

1. **TFT filters** (`teid_tft_map`, exact-match hash): the eBPF subset
   of a TS 24.008 TFT packet filter — inner `{family, protocol,
   UE port, remote port}` with 0 as wildcard, probed in four tiers from
   most to least specific. Port ranges expand to multiple entries.
2. **Default bearer** (`teid_tx4/6_map`, LPM trie): longest-prefix match
   on the inner destination (UE) address; supports per-UE /32 or /128
   entries as well as aggregate test prefixes.

5G QoS flows: a tunnel with `has_qfi` set emits the PDU Session
Container extension header (type 0x85) carrying the QFI.

## Userspace

`gtpu_ebpf.h` wraps loading (libbpf skeleton), attachment
(`bpf_tc_hook_create`/`bpf_tc_attach`, no `tc` CLI), map pinning under
`/sys/fs/bpf/gtpu` (state survives reloads; ABI-versioned, mismatches
refuse to load), the control-plane table ops (`gtpu_teid_add/update/del`,
`gtpu_tft_add/del`), per-TEID stats (per-CPU, summed on read) and the
event ring buffer. Without CAP_BPF/CAP_NET_ADMIN — or when built
without the toolchain — `gtpu_ebpf_open()` returns
`GTPU_E_UNSUPPORTED` so callers fall back to the userspace datapath.

The map/wire contract shared by both sides lives in `gtpu_abi.h`;
`test_gtpu` locks its layout.

## Build

clang, bpftool and libbpf ≥ 1.0 are auto-detected
(`cmake/BpfCompile.cmake`); BPF objects compile with
`clang -target bpf -g -O2`, DWARF stripped (BTF kept), skeletons via
`bpftool gen skeleton`.

```cmake
add_subdirectory(gtp/u)
target_link_libraries(your_target PRIVATE gtpu)
```

## Tests

`test_gtpu` runs anywhere. `test_gtpu_bpf` pushes crafted frames
through both programs with `BPF_PROG_TEST_RUN` — decap/encap field
checks, TFT tier selection, IPv6 outer UDP checksum validation, and a
decap(encap(pkt)) round trip — and skips cleanly without privileges:

```sh
sudo ./build/gtpu/test/test_gtpu_bpf
```

## Deviations from PLAN.md worth knowing

- Outer IPv4 packets with IP options and outer IPv6 with extension
  headers fall through to the stack (verifier-bounded parsing).
- The IPv4 header checksum is computed in-program over the 20 bytes we
  build (`bpf_l3_csum_replace` patches existing checksums; a
  from-scratch header needs the full sum). Same reasoning for the
  IPv6 UDP checksum, computed with `bpf_csum_diff` over 256-byte
  chunks; IPv6-outer payloads over 2 KB fall back to userspace.
- MAC resolution tries `bpf_fib_lookup` first with static per-tunnel
  MACs as fallback; `static_mac` skips the FIB entirely for
  deterministic lab topologies.
