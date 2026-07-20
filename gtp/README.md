# GTP — GPRS Tunnelling Protocol

The three protocol modules share this directory because they share the
wire: a GTP node signals sessions over GTP-C and moves user traffic
over GTP-U tunnels the signalling created.

| Module           | Protocol | Spec         | Library | Role                                            |
| ---------------- | -------- | ------------ | ------- | ----------------------------------------------- |
| [`v1/`](v1)      | GTPv1-C  | TS 29.060    | `gtp1`  | 2G/3G control plane (Gn/Gp: SGSN ↔ GGSN)        |
| [`v2/`](v2)      | GTPv2-C  | TS 29.274    | `gtp2`  | EPC control plane (S11, S5/S8: MME ↔ SGW ↔ PGW) |
| [`u/`](u)        | GTP-U    | TS 29.281    | `gtpu`  | user plane (S1-U, S5/S8-U), eBPF TC datapath    |

Scripting bindings for GTPv2-C sessions and the GTP-U datapath live in
[`bindings/`](../bindings) (Python via SWIG).

## How the pieces fit

A subscriber session ("PDN connection") is created over GTP-C; the
messages carry each side's **F-TEID** (IP address + Tunnel Endpoint
Identifier) for both the control plane and, per bearer, the user
plane. Once both ends know each other's user-plane F-TEID, IP packets
for the UE flow inside GTP-U G-PDUs between those endpoints:

```
   MME ──S11 (GTPv2-C)── SGW ──S5/S8 (GTPv2-C)── PGW
                          │                       │
  eNB ═══ S1-U (GTP-U) ═══╧═══ S5/S8-U (GTP-U) ═══╧═══ internet
```

- **Create Session Request/Response** establishes the session and the
  default bearer, and exchanges the user-plane F-TEIDs — the response
  is the moment a node can install its forwarding entry (`gtpu`'s
  `gtpu_teid_add`, or `on_user_plane()` in the bindings).
- **Modify Bearer Request/Response** re-anchors the user plane (e.g.
  after handover the eNB-side F-TEID changes).
- **Create/Update/Delete Bearer** manage dedicated bearers: extra
  TEID pairs selected by traffic filters (TFT).
- **Delete Session Request/Response** tears everything down.
- **Echo Request/Response** is path management; the Recovery IE's
  restart counter tells peers a node rebooted.

GTPv1-C plays the same role for 2G/3G (Create/Update/Delete PDP
Context); GTP-U is shared by both generations — its header is the
GTPv1 header with message type 255 (G-PDU) carrying the inner packet.

## Layering

Each control-plane module has the same three layers:

1. **header + IE codec** (`gtp1.h` / `gtp2.h`) — zero-copy iterators
   over IEs, allocation-free writers into caller buffers;
2. **sub-IE codecs** (`gtp2_ie.h`) — typed views of composite values
   (F-TEID, Bearer QoS, PAA, AMBR);
3. **typed messages** (`gtp1_msg.h` / `gtp2_msg.h`) — struct-level
   encode/decode per message, mandatory-IE validation.

The message layers are generated at build time by [`gen/`](gen), a
small dependency-free Go program holding the curated message grammars
(`gen/gtp1.go`, `gen/gtp2.go`) and the C templates (`gen/templates/`);
the generated sources exist only in the build tree, so building gtp1/
gtp2 requires a Go toolchain. Both v1 and v2 bind the
shared zero-copy TLV codec / write buffer from `task/inc/tlv.h`
(GTPv1 only for the write side — its mixed TV/TLV IE encoding needs a
local iterator).

The GTP-U module is different in kind: the per-packet work runs as two
TC eBPF programs in the kernel, and `gtpu_ebpf.h` is the userspace
loader plus the control-plane API that keeps the kernel forwarding
maps in sync with GTP-C signalling. See [`u/README.md`](u/README.md).

## Choosing an entry point

- Building a node or tester in C: use the typed message layer
  (`gtp2_msg.h`), drop to the IE codec for messages it doesn't cover.
- Scripting (load tests, protocol experiments, lab tooling): use the
  Python bindings — session workflow, event loop and user-plane
  install are packaged behind callbacks. See
  [`bindings/README.md`](../bindings/README.md).
- Forwarding only (a pure user-plane node): `gtpu` standalone.

## Specs

The pinned spec releases live under [`specs/`](../specs): TS 29.060
(GTPv1-C), TS 29.274 (GTPv2-C). TS 29.281 (GTP-U) is small enough
that `u/` documents the relevant parts inline.
