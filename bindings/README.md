# bindings — scripting the protocol stacks

SWIG bindings for the C libraries. The GTP stack (`gtp`) is exposed as
both a Python and a Lua module; the IPsec/XFRM (`ipsec`), SIP codec
(`sip`), Diameter codec (`diam`) and transport layer (`net`) modules are
Lua. Each is the same two-layer pattern; the GTP module described below
is the most involved:

- **`cxx/` — gtpxx**, a C++17 facade over the C libraries, written to
  be wrapped: value-type messages (nothing borrows from decode
  buffers), human-format fields (IMSI digit strings, dotted APNs,
  literal IP addresses), exceptions instead of return codes, and
  virtual-method handler classes for every callback. Usable directly
  from C++ as well.
- **`swig/gtp.i`** — the SWIG interface: the same facade drives both
  languages. Byte fields map to `bytes` (Python) or strings (Lua).
  Callbacks differ: Python uses SWIG directors (subclass the handler
  classes) plus keep-alive pinning; SWIG has no Lua directors, so Lua
  callbacks are bridged by hand — a handler is a table of functions, a
  timer/io callback a bare function, and the adapters are pinned in C++
  registries so the collector cannot free one the C++ side still calls.

What it covers:

| Area | API |
| ---- | --- |
| GTPv2-C session workflow | `Loop`, `Endpoint`, `Session`, `EndpointHandler` |
| Typed messages (TS 29.274 §7.2) | `CreateSessionRequest/Response`, `ModifyBearerRequest/Response`, `DeleteSessionRequest/Response` |
| Any other GTPv2-C message | `RawMessage` + `Ie` trees (grouped IEs included) |
| GTP-U eBPF datapath (gtp/u) | `UserPlane`, `Tunnel`, `TrafficFilter` |
| Script transport | `UdpSocket` (thin synchronous UDP over the loop machinery) |
| Wire helpers | `bcd_encode/decode`, `apn_encode/decode` |
| Constants | all `GTP2_MT_*`, `GTP2_IE_*`, `GTP2_CAUSE_*`, `GTP2_RAT_*`, `GTP2_IF_*`, `GTP2_PDN_*` |

## Build

Needs SWIG >= 4.0 and the Python development files; without them the
directory is skipped and the C build is unaffected.

```sh
cmake -B build && cmake --build build      # python/{gtp.py,_gtp.so}, lua/{gtp,sip,ipsec}.so
export PYTHONPATH=$PWD/build/bindings/python
python3 -c "import gtp; print(gtp.GTPC_PORT)"
export LUA_CPATH=$PWD/build/bindings/lua/'?.so'
lua -e 'print(require("gtp").GTPC_PORT)'
```

`ctest` runs the binding suites — `test/test_bindings.py` and the Lua
`test_gtp_bindings.lua` / `test_sip_bindings.lua` /
`test_diam_bindings.lua` / `test_bindings.lua` (ipsec) — along with the
C tests.

## Creating a session

The `Endpoint` owns a GTP-C UDP socket registered with a `net.Loop`
(the transport module's epoll dispatcher, `net/inc/net_loop.h` — the
same one the C libraries use, shared across the gtp/sip/diam stacks).
It allocates sequence numbers and local control TEIDs, retransmits
requests (T3-RESPONSE/N3, configurable via `set_t3_ms`/`set_n3`),
matches responses to transactions, and answers Echo Requests by
itself. You implement an `EndpointHandler` and react:

```python
import gtp
import net

loop = net.Loop()
ep = gtp.Endpoint(loop, "10.0.0.1")          # binds 10.0.0.1:2123

class Handler(gtp.EndpointHandler):
    def on_create_session_response(self, sess, rsp):
        print("cause", rsp.cause, "UE addr",
              rsp.paa.addr4 if rsp.has_paa else "-")

    def on_user_plane(self, sess, tun):
        # Fired once per bearer F-TEID in an accepted response: the
        # peer's data-plane endpoint is known, create the tunnel here.
        print(f"EBI {tun.ebi}: {tun.local_teid:#x} -> "
              f"{tun.remote_teid:#x} @ {tun.remote_addr}")

    def on_timeout(self, sess, message_type):
        print("no answer")

ep.set_handler(Handler())

req = gtp.CreateSessionRequest()
req.imsi = "001010123456789"                 # digit string -> BCD
req.apn = "internet"                         # dotted name -> labels
req.rat_type = gtp.GTP2_RAT_EUTRAN
req.pdn_type = gtp.GTP2_PDN_IPV4

bearer = gtp.BearerContext()                 # EBI defaults to 5
up = gtp.Fteid()
up.if_type = gtp.GTP2_IF_S1U_ENODEB          # our user-plane F-TEID
up.teid = 0x100
up.addr4 = "10.0.0.1"
bearer.add_fteid(0, up)
req.add_bearer(bearer)

sess = ep.create_session(req, "10.0.0.2")    # -> Session, request sent
loop.run()                                   # or loop.step(ms) yourself
```

`create_session` fills in whatever was left unset: the sequence
number, the sender F-TEID's TEID (a fresh local control TEID) and
address (the endpoint's bound address); a fully default `sender_fteid`
also gets interface type S11 MME. The returned `Session` tracks state
(`CREATING → ACTIVE → DELETING → DELETED`, or `FAILED`) and drives the
rest of the workflow:

```python
sess.modify_bearer(mb_req)     # TEID/sequence filled in
sess.delete_session()          # DSReq with the default bearer's EBI
sess.user_plane()              # tunnels from the last accepted response
```

Sessions are owned by the endpoint and stay valid (state `DELETED`)
until `ep.purge()` drops finished ones.

## Setting up the user-plane tunnel

`on_user_plane(sess, tun)` gives you the peer's data-plane F-TEID
(`tun.remote_teid`, `tun.remote_addr`) paired with the TEID you put in
the request's bearer (`tun.local_teid`), per bearer, whenever a Create
Session or Modify Bearer Response carries one. What "creating the user
plane" means is up to the node; with the kernel eBPF datapath
(`gtp/u`) it is one call:

```python
up = gtp.UserPlane(gtp.UserPlaneConfig())    # needs CAP_BPF + CAP_NET_ADMIN
up.attach(gtpu_ifindex, inner_ifindex)

def on_user_plane(self, sess, tun):
    t = gtp.Tunnel()
    t.local_teid  = tun.local_teid           # RX: G-PDUs addressed to us
    t.remote_teid = tun.remote_teid          # TX: written to outgoing G-PDUs
    t.remote_addr = tun.remote_addr
    t.ue_addr     = ue_ip                    # from rsp.paa
    t.ebi         = tun.ebi
    up.add_tunnel(t)
```

`UserPlane.supported()` reports whether the process has the
capabilities; construction raises otherwise. A tunnel at the anchor end
of the bearer (a PGW/UPF, which decapsulates uplink coming *from* the UE
rather than downlink heading to it) sets `t.core_side = True`; `ue_addr`
still steers the downlink encap, but decap stops requiring the inner
destination to be the UE. Dedicated bearers add a
`TrafficFilter` (`add_filter`) steering inner packets by protocol and
ports onto their own TEID pair. `stats(teid)` reads the per-TEID
counters, and the datapath's ring-buffer events (unknown TEID, end
marker, ...) integrate with the loop:

```python
class Events(gtp.UserPlaneEventHandler):
    def on_event(self, kind, teid, src_addr, src_port): ...

class UpIo(gtp.IoHandler):
    def on_io(self, fd, events):
        up.poll_events(0, ev_handler)

loop.add_fd(up.events_fd(), gtp.NET_RD, UpIo())
```

## Server role and raw messages

Incoming requests are decoded and handed to the handler; reply with
the matching send, echoing the request's sequence and addressing the
peer's control TEID:

```python
class Server(gtp.EndpointHandler):
    def on_create_session_request(self, req, host, port):
        rsp = gtp.CreateSessionResponse()
        rsp.sequence = req.sequence
        rsp.teid = req.sender_fteid.teid
        rsp.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
        ...
        ep.send_create_session_response(rsp, host, port)
```

Messages without a typed struct arrive at `on_message(mt, wire, host,
port)` as bytes; `RawMessage` covers the full protocol:

```python
m = gtp.RawMessage()
m.message_type = gtp.GTP2_MT_CREATE_BEARER_RESPONSE
m.teid, m.sequence = peer_ctrl_teid, req_seq
bc = gtp.Ie()
bc.type = gtp.GTP2_IE_BEARER_CONTEXT           # grouped: children nest
bc.add_child(gtp.Ie(gtp.GTP2_IE_EBI, b"\x06"))
m.add_ie(bc)
ep.send_raw(m.encode(), host, port)

d = gtp.RawMessage.decode(wire)                # .ies, .find(), .has()
```

Decode recurses into the known grouped IE types; `gtp.ie_children()`
walks any other grouped value.

## gtp from Lua

The same workflow in Lua. There are no director subclasses: a handler
is a table of callback functions (absent keys are no-ops), methods are
called with `:`, and a timer or fd callback is a bare function. Field
access, enums (`gtp.GTP2_RAT_EUTRAN`, `gtp.Session.ACTIVE`) and the
value-type messages are identical to the Python surface; byte fields are
plain Lua strings.

```lua
local gtp = require("gtp")
local net = require("net")

local loop = net.Loop()
local ep   = gtp.Endpoint(loop, "10.0.0.1")

ep:set_handler({
    on_create_session_response = function(sess, rsp)
        print("cause", rsp.cause, "UE addr", rsp.has_paa and rsp.paa.addr4 or "-")
    end,
    on_user_plane = function(sess, tun)     -- install the GTP-U tunnel here
        print(("EBI %d: %#x -> %#x @ %s")
            :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
    end,
    on_timeout = function(sess, message_type) print("no answer") end,
})

local req = gtp.CreateSessionRequest()
req.imsi = "001010123456789"                 -- digit string -> BCD
req.apn  = "internet"                         -- dotted name -> labels
req.rat_type = gtp.GTP2_RAT_EUTRAN
local bc = gtp.BearerContext()                -- EBI defaults to 5
local up = gtp.Fteid()
up.if_type, up.teid, up.addr4 = gtp.GTP2_IF_S1U_ENODEB, 0x100, "10.0.0.1"
bc:add_fteid(0, up)
req:add_bearer(bc)

local sess = ep:create_session(req, "10.0.0.2")   -- request sent
loop:run()                                          -- or loop:step(ms) yourself
```

Raw messages, the user plane and the loop's `after`/`add_fd` map the
same way: `loop:after(3000, function() ... end)`, `up:poll_events(0,
function(kind, teid, addr, port) ... end)`, `gtp.RawMessage`, `gtp.Ie`.
A Lua error raised in any handler stops the loop and re-raises from
`loop:step()`/`loop:run()`, just as a Python exception does.

## Conventions and lifetime rules

- Absent optional scalars are `-1`; absent struct-valued fields have a
  `has_*` flag; absent strings/bytes are empty. `encode()` raises on
  missing mandatory IEs (`RuntimeError`, like every other failure).
- Exceptions raised inside Python callbacks do not vanish: the loop
  stops and the exception re-raises from `loop.step()`/`loop.run()`
  with its type intact.
- The C++ side borrows handlers and the loop; the Python layer pins
  them (`ep._loop`, `ep._handler`, timer/io handlers on the `Loop`,
  the endpoint on returned `Session` proxies) so normal code cannot
  free them prematurely. The one rule that remains yours: a `Session`
  reference obtained inside a callback is only valid until that
  endpoint's `purge()`.
- Everything is single-threaded by design, like the loop it wraps.
  Run one `Loop` per thread if you need more.

## Lua: sip

The `sip` module wraps the sipxx facade (`cxx/inc/sipxx.hpp`) over the
SIP codec ([`sip/`](../sip)). Value types only — messages are parsed
into owned copies, methods and header fields are enum constants
(`sip.INVITE`, `sip.H_VIA`, ...) so a compact `v:` and a long `Via:`
are the same id, and failures raise Lua errors:

```lua
local sip = require("sip")

local wire = sip.Builder()
    :request(sip.INVITE, "sip:bob@biloxi.example.com")
    :header(sip.H_VIA, "SIP/2.0/UDP host;branch=z9hG4bK1")
    :header_u32(sip.H_MAX_FORWARDS, 70)
    :done(sdp)                       -- adds Content-Length itself

local msg = sip.parse(wire)
print(msg.uri, msg:call_id(), msg:cseq().number, msg:top_via().branch)
```

`sip.Transaction` wraps the RFC 3261 §17 transaction machines
(`sip/inc/sip_fsm.h`): pick a kind (`sip.INVITE_CLIENT`,
`sip.INVITE_SERVER`, `sip.NON_INVITE_CLIENT`, `sip.NON_INVITE_SERVER`)
and drive it straight from the traffic — `send(msg)`/`recv(msg)`
derive the event from the message, `event()` injects timers
(`sip.TE_TIMER_TIMEOUT`, ...). Illegal moves raise:

```lua
local t = sip.Transaction(sip.INVITE_CLIENT)
t:send(sip.parse(invite))            -- Init -> Calling
t:recv(sip.parse(ringing))           -- Calling -> Proceeding
t:recv(sip.parse(ok200))             -- Proceeding -> Terminated
print(t:state_name(), t:terminated())
```

The layers above transactions (`sip/inc/sip_dialog.h`) wrap the same
way, state-only and driven from the traffic:

- `sip.Dialog` — the RFC 3261 §12 dialog (Init → Early → Confirmed →
  Terminated): `recv`/`send` read an INVITE's dialog-forming 1xx (a
  To-tag present), its 2xx, or a BYE; `early()`/`confirmed()`/
  `terminated()` report where it is.
- `sip.Registration` — the RFC 3261 §10 / TS 24.229 §5.1 registration
  usage: `send(register)` registers, `recv` splits the reply (401/407
  challenges, 2xx advances, else fails), and once `registered()` a
  further `send` refreshes — or de-registers when the REGISTER carries
  `Expires: 0`, ending in `done()`.
- `sip.AuthChallenge` — the RFC 3261 §22 / RFC 2617 digest challenge-
  response the registration delegates to; IMS-AKA (RFC 3310) drives the
  same machine.

```lua
local reg  = sip.Registration()
local auth = sip.AuthChallenge()
local txn  = sip.Transaction(sip.NON_INVITE_CLIENT)  -- one per REGISTER

reg:send(sip.parse(register1)); auth:send(sip.parse(register1)); txn:send(sip.parse(register1))
reg:recv(sip.parse(challenge)); auth:recv(sip.parse(challenge))  -- -> Challenged
reg:send(sip.parse(register2)); auth:send(sip.parse(register2))  -- credentialed
reg:recv(sip.parse(ok200));     auth:recv(sip.parse(ok200))      -- -> Registered
print(reg:state_name(), reg:registered(), auth:authenticated())
```

The `ipsec` module (same pattern over [`netlink/xfrm/`](../netlink/xfrm))
is described in `swig/ipsec.i`: `ipsec.Xfrm` for SAs and policies, plus the
IMS-AKA primitives its ESP keys come from — `ipsec.aka_opc`,
`ipsec.aka_milenage` and `ipsec.aka_verify` (Milenage, TS 35.206) and
`ipsec.md5` (for the HTTP Digest AKAv1-MD5 response).

## Lua: diam

The `diam` module wraps the diamxx facade (`cxx/inc/diamxx.hpp`) over
the Diameter codec and generated dictionary ([`diam/`](../diam)).
Value types only — grouped AVPs parse into `children` eagerly, all
dictionary constants are exposed with the `DIAM_` prefix stripped
(`diam.AVP_SESSION_ID`, `diam.CMD_CREDIT_CONTROL`, `diam.APP_CX`,
`diam.APP_GX`, `diam.CC_REQUEST_TYPE_INITIAL_REQUEST`,
`diam.AVP_CHARGING_RULE_INSTALL`, ...), and the Builder fills in
each AVP's vendor id and mandatory/vendor flags from the dictionary.
Codes shared between the IETF and 3GPP registries (the Rx media AVPs)
take the vendor explicitly:

```lua
local diam = require("diam")

local wire = diam.Builder()
    :request(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
    :ids(hbh, e2e)
    :put_str(diam.AVP_SESSION_ID, "gw;1;1")
    :put_u32(diam.AVP_CC_REQUEST_TYPE, diam.CC_REQUEST_TYPE_INITIAL_REQUEST)
    :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :put_u32(diam.AVP_RATING_GROUP, 100)
    :end_group()
    :done()

local msg = diam.parse(wire)
print(msg:name(), msg:str(diam.AVP_SESSION_ID),
      msg:find(diam.AVP_CC_REQUEST_TYPE):value_name())
```

`diam.Session` wraps the RFC 6733 §8.1 authorization session machines
(`diam/inc/diam_fsm.h`): `diam.Session(diam.SESS_CLIENT)` or
`diam.SESS_SERVER`, then `send(msg)`/`recv(msg)` as the session's
messages flow — an auth request opens it, STR/STA close it, answers
split on a 2xxx Result-Code (Experimental-Result-Code included).
Illegal moves raise:

```lua
local s = diam.Session(diam.SESS_CLIENT)
s:send(diam.parse(aar))              -- Idle -> Pending
s:recv(diam.parse(aaa))              -- Pending -> Open
s:send(diam.parse(str))              -- Open -> Discon
s:recv(diam.parse(sta))              -- Discon -> Closed
print(s:state_name(), s:closed())
```

## Lua: net

The `net` module wraps the netxx facade (`cxx/inc/netxx.hpp`) over the
transport layer ([`net/`](../net)): the epoll event loop, a non-blocking
UDP socket and a TCP/SCTP stream socket — the same machinery the gtp
module embeds for GTPv2-C, exposed on its own for scripts that just need
to move bytes and drive a loop (put SIP or Diameter on the wire, run their
own timers). It is the transport a codec-only module (`sip`, `diam`) pairs
with.

`net.Loop` is the dispatcher: `step(ms)`/`run()`/`stop()`, one-shot
timers with `after(ms, fn)` / `cancel(id)`, and arbitrary fds with
`add_fd(fd, events, fn)` / `mod_fd` / `del_fd`. As in gtp there are no
director subclasses — a timer or fd callback is a bare function, and an
error raised inside one stops the loop and re-raises from
`step()`/`run()`. `net.UdpSocket` binds a host/port (port 0 =
ephemeral), then `sendto`/`recv` (or `connect` + `send`); `recv(ms)`
emulates blocking up to the timeout, `recv(-1)` polls once to drain an
fd the loop signalled. Its `fd()` goes straight into `add_fd` for
event-driven receive:

```lua
local net  = require("net")
local loop = net.Loop()

local sock = net.UdpSocket("127.0.0.1", 0)          -- ephemeral port
loop:add_fd(sock:fd(), net.NET_RD, function(fd, ev)
    local dg = sock:recv(-1)                         -- non-blocking drain
    print(dg.host, dg.port, dg.data)                -- data is a byte string
    loop:stop()
end)

sock:sendto("ping", "127.0.0.1", sock:local_port())
loop:after(1000, function() loop:stop() end)        -- bound the wait
loop:run()
```

### Sends on the loop

By default a `sendto` is a `sendto(2)`: the caller enters the kernel once
per datagram. `sock:tx_loop(loop [, base_events])` moves the send side onto
the loop instead ([`net/inc/net_txq.h`](../net/inc/net_txq.h)) — a `sendto`
then copies the datagram into the socket's queue and returns, and the loop
pushes the queue out at the top of its next iteration with `sendmmsg(2)`,
up to `net.NET_TXQ_BATCH` (64) datagrams per syscall. Two things follow:

* a handler that emits a burst (N sessions opened, N responses answered)
  does not stop in the kernel between messages, and N datagrams on one
  socket leave in `ceil(N/64)` syscalls instead of N;
* a full socket buffer or qdisc (`EAGAIN`/`ENOBUFS`) suspends the queue and
  resumes it on writability, instead of failing the send — under burst that
  failure was indistinguishable from a real error.

Ordering is preserved, `base_events` is the fd's steady-state interest so
this composes with `add_fd` on the same fd, and the counters make the effect
visible: `tx_sent()`, `tx_calls()` (`sent/calls` = the batching ratio),
`tx_pending()`, `tx_blocked()`, `tx_dropped()`, plus `tx_flush()` to force
the queue out without running the loop. Leave it off for a linear script
that sends and then blocks in `recv()` — nothing would ever flush it.

`gtp.Endpoint` does this for its own socket by default (it is loop-driven by
construction); `ep:set_tx_loop(false)` reverts it to a direct send, and the
same `tx_*` counters apply. [`examples/udp_tx_bench.lua`](examples/udp_tx_bench.lua)
measures one loop's send path both ways, and `TX_MODE=loop|sync` switches
[`examples/ims_test_s5.lua`](examples/ims_test_s5.lua) between them.

For connection-oriented Diameter there is a stream socket. `net.Stream
Listener(host, port, proto)` binds and listens (proto `net.PROTO_TCP` or
`net.PROTO_SCTP`); its `fd()` goes into `add_fd`, and `accept(-1)` drains
the backlog (nil when nothing is pending). Each accepted `StreamConn`
(also what `net.stream_connect(host, port, proto)` returns for the client
side) is `recv(ms)` / `send(data)`; `recv` returns a `{data, timed_out,
closed}` record so a peer close is distinct from a timeout, and `recv(-1)`
polls once to drain a loop-signalled fd. Caller frames messages out of the
byte stream (for Diameter, by the header's Message Length). See
[`examples/cx_hss.lua`](examples/cx_hss.lua).

The module also exposes a few interface helpers: `net.if_index(name)` and
`net.if_addr4(name)` (introspection), and `net.addr_add(name, addr,
prefixlen)` / `net.addr_del(...)` — the `ip addr add/del` equivalents over
RTNETLINK ([`netlink/rtnl/`](../netlink/rtnl)), so a script can make an
address locally deliverable without shelling out to `ip` (they need
CAP_NET_ADMIN and raise on failure).

### net.IpPool

`net.IpPool` is the address allocator from
[`task/inc/ippool.h`](../task/inc/ippool.h) with a literal-string
surface — what a PGW/SMF assigns PDN addresses from, or a DHCP server its
leases. A scope is a CIDR prefix or a first..last pair; an IPv4 prefix
shorter than /31 excludes its network and broadcast address, as a DHCP
scope does. Allocation and release are O(1) over one occupancy bit per
address, and a released address is not handed out again until the
allocator has swept the rest of the pool — so a detaching UE's address
does not go straight to the next attach:

```lua
local pool = net.IpPool("10.45.0.0/16")     -- 65534 addresses
pool:reserve("10.45.0.1")                    -- keep the gateway out
if pool:available() > 0 then
    local ue = pool:alloc()                  -- "10.45.0.2"
    print(pool:used(), pool:allocated(ue), pool:index_of(ue))
    pool:release(ue)
end
local dhcp = net.IpPool("10.45.9.100", "10.45.9.200")   -- explicit range
local v6   = net.IpPool("2001:db8:0:1::/64")            -- IPv6 too
```

`alloc()` raises when the pool is exhausted (check `available()` first if
a caller would rather branch than catch), as do `reserve()` on an
already-taken address and `release()` on one that is not allocated —
double-release bugs surface instead of corrupting the accounting.
`reset()` releases everything.

## Examples

All in Lua; run each with `LUA_CPATH=<build>/bindings/lua/?.so lua …`.

- [`examples/udp_echo.lua`](examples/udp_echo.lua) — UDP send and
  receive driven by the `net` event loop: an echo server and a client
  over loopback, both fds registered with one `net.Loop`. Runs
  standalone.
- [`examples/udp_tx_bench.lua`](examples/udp_tx_bench.lua) — what one
  `net.Loop` can put on the wire, with and without the loop-driven send
  path (`TX_MODE=loop|sync`): datagrams/s offered, the send syscalls it
  took (batched `sendmmsg` vs one `sendto` each) and the back-pressure
  absorbed. Loopback only, so it measures the send path and not a core.
- [`examples/echo_probe.lua`](examples/echo_probe.lua) — liveness-probe
  a peer with Echo.
- [`examples/session_setup.lua`](examples/session_setup.lua) — attach a
  UE and install the GTP-U tunnel.
- [`examples/sip_transaction.lua`](examples/sip_transaction.lua) — a
  full INVITE transaction, both sides, offline.
- [`examples/sip_register.lua`](examples/sip_register.lua) — the RFC 3261
  §10 registration procedure, both sides, offline: a UAC composes
  `sip.Registration` (the §10 usage), `sip.AuthChallenge` (the §22 Digest
  challenge) and a per-REGISTER `sip.Transaction` against a stub registrar
  that challenges once and validates the digest, walking initial REGISTER
  → 401 → authenticated REGISTER → 200 → refresh → de-register and
  printing all three machines' states at each step.
- [`examples/sip_dump.lua`](examples/sip_dump.lua) — parse and dump a
  SIP message with resolved header ids.
- [`examples/ipsec_sa.lua`](examples/ipsec_sa.lua) — install and tear
  down a site-to-site ESP tunnel (SAs + policy) over XFRM.
- [`examples/cx_registration.lua`](examples/cx_registration.lua) — an
  IMS registration over Cx (UAR/MAR/SAR), both sides, offline.
- [`examples/cx_hss.lua`](examples/cx_hss.lua) — the HSS side of Cx as a
  live server: a `net.StreamListener` on TCP:3868 that the I-CSCF/S-CSCF
  connect to instead of a real HSS. It runs the Diameter base peer
  protocol (CER/CEA, DWR/DWA, DPR/DPA) and answers the Cx exchanges —
  UAR/UAA, MAR/MAA (a real Milenage vector minted with `ipsec.aka_milenage`
  from the shared USIM secret, for any IMSI, so the range registers without
  provisioning), SAR/SAA (returns the IMS subscription profile) and
  LIR/LIA. Point the CSCFs' Diameter peer at it to run the IMS core with no
  real HSS behind it (load testing the CSCF chain, not the HSS).
- [`examples/pgw_stub.lua`](examples/pgw_stub.lua) — a PGW stub: the
  S5/S8 anchor a test SGW attaches to, standing in for a real PGW-C+U.
  Three parts on one `net.Loop`: **GTP-C** in `gtp.Endpoint`'s server role
  (Create Session / Modify Bearer / Delete Session answered, a
  PCRF-installed rule pushed back out as a Create Bearer Request),
  **Gx** towards the PCRF (TS 29.212) over a `net.StreamConn` — CER/CEA
  and the watchdog, a CCR-I per PDN connection whose CCA-I supplies the
  QoS the Create Session Response grants, CCR-T on teardown, RAR/RAA —
  and the **eBPF GTP-U** datapath, one `core_side` tunnel per bearer.
  UE addresses come from `net.IpPool`: a specific requested address is
  honoured when free, exhaustion is answered with cause 84, and every
  Delete Session releases the address and reports what the bearer
  carried. With no `$GX_PCRF` the Gx interface stays down and a local
  default policy is used, so it runs standalone against
  [`examples/ims_test_s5.lua`](examples/ims_test_s5.lua).
- [`examples/rx_media_auth.lua`](examples/rx_media_auth.lua) — a VoLTE
  call's media authorization over Rx (AAR/STR), both sides, offline.
- [`examples/ro_credit_control.lua`](examples/ro_credit_control.lua) —
  an online-charging session over Ro (CCR-I/U/T against an OCS), both
  sides, offline.
- [`examples/ims_call_s5.lua`](examples/ims_call_s5.lua) — the UE side
  of an IMS-AKA registration and call over Gm, sent over a real UDP
  socket (`net.UdpSocket`) so it can run against a live IMS core: the
  Security-Client/Server agreement, Milenage on the USIM secret
  (`ipsec.aka_verify`) to verify AUTN and derive CK/IK, four
  transport-mode ESP SAs keyed from those (`ipsec.Xfrm`), then the
  protected REGISTER (AKAv1-MD5 via `ipsec.md5`) and INVITE, with a
  `sip.Transaction` tracking each transaction. Given a PGW address it
  first raises the PDN connection the access rides on — acting as the
  SGW it sends a GTPv2-C Create Session to the PGW over S5/S8
  (`gtp.Endpoint`) and registers callbacks for the PGW's responses (the
  PAA carries the UE's assigned address, `on_user_plane` the PGW's
  data-plane F-TEID), tearing it down with a Delete Session at the end.
  Run with no P-CSCF address it instead executes an offline self-test
  (Milenage known-answer vector, AUTN round-trip, message and SA
  construction) and needs neither network nor privilege.

## Extending

Adding a typed message (say Create Bearer Request) is mechanical: add a
value type in `cxx/inc/gtpxx.hpp` and write its `encode()`/`decode()` in
`cxx/src/msg.cpp` against the base IE codec (`gtp2.h` / `gtp2_ie.h`) —
the generated `gtp2_msg.h` layer exposes each IE only as an opaque view,
so the facade lays out and parses the IE stream itself. Rebuild and SWIG
picks it up from the header, in both languages. A further language is mostly a `swig_add_library(...
LANGUAGE ...)` away, but the callback story is per-language: Python
leans on SWIG directors with GC pinning, while Lua — which SWIG cannot
generate directors for — needs the hand-written adapter bridge in
`gtp.i`.
