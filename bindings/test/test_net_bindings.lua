#!/usr/bin/env lua
-- Tests for the SWIG Lua net module (bindings/swig/net.i).
--
-- SWIG has no Lua directors, so the loop callbacks are bridged by hand:
-- a timer or fd callback is a bare function (see the SWIGLUA block in
-- net.i). These cover the two layers of the facade end to end:
--   - loop: timers fire in due order, cancel() suppresses one, a Lua
--     error in a handler surfaces from run(), fds dispatch on readable;
--   - UDP socket: ephemeral bind, loopback send/recv (blocking and via
--     the loop), recv timeout, binary-safe payloads, connected send, and
--     loop-driven output (tx_loop: queue now, batched sendmmsg later).
--
-- Everything runs over 127.0.0.1 loopback, so no network or privilege.
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_net_bindings.lua

local net = require("net")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end
local function raises(fn)
    return not pcall(fn)
end

-- constants -----------------------------------------------------------
check(net.NET_RD == 1, "NET_RD")
check(net.NET_WR == 2, "NET_WR")
check(net.NET_ER == 4, "NET_ER")
check(net.NET_TIMEOUT == -2, "NET_TIMEOUT")

-- monotonic clock -----------------------------------------------------
check(type(net.now_ms()) == "number", "now_ms returns a number")
check(net.now_ms() >= 0, "now_ms non-negative")

-- timers fire, in due order -------------------------------------------
do
    local loop  = net.Loop()
    local fired = {}
    loop:after(1, function() fired[#fired + 1] = "a" end)
    loop:after(6, function() fired[#fired + 1] = "b"; loop:stop() end)
    loop:run()
    check(#fired == 2, "both timers fired before stop")
    check(fired[1] == "a" and fired[2] == "b", "timers fire in due order")
end

-- cancel suppresses a pending timer -----------------------------------
do
    local loop = net.Loop()
    local hit  = false
    local id   = loop:after(10, function() hit = true end)
    loop:cancel(id)
    loop:after(20, function() loop:stop() end)
    loop:run()
    check(not hit, "cancelled timer does not fire")
end

-- a Lua error in a handler surfaces from run() ------------------------
do
    local loop = net.Loop()
    loop:after(0, function() error("boom") end)
    check(raises(function() loop:run() end), "handler error surfaces from run")
end

-- UDP: ephemeral bind, loopback send/recv (blocking) ------------------
do
    local a = net.UdpSocket("127.0.0.1", 0)
    local b = net.UdpSocket("127.0.0.1", 0)
    check(a:local_port() ~= 0, "ephemeral port assigned")
    check(a:local_host() == "127.0.0.1", "local host reported")

    b:sendto("hello", "127.0.0.1", a:local_port())
    local dg = a:recv(1000)
    check(not dg.timed_out, "recv got a datagram")
    check(dg.data == "hello", "payload round-trips")
    check(dg.port == b:local_port(), "sender port reported")
    check(dg.host == "127.0.0.1", "sender host reported")

    -- nothing pending -> timeout
    check(a:recv(0).timed_out, "recv times out when nothing is queued")

    -- payloads are byte strings: embedded NULs and high bytes survive
    local blob = "\0\1\2\255\0end"
    b:sendto(blob, "127.0.0.1", a:local_port())
    check(a:recv(1000).data == blob, "binary payload survives")
end

-- UDP: event-loop receive via add_fd ----------------------------------
do
    local loop = net.Loop()
    local srv  = net.UdpSocket("127.0.0.1", 0)
    local got
    loop:add_fd(srv:fd(), net.NET_RD, function(fd, ev)
        check(fd == srv:fd(), "io callback gets the fd")
        check(ev ~= 0, "io callback reports an event mask") -- no bitwise: 5.1-safe
        got = srv:recv(-1).data
        loop:stop()
    end)
    local cli = net.UdpSocket("127.0.0.1", 0)
    cli:sendto("via-loop", "127.0.0.1", srv:local_port())
    loop:after(1000, function() loop:stop() end) -- safety net
    loop:run()
    check(got == "via-loop", "event loop delivered the datagram")
end

-- UDP: connected send (no per-call address) ---------------------------
do
    local peer = net.UdpSocket("127.0.0.1", 0)
    local c    = net.UdpSocket("127.0.0.1", 0)
    c:connect("127.0.0.1", peer:local_port())
    c:send("connected")
    check(peer:recv(1000).data == "connected", "connected send delivers")
end

-- UDP: loop-driven output (tx_loop) -----------------------------------
-- After tx_loop() a sendto() only queues the datagram; the loop pushes the
-- queue out with sendmmsg() at the top of the next iteration, so a whole
-- burst leaves in one syscall instead of one per datagram.
do
    check(net.NET_TXQ_BATCH == 64, "NET_TXQ_BATCH")

    local loop = net.Loop()
    local srv  = net.UdpSocket("127.0.0.1", 0)
    local cli  = net.UdpSocket("127.0.0.1", 0)
    check(not cli:tx_queued(), "output is direct by default")
    cli:tx_loop(loop)
    check(cli:tx_queued(), "output moved onto the loop")

    local N = 10
    for i = 1, N do cli:sendto("q" .. i, "127.0.0.1", srv:local_port()) end
    check(cli:tx_pending() == N, "sends only queued, no syscall yet")
    check(srv:recv(-1).timed_out, "nothing on the wire before the loop runs")

    check(cli:tx_flush() == N, "flush pushes the whole queue")
    check(cli:tx_pending() == 0, "queue drained")
    check(cli:tx_sent() == N, "sent counted")
    check(cli:tx_calls() == 1, "the batch went out in ONE sendmmsg call")
    check(cli:tx_dropped() == 0, "nothing dropped")

    local got = {}
    for _ = 1, N do
        local dg = srv:recv(500)
        if dg.timed_out then break end
        got[#got + 1] = dg.data
    end
    check(#got == N, "every queued datagram arrived")
    check(got[1] == "q1" and got[N] == "q" .. N, "FIFO order preserved")

    -- the loop flushes on its own, before it polls
    cli:sendto("via-step", "127.0.0.1", srv:local_port())
    check(cli:tx_pending() == 1, "queued, awaiting the loop")
    loop:step(0)
    check(cli:tx_pending() == 0, "the loop flushed it")
    check(srv:recv(500).data == "via-step", "loop-flushed datagram arrived")

    -- a connected socket queues without a per-call address
    local c2 = net.UdpSocket("127.0.0.1", 0)
    c2:connect("127.0.0.1", srv:local_port())
    c2:tx_loop(loop)
    c2:send("connected-queued")
    check(c2:tx_flush() == 1, "connected send flushes")
    check(srv:recv(500).data == "connected-queued", "connected queued send delivers")

    check(raises(function() cli:tx_loop(loop) end), "tx_loop twice raises")
end

-- bad address is rejected ---------------------------------------------
check(raises(function() net.UdpSocket("not-an-ip", 0) end),
    "bad bind address raises")

-- interface helpers ---------------------------------------------------
do
    -- introspection over the always-present loopback interface
    check(net.if_index("lo") ~= 0, "if_index resolves lo")
    check(net.if_index("nosuchif0") == 0, "if_index is 0 for an absent interface")
    check(net.if_addr4("lo"):match("^%d+%.%d+%.%d+%.%d+$") ~= nil,
        "if_addr4 reports the loopback address")

    -- addr_add/addr_del validate the interface before any privileged
    -- netlink op, so an unknown name raises without CAP_NET_ADMIN. The
    -- live add/del round-trip is covered by netlink/rtnl's C test.
    check(raises(function() net.addr_add("nosuchif0", "10.0.0.1", 32) end),
        "addr_add raises for an unknown interface")
    check(raises(function() net.addr_del("nosuchif0", "10.0.0.1", 32) end),
        "addr_del raises for an unknown interface")
end

-- stream socket: listen / connect / accept / send / recv / close --------
do
    check(net.PROTO_TCP == 0, "PROTO_TCP")
    check(net.PROTO_SCTP == 132, "PROTO_SCTP")

    local lst = net.StreamListener("127.0.0.1", 0, net.PROTO_TCP)
    check(lst:local_port() ~= 0, "listener ephemeral port assigned")
    check(lst:local_host() == "127.0.0.1", "listener local host reported")
    -- nothing pending yet -> accept polls once and returns nil
    check(lst:accept(-1) == nil, "accept returns nil when nothing is pending")

    local cli = net.stream_connect("127.0.0.1", lst:local_port(), net.PROTO_TCP)
    local srv = lst:accept(200)
    check(srv ~= nil, "accept returns a connection")
    check(srv:peer_host() == "127.0.0.1", "accepted peer host reported")

    -- byte-safe round trip (embedded NULs / high bytes)
    local blob = "\0\1\2\255diameter\0"
    cli:send(blob)
    local d = srv:recv(1000)
    check(not d.timed_out and not d.closed, "server received data")
    check(d.data == blob, "stream payload round-trips byte-for-byte")

    srv:send("pong")
    check(cli:recv(1000).data == "pong", "reply round-trips")

    -- nothing pending -> recv polls once and times out
    check(srv:recv(-1).timed_out, "recv times out when nothing is queued")

    -- a peer close surfaces as closed (not a timeout)
    cli:close()
    local closed
    for _ = 1, 50 do
        local r = srv:recv(20)
        if r.closed then closed = true; break end
        if not r.timed_out then break end
    end
    check(closed, "peer close is reported as closed")
    srv:close()

    check(raises(function() net.StreamListener("not-an-ip", 0) end),
        "bad listen address raises")
    check(raises(function() net.stream_connect("127.0.0.1", 1, net.PROTO_TCP, 200) end),
        "connect to a dead port raises")
end

-- IP pool: scope layout, reuse, reservation ---------------------------
do
    local p = net.IpPool("10.45.0.0/16")
    -- an IPv4 scope keeps its network and broadcast address out
    check(p:size() == 65534, "scope excludes network and broadcast")
    check(p:available() == 65534 and p:used() == 0, "empty pool")
    check(p:alloc() == "10.45.0.1", "first address is the network + 1")
    check(p:used() == 1, "used counted")
    check(p:allocated("10.45.0.1"), "allocated address reported")
    check(not p:allocated("10.45.0.2"), "free address reported")
    check(p:index_of("10.45.0.1") == 0, "slot numbering starts at the first")
    check(p:index_of("10.99.0.1") == -1, "foreign address has no slot")
    check(p:addr_at(65533) == "10.45.255.254", "last slot is broadcast - 1")

    -- a released address waits for the cursor to come round again
    p:release("10.45.0.1")
    check(p:used() == 0, "release accounted")
    check(p:alloc() == "10.45.0.2", "released address is not reused at once")
    check(raises(function() p:release("10.45.0.1") end), "double release raises")
    check(raises(function() p:release("10.99.0.1") end),
        "release of a foreign address raises")

    -- reservation takes a specific address (a gateway) out of circulation
    p:reserve("10.45.0.3")
    check(raises(function() p:reserve("10.45.0.3") end), "double reserve raises")
    check(p:alloc() == "10.45.0.4", "allocation skips the reserved address")

    p:reset()
    check(p:used() == 0 and p:alloc() == "10.45.0.1", "reset starts over")

    -- explicit range, both ends usable, then exhaustion
    local r = net.IpPool("10.45.9.10", "10.45.9.12")
    check(r:size() == 3, "range size")
    check(r:alloc() == "10.45.9.10" and r:alloc() == "10.45.9.11" and
          r:alloc() == "10.45.9.12", "range hands out both ends")
    check(raises(function() return r:alloc() end), "exhausted pool raises")
    check(r:available() == 0, "no addresses left")

    -- IPv6 scopes use every address of the prefix
    local v6 = net.IpPool("2001:db8::/120")
    check(v6:size() == 256, "IPv6 prefix keeps its network address")
    check(v6:alloc() == "2001:db8::" and v6:alloc() == "2001:db8::1",
        "IPv6 addresses round-trip as literals")
    check(v6:index_of("10.45.0.1") == -1, "families stay apart")

    check(raises(function() net.IpPool("10.0.0.0") end), "scope needs a prefix length")
    check(raises(function() net.IpPool("nope/24") end), "bad scope address raises")
    check(raises(function() net.IpPool("10.0.0.0/33") end), "bad prefix length raises")
end

if failed == 0 then
    print(string.format("ok - %d checks passed", tests))
    os.exit(0)
else
    print(string.format("FAILED - %d/%d checks failed", failed, tests))
    os.exit(1)
end
