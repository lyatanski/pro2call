#!/usr/bin/env lua
-- Tests for the SWIG Lua net module (bindings/swig/net.i).
--
-- SWIG has no Lua directors, so the loop callbacks are bridged by hand:
-- a timer or fd callback is a bare function (see the SWIGLUA block in
-- net.i). These cover the two layers of the facade end to end:
--   - loop: timers fire in due order, cancel() suppresses one, a Lua
--     error in a handler surfaces from run(), fds dispatch on readable;
--   - UDP socket: ephemeral bind, loopback send/recv (blocking and via
--     the loop), recv timeout, binary-safe payloads, connected send.
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

-- bad address is rejected ---------------------------------------------
check(raises(function() net.UdpSocket("not-an-ip", 0) end),
    "bad bind address raises")

if failed == 0 then
    print(string.format("ok - %d checks passed", tests))
    os.exit(0)
else
    print(string.format("FAILED - %d/%d checks failed", failed, tests))
    os.exit(1)
end
