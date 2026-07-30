#!/usr/bin/env lua
-- Tests for the SWIG Lua rtp module (bindings/swig/rtp.i).
--
-- Two layers, both covered end to end:
--   - the packet codec as a value type: encode/parse round trip with
--     CSRCs and a header extension, and a raise on non-RTP input;
--   - the media session: a pair of them on ONE net.Loop, sending both
--     ways, with sequence/timestamp advance, receive statistics, the
--     RFC 3550 §6 report exchange (SR -> RR -> RTT) and BYE.
--
-- The loop is the point as much as the codec is: rtp.Stream takes a
-- net.Loop (not a private rtp loop), so the last case puts a
-- gtp.Endpoint on the same loop and checks media still flows — that is
-- what lets one script drive GTP-C, SIP and RTP with a single run().
--
-- Everything runs over 127.0.0.1 loopback, so no network or privilege.
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_rtp_bindings.lua

local net = require("net")
local rtp = require("rtp")

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

-- Run the loop for ms milliseconds (the sessions' own report timers keep
-- it busy; the deadline is what ends it).
local function pump(loop, ms)
    loop:after(ms, function() loop:stop() end)
    loop:run()
end

-- Ports are picked from a per-run base so two sessions (each binding
-- port and port + 1) never collide with each other.
local PORT = 41000
local function port_pair()
    PORT = PORT + 4
    return PORT
end

local PCMU_160 = ("\170"):rep(160)   -- one 20 ms G.711 payload

-- constants -------------------------------------------------------------
check(rtp.PT_PCMU == 0, "PT_PCMU")
check(rtp.PT_PCMA == 8, "PT_PCMA")
check(rtp.PT_G729 == 18, "PT_G729")
check(rtp.PT_DYNAMIC == 96, "PT_DYNAMIC")

-- packet codec: round trip ---------------------------------------------
do
    local p = rtp.Packet()
    p.pt, p.marker, p.seq, p.ts, p.ssrc = rtp.PT_PCMU, true, 1234, 0x11223344, 0xdeadbeef
    p.payload = PCMU_160

    local wire = p:encode()
    check(#wire == 12 + 160, "encoded length is header + payload")

    local q = rtp.Packet.parse(wire)
    check(q.pt == rtp.PT_PCMU, "pt survives the round trip")
    check(q.marker == true, "marker survives")
    check(q.seq == 1234, "seq survives")
    check(q.ts == 0x11223344, "timestamp survives")
    check(q.ssrc == 0xdeadbeef, "ssrc survives")
    check(q.payload == PCMU_160, "payload survives byte for byte")
    check(q.has_ext == false, "no extension by default")
end

-- packet codec: CSRCs and a header extension ---------------------------
do
    local p = rtp.Packet()
    p.pt, p.seq, p.ssrc = rtp.PT_PCMA, 7, 1
    p.csrc:push_back(0xaaaaaaaa)
    p.csrc:push_back(0xbbbbbbbb)
    p.has_ext, p.ext_profile, p.ext = true, 0xbede, "\1\2\3\4"
    p.payload = "hi"

    local q = rtp.Packet.parse(p:encode())
    check(q.csrc:size() == 2, "both CSRCs survive")
    check(q.csrc[0] == 0xaaaaaaaa and q.csrc[1] == 0xbbbbbbbb, "CSRC values survive")
    check(q.has_ext and q.ext_profile == 0xbede, "extension profile survives")
    check(q.ext == "\1\2\3\4", "extension data survives")
    check(q.payload == "hi", "payload after ext survives")
end

-- packet codec: refuses what is not RTP --------------------------------
do
    check(raises(function() return rtp.Packet.parse("short") end),
          "parse raises on a truncated packet")
    check(raises(function() return rtp.Packet.parse(("\0"):rep(16)) end),
          "parse raises on version 0")
end

-- one loop, two sessions, both directions ------------------------------
do
    local loop = net.Loop()
    local pa, pb = port_pair(), port_pair()
    local a = rtp.Stream(loop, "127.0.0.1", pa)
    local b = rtp.Stream(loop, "127.0.0.1", pb)

    check(a:rtp_port() == pa, "session binds the requested RTP port")
    check(a:local_host() == "127.0.0.1", "local_host reads back")
    check(a:ssrc() ~= 0, "an SSRC was assigned")

    check(raises(function() a:send(PCMU_160, 160) end), "send without a peer raises")
    check(raises(function() a:set_payload_type(200) end), "payload type is range-checked")

    local got = {}
    b:set_handler({
        on_rtp = function(pkt, host, port)
            got[#got + 1] = { seq = pkt.seq, ts = pkt.ts, ssrc = pkt.ssrc,
                              len = #pkt.payload, host = host, port = port }
        end,
    })

    a:set_peer("127.0.0.1", pb)
    b:set_peer("127.0.0.1", pa)

    for _ = 1, 5 do a:send(PCMU_160, 160) end
    pump(loop, 60)

    check(#got == 5, ("all 5 packets arrived (got %d)"):format(#got))
    if #got == 5 then
        local seq_ok, ts_ok, ssrc_ok = true, true, true
        for i = 2, #got do
            if got[i].seq ~= (got[i - 1].seq + 1) % 65536 then seq_ok = false end
            if got[i].ts ~= (got[i - 1].ts + 160) % 4294967296 then ts_ok = false end
            if got[i].ssrc ~= got[1].ssrc then ssrc_ok = false end
        end
        check(seq_ok, "sequence advances by one per packet")
        check(ts_ok, "timestamp advances by ts_step per packet")
        check(ssrc_ok, "every packet carries the one SSRC")
        check(got[1].ssrc == a:ssrc(), "the SSRC is the sender's")
        check(got[1].len == 160, "payload length preserved on the wire")
        check(got[1].host == "127.0.0.1" and got[1].port == pa,
              "the source address/port is the sender's")
    end

    local sa, sb = a:stats(), b:stats()
    check(sa.tx_packets == 5, "sender counts 5 sent")
    check(sa.tx_octets == 5 * 160, "sender counts payload octets")
    check(sb.rx_packets == 5, "receiver counts 5 received")
    check(sb.rx_octets == 5 * 160, "receiver counts payload octets")
    check(sb.remote_ssrc == a:ssrc(), "receiver identified the remote SSRC")
    check(sb.rx_lost == 0, "no loss over loopback")

    -- and back the other way, on the same loop
    local back = 0
    a:set_handler({ on_rtp = function() back = back + 1 end })
    for _ = 1, 3 do b:send(PCMU_160, 160) end
    pump(loop, 60)
    check(back == 3, ("the reverse direction carries too (got %d)"):format(back))
    check(a:stats().rx_packets == 3, "reverse receive counted")
end

-- RTCP: SR out, RR back, and an RTT from the report block --------------
do
    local loop = net.Loop()
    local pa, pb = port_pair(), port_pair()
    local a = rtp.Stream(loop, "127.0.0.1", pa)
    local b = rtp.Stream(loop, "127.0.0.1", pb)

    -- 50 ms is far below RFC 3550's recommended minimum interval; that is
    -- deliberate here, so a sub-second test sees several reports.
    a:set_rtcp_interval(50)
    b:set_rtcp_interval(50)

    local srs, rrs, byes = 0, 0, {}
    local rr_blocks = {}
    b:set_handler({
        on_sender_report = function(ssrc, si, reports)
            srs = srs + 1
            check(ssrc == a:ssrc(), "SR carries the sender's SSRC")
            check(si.packet_count > 0, "SR sender info counts our packets")
        end,
        on_bye = function(ssrc, reason) byes[#byes + 1] = { ssrc = ssrc, reason = reason } end,
    })
    a:set_handler({
        on_receiver_report = function(ssrc, reports)
            rrs = rrs + 1
            for _, r in ipairs(reports) do rr_blocks[#rr_blocks + 1] = r end
        end,
    })

    a:set_peer("127.0.0.1", pb)
    b:set_peer("127.0.0.1", pa)

    -- Send enough to clear the receiver's probation (RFC 3550 A.1) so b
    -- has a source to report on.
    for _ = 1, 10 do a:send(PCMU_160, 160) end
    pump(loop, 400)

    check(srs > 0, ("b received a sender report (%d)"):format(srs))
    check(rrs > 0, ("a received a receiver report (%d)"):format(rrs))
    local about_us = nil
    for _, r in ipairs(rr_blocks) do
        if r.ssrc == a:ssrc() then about_us = r end
    end
    check(about_us ~= nil, "a report block describes our stream")
    if about_us then
        check(about_us.fraction_lost == 0, "the peer reports no loss")
        check(about_us.lsr ~= 0, "the block echoes our last SR (lsr)")
    end
    check(a:stats().rtt_ms >= 0,
          ("RTT was measured from the report block (%s)"):format(tostring(a:stats().rtt_ms)))
    check(b:stats().rtt_ms < 0, "the side that never sent an SR has no RTT")

    -- BYE closes the stream and stops the periodic reports.
    a:bye("test over")
    pump(loop, 60)
    check(#byes == 1, ("the peer saw one BYE (%d)"):format(#byes))
    if #byes == 1 then
        check(byes[1].ssrc == a:ssrc(), "BYE carries our SSRC")
        check(byes[1].reason == "test over", "BYE carries the reason")
    end
end

-- a handler error surfaces from run(), not through the C dispatcher ----
do
    local loop = net.Loop()
    local pa, pb = port_pair(), port_pair()
    local a = rtp.Stream(loop, "127.0.0.1", pa)
    local b = rtp.Stream(loop, "127.0.0.1", pb)
    a:set_peer("127.0.0.1", pb)
    b:set_handler({ on_rtp = function() error("boom") end })
    a:send(PCMU_160, 160)
    check(raises(function() pump(loop, 60) end), "handler error surfaces from run")
end

-- media and signalling on ONE loop (the loop unification) --------------
do
    local gtp  = require("gtp")
    local loop = net.Loop()

    -- A GTP-C endpoint on an ephemeral port, sharing the loop: this is
    -- the arrangement ims_test_s5.lua uses, and it could not be built
    -- while rtp carried its own Loop type.
    local ep = gtp.Endpoint(loop, "127.0.0.1", 0)
    check(ep ~= nil, "a gtp.Endpoint shares the loop")

    local pa, pb = port_pair(), port_pair()
    local a = rtp.Stream(loop, "127.0.0.1", pa)
    local b = rtp.Stream(loop, "127.0.0.1", pb)
    a:set_peer("127.0.0.1", pb)
    b:set_peer("127.0.0.1", pa)

    local rx = 0
    b:set_handler({ on_rtp = function() rx = rx + 1 end })

    -- A loop timer alongside the media, as the call phase's ring/hold
    -- timers are: both must run under the one dispatcher.
    local ticks = 0
    local function tick()
        ticks = ticks + 1
        a:send(PCMU_160, 160)
        if ticks < 5 then loop:after(10, tick) end
    end
    loop:after(10, tick)
    pump(loop, 200)

    check(ticks == 5, ("timers ran under the shared loop (%d ticks)"):format(ticks))
    check(rx == 5, ("media flowed under the shared loop (%d packets)"):format(rx))
end

-- the non-local source flag is accepted (binding it needs CAP_NET_ADMIN)
do
    local loop = net.Loop()
    local ok, err = pcall(rtp.Stream, loop, "127.0.0.1", port_pair(), true)
    -- Either it bound (privileged) or the kernel refused it; what must
    -- not happen is SWIG failing to find the 4-argument overload.
    check(ok or not tostring(err):match("no matching function"),
          "the nonlocal_src overload exists (" .. (ok and "bound" or tostring(err)) .. ")")
end

print(string.format("%s: %d checks, %d failed",
                    failed == 0 and "PASS" or "FAIL", tests, failed))
os.exit(failed == 0 and 0 or 1)
