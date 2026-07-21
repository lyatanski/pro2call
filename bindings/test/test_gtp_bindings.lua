#!/usr/bin/env lua
-- Tests for the SWIG Lua gtp module (bindings/swig/gtp.i).
--
-- SWIG has no Lua directors, so the handler callbacks are bridged by
-- hand: a handler is a table of functions, a timer/io callback a bare
-- function (see the SWIGLUA block in gtp.i). These tests cover the three
-- layers of the facade, with the loopback session flow exercising that
-- bridge end to end:
--   - codec: helpers, typed message round-trips, raw IE trees, errors;
--   - loop: timers fire, a Lua error in a handler surfaces from step();
--   - session: a client and a server endpoint over loopback drive
--     Create/Modify/Delete Session, on_user_plane, echo and the T3/N3
--     retransmission timeout, all through Lua callback tables.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_gtp_bindings.lua

local gtp = require("gtp")
local net = require("net")   -- event loop the endpoint runs on

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

-- helpers -------------------------------------------------------------
check(gtp.bcd_decode(gtp.bcd_encode("234150999999999")) == "234150999999999", "bcd roundtrip")
check(gtp.bcd_encode("21") == string.char(0x12), "bcd wire: low nibble first")
check(gtp.bcd_encode("123") == string.char(0x21, 0xf3), "bcd wire: odd length padded 0xF")
check(raises(function() gtp.bcd_encode("12a") end), "bcd rejects non-digit")
local apn = gtp.apn_encode("internet.mnc015.mcc234.gprs")
check(apn:byte(1) == 8, "apn first label length")
check(gtp.apn_decode(apn) == "internet.mnc015.mcc234.gprs", "apn roundtrip")

-- a reusable sample Create Session Request ----------------------------
local function sample_cs_req()
    local req = gtp.CreateSessionRequest()
    req.sequence = 0x42
    req.imsi = "001010123456789"
    req.msisdn = "491701234567"
    req.apn = "internet"
    req.rat_type = gtp.GTP2_RAT_EUTRAN
    req.pdn_type = gtp.GTP2_PDN_IPV4
    local f = gtp.Fteid()
    f.if_type, f.teid, f.addr4 = gtp.GTP2_IF_S11_MME, 0x11111111, "10.0.0.1"
    req.sender_fteid = f
    local bc = gtp.BearerContext()
    bc.ebi = 5
    bc.has_qos = true
    bc.qos.qci = 9
    local u = gtp.Fteid()
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S1U_ENODEB, 0xBEEF, "10.0.0.9"
    bc:add_fteid(0, u)
    req:add_bearer(bc)
    return req
end

-- typed messages ------------------------------------------------------
local d = gtp.CreateSessionRequest.decode(sample_cs_req():encode())
check(d.sequence == 0x42, "typed: sequence")
check(d.imsi == "001010123456789", "typed: imsi")
check(d.msisdn == "491701234567", "typed: msisdn")
check(d.apn == "internet", "typed: apn")
check(d.sender_fteid.addr4 == "10.0.0.1", "typed: fteid addr")
check(d.sender_fteid.teid == 0x11111111, "typed: fteid teid")
check(d.bearers:size() == 1, "typed: bearer count")
check(d.bearers[0].ebi == 5, "typed: bearer ebi")
check(d.bearers[0].fteids[0].fteid.teid == 0xBEEF, "typed: bearer fteid")
-- absent fields stay absent
check(d.selection_mode == -1, "absent scalar is -1")
check(d.has_pgw_fteid == false, "absent struct has flag false")
check(d.mei == "", "absent string empty")
check(d.pco == "", "absent bytes empty")
check(raises(function() gtp.CreateSessionRequest():encode() end), "missing mandatory IE raises")
check(raises(function() gtp.DeleteSessionResponse.decode("\0\1\2") end), "garbage decode raises")

-- raw messages --------------------------------------------------------
local m = gtp.RawMessage()
m.message_type = gtp.GTP2_MT_ECHO_REQUEST
m.has_teid = false
m.sequence = 7
m:add_ie(gtp.Ie(gtp.GTP2_IE_RECOVERY, string.char(0x2a)))
local dm = gtp.RawMessage.decode(m:encode())
check(dm.message_type == gtp.GTP2_MT_ECHO_REQUEST, "raw: message type")
check(dm.has_teid == false, "raw: teid absent")
check(dm:has(gtp.GTP2_IE_RECOVERY), "raw: has() finds IE")
check(dm:find(gtp.GTP2_IE_RECOVERY).value == string.char(0x2a), "raw: find() value")

local g = gtp.RawMessage()
g.message_type = gtp.GTP2_MT_CREATE_BEARER_REQUEST
g.teid, g.sequence = 0x5511, 9
local ctx = gtp.Ie()
ctx.type = gtp.GTP2_IE_BEARER_CONTEXT
ctx:add_child(gtp.Ie(gtp.GTP2_IE_EBI, "\6"))
ctx:add_child(gtp.Ie(gtp.GTP2_IE_CHARGING_ID, string.char(0, 0, 0, 0x63)))
g:add_ie(ctx)
local kids = gtp.RawMessage.decode(g:encode()):find(gtp.GTP2_IE_BEARER_CONTEXT).children
check(kids:size() == 2, "raw: grouped IE recursed")
check(kids[0].type == gtp.GTP2_IE_EBI and kids[0].value == "\6", "raw: first child")
check(kids[1].value == string.char(0, 0, 0, 0x63), "raw: second child")
check(raises(function()
    gtp.RawMessage.decode(sample_cs_req():encode()):find(gtp.GTP2_IE_PRIVATE_EXTENSION)
end), "raw: find() missing raises")

-- loop: timers and handler errors -------------------------------------
do
    local loop = net.Loop()
    local fired = false
    loop:after(5, function() fired = true; loop:stop() end)
    for _ = 1, 100 do loop:step(20); if fired then break end end
    check(fired, "timer fires")
end
do
    local loop = net.Loop()
    local fired = false
    local id = loop:after(5, function() fired = true end)
    loop:cancel(id)
    loop:step(20)
    check(not fired, "cancelled timer does not fire")
end
do
    -- A Lua error inside a handler crosses the C dispatcher, stops the
    -- loop, and re-raises from step().
    local loop = net.Loop()
    loop:after(1, function() error("boom") end)
    local ok, err = pcall(function()
        for _ = 1, 100 do loop:step(20) end
    end)
    check(not ok and tostring(err):find("boom"), "handler error surfaces from step")
end

-- session flow over loopback ------------------------------------------
local function server_handler(ep)
    local CTRL, UP = 0x5511, 0xD00D
    return {
        on_create_session_request = function(req, host, port)
            local rsp = gtp.CreateSessionResponse()
            rsp.sequence = req.sequence
            rsp.teid = req.sender_fteid.teid
            rsp.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            rsp.has_sender_fteid = true
            local f = gtp.Fteid()
            f.if_type, f.teid, f.addr4 = gtp.GTP2_IF_S11S4_SGW, CTRL, "127.0.0.1"
            rsp.sender_fteid = f
            local bc = gtp.BearerContext()
            bc.ebi = req.bearers[0].ebi
            bc.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S1U_SGW, UP, "127.0.0.1"
            bc:add_fteid(0, u)
            rsp:add_bearer(bc)
            ep:send_create_session_response(rsp, host, port)
        end,
        on_modify_bearer_request = function(req, host, port)
            local rsp = gtp.ModifyBearerResponse()
            rsp.sequence, rsp.teid = req.sequence, req.teid
            rsp.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local bc = gtp.BearerContext()
            bc.ebi = req.bearers[0].ebi
            bc.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S1U_SGW, UP + 1, "127.0.0.1"
            bc:add_fteid(0, u)
            rsp:add_bearer(bc)
            ep:send_modify_bearer_response(rsp, host, port)
        end,
        on_delete_session_request = function(req, host, port)
            local rsp = gtp.DeleteSessionResponse()
            rsp.sequence, rsp.teid = req.sequence, 0
            rsp.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            ep:send_delete_session_response(rsp, host, port)
        end,
    }
end

do
    local loop = net.Loop()
    local server = gtp.Endpoint(loop, "127.0.0.1", 0)
    local client = gtp.Endpoint(loop, "127.0.0.1", 0)
    local ev = {}
    local function pump(done)
        for _ = 1, 200 do loop:step(20); if done() then return true end end
        return false
    end

    server:set_handler(server_handler(server))
    client:set_handler({
        on_create_session_response = function(s, rsp) ev.cs = rsp.cause end,
        on_user_plane = function(s, t)
            ev.up = { ebi = t.ebi, local_teid = t.local_teid,
                      remote_teid = t.remote_teid, addr = t.remote_addr }
        end,
        on_modify_bearer_response = function(s, rsp) ev.mb = rsp.cause end,
        on_delete_session_response = function(s, rsp) ev.ds = rsp.cause end,
    })

    local sess = client:create_session(sample_cs_req(),
                                        server:local_host(), server:local_port())
    check(sess:state() == gtp.Session.CREATING, "session starts CREATING")

    check(pump(function() return ev.up ~= nil and ev.cs ~= nil end), "create session completes")
    check(ev.cs == gtp.GTP2_CAUSE_REQUEST_ACCEPTED, "accepted cause delivered")
    check(sess:state() == gtp.Session.ACTIVE, "session ACTIVE")
    check(sess:remote_teid() == 0x5511, "remote control TEID learned")
    check(sess:imsi() == "001010123456789", "session imsi")
    check(ev.up and ev.up.ebi == 5 and ev.up.local_teid == 0xBEEF
          and ev.up.remote_teid == 0xD00D and ev.up.addr == "127.0.0.1",
          "on_user_plane carries both ends of the tunnel")
    check(sess:user_plane():size() == 1, "session.user_plane() tunnel list")

    -- Modify Bearer: the relocated user plane surfaces via on_user_plane
    ev.up = nil
    local mb = gtp.ModifyBearerRequest()
    local bc = gtp.BearerContext()
    bc.ebi = 5
    local f = gtp.Fteid()
    f.if_type, f.teid, f.addr4 = gtp.GTP2_IF_S1U_ENODEB, 0xBEF0, "127.0.0.1"
    bc:add_fteid(0, f)
    mb:add_bearer(bc)
    sess:modify_bearer(mb)
    check(pump(function() return ev.mb ~= nil end), "modify bearer completes")
    check(ev.up and ev.up.remote_teid == 0xD00E, "relocated tunnel re-signalled")

    sess:delete_session()
    check(sess:state() == gtp.Session.DELETING, "session DELETING")
    check(pump(function() return ev.ds ~= nil end), "delete session completes")
    check(sess:state() == gtp.Session.DELETED, "session DELETED")

    check(client:sessions():size() == 1, "session retained until purge")
    client:purge()
    check(client:sessions():size() == 0, "purge drops finished session")
end

-- rejection and timeout ------------------------------------------------
do
    local loop = net.Loop()
    local server = gtp.Endpoint(loop, "127.0.0.1", 0)
    local client = gtp.Endpoint(loop, "127.0.0.1", 0)
    local cause
    server:set_handler({
        on_create_session_request = function(req, host, port)
            local rsp = gtp.CreateSessionResponse()
            rsp.sequence, rsp.teid = req.sequence, req.sender_fteid.teid
            rsp.cause = gtp.GTP2_CAUSE_REQUEST_REJECTED
            server:send_create_session_response(rsp, host, port)
        end,
    })
    client:set_handler({ on_create_session_response = function(s, rsp) cause = rsp.cause end })
    local sess = client:create_session(sample_cs_req(),
                                       server:local_host(), server:local_port())
    for _ = 1, 200 do loop:step(20); if cause then break end end
    check(cause == gtp.GTP2_CAUSE_REQUEST_REJECTED, "rejection delivered")
    check(sess:state() == gtp.Session.FAILED, "rejected session FAILED")
end
do
    local loop = net.Loop()
    local client = gtp.Endpoint(loop, "127.0.0.1", 0)
    local timed_out
    client:set_handler({ on_timeout = function(s, mt) timed_out = mt end })
    client:set_t3_ms(20)
    client:set_n3(2)
    local sess = client:create_session(sample_cs_req(), "127.0.0.1", 1)  -- dead port
    for _ = 1, 400 do loop:step(20); if timed_out then break end end
    check(timed_out == gtp.GTP2_MT_CREATE_SESSION_REQUEST, "timeout after N3 sends")
    check(sess:state() == gtp.Session.FAILED, "timed-out session FAILED")
end

-- echo answered automatically -----------------------------------------
do
    local loop = net.Loop()
    local server = gtp.Endpoint(loop, "127.0.0.1", 0)
    local client = gtp.Endpoint(loop, "127.0.0.1", 0)
    server:set_recovery(42)
    local recovery
    client:set_handler({ on_echo_response = function(host, port, r) recovery = r end })
    client:send_echo(server:local_host(), server:local_port())
    for _ = 1, 200 do loop:step(20); if recovery then break end end
    check(recovery == 42, "echo answered with recovery counter")
end

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
