#!/usr/bin/env lua
-- sms beside sip, sdp and diam in ONE interpreter.
--
-- SWIG's Lua runtime keys every wrapped class's metatable in a registry
-- shared by all modules loaded into one lua_State, under the UNSCOPED
-- class name (swig_lua_class::fqname is "Msg", not "sip::Msg"). A second
-- module wrapping a class of the same name silently replaces the first
-- one's metatables, and every method on the loser's objects comes back
-- nil — at runtime, with no warning from SWIG at build or load time.
--
-- The sms facade was written to avoid the clash (Address rather than
-- Addr, which netxx wraps; Tpdu/Rpdu rather than Msg; no Builder at
-- all), so there is nothing for sms.i to %rename. This test is what
-- keeps that true: it is the assertion that the *next* type added to
-- smsxx.hpp has not quietly collided with one of the other six modules.
--
-- ipsmgw.lua loads sms, sip, diam and net together, so this is not
-- hypothetical.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_sms_coexist.lua

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- Load order matters to the bug, so load sms in the middle: after two
-- modules that already registered types, before one that will.
local sip  = require("sip")
local sdp  = require("sdp")
local sms  = require("sms")
local diam = require("diam")

-- Each module still builds and parses its own format ----------------------

local rpdu = sms.submit{ to = "+447700900123", text = "coexist" }
local body = sdp.offer{ addr = "10.45.0.2", port = 40000, id = 1 }

local invite = sip.Builder()
    :request(sip.INVITE, "sip:bob@example.com")
    :header(sip.H_VIA, "SIP/2.0/UDP h;branch=z9hG4bK1")
    :header(sip.H_CONTENT_TYPE, "application/sdp")
    :done(body)
check(sip.parse(invite).method == sip.INVITE, "sip still parses")
check(sdp.parse(sdp.parse(body) and body):has_audio(), "sdp still parses")

-- A MESSAGE carrying the RPDU: the real shape of SMS over IMS, and the
-- test that a binary body survives being handed from sms to sip and back
-- (TS 24.341 §5.3.2). The RPDU contains no NUL here, so also check one
-- that does.
local message = sip.Builder()
    :request(sip.MESSAGE, "sip:+123456789@ims.example.net;user=phone")
    :header(sip.H_VIA, "SIP/2.0/UDP h;branch=z9hG4bK2")
    :header(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)
    :done(rpdu)
local req = sip.parse(message)
check(req.method == sip.MESSAGE, "sip parses a MESSAGE")
check(req.body == rpdu, "the RPDU survived the SIP round trip")
check(sms.parse_rpdu(req.body, sms.DIR_MS_TO_SC):tpdu():text() == "coexist",
      "and the sms module can still read it")

local nul = sms.submit{ to = "+1", text = "@@@@@@@@" } -- septet 0 is '@'
check(nul:find("\0", 1, true) ~= nil, "this RPDU contains a 0x00")
local m2 = sip.parse(sip.Builder()
    :request(sip.MESSAGE, "sip:x@y")
    :header(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)
    :done(nul))
check(m2.body == nul, "a body with an embedded NUL survives sip too")
check(#m2.body == #nul, "and keeps its length")

-- diam still works, and carries the RPDU in SM-RP-UI the way SGd does
local sgd = diam.Builder()
    :request(diam.CMD_MO_FORWARD_SHORT_MESSAGE, diam.APP_SGD)
    :put_str(diam.AVP_SESSION_ID, "ipsmgw;1;1")
    :put_str(diam.AVP_SM_RP_UI, nul)
    :done()
check(diam.parse(sgd):str(diam.AVP_SM_RP_UI, diam.VENDOR_3GPP) == nul,
      "the RPDU survives SM-RP-UI too")

-- The types must not be interchangeable ----------------------------------
-- If the metatables had been crossed, one of these would succeed.

local tpdu = sms.parse_rpdu(rpdu, sms.DIR_MS_TO_SC):tpdu()
check(not pcall(function() return tpdu:call_id() end),
      "an sms.Tpdu has no sip method")
check(not pcall(function() return tpdu:media_count() end),
      "an sms.Tpdu has no sdp method")
check(not pcall(function() return req:text() end),
      "a sip.Msg has no sms method")
check(not pcall(function() return sdp.parse(body):text() end),
      "an sdp.Msg has no sms method")

-- sms.Address vs net.Addr: the near-miss this naming exists to avoid.
-- Loading net last is the worst case for the registry.
local net = require("net")
check(net ~= nil, "net loads after sms")
check(tpdu.addr.digits == "447700900123",
      "sms.Address still works with net.Addr registered")
check(tpdu.addr:display() == "+447700900123", "and its methods dispatch")

-- Module tables are distinct: a swapped one would show up here.
check(sms.type_name(sms.T_SUBMIT) == "SMS-SUBMIT", "sms name table")
check(sip.method_name(sip.MESSAGE) == "MESSAGE", "sip name table")
check(sdp.attr_name(sdp.A_RTPMAP) == "rtpmap", "sdp name table")
check(diam.cmd_name(diam.CMD_MO_FORWARD_SHORT_MESSAGE) ==
      "MO-Forward-Short-Message", "diam name table")

-- Same-named constants live in their own tables and do not leak.
check(sms.DIR_MS_TO_SC == 0 and sdp.DIR_SENDRECV == 0,
      "each module's DIR_* constants are its own")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
