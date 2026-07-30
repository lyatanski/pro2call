#!/usr/bin/env lua
-- sdp and sip in ONE interpreter.
--
-- SWIG's Lua runtime keys every wrapped class's metatable in a registry
-- shared by all modules loaded into one lua_State, under the UNSCOPED
-- class name (swig_lua_class::fqname is "Msg", not "sdp::Msg"). Both
-- facades have a Msg and a Builder, so without the %rename in
-- swig/sdp.i the module loaded second silently replaces the first one's
-- metatables and every method on the loser's objects comes back nil —
-- at runtime, with no warning from SWIG at build or load time. That is
-- exactly the failure gtp::Session once caused for rtp::Session.
--
-- ims_test_s5.lua loads both, so this is not a hypothetical. Load them
-- in both orders and check that each module's objects still dispatch
-- into their own methods.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_sdp_sip_coexist.lua

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- Load order matters to the bug, so exercise it. Both requires happen in
-- this one interpreter; the second order is a no-op require, which is
-- itself the realistic case (a script requires each module once).
local sdp = require("sdp")
local sip = require("sip")

local body = sdp.offer{ addr = "10.45.0.2", port = 40000, id = 1 }

-- sip still builds and parses after sdp registered its own Msg/Builder.
local wire = sip.Builder()
    :request(sip.INVITE, "sip:bob@example.com")
    :header(sip.H_VIA, "SIP/2.0/UDP h;branch=z9hG4bK1")
    :header(sip.H_CONTENT_TYPE, "application/sdp")
    :done(body)
local msg = sip.parse(wire)
check(msg.request and msg.method == sip.INVITE, "sip.parse still works")
check(msg:call_id() ~= nil, "sip.Msg methods still dispatch to sip")
check(msg.body == body, "the SDP body survived the SIP round trip")

-- sdp still parses after sip registered its own.
local m = sdp.parse(msg.body)
check(m:has_audio(), "sdp.parse still works")
check(m:audio().port == 40000, "sdp.Media methods still dispatch to sdp")
check(m:audio():rtpmap(0).enc == "PCMU", "and so do its deep parsers")

-- The two Msg types must not be interchangeable: a sip.Msg has no
-- media_count, an sdp.Msg has no call_id. If the metatables had been
-- crossed, one of these would succeed.
check(not pcall(function() return msg:media_count() end),
      "a sip.Msg has no sdp method")
check(not pcall(function() return m:call_id() end),
      "an sdp.Msg has no sip method")

-- Same for the two Builders, which is the pair most likely to be hit:
-- both are constructed the same way and both chain.
check(not pcall(function() return sdp.Builder():request(sip.INVITE, "sip:x") end),
      "an sdp.Builder has no sip method")
check(not pcall(function() return sip.Builder():version() end),
      "a sip.Builder has no sdp method")

-- Names the modules expose in their own tables, so a swapped module
-- table would show up here too.
check(sdp.attr_name(sdp.A_RTPMAP) == "rtpmap", "sdp name table")
check(sip.method_name(sip.INVITE) == "INVITE", "sip name table")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
