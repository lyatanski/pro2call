#!/usr/bin/env lua
-- Tests for the SWIG Lua diam module (bindings/swig/diam.i).
--
-- Everything here runs unprivileged and offline: the module is a pure
-- codec. Covered:
--   - the module loads and exposes dictionary constants (apps,
--     commands, AVPs, enum values) and name tables;
--   - Builder -> wire -> parse round-trips, header flags included;
--   - vendor AVPs get their Vendor-ID and V flag from the dictionary;
--   - grouped AVPs nest on encode and parse into children;
--   - typed accessors and their errors;
--   - malformed input raises a Lua error naming the operation.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_diam_bindings.lua

local diam = require("diam")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- constants -------------------------------------------------------------
check(diam.APP_CX == 16777216, "Cx app id")
check(diam.APP_RX == 16777236, "Rx app id")
check(diam.APP_CREDIT_CONTROL == 4, "Ro app id")
check(diam.APP_BASE_ACCOUNTING == 3, "Rf app id")
check(diam.CMD_CREDIT_CONTROL == 272, "CCR command code")
check(diam.CMD_USER_AUTHORIZATION == 300, "UAR command code")
check(diam.AVP_SESSION_ID == 263, "Session-Id code")
check(diam.VENDOR_3GPP == 10415, "3GPP vendor id")
check(diam.CC_REQUEST_TYPE_INITIAL_REQUEST == 1, "enum constant")

-- name tables -------------------------------------------------------------
check(diam.app_name(diam.APP_CX) == "Cx", "app_name")
check(diam.cmd_name(272) == "Credit-Control", "cmd_name")
check(diam.avp_name(263, 0) == "Session-Id", "avp_name")
check(diam.avp_name(601, diam.VENDOR_3GPP) == "Public-Identity", "vendor avp_name")
check(diam.enum_name(diam.AVP_RESULT_CODE, 0, 2001) == "DIAMETER_SUCCESS", "enum_name")
check(diam.avp_name(999999, 0) == nil, "unknown avp_name is nil")

-- dictionary metadata ---------------------------------------------------
local e = diam.dict_get(diam.AVP_SESSION_ID, 0)
check(e ~= nil and e.type == diam.TYPE_UTF8_STRING, "dict entry type")
check(diam.dict_count() > 1000, "dict_count")

-- build -------------------------------------------------------------------
local wire = diam.Builder()
    :request(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
    :ids(0x1111, 0x2222)
    :proxiable()
    :put_str(diam.AVP_SESSION_ID, "gw.example.net;1;1")
    :put_str(diam.AVP_ORIGIN_HOST, "gw.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "example.net")
    :put_str(diam.AVP_DESTINATION_REALM, "example.net")
    :put_u32(diam.AVP_CC_REQUEST_TYPE, diam.CC_REQUEST_TYPE_INITIAL_REQUEST)
    :put_u32(diam.AVP_CC_REQUEST_NUMBER, 0)
    :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :put_u32(diam.AVP_RATING_GROUP, 100)
        :begin_group(diam.AVP_REQUESTED_SERVICE_UNIT)
            :put_u64(diam.AVP_CC_TOTAL_OCTETS, 5 * 1024 * 1024)
        :end_group()
    :end_group()
    :put_str(diam.AVP_PUBLIC_IDENTITY, "sip:alice@ims.example.net")
    :done()
check(#wire % 4 == 0, "wire length is 4-aligned")
check(#wire > 20, "wire has AVPs")
-- version 1, R+P flags on the wire
check(wire:byte(1) == 1, "version octet")
check(wire:byte(5) == 0xC0, "R and P flags set")

-- parse -------------------------------------------------------------------
local msg = diam.parse(wire)
check(msg.request == true and msg.proxiable == true, "header flags")
check(msg.cmd == diam.CMD_CREDIT_CONTROL, "command code")
check(msg.app == diam.APP_CREDIT_CONTROL, "application id")
check(msg.hbh == 0x1111 and msg.e2e == 0x2222, "hop-by-hop / end-to-end")
check(msg:name() == "Credit-Control", "command name")
check(msg:avp_count() == 8, "top-level AVP count")
check(msg:str(diam.AVP_SESSION_ID) == "gw.example.net;1;1", "Session-Id round-trip")
check(msg:u32(diam.AVP_CC_REQUEST_TYPE) == 1, "u32 shortcut")

-- vendor AVP: dictionary filled in vendor id and V+M flags
local pid = msg:find(diam.AVP_PUBLIC_IDENTITY, diam.VENDOR_3GPP)
check(pid.vendor_id == diam.VENDOR_3GPP, "vendor id on the wire")
check(pid:name() == "Public-Identity", "vendor avp name")
check(pid:str() == "sip:alice@ims.example.net", "vendor avp data")
check(not msg:has(diam.AVP_PUBLIC_IDENTITY, 0), "not visible as standard avp")

-- grouped AVPs parse into children, two levels deep
local mscc = msg:find(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
check(mscc:grouped(), "MSCC is grouped")
check(mscc:child(diam.AVP_RATING_GROUP):u32() == 100, "child u32")
local rsu = mscc:child(diam.AVP_REQUESTED_SERVICE_UNIT)
check(rsu:grouped(), "nested group")
check(rsu:child(diam.AVP_CC_TOTAL_OCTETS):u64() == 5 * 1024 * 1024, "nested child u64")
check(mscc:has_child(diam.AVP_RATING_GROUP), "has_child")
check(not mscc:has_child(diam.AVP_SESSION_ID), "has_child negative")

-- enum value names ------------------------------------------------------
local rt = msg:find(diam.AVP_CC_REQUEST_TYPE)
check(rt:value_name() == "INITIAL_REQUEST", "value_name")
check(msg:find(diam.AVP_SESSION_ID):value_name() == "", "no value_name for strings")

-- avp_at ordering -------------------------------------------------------
check(msg:avp_at(0).code == diam.AVP_SESSION_ID, "avp_at keeps wire order")

-- answers ---------------------------------------------------------------
local ans = diam.Builder()
    :answer(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
    :ids(msg.hbh, msg.e2e)
    :put_str(diam.AVP_SESSION_ID, msg:str(diam.AVP_SESSION_ID))
    :put_u32(diam.AVP_RESULT_CODE, 2001)
    :done()
local a = diam.parse(ans)
check(a.request == false, "answer R flag clear")
check(a:u32(diam.AVP_RESULT_CODE) == 2001, "Result-Code")
check(diam.enum_name(diam.AVP_RESULT_CODE, 0, a:u32(diam.AVP_RESULT_CODE))
      == "DIAMETER_SUCCESS", "result name")

-- addresses -------------------------------------------------------------
local cer = diam.Builder()
    :request(diam.CMD_CAPABILITIES_EXCHANGE, diam.APP_BASE)
    :put_str(diam.AVP_ORIGIN_HOST, "peer.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "example.net")
    :put_addr4(diam.AVP_HOST_IP_ADDRESS, "192.0.2.1")
    :put_u32(diam.AVP_VENDOR_ID, 0)
    :put_str(diam.AVP_PRODUCT_NAME, "pro2call")
    :done()
local c = diam.parse(cer)
local hip = c:find(diam.AVP_HOST_IP_ADDRESS)
check(#hip:str() == 6, "Address = family(2) + IPv4(4)")
check(hip:str():byte(2) == 1, "IANA IPv4 family")

-- errors ----------------------------------------------------------------
local ok, err = pcall(function() diam.parse("not diameter") end)
check(not ok, "malformed input raises")
check(type(err) == "string" and err:find("parse"), "error names the operation")

ok, err = pcall(function() diam.parse(wire:sub(1, 30)) end)
check(not ok and err:find("length"), "truncated message raises")

ok, err = pcall(function() msg:find(diam.AVP_TERMINATION_CAUSE) end)
check(not ok and err:find("absent"), "find on absent AVP raises")

ok, err = pcall(function() msg:find(diam.AVP_SESSION_ID):u32() end)
check(not ok and err:find("type"), "u32 on a string AVP raises")

ok, err = pcall(function()
    diam.Builder():put_str(diam.AVP_SESSION_ID, "x")
end)
check(not ok and err:find("request"), "put before request() raises")

ok, err = pcall(function()
    diam.Builder()
        :request(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
        :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :done()
end)
check(not ok and err:find("unclosed"), "unclosed group raises")

-- session state machines (RFC 6733 §8.1) -------------------------------
check(diam.SESS_CLIENT ~= nil and diam.SESS_SERVER ~= nil, "kind constants")
check(diam.SS_OPEN ~= nil and diam.SE_TIMEOUT ~= nil, "state/event constants")

local function rx(b)
    return b:ids(1, 1):put_str(diam.AVP_SESSION_ID, "af.example.net;1;1")
end
local aar = rx(diam.Builder():request(diam.CMD_AA, diam.APP_RX)):done()
local aaa = rx(diam.Builder():answer(diam.CMD_AA, diam.APP_RX))
    :put_u32(diam.AVP_RESULT_CODE, 2001):done()
local str = rx(diam.Builder():request(diam.CMD_SESSION_TERMINATION, diam.APP_RX)):done()
local sta = rx(diam.Builder():answer(diam.CMD_SESSION_TERMINATION, diam.APP_RX))
    :put_u32(diam.AVP_RESULT_CODE, 2001):done()

local cli = diam.Session(diam.SESS_CLIENT)
check(cli:kind() == diam.SESS_CLIENT, "session kind")
check(cli:state() == diam.SS_IDLE and cli:state_name() == "Idle", "starts Idle")
cli:send(diam.parse(aar))
check(cli:state() == diam.SS_PENDING, "AAR out -> Pending")
cli:recv(diam.parse(aaa))
check(cli:state() == diam.SS_OPEN and cli:open(), "2001 answer -> Open")
cli:send(diam.parse(str))
check(cli:state() == diam.SS_DISCON, "STR out -> Discon")
cli:recv(diam.parse(sta))
check(cli:closed(), "STA -> Closed")

local srv = diam.Session(diam.SESS_SERVER)
srv:recv(diam.parse(aar))
srv:send(diam.parse(aaa))
check(srv:open(), "server side reaches Open")
srv:recv(diam.parse(str))
check(srv:closed(), "STR closes the server session (STA implied)")
srv:send(diam.parse(sta))                       -- no state change, no error
check(srv:closed(), "sending the STA is a no-op")

-- a failed answer closes the session
local nok = rx(diam.Builder():answer(diam.CMD_AA, diam.APP_RX))
    :put_u32(diam.AVP_RESULT_CODE, 5003):done() -- DIAMETER_AUTHORIZATION_REJECTED
local cli2 = diam.Session(diam.SESS_CLIENT)
cli2:send(diam.parse(aar))
cli2:recv(diam.parse(nok))
check(cli2:closed(), "failed answer -> Closed")

ok, err = pcall(function() cli:event(diam.SE_SEND_REQUEST) end)
check(not ok and err:find("illegal"), "event on a closed session raises")

ok, err = pcall(function() diam.Session(7) end)
check(not ok and err:find("invalid"), "bad session kind raises")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
