#!/usr/bin/env lua
-- Tests for the SWIG Lua sip module (bindings/swig/sip.i).
--
-- Everything here runs unprivileged and offline: the module is a pure
-- codec. Covered:
--   - the module loads and exposes method/header enum constants;
--   - Builder -> wire -> parse round-trips, body bytes included;
--   - enum-based header access: compact "v:" arrives as sip.H_VIA;
--   - typed accessors (cseq, from_/to_, top_via) and their errors;
--   - malformed input raises a Lua error naming the operation.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_sip_bindings.lua

local sip = require("sip")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- constants -----------------------------------------------------------
check(sip.INVITE ~= nil and sip.REGISTER ~= nil, "method constants")
check(sip.H_VIA ~= nil and sip.H_CALL_ID ~= nil, "header constants")
check(sip.method_name(sip.INVITE) == "INVITE", "method_name")
check(sip.hdr_name(sip.H_CONTENT_TYPE) == "Content-Type", "hdr_name")
check(sip.status_phrase(486) == "Busy Here", "status_phrase")

-- build ---------------------------------------------------------------
local sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n"
local wire = sip.Builder()
    :request(sip.INVITE, "sip:bob@biloxi.example.com")
    :header(sip.H_VIA, "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776")
    :header_u32(sip.H_MAX_FORWARDS, 70)
    :header(sip.H_FROM, "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
    :header(sip.H_TO, "Bob <sip:bob@biloxi.example.com>")
    :header(sip.H_CALL_ID, "a84b4c76e66710")
    :header(sip.H_CSEQ, "314159 INVITE")
    :header(sip.H_CONTENT_TYPE, "application/sdp")
    :header_name("X-Custom", "hello")
    :done(sdp)
check(wire:find("^INVITE sip:bob") == 1, "request line first")
check(wire:find("Content%-Length: " .. #sdp .. "\r\n") ~= nil, "auto Content-Length")

-- parse ---------------------------------------------------------------
local msg = sip.parse(wire)
check(msg.request == true, "is a request")
check(msg.method == sip.INVITE, "method enum")
check(msg.uri == "sip:bob@biloxi.example.com", "request uri")
check(msg.body == sdp, "body round-trip (CRLFs intact)")
check(msg:header("Call-ID") == "a84b4c76e66710", "header by long name")
check(msg:header("i") == "a84b4c76e66710", "header by compact name")
check(msg:header("x-custom") == "hello", "extension header, any case")
check(msg:header_count() == 9, "header count")   -- 8 puts + Content-Length
check(msg:header_at(0).id == sip.H_VIA, "header_at yields enum ids")

-- typed accessors -----------------------------------------------------
local cseq = msg:cseq()
check(cseq.number == 314159 and cseq.method == sip.INVITE, "cseq")
local from = msg:from_()
check(from.display == "Alice", "from display")
check(from.uri == "sip:alice@atlanta.example.com", "from uri")
check(from.tag == "1928301774", "from tag")
local via = msg:top_via()
check(via.transport == "UDP", "via transport")
check(via.host == "pc33.atlanta.example.com", "via host")
check(via.branch == "z9hG4bK776", "via branch")

local uri = sip.parse_uri("sips:alice@atlanta.example.com:5061;transport=tls")
check(uri.scheme == "sips" and uri.port == 5061, "parse_uri")
check(uri.params == "transport=tls", "uri params")

-- compact form on the wire --------------------------------------------
local compact = "OPTIONS sip:x@y SIP/2.0\r\n" ..
                "v: SIP/2.0/TCP h;branch=z9\r\n" ..
                "l: 0\r\n\r\n"
local m2 = sip.parse(compact)
check(m2:header_at(0).id == sip.H_VIA, "compact v: is H_VIA")
check(m2:header_at(0).name == "v", "wire name preserved")
check(m2:has_header("Via"), "long-form lookup finds compact")

-- responses ------------------------------------------------------------
local resp = sip.Builder()
    :response(180)                       -- default phrase
    :header(sip.H_CSEQ, "1 INVITE")
    :done()
local r = sip.parse(resp)
check(r.request == false and r.status == 180, "response status")
check(r.reason == "Ringing", "default reason phrase")

-- errors ----------------------------------------------------------------
local ok, err = pcall(function() sip.parse("not sip at all\r\n\r\n") end)
check(not ok, "malformed input raises")
check(type(err) == "string" and err:find("parse"), "error names the operation")

ok, err = pcall(function() sip.parse("INVITE sip:x@y SIP/2.0\r\nVia: a") end)
check(not ok and err:find("incomplete"), "truncated input raises 'incomplete'")

ok, err = pcall(function() return r:top_via() end)
check(not ok and err:find("top_via"), "missing typed header raises")

local values = msg:header_values("Via")   -- StringList proxy, 0-based
check(values:size() == 1 and values[0]:find("z9hG4bK776"), "header_values")

-- transaction state machines (RFC 3261 §17) ----------------------------
check(sip.INVITE_CLIENT ~= nil and sip.NON_INVITE_SERVER ~= nil, "kind constants")
check(sip.TS_CALLING ~= nil and sip.TE_TIMER_TIMEOUT ~= nil, "state/event constants")

local t = sip.Transaction(sip.INVITE_CLIENT)
check(t:kind() == sip.INVITE_CLIENT, "transaction kind")
check(t:state() == sip.TS_INIT and t:state_name() == "Init", "starts in Init")
t:send(msg)                                    -- the INVITE built above
check(t:state() == sip.TS_CALLING, "INVITE out -> Calling")
t:recv(r)                                      -- the 180 built above
check(t:state() == sip.TS_PROCEEDING, "1xx -> Proceeding")
local ok200 = sip.parse(sip.Builder():response(200):header(sip.H_CSEQ, "1 INVITE"):done())
t:recv(ok200)
check(t:state() == sip.TS_TERMINATED and t:terminated(), "2xx -> Terminated")

ok, err = pcall(function() t:recv(ok200) end)  -- machine already closed
check(not ok and err:find("illegal"), "event on a terminated machine raises")

local uas = sip.Transaction(sip.INVITE_SERVER)
uas:recv(msg)
uas:send(sip.parse(sip.Builder():response(486):header(sip.H_CSEQ, "1 INVITE"):done()))
check(uas:state() == sip.TS_COMPLETED, "final error -> Completed")
local ack = sip.parse(sip.Builder():request(sip.ACK, "sip:x@y"):header(sip.H_CSEQ, "1 ACK"):done())
uas:recv(ack)
check(uas:state() == sip.TS_CONFIRMED, "ACK -> Confirmed")
uas:event(sip.TE_TIMER_TERMINATE)
check(uas:terminated(), "timer I -> Terminated")

local reg = sip.Transaction(sip.NON_INVITE_CLIENT)
local register = sip.parse(sip.Builder():request(sip.REGISTER, "sip:reg"):header(sip.H_CSEQ, "1 REGISTER"):done())
reg:send(register)
check(reg:state() == sip.TS_TRYING, "REGISTER out -> Trying")
reg:recv(ok200)
check(reg:state() == sip.TS_COMPLETED, "2xx -> Completed (waits out timer K)")

ok, err = pcall(function() sip.Transaction(99) end)
check(not ok and err:find("invalid"), "bad transaction kind raises")

-- dialog / usage state machines (RFC 3261 §12 / §10 / §22) --------------
check(sip.DS_EARLY ~= nil and sip.RE_CHALLENGE ~= nil and sip.AS_AUTHENTICATED ~= nil,
      "dialog/usage constants")

-- dialog: 100 forms nothing, 180 (with a To-tag) -> early, 200 ->
-- confirmed, BYE -> terminated (RFC 3261 §12)
local function invite_response(status, to_tag)
    local to = to_tag and ("<sip:bob@biloxi>;tag=" .. to_tag) or "<sip:bob@biloxi>"
    return sip.parse(sip.Builder():response(status)
        :header(sip.H_TO, to):header(sip.H_CSEQ, "1 INVITE"):done())
end
local dlg = sip.Dialog()
check(dlg:state() == sip.DS_INIT, "dialog starts in Init")
dlg:recv(invite_response(100))
check(dlg:state() == sip.DS_INIT, "100 Trying forms no dialog")
dlg:recv(invite_response(180, "b1"))
check(dlg:early(), "180 with To-tag -> Early")
dlg:recv(invite_response(200, "b1"))
check(dlg:confirmed(), "2xx -> Confirmed")
local bye = sip.parse(sip.Builder():request(sip.BYE, "sip:bob@biloxi")
    :header(sip.H_CSEQ, "2 BYE"):done())
dlg:send(bye)
check(dlg:terminated(), "BYE -> Terminated")

-- registration: REGISTER -> 401 -> authed REGISTER -> 200, then refresh
-- and de-register (RFC 3261 §10, TS 24.229 §5.1)
local function register(expires)
    local b = sip.Builder():request(sip.REGISTER, "sip:reg")
        :header(sip.H_CSEQ, "1 REGISTER"):header(sip.H_CONTACT, "<sip:u@h>")
    if expires then b:header_u32(sip.H_EXPIRES, expires) end
    return sip.parse(b:done())
end
local function reg_response(status)
    return sip.parse(sip.Builder():response(status):header(sip.H_CSEQ, "1 REGISTER"):done())
end
local reg = sip.Registration()
check(reg:state() == sip.RS_IDLE, "registration starts in Idle")
reg:send(register(600))
check(reg:state() == sip.RS_REGISTERING, "REGISTER out -> Registering")
reg:recv(reg_response(401))
check(reg:state() == sip.RS_CHALLENGED, "401 -> Challenged")
reg:send(register(600))
check(reg:state() == sip.RS_AUTHENTICATING, "credentialed REGISTER -> Authenticating")
reg:recv(reg_response(200))
check(reg:registered(), "200 -> Registered")
reg:send(register(600))
check(reg:state() == sip.RS_REFRESHING, "re-REGISTER -> Refreshing")
reg:recv(reg_response(200))
check(reg:registered(), "refresh 200 -> Registered")
reg:send(register(0))                                    -- Expires: 0 == de-register
check(reg:state() == sip.RS_DEREGISTERING, "REGISTER Expires:0 -> Deregistering")
reg:recv(reg_response(200))
check(reg:done(), "de-register 200 -> Done")

local reg2 = sip.Registration()
reg2:send(register(600))
reg2:recv(reg_response(403))
check(reg2:failed(), "403 -> Failed")
ok, err = pcall(function() sip.Registration():recv(reg_response(200)) end)
check(not ok and err:find("illegal"), "a 200 before any REGISTER raises")

-- digest auth sub-FSM: request -> 401 -> creds -> 2xx, then re-auth
-- (RFC 3261 §22, RFC 2617/7616)
local ac = sip.AuthChallenge()
ac:send(register(600))
check(ac:state() == sip.AS_PENDING, "request -> Pending")
ac:recv(reg_response(401))
check(ac:challenged(), "401 -> Challenged")
ac:send(register(600))
ac:recv(reg_response(200))
check(ac:authenticated(), "2xx -> Authenticated")
ac:event(sip.AE_SEND)
check(ac:state() == sip.AS_PENDING, "re-auth from Authenticated -> Pending")
ac:event(sip.AE_CHALLENGE)
ac:event(sip.AE_GIVE_UP)
check(ac:failed(), "give up at the retry cap -> Failed")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
