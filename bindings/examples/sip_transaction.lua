#!/usr/bin/env lua
-- A complete SIP INVITE transaction, both sides, offline: the UAC
-- builds an INVITE, the "UAS" answers 180 Ringing and 200 OK following
-- the RFC 3261 copying rules (Via/From/Call-ID/CSeq mirrored, To gets
-- the dialog tag), and the UAC closes with the ACK addressed at the
-- answerer's Contact. Wire in, wire out — point the send/receive at a
-- UDP socket and it is a softphone skeleton.
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua sip_transaction.lua

local sip = require("sip")

local function show(who, wire)
    print(("--- %s (%d bytes)"):format(who, #wire))
    io.write((wire:gsub("\r\n", "\n")))
end

-- UAC: the caller ------------------------------------------------------

local branch  = "z9hG4bK-1-1"           -- unique per transaction
local call_id = "3848276298220188511@atlanta.example.com"
local sdp     = "v=0\r\no=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n"

local invite = sip.Builder()
    :request(sip.INVITE, "sip:bob@biloxi.example.com")
    :header(sip.H_VIA, "SIP/2.0/UDP pc33.atlanta.example.com;branch=" .. branch)
    :header_u32(sip.H_MAX_FORWARDS, 70)
    :header(sip.H_FROM, "Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl")
    :header(sip.H_TO, "Bob <sip:bob@biloxi.example.com>")
    :header(sip.H_CALL_ID, call_id)
    :header(sip.H_CSEQ, "1 INVITE")
    :header(sip.H_CONTACT, "<sip:alice@pc33.atlanta.example.com>")
    :header(sip.H_CONTENT_TYPE, "application/sdp")
    :done(sdp)
show("UAC sends INVITE", invite)

-- UAS: the callee ------------------------------------------------------

-- A response copies these from the request verbatim (Via order matters);
-- To additionally carries the UAS dialog tag once the dialog is formed.
local MIRROR = { "Via", "From", "Call-ID", "CSeq" }

local function respond(req, status, to_tag, body, contact)
    local b = sip.Builder():response(status)   -- default reason phrase
    for _, name in ipairs(MIRROR) do
        b:header_name(name, req:header(name))
    end
    local to = req:header("To")
    if to_tag then to = to .. ";tag=" .. to_tag end
    b:header(sip.H_TO, to)
    if contact then b:header(sip.H_CONTACT, contact) end
    if body and #body > 0 then
        b:header(sip.H_CONTENT_TYPE, "application/sdp")
    end
    return b:done(body or "")
end

local req = sip.parse(invite)
assert(req.request and req.method == sip.INVITE)
print(("UAS got %s for %s from %s (branch %s)\n"):format(
    req.method_name, req.uri, req:from_().uri, req:top_via().branch))

local ringing = respond(req, 180, nil)
show("UAS sends", ringing)

local answer  = "v=0\r\no=bob 2890844527 2890844527 IN IP4 biloxi.example.com\r\n"
local ok200   = respond(req, 200, "314159", answer, "<sip:bob@biloxi.example.com>")
show("UAS sends", ok200)

-- UAC again: match the response, ACK the final one ---------------------

local rsp = sip.parse(ok200)
assert(not rsp.request)

-- Responses are matched to transactions by branch + CSeq method.
assert(rsp:top_via().branch == branch, "branch matches our transaction")
assert(rsp:cseq().method == sip.INVITE)
print(("\nUAC got %d %s, dialog tags %s / %s\n"):format(
    rsp.status, rsp.reason, rsp:from_().tag, rsp:to_().tag))

if rsp.status >= 200 and rsp.status < 300 then
    -- The ACK for a 2xx is a fresh transaction aimed at the answerer's
    -- Contact (its bare URI), falling back to the original Request-URI.
    local contact = rsp:header("Contact")
    local target  = contact ~= "" and sip.parse_addr(contact).uri or req.uri
    local ack = sip.Builder()
        :request(sip.ACK, target)
        :header(sip.H_VIA, "SIP/2.0/UDP pc33.atlanta.example.com;branch=" .. branch)
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header_name("From", rsp:header("From"))
        :header_name("To", rsp:header("To"))       -- with the UAS tag
        :header(sip.H_CALL_ID, call_id)
        :header(sip.H_CSEQ, ("%d ACK"):format(rsp:cseq().number))
        :done()
    show("UAC sends", ack)
end
