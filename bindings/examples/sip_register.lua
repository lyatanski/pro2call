#!/usr/bin/env lua
-- SIP registration usage, both sides, offline. A UAC drives the RFC 3261
-- §10 / 3GPP TS 24.229 §5.1 registration procedure as a `sip.Registration`
-- machine, delegates the §22 HTTP Digest challenge to a `sip.AuthChallenge`
-- machine, and runs each REGISTER over its own non-INVITE client
-- `sip.Transaction` (RFC 3261 §17.1.2) — the three layers composed exactly
-- as sip_state_machines.md describes. It exchanges wire messages with a
-- stub registrar that challenges once and validates the digest like a real
-- one. Wire in, wire out: point send/receive at a `net.UdpSocket` and it
-- registers a live UE (that is what ims_test_s5.lua does over GTP-U).
--
-- The full lifecycle is walked: initial REGISTER -> 401 challenge ->
-- authenticated REGISTER -> 200 (Registered), a refresh, then a
-- de-registration (Expires: 0) to Done. Each step prints the state of all
-- three machines so the composition is visible.
--
-- No network or privilege needed. Run:
--   LUA_CPATH=<build>/bindings/lua/?.so lua sip_register.lua

local sip   = require("sip")   -- codec + Registration / AuthChallenge / Transaction FSMs
local ipsec = require("ipsec") -- ipsec.md5 for the HTTP Digest response

-- ---- configuration (a shared secret both sides know) ------------------

local realm    = "registrar.example.com"
local user     = "alice"
local password = "secret"
local aor      = "sip:alice@example.com"          -- address of record
local contact  = "sip:alice@192.0.2.10:5060"      -- where the UE is reachable
local reg_uri  = "sip:registrar.example.com"      -- Request-URI (the registrar)
local call_id  = "reg-3848276298@192.0.2.10"      -- stable across the whole flow
local NONCE    = "dcd98b7102dd2f0e8b11d0f600bfb0c093" -- the registrar's challenge nonce

-- ---- HTTP Digest, RFC 2617 (qop=auth) ---------------------------------

local function hex(s) return (s:gsub(".", function(c) return ("%02x"):format(c:byte()) end)) end
local function md5(s) return hex(ipsec.md5(s)) end

-- response = MD5(HA1:nonce:nc:cnonce:qop:HA2), HA1 = MD5(user:realm:pass),
-- HA2 = MD5(method:uri). Both sides compute it the same way; the UAC
-- proves knowledge of the password, the registrar re-derives and compares.
local function digest_response(nonce, nc, cnonce, uri)
    local ha1 = md5(("%s:%s:%s"):format(user, realm, password))
    local ha2 = md5(("REGISTER:%s"):format(uri))
    return md5(("%s:%s:%s:%s:auth:%s"):format(ha1, nonce, nc, cnonce, ha2))
end

local authcount = 0 -- the nonce-count increments per authenticated request
local function authorization(nonce)
    authcount = authcount + 1
    local nc, cnonce = ("%08x"):format(authcount), "0a4f113b6d2c"
    local response = digest_response(nonce, nc, cnonce, reg_uri)
    return ('Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",'
         .. 'algorithm=MD5,qop=auth,nc=%s,cnonce="%s"')
        :format(user, realm, nonce, reg_uri, response, nc, cnonce)
end

-- ---- UAC: build a REGISTER --------------------------------------------

-- A fresh transaction per REGISTER means a fresh branch and From-tag keyed
-- on the CSeq; the Call-ID is stable across the binding's lifetime.
-- `expires` is 0 to remove the binding (de-registration); `authz` carries
-- the Digest credentials once the challenge is known.
local function register(cseq, expires, authz)
    local b = sip.Builder()
        :request(sip.REGISTER, reg_uri)
        :header(sip.H_VIA, ("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-reg-%d"):format(cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=uac-%d"):format(aor, cseq))
        :header(sip.H_TO, ("<%s>"):format(aor))
        :header(sip.H_CALL_ID, call_id)
        :header(sip.H_CSEQ, ("%d REGISTER"):format(cseq))
        :header(sip.H_CONTACT, ("<%s>"):format(contact))
        :header_u32(sip.H_EXPIRES, expires)
    if authz then b:header(sip.H_AUTHORIZATION, authz) end
    return b:done()
end

-- ---- Registrar: stateless stub, challenges then validates -------------

-- A response echoes Via/From/Call-ID/CSeq and stamps a To-tag (dialog id).
local function respond(req, status, extra)
    local b = sip.Builder():response(status)
        :header(sip.H_VIA, req:header("Via"))
        :header(sip.H_FROM, req:header("From"))
        :header(sip.H_TO, req:header("To") .. ";tag=reg-9a3f")
        :header(sip.H_CALL_ID, req:header("Call-ID"))
        :header(sip.H_CSEQ, req:header("CSeq"))
    if extra then extra(b) end
    return b:done()
end

local function registrar(wire)
    local m = sip.parse(wire)
    assert(m.request and m.method == sip.REGISTER, "registrar handles REGISTER only")
    local authz = m:header("Authorization")

    -- No credentials yet: challenge with a Digest nonce (RFC 3261 §22.3).
    if authz == "" then
        return respond(m, 401, function(b)
            b:header(sip.H_WWW_AUTHENTICATE,
                ('Digest realm="%s",nonce="%s",qop="auth",algorithm=MD5'):format(realm, NONCE))
        end)
    end

    -- Validate the digest the way a real registrar does: recompute the
    -- response from the header's own nonce/nc/cnonce/uri and the shared
    -- password, and compare. A stale or wrong nonce re-challenges.
    local nonce  = sip.auth_param(authz, "nonce")
    local expect = digest_response(nonce, sip.auth_param(authz, "nc"),
                                   sip.auth_param(authz, "cnonce"),
                                   sip.auth_param(authz, "uri"))
    if nonce ~= NONCE or sip.auth_param(authz, "response") ~= expect then
        return respond(m, 401, function(b)
            b:header(sip.H_WWW_AUTHENTICATE,
                ('Digest realm="%s",nonce="%s",qop="auth",algorithm=MD5,stale=true'):format(realm, NONCE))
        end)
    end

    -- Accept: echo the Contact with the granted Expires (0 on de-register).
    local expires = m:header("Expires")
    return respond(m, 200, function(b)
        b:header(sip.H_CONTACT, ("<%s>;expires=%s"):format(contact, expires ~= "" and expires or "3600"))
    end)
end

-- ---- one REGISTER round-trip, driving all three machines --------------

local reg  = sip.Registration()   -- the §10 usage (top level)
local auth = sip.AuthChallenge()  -- the §22 challenge it delegates to
local cseq = 0

local function line(label, txn)
    print(("   %-30s reg=%-14s auth=%-14s txn=%s")
        :format(label, reg:state_name(), auth:state_name(), txn:state_name()))
end

-- Send `wire` (a REGISTER), feed it to the usage/auth/transaction
-- machines, hand it to the registrar and feed the reply back. Returns the
-- parsed response so the caller can read the challenge from it.
local function exchange(wire, label)
    local txn = sip.Transaction(sip.NON_INVITE_CLIENT)
    local out = sip.parse(wire)
    reg:send(out); auth:send(out); txn:send(out)
    line("-> " .. label, txn)

    local rsp = sip.parse(registrar(wire))
    reg:recv(rsp); auth:recv(rsp); txn:recv(rsp)
    line(("<- %d %s"):format(rsp.status, rsp.reason), txn)
    return rsp
end

-- ---- walk the registration lifecycle ----------------------------------

print("== Register (initial + IMS-style Digest challenge)")
cseq = cseq + 1
local rsp = exchange(register(cseq, 3600, nil), "REGISTER (no credentials)")
assert(reg:state() == sip.RS_CHALLENGED and auth:challenged(), "expected a 401 challenge")

local nonce = sip.auth_param(rsp:header("WWW-Authenticate"), "nonce")
cseq = cseq + 1
exchange(register(cseq, 3600, authorization(nonce)), "REGISTER (Digest MD5)")
assert(reg:registered() and auth:authenticated(), "expected 200 OK / registered")

print("\n== Refresh (re-REGISTER before Expires)")
cseq = cseq + 1
exchange(register(cseq, 3600, authorization(nonce)), "REGISTER (refresh)")
assert(reg:registered(), "expected the binding to be refreshed")

print("\n== De-register (Expires: 0)")
cseq = cseq + 1
exchange(register(cseq, 0, authorization(nonce)), "REGISTER (Expires: 0)")
assert(reg:done(), "expected a clean de-registration")

print(("\nresult: %s -> %s -> %s (registration usage complete)")
    :format(user, "registered", reg:state_name()))
