#!/usr/bin/env lua
--
-- cx_hss.lua — an HSS emulator on the Cx interface (3GPP TS 29.229), the
-- side the CSCFs talk Diameter to. It listens where the real HSS does; the
-- Kamailio I-CSCF / S-CSCF (the `cdp` C Diameter Peer) connect in and this
-- script answers their requests, so the CSCF chain runs with no real HSS
-- (and no mongo) behind it.
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so \
--     [HSS_PORT=3868] [HSS_PROTO=tcp|sctp] [HSS_REALM=mnc01.mcc001.3gppnetwork.org] \
--     [HSS_SCSCF=sip:scscf.ims.<realm>] [IMS_K=..] [IMS_OPC=..] [HSS_VERBOSE=1] \
--     lua cx_hss.lua
--
-- What it speaks:
--   * Diameter base peer protocol — CER/CEA (advertising Cx, app 16777216,
--     vendor 3GPP), DWR/DWA (watchdog), DPR/DPA (disconnect).
--   * Cx registration — UAR/UAA (I-CSCF: where does this user go),
--     MAR/MAA (S-CSCF: authentication vectors), SAR/SAA (S-CSCF: claim the
--     registration + pull the profile).
--   * Cx terminating — LIR/LIA (I-CSCF: which S-CSCF serves this callee).
--
-- The point of difference from a real HSS: MAA mints a *real* Milenage
-- vector (ipsec.aka_milenage) from the SAME USIM secret the UEs use
-- (IMS_K/IMS_OPC), for ANY IMSI derived from the request's IMPI — so the
-- whole IMSI range registers end-to-end without provisioning. That removes
-- both the mongo/HSS bottleneck and the "HSS User Unknown" provisioning
-- ceiling, leaving the CSCF chain as the thing under load.
--
-- One net.Loop drives a listening TCP (or SCTP) socket: each accepted
-- connection is a peer whose byte stream is de-framed by the Diameter
-- header's Message Length and dispatched by command code. Stateless
-- application (Cx is AUTH_SESSION_STATE_NO_STATE_MAINTAINED); the only
-- per-subscriber state kept is an SQN counter and a registered flag.

local net   = require("net")   -- event loop + listening stream socket
local diam  = require("diam")  -- Diameter codec + Cx dictionary
local ipsec = require("ipsec") -- Milenage (aka_milenage) + md5

-- ---- configuration ----------------------------------------------------

local BIND    = os.getenv("HSS_BIND")  or "0.0.0.0"
local PORT    = tonumber(os.getenv("HSS_PORT") or "3868")
local PROTO   = (os.getenv("HSS_PROTO") or "tcp"):lower()
local REALM   = os.getenv("HSS_REALM") or "mnc01.mcc001.3gppnetwork.org"
local VERBOSE = (os.getenv("HSS_VERBOSE") or "0") ~= "0"

-- Diameter identity of this HSS and the home domain the IMPU/IMPI live in.
local ORIGIN_HOST  = os.getenv("HSS_ORIGIN_HOST")  or ("hss.epc." .. REALM)
local ORIGIN_REALM = os.getenv("HSS_ORIGIN_REALM") or ("epc." .. REALM)
local HOME_REALM   = os.getenv("HSS_HOME")         or ("ims." .. REALM)

-- The S-CSCF this HSS hands back (Server-Name in UAA/LIA, and what the
-- I-CSCF forwards the REGISTER to). A single S-CSCF is enough for a mock.
local SCSCF = os.getenv("HSS_SCSCF") or ("sip:scscf." .. HOME_REALM)

-- Host-IP-Address advertised in CEA (informational). Best-effort from the
-- container's interface, else loopback.
local HOST_IP = net.if_addr4(os.getenv("HSS_IFACE") or "eth0")
if HOST_IP == "" then HOST_IP = "127.0.0.1" end

-- USIM secret (raw 16-byte hex). Defaults are the ims stack's shared keys
-- (TS 35.207 Milenage Test Set 1), matching bindings/examples/ims_test_s5.lua.
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end

local K   = unhex(os.getenv("IMS_K")   or "3919F39741B626604B4BACE23ACFB094")
local OPc = unhex(os.getenv("IMS_OPC")  or "177FAD988A964A3AD0421B4693257056")
local AMF = unhex(os.getenv("IMS_AMF")  or "8000")   -- 2-byte AKA management field

local PROTO_ID = (PROTO == "sctp") and net.PROTO_SCTP or net.PROTO_TCP

-- Short names for the constants used throughout.
local V3GPP     = diam.VENDOR_3GPP
local APP_CX    = diam.APP_CX
local RC_OK     = diam.RESULT_CODE_DIAMETER_SUCCESS
local RC_NOCOMP = diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY

-- ---- little helpers ---------------------------------------------------

local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end
local function log(fmt, ...) io.write(("%s\n"):format(fmt:format(...))); io.flush() end
local function vlog(fmt, ...) if VERBOSE then log("      " .. fmt, ...) end end

-- Byte-wise XOR of two equal-length strings, arithmetic only (Lua 5.1 /
-- LuaJIT-safe — no bitwise operators). Used once per MAR on the 6-byte
-- SQN and AK to form AUTN.
local function bxor(a, b)
    local r, p = 0, 1
    for _ = 1, 8 do
        local ab, bb = a % 2, b % 2
        if ab ~= bb then r = r + p end
        a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
    end
    return r
end
local function xorstr(x, y)
    local t = {}
    for i = 1, #x do t[i] = string.char(bxor(x:byte(i), y:byte(i))) end
    return table.concat(t)
end

-- 6-byte big-endian SQN from a Lua number (< 2^48, exact as a double).
local function sqn6(n)
    local b = {}
    for i = 6, 1, -1 do b[i] = string.char(n % 256); n = math.floor(n / 256) end
    return table.concat(b)
end

-- Read an optional AVP as a string / u32; nil when absent (m:str/:u32 throw
-- on a missing AVP, so gate on has()).
local function ostr(m, code, vendor)
    vendor = vendor or 0
    if m:has(code, vendor) then return m:str(code, vendor) end
    return nil
end
local function ou32(m, code, vendor)
    vendor = vendor or 0
    if m:has(code, vendor) then return m:u32(code, vendor) end
    return nil
end

-- IMSI from an IMPI ("<imsi>@realm"); the leading run of digits.
local function imsi_of(impi)
    return impi and impi:match("^(%d+)") or nil
end

-- ---- per-subscriber state ---------------------------------------------

-- Keyed by IMSI. sqn increments per authentication (0x20 steps, TS 33.102
-- style); the UE's ipsec.aka_verify checks only MAC-A (no freshness), so any
-- SQN authenticates. registered flips on the S-CSCF's SAR.
local subs = {}
local function sub_of(imsi)
    local s = subs[imsi]
    if not s then s = { sqn = 0x20, registered = false }; subs[imsi] = s end
    return s
end

-- ---- throughput counters ----------------------------------------------

local now = net.now_ms
local stats = { total = 0, by_cmd = {}, start = now(), win0 = now(), win_total = 0 }
local function count(name)
    stats.total = stats.total + 1
    stats.win_total = stats.win_total + 1
    stats.by_cmd[name] = (stats.by_cmd[name] or 0) + 1
end

-- ---- Diameter message builders ----------------------------------------

-- Base-protocol answer (CER/DWR/DPR): no Session-Id, application 0.
local function base_answer(m)
    return diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
        :put_u32(diam.AVP_RESULT_CODE, RC_OK)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
end

-- Cx answer preamble (TS 29.229 §6): Session-Id echoed, Vendor-Specific-
-- Application-Id{3GPP, Cx}, stateless, our Origin-Host/Realm. Mirrors the
-- request's proxiable bit. Returns the Builder for the caller to extend.
local function cx_answer(m)
    local b = diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
    if m.proxiable then b:proxiable() end
    b:put_str(diam.AVP_SESSION_ID, ostr(m, diam.AVP_SESSION_ID) or "")
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_CX)
        :end_group()
        :put_u32(diam.AVP_AUTH_SESSION_STATE,
                 diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
    return b
end

-- ---- command handlers (return the wire answer, or nil to send nothing) --

-- CER -> CEA: accept and advertise the Cx application both ways (a plain
-- Auth-Application-Id and the Vendor-Specific-Application-Id group) plus the
-- 3GPP Supported-Vendor-Id, so the peer's application match succeeds.
local function on_cer(m, peer)
    peer.origin_host = ostr(m, diam.AVP_ORIGIN_HOST) or peer.origin_host
    log("   <- CER from %s (%s)", peer.origin_host or "?", peer.addr)
    return base_answer(m)
        :put_addr4(diam.AVP_HOST_IP_ADDRESS, HOST_IP)
        :put_u32(diam.AVP_VENDOR_ID, V3GPP)
        :put_str(diam.AVP_PRODUCT_NAME, "pro2call-cx-hss")
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_CX)
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_CX)
        :end_group()
        :put_u32(diam.AVP_SUPPORTED_VENDOR_ID, V3GPP)
        :put_u32(diam.AVP_FIRMWARE_REVISION, 1)
        :done()
end

local function on_dwr(m) return base_answer(m):done() end

-- DPR -> DPA, then the caller drops the connection.
local function on_dpr(m, peer)
    log("   <- DPR from %s -- closing", peer.origin_host or peer.addr)
    peer.closing = true
    return base_answer(m):done()
end

-- UAR -> UAA: assign (always) the one S-CSCF. First time this IMPU is seen
-- registered -> FIRST_REGISTRATION, else SUBSEQUENT_REGISTRATION; a
-- de-registration authorization just succeeds with the Server-Name.
local function on_uar(m)
    local impi = ostr(m, diam.AVP_USER_NAME)
    local impu = ostr(m, diam.AVP_PUBLIC_IDENTITY, V3GPP)
    local atype = ou32(m, diam.AVP_USER_AUTHORIZATION_TYPE, V3GPP) or 0
    local imsi = imsi_of(impi)
    local s = imsi and sub_of(imsi)
    vlog("UAR impi=%s impu=%s type=%d", impi or "?", impu or "?", atype)

    local b = cx_answer(m)
    if atype == 1 then                        -- DE_REGISTRATION
        b:put_u32(diam.AVP_RESULT_CODE, RC_OK)
         :put_str(diam.AVP_SERVER_NAME, SCSCF)
    else                                      -- REGISTRATION / *_AND_CAPABILITIES
        local code = (s and s.registered)
            and diam.EXPERIMENTAL_RESULT_CODE_DIAMETER_SUBSEQUENT_REGISTRATION
            or  diam.EXPERIMENTAL_RESULT_CODE_DIAMETER_FIRST_REGISTRATION
        b:begin_group(diam.AVP_EXPERIMENTAL_RESULT)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_EXPERIMENTAL_RESULT_CODE, code)
         :end_group()
         :put_str(diam.AVP_SERVER_NAME, SCSCF)
    end
    log("   <- UAR %s  -> UAA (S-CSCF %s)", impu or impi or "?", SCSCF)
    return b:done()
end

-- MAR -> MAA: one (or as many as asked, capped) Milenage AKAv1-MD5 vector(s).
-- Per item: RAND = md5(imsi|sqn|salt) (deterministic, no RNG needed), then
-- ipsec.aka_milenage -> RES/CK/IK/AK/MAC; AUTN = (SQN^AK)|AMF|MAC. The item
-- carries SIP-Authenticate = RAND|AUTN, SIP-Authorization = XRES (RES) and
-- the CK/IK the S-CSCF forwards to the P-CSCF for the IPsec SAs.
local function on_mar(m)
    local impi = ostr(m, diam.AVP_USER_NAME)
    local impu = ostr(m, diam.AVP_PUBLIC_IDENTITY, V3GPP)
    local imsi = imsi_of(impi)
    if not imsi then
        log("   <- MAR without a numeric IMPI (%s) -> UNABLE_TO_COMPLY", impi or "?")
        return cx_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_NOCOMP):done()
    end
    local want = ou32(m, diam.AVP_3GPP_SIP_NUMBER_AUTH_ITEMS, V3GPP) or 1
    if want < 1 then want = 1 end
    if want > 5 then want = 5 end
    local scheme = "Digest-AKAv1-MD5"
    if m:has(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM, V3GPP) then
        local it = m:find(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM, V3GPP)
        if it:has_child(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, V3GPP) then
            local sc = it:child(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, V3GPP):str()
            if sc ~= "" and sc:lower() ~= "unknown" then scheme = sc end
        end
    end
    local s = sub_of(imsi)

    local b = cx_answer(m)
        :put_u32(diam.AVP_RESULT_CODE, RC_OK)
        :put_str(diam.AVP_USER_NAME, impi)
        :put_str(diam.AVP_PUBLIC_IDENTITY, impu or ("sip:" .. impi))
        :put_u32(diam.AVP_3GPP_SIP_NUMBER_AUTH_ITEMS, want)

    local first_rand
    for i = 1, want do
        local sqn = sqn6(s.sqn)
        local rand = ipsec.md5(imsi .. "|" .. hex(sqn) .. "|cx_hss")
        local v = ipsec.aka_milenage(K, OPc, rand, sqn, AMF)
        local autn = xorstr(v.sqn, v.ak) .. AMF .. v.mac        -- 6+2+8 = 16 bytes
        b:begin_group(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM)
            :put_u32(diam.AVP_3GPP_SIP_ITEM_NUMBER, i)
            :put_str(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, scheme)
            :put_str(diam.AVP_3GPP_SIP_AUTHENTICATE, rand .. autn)   -- RAND || AUTN
            :put_str(diam.AVP_3GPP_SIP_AUTHORIZATION, v.res)         -- XRES
            -- CK/IK codes 625/626 collide with standard AVPs, so name the
            -- 3GPP vendor explicitly (else VENDOR_AUTO picks the IETF entry
            -- and writes vendor 0 — the S-CSCF then can't find them).
            :put_str(diam.AVP_CONFIDENTIALITY_KEY, v.ck, V3GPP)
            :put_str(diam.AVP_INTEGRITY_KEY, v.ik, V3GPP)
        :end_group()
        first_rand = first_rand or rand
        s.sqn = s.sqn + 0x20
    end
    log("   <- MAR %s  -> MAA (%dx %s, RAND %s)", impi, want, scheme, hex(first_rand))
    return b:done()
end

-- SAR -> SAA: on a (re-)registration return SUCCESS + the IMS subscription
-- profile (Cx-User-Data) and mark the user registered; on a de-registration
-- just succeed and clear the flag.
local DEREG = {
    [diam.SERVER_ASSIGNMENT_TYPE_USER_DEREGISTRATION] = true,
    [diam.SERVER_ASSIGNMENT_TYPE_TIMEOUT_DEREGISTRATION] = true,
    [diam.SERVER_ASSIGNMENT_TYPE_USER_DEREGISTRATION_STORE_SERVER_NAME] = true,
    [diam.SERVER_ASSIGNMENT_TYPE_TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME] = true,
    [diam.SERVER_ASSIGNMENT_TYPE_AUTHENTICATION_FAILURE] = true,
}

-- An initial filter criterion sending MESSAGE requests to an application
-- server — the IP-SM-GW, for SMS over IMS (TS 24.341 §5.3.2). The S-CSCF
-- triggers application servers from the iFC in the profile returned here
-- and nowhere else (serving.cfg loads ims_isc and calls
-- isc_match_filter), so this is what puts bindings/examples/ipsmgw.lua in
-- the path without touching the ims stack's own configuration.
--
-- SessionCase values are TS 29.228 §6.3.5: 0 originating, 1 terminating
-- for a registered user. DefaultHandling 0 is SESSION_CONTINUED, so a
-- gateway that is down does not break every other MESSAGE.
--
-- The Content-Type service point is deliberately not added. It would be
-- more precise, but this stack's isc_match_filter only evaluates the
-- header-based service points it was compiled with, and a criterion whose
-- extra term never matches sends nothing to the gateway at all — which
-- looks exactly like a broken iFC.
local function ifc(as_uri, session_case, priority)
    return table.concat({
        '<InitialFilterCriteria>',
        '<Priority>', tostring(priority), '</Priority>',
        '<TriggerPoint>',
        '<ConditionTypeCNF>1</ConditionTypeCNF>',
        '<SPT><ConditionNegated>0</ConditionNegated><Group>0</Group>',
        '<Method>MESSAGE</Method></SPT>',
        '<SPT><ConditionNegated>0</ConditionNegated><Group>0</Group>',
        '<SessionCase>', tostring(session_case), '</SessionCase></SPT>',
        '</TriggerPoint>',
        '<ApplicationServer>',
        '<ServerName>', as_uri, '</ServerName>',
        '<DefaultHandling>0</DefaultHandling>',
        '</ApplicationServer>',
        '</InitialFilterCriteria>',
    })
end

-- HSS_IPSMGW is the application server URI, e.g.
-- "sip:ipsmgw.ims.mnc001.mcc001.3gppnetwork.org:5065". Unset means no iFC
-- at all, which is what a bare REGISTER needs and what this emulator did
-- before SMS existed. HSS_IPSMGW_TERM=0 drops the terminating criterion,
-- for a deployment where the gateway originates its own MT MESSAGE (the
-- design ipsmgw.lua actually uses) rather than being forked into the
-- terminating path.
local IPSMGW      = os.getenv("HSS_IPSMGW")
local IPSMGW_TERM = (os.getenv("HSS_IPSMGW_TERM") or "1") ~= "0"

-- A minimal but complete IMS subscription (TS 29.228 Annex): one unbarred
-- public identity, plus the SMS iFC when an IP-SM-GW is configured.
local function profile(impi, impu)
    local parts = {
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<IMSSubscription>',
        '<PrivateID>', impi, '</PrivateID>',
        '<ServiceProfile>',
        '<PublicIdentity>',
        '<BarringIndication>0</BarringIndication>',
        '<Identity>', impu, '</Identity>',
        '</PublicIdentity>',
    }
    if IPSMGW then
        parts[#parts + 1] = ifc(IPSMGW, 0, 0)               -- originating
        if IPSMGW_TERM then
            parts[#parts + 1] = ifc(IPSMGW, 1, 1)           -- terminating
        end
    end
    parts[#parts + 1] = '</ServiceProfile>'
    parts[#parts + 1] = '</IMSSubscription>'
    return table.concat(parts)
end

local function on_sar(m)
    local impi = ostr(m, diam.AVP_USER_NAME)
    local impu = ostr(m, diam.AVP_PUBLIC_IDENTITY, V3GPP) or ("sip:" .. (impi or ""))
    local sat  = ou32(m, diam.AVP_SERVER_ASSIGNMENT_TYPE, V3GPP) or
                 diam.SERVER_ASSIGNMENT_TYPE_REGISTRATION
    local imsi = imsi_of(impi)
    local s = imsi and sub_of(imsi)
    vlog("SAR impi=%s impu=%s type=%d", impi or "?", impu, sat)

    local b = cx_answer(m)
        :put_u32(diam.AVP_RESULT_CODE, RC_OK)
        :put_str(diam.AVP_USER_NAME, impi or "")
    if DEREG[sat] then
        if s then s.registered = false end
        log("   <- SAR %s (type %d, de-register) -> SAA", impu, sat)
    else
        if s then s.registered = true end
        b:put_str(diam.AVP_CX_USER_DATA, profile(impi or "", impu))
        log("   <- SAR %s (type %d, register)   -> SAA + profile", impu, sat)
    end
    return b:done()
end

-- LIR -> LIA: hand back the serving S-CSCF so a mobile-terminated request
-- routes to it.
local function on_lir(m)
    local impu = ostr(m, diam.AVP_PUBLIC_IDENTITY, V3GPP)
    log("   <- LIR %s -> LIA (S-CSCF %s)", impu or "?", SCSCF)
    return cx_answer(m)
        :put_u32(diam.AVP_RESULT_CODE, RC_OK)
        :put_str(diam.AVP_SERVER_NAME, SCSCF)
        :done()
end

local HANDLERS = {
    [diam.CMD_CAPABILITIES_EXCHANGE] = { name = "CER", fn = on_cer },
    [diam.CMD_DEVICE_WATCHDOG]       = { name = "DWR", fn = on_dwr },
    [diam.CMD_DISCONNECT_PEER]       = { name = "DPR", fn = on_dpr },
    [diam.CMD_USER_AUTHORIZATION]    = { name = "UAR", fn = on_uar },
    [diam.CMD_MULTIMEDIA_AUTH]       = { name = "MAR", fn = on_mar },
    [diam.CMD_SERVER_ASSIGNMENT]     = { name = "SAR", fn = on_sar },
    [diam.CMD_LOCATION_INFO]         = { name = "LIR", fn = on_lir },
}

-- ---- connection handling ----------------------------------------------

local loop = net.Loop()
local peers = {}   -- fd -> { conn, rxbuf, addr, origin_host, closing }

local function drop(peer)
    local fd = peer.conn:fd()
    if peers[fd] then
        peers[fd] = nil
        pcall(function() loop:del_fd(fd) end)
        peer.conn:close()
        log("   -- peer %s disconnected", peer.origin_host or peer.addr)
    end
end

-- Dispatch one complete Diameter message.
local function dispatch(peer, frame)
    local ok, m = pcall(diam.parse, frame)
    if not ok then
        log("   !! unparseable %d-byte message from %s: %s", #frame, peer.addr, why(m))
        return
    end
    if not m.request then                     -- we are a server; ignore answers
        vlog("ignoring %s answer", m:name())
        return
    end
    local h = HANDLERS[m.cmd]
    if not h then
        log("   ?? unhandled command %d (%s) from %s", m.cmd, m:name(), peer.addr)
        local ans = cx_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_NOCOMP):done()
        pcall(function() peer.conn:send(ans, 1000) end)
        return
    end
    count(h.name)
    local sok, ans = pcall(h.fn, m, peer)
    if not sok then
        log("   !! %s handler error: %s", h.name, why(ans))
        return
    end
    if ans then
        local wok, werr = pcall(function() peer.conn:send(ans, 1000) end)
        if not wok then log("   !! send failed to %s: %s", peer.addr, why(werr)); return drop(peer) end
    end
    if peer.closing then drop(peer) end
end

-- Pull the header's 24-bit Message Length and slice whole messages out of
-- the peer's byte stream (TCP may coalesce or split them).
local function frame_stream(peer)
    while #peer.rxbuf >= 20 do
        local b = peer.rxbuf
        local mlen = b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
        if mlen < 20 then
            log("   !! bad Message Length %d from %s -- dropping", mlen, peer.addr)
            return drop(peer)
        end
        if #b < mlen then return end          -- wait for the rest
        peer.rxbuf = b:sub(mlen + 1)
        dispatch(peer, b:sub(1, mlen))
        if not peers[peer.conn:fd()] then return end   -- dropped mid-dispatch
    end
end

local function on_readable(peer)
    while true do
        local ok, d = pcall(function() return peer.conn:recv(-1) end)
        if not ok then log("   !! recv error from %s: %s", peer.addr, why(d)); return drop(peer) end
        if d.closed then return drop(peer) end
        if d.timed_out then break end
        peer.rxbuf = peer.rxbuf .. d.data
    end
    frame_stream(peer)
end

local function on_accept(lst)
    while true do
        local c = lst:accept(-1)
        if not c then break end
        local peer = {
            conn = c, rxbuf = "",
            addr = ("%s:%d"):format(c:peer_host(), c:peer_port()),
        }
        peers[c:fd()] = peer
        loop:add_fd(c:fd(), net.NET_RD, function() on_readable(peer) end)
        log("   ++ connection from %s", peer.addr)
    end
end

-- ---- periodic throughput line -----------------------------------------

local STATS_MS = tonumber(os.getenv("HSS_STATS_MS") or "5000")
local function tick()
    local t = now()
    local win = (t - stats.win0) / 1000
    local rate = win > 0 and (stats.win_total / win) or 0
    local parts = {}
    for _, k in ipairs({ "CER", "DWR", "DPR", "UAR", "MAR", "SAR", "LIR" }) do
        if stats.by_cmd[k] then parts[#parts + 1] = ("%s=%d"):format(k, stats.by_cmd[k]) end
    end
    log("== %d req total (%.0f/s last %.0fs) | %s",
        stats.total, rate, win, table.concat(parts, " "))
    stats.win0, stats.win_total = t, 0
    loop:after(STATS_MS, tick)
end

-- ---- run --------------------------------------------------------------

local ok, lst = pcall(net.StreamListener, BIND, PORT, PROTO_ID)
if not ok then
    io.stderr:write(("cannot listen on %s:%d/%s: %s\n"):format(BIND, PORT, PROTO, why(lst)))
    os.exit(1)
end
loop:add_fd(lst:fd(), net.NET_RD, function() on_accept(lst) end)

log("== Cx/HSS emulator ready")
log("   listen         %s:%d/%s", BIND, PORT, PROTO)
log("   Origin-Host    %s", ORIGIN_HOST)
log("   Origin-Realm   %s", ORIGIN_REALM)
log("   S-CSCF         %s", SCSCF)
log("   SMS iFC        %s", IPSMGW
    and ("%s (orig%s)"):format(IPSMGW, IPSMGW_TERM and " + term" or " only")
    or "none (set HSS_IPSMGW to put an IP-SM-GW in the MESSAGE path)")
log("   Host-IP        %s", HOST_IP)
log("   USIM           K=%s OPc=%s AMF=%s (accept-any-IMSI)", hex(K), hex(OPc), hex(AMF))

loop:after(STATS_MS, tick)
local rok, rerr = pcall(function() loop:run() end)
if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n"); os.exit(1) end
