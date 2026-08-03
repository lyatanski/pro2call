#!/usr/bin/env lua
--
-- ipsmgw.lua — an IP-SM-GW emulator: the application server that bridges
-- IMS SIP MESSAGE traffic (3GPP TS 24.341) to a Service Centre over
-- Diameter (TS 29.338 SGd).
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so \
--     [IPSMGW_BIND=0.0.0.0] [IPSMGW_PORT=5065] [IPSMGW_REALM=ims....] \
--     [IPSMGW_MODE=sgd|loopback] [IPSMGW_SC_ADDR=+123456789] \
--     [SMSC_HOST=smsc] [SMSC_PORT=3870] [SMSC_PROTO=tcp|sctp] \
--     [IPSMGW_SCSCF=scscf:6060] [IPSMGW_MAP="447700900001=sip:..,.."] \
--     [IPSMGW_VERBOSE=1] lua ipsmgw.lua
--
-- Two roles on one net.Loop:
--
--   1. ISC/AS side (SIP over UDP). It receives MESSAGE requests whose
--      Content-Type is application/vnd.3gpp.sms, either because the
--      S-CSCF forked them here on an initial filter criterion or because
--      the UE addressed the service centre PSI directly at this port.
--      Mobile originated: parse the RPDU, answer 202 Accepted
--      (TS 24.341 §5.3.2.4), submit, then hand the UE an RP-ACK (or
--      RP-ERROR) in a NEW out-of-dialog MESSAGE.
--      Mobile terminated: originate a MESSAGE towards the recipient's
--      IMPU through the S-CSCF, so the delivery takes the same proven
--      terminating path as an MT INVITE — the UE's inbound ESP security
--      association terminates on the P-CSCF, so nothing else can reach it.
--
--   2. SGd side (Diameter over TCP/SCTP). CER/CEA advertising SGd,
--      DWR/DWA keepalive, OFR for each submit, and inbound TFR for each
--      delivery the SC pushes — on the connection this gateway opened,
--      because RFC 6733 connections are bidirectional.
--
-- Modes:
--   sgd       (default) MO goes to the SC as an OFR; MT is driven by the
--             SC's TFR. Exercises the Diameter interface.
--   loopback  a submit whose destination resolves to a known subscriber
--             is turned straight into a delivery, with no SC and no
--             Diameter at all. Everything in the path is from this repo,
--             which is what makes it the right tool for bisecting an
--             IMS-side failure from an SGd-side one.
--
-- Two boundaries that are easy to get wrong, and are therefore explicit
-- here:
--
--   * The relay layer terminates at this gateway. The SIP body is an
--     RPDU (RP-DATA / RP-ACK / RP-ERROR, TS 24.011); SM-RP-UI on SGd
--     carries the bare TPDU (TS 29.338 §7.3.4). This script strips the RP
--     layer on the way out and re-applies it on the way in, and asserts
--     what it parsed rather than forwarding bytes it did not understand.
--   * A delivery keeps TP-PID, TP-DCS, TP-UDHI and TP-UD byte for byte
--     (sms.deliver_from_submit). Re-encoding would destroy 8-bit
--     payloads, a user data header and any concatenation element, and
--     would quietly turn an end-to-end content assertion into a test of
--     the codec against itself.
--
-- Note on the reference point: TS 23.204 puts MAP over the E interface
-- between the IP-SM-GW and the SC in the classic architecture. This
-- implements TS 29.338 SGd instead — it is Diameter, it is what modern
-- deployments use towards the SC, and its commands and AVPs are already
-- in this repo's dictionary. It is not a literal 23.204 E interface.

local net  = require("net")
local sip  = require("sip")
local sms  = require("sms")
local diam = require("diam")

-- ---- configuration ----------------------------------------------------

local BIND    = os.getenv("IPSMGW_BIND") or "0.0.0.0"
local PORT    = tonumber(os.getenv("IPSMGW_PORT") or "5065")
local MODE    = (os.getenv("IPSMGW_MODE") or "sgd"):lower()
local VERBOSE = (os.getenv("IPSMGW_VERBOSE") or "0") ~= "0"

-- The home domain, and it MUST match the realm in the IMPUs the UEs
-- register: this gateway turns a recipient's digits into
-- sip:<digits>@<REALM>, and an S-CSCF will not route a Request-URI whose
-- domain it does not serve — the delivery would come back 404 and look
-- like an addressing bug in the core.
--
-- TS 23.003 pads the MNC to three digits, which is what
-- bindings/examples/ims_test_s5.lua builds its IMPUs from, so the default
-- is derived the same way from the same two variables.
local MCC = os.getenv("IMS_MCC") or "001"
local MNC = os.getenv("IMS_MNC") or "01"
local function mnc3(n) return (#n == 2) and ("0" .. n) or n end
local CORE_REALM = os.getenv("IPSMGW_CORE_REALM")
    or ("mnc%s.mcc%s.3gppnetwork.org"):format(mnc3(MNC), MCC)
local REALM = os.getenv("IPSMGW_REALM") or ("ims." .. CORE_REALM)

-- Our own SIP identity. PSI is the public service identity a UE addresses
-- when it submits directly (the service centre address in SIP form).
local ADVERTISED = os.getenv("IPSMGW_HOST") or ""   -- resolved below
local PSI     = os.getenv("IPSMGW_PSI") or ("sip:smsc@" .. REALM)
local SC_ADDR = os.getenv("IPSMGW_SC_ADDR") or "+123456789"

-- Where an MT MESSAGE is sent so the core routes it terminating. Empty
-- means "answer to whatever address the MO came from", which only works
-- in a direct-addressing lab setup.
local SCSCF      = os.getenv("IPSMGW_SCSCF") or ""
local SCSCF_HOST, SCSCF_PORT = SCSCF:match("^([^:]+):?(%d*)$")
SCSCF_PORT = tonumber(SCSCF_PORT ~= "" and SCSCF_PORT or "6060")

-- SGd peer.
local SMSC_HOST  = os.getenv("SMSC_HOST") or "smsc"
local SMSC_PORT  = tonumber(os.getenv("SMSC_PORT") or "3870")
local SMSC_PROTO = (os.getenv("SMSC_PROTO") or "tcp"):lower()
local SMSC_PROTO_ID = (SMSC_PROTO == "sctp") and net.PROTO_SCTP or net.PROTO_TCP

-- Diameter identity. The SGd realm is the core realm, not the IMS one —
-- cx_hss.lua puts its own HSS under "epc.<core realm>" for the same reason.
local ORIGIN_HOST  = os.getenv("IPSMGW_ORIGIN_HOST") or ("ipsmgw." .. REALM)
local ORIGIN_REALM = os.getenv("IPSMGW_ORIGIN_REALM") or ("epc." .. CORE_REALM)
local DEST_REALM   = os.getenv("IPSMGW_DEST_REALM") or ORIGIN_REALM

-- Deadlines. MO: how long a submit may take before the UE is told it
-- failed. MT: how long the UE has to answer a delivery (TS 24.011 TR2M
-- is 15..25 s; the SIP hops make this the outer bound).
local MO_T_MS = tonumber(os.getenv("IPSMGW_MO_T_MS") or "20000")
local MT_T_MS = tonumber(os.getenv("IPSMGW_MT_T_MS") or "20000")
local DWR_MS  = tonumber(os.getenv("IPSMGW_DWR_MS") or "30000")

-- ---- little helpers ---------------------------------------------------

local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end
local function log(fmt, ...) io.write(("%s\n"):format(fmt:format(...))); io.flush() end
local function vlog(fmt, ...) if VERBOSE then log("      " .. fmt, ...) end end

local now = net.now_ms

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

local V3GPP   = diam.VENDOR_3GPP
local APP_SGD = diam.APP_SGD
local RC_OK   = diam.RESULT_CODE_DIAMETER_SUCCESS

-- ---- MSISDN <-> IMPU resolution ---------------------------------------
--
-- A real IP-SM-GW learns the recipient's public identity from the HSS
-- (Sh UDR for IMSPublicIdentity, keyed by the IMSI the SC put in TFR's
-- User-Name). That round trip buys nothing for a lab whose subscribers
-- are generated from a numeric range, so two cheaper rules are used and
-- the Sh interface is left for later:
--
--   1. IPSMGW_MAP, an explicit "digits=impu,digits=impu" list.
--   2. otherwise the digits ARE the subscriber identity, giving
--      sip:<digits>@<realm> — which is exactly the IMPU
--      bindings/examples/ims_test_s5.lua registers, because it derives
--      both from the IMSI.
--
-- Set IPSMGW_TEL=1 for the tel-URI form a real network would use
-- (sip:+<digits>@<realm>;user=phone).

local MAP = {}
do
    local spec = os.getenv("IPSMGW_MAP") or ""
    for pair in spec:gmatch("[^,]+") do
        local k, v = pair:match("^%s*([%+%d]+)%s*=%s*(.-)%s*$")
        if k and v and v ~= "" then MAP[(k:gsub("^%+", ""))] = v end
    end
end
local TEL = (os.getenv("IPSMGW_TEL") or "0") ~= "0"

local function impu_of(digits)
    if not digits or digits == "" then return nil end
    local d = digits:gsub("^%+", "")
    if MAP[d] then return MAP[d] end
    if TEL then return ("sip:+%s@%s;user=phone"):format(d, REALM) end
    return ("sip:%s@%s"):format(d, REALM)
end

-- The MSISDN a submitting UE identifies itself by. P-Asserted-Identity is
-- what a trusted network inserts (RFC 3325) and is therefore the only
-- honest source; From is accepted as a fallback for a direct-addressing
-- lab where no P-CSCF asserted anything.
local function digits_of_uri(uri)
    -- sip:+441234@realm / sip:001010000000001@realm / tel:+441234
    local user = uri:match("^%s*<?%s*sips?:([^@;>%s]+)") or
                 uri:match("^%s*<?%s*tel:([^;>%s]+)")
    if not user then return nil end
    user = user:gsub("^%+", ""):gsub("%D", "")
    return user ~= "" and user or nil
end

local function msisdn_of(req)
    local pai = req:header("P-Asserted-Identity")
    local d = pai ~= "" and digits_of_uri(pai) or nil
    if d then return d, "P-Asserted-Identity" end
    d = digits_of_uri(req:header("From"))
    if d then return d, "From" end
    return nil, nil
end

-- ---- counters ---------------------------------------------------------

local stats = {
    start = now(), win0 = now(),
    mo_in = 0, mo_ok = 0, mo_fail = 0,
    mt_out = 0, mt_ok = 0, mt_fail = 0,
    ofr = 0, ofa_ok = 0, ofa_fail = 0, tfr = 0,
    ignored = 0, bad_body = 0,
}

-- ---- SIP side ---------------------------------------------------------

local loop = net.Loop()
local sock = nil     -- net.UdpSocket bound at BIND:PORT

-- Local address to put in Via / Contact. The socket's bound address is
-- the any-address, which is not routable back, so resolve an interface.
local function local_addr()
    if ADVERTISED ~= "" then return ADVERTISED end
    local a = net.if_addr4(os.getenv("IPSMGW_IFACE") or "eth0")
    if a == "" then a = "127.0.0.1" end
    return a
end
local MY_ADDR = nil   -- filled at start

local seq = { branch = 0, cseq = 0, callid = 0, mr = 0 }
local function branch()
    seq.branch = seq.branch + 1
    return ("z9hG4bK-ipsmgw-%d-%d"):format(now() % 1000000, seq.branch)
end
local function call_id()
    seq.callid = seq.callid + 1
    return ("ipsmgw-%d-%d@%s"):format(now() % 1000000, seq.callid, MY_ADDR)
end
local function next_mr()
    seq.mr = (seq.mr + 1) % 256
    return seq.mr
end

-- MT transactions we originated, and the RP-ACK we are waiting for.
local mt_by_callid = {}   -- call-id -> mt state
local mt_by_mr     = {}   -- rp-mr   -> mt state (the UE answers out of dialog)

-- MO transactions in flight (waiting for an OFA, or for the loopback MT).
local mo_pending = {}     -- key -> mo state

-- Answer a request we received, echoing the fields RFC 3261 §8.2.6 wants.
local function respond(req, status, reason, host, port)
    local b = sip.Builder():response(status, reason)
    -- header_values() is a 0-based StringList proxy, not a Lua array.
    local vias = req:header_values("Via")
    for i = 0, vias:size() - 1 do b:header(sip.H_VIA, vias[i]) end
    b:header(sip.H_FROM, req:header("From"))
     :header(sip.H_TO, req:header("To"))
     :header(sip.H_CALL_ID, req:call_id())
     :header(sip.H_CSEQ, req:header("CSeq"))
    local wire = b:done()
    local ok, err = pcall(function() sock:sendto(wire, host, port) end)
    if not ok then log("   !! %d %s send failed: %s", status, reason or "", why(err)) end
    vlog("-> %d %s to %s:%d", status, reason or "", host, port)
    return ok
end

-- Build an out-of-dialog MESSAGE carrying an RPDU. Returns the wire bytes
-- and the Call-ID, so a caller that needs to match the response does not
-- have to re-parse what it just built.
local function build_message(ruri, from_uri, to_uri, rpdu, route)
    local cid = call_id()
    local b = sip.Builder():request(sip.MESSAGE, ruri)
    b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s;rport"):format(
                             MY_ADDR, PORT, branch()))
    if route then b:header(sip.H_ROUTE, route) end
    seq.cseq = seq.cseq + 1
    b:header(sip.H_FROM, ("<%s>;tag=ipsmgw%d"):format(from_uri, seq.cseq))
     :header(sip.H_TO, ("<%s>"):format(to_uri))
     :header(sip.H_CALL_ID, cid)
     :header(sip.H_CSEQ, ("%d MESSAGE"):format(seq.cseq))
     :header(sip.H_MAX_FORWARDS, "70")
     :header_name("P-Asserted-Identity", ("<%s>"):format(from_uri))
     :header(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)
    return b:done(rpdu), cid
end

-- ---- where a delivery goes ---------------------------------------------
--
-- In a real deployment there is exactly one answer: through the S-CSCF.
-- A UE is reachable only via the P-CSCF that terminates its ESP tunnel, so
-- a UE's source address is not a route and must never be treated as one —
-- set IPSMGW_SCSCF and nothing below is consulted.
--
-- Without an S-CSCF (a direct-addressing lab, where the UEs speak to this
-- port themselves) the source address is the only route there is. Two
-- sources for it, in order:
--
--   1. IPSMGW_ADDR, an explicit "digits=host:port,..." list. Deterministic,
--      and the only thing that works for a recipient that has not sent
--      anything yet — which is the normal case for a receive-only UE.
--   2. otherwise, wherever that subscriber was last seen submitting from.
local ADDRS = {}
do
    local spec = os.getenv("IPSMGW_ADDR") or ""
    for entry in spec:gmatch("[^,]+") do
        local k, h, prt = entry:match("^%s*([%+%d]+)%s*=%s*([^:%s]+):(%d+)%s*$")
        if k then
            ADDRS[(k:gsub("^%+", ""))] = { host = h, port = tonumber(prt) }
        end
    end
end

local seen = {}   -- digits -> { host, port, at }

local function mt_target(digits, fallback_host, fallback_port)
    if SCSCF ~= "" then return SCSCF_HOST, SCSCF_PORT end
    local d = digits and tostring(digits):gsub("^%+", "")
    local a = d and (ADDRS[d] or seen[d])
    if a then return a.host, a.port end
    return fallback_host, fallback_port
end

-- ---- the mobile-terminated leg ----------------------------------------

local function mt_finish(mt, ok, detail)
    if mt.done then return end
    mt.done = true
    if mt.timer then loop:cancel(mt.timer); mt.timer = nil end
    mt_by_callid[mt.call_id] = nil
    mt_by_mr[mt.mr] = nil
    if ok then
        stats.mt_ok = stats.mt_ok + 1
        log("   == delivered to %s in %d ms", mt.to, now() - mt.t0)
    else
        stats.mt_fail = stats.mt_fail + 1
        log("   !! delivery to %s failed: %s", mt.to, detail or "?")
    end
    if mt.on_done then mt.on_done(ok, detail) end
end

-- Deliver a TPDU (an SMS-DELIVER) to whoever TP-DA said, wrapped in
-- RP-DATA towards the MS. on_done(ok, detail) reports the outcome, so the
-- SGd side can answer the TFR and the loopback side can log.
local function deliver(tpdu, to_digits, host, port, on_done)
    local impu = impu_of(to_digits)
    if not impu then
        if on_done then on_done(false, "no public identity for " .. tostring(to_digits)) end
        return
    end

    local mr = next_mr()
    local okr, rpdu = pcall(sms.rp_data, sms.DIR_SC_TO_MS, mr, SC_ADDR, tpdu)
    if not okr then
        if on_done then on_done(false, "RP-DATA: " .. why(rpdu)) end
        return
    end

    local h, p = mt_target(to_digits, host, port)
    local wire, cid = build_message(impu, PSI, impu, rpdu, nil)
    local mt = {
        call_id = cid, mr = mr, to = impu,
        t0 = now(), on_done = on_done, done = false,
    }
    mt_by_callid[mt.call_id] = mt
    mt_by_mr[mr] = mt
    stats.mt_out = stats.mt_out + 1

    local sok, serr = pcall(function() sock:sendto(wire, h, p) end)
    if not sok then
        return mt_finish(mt, false, "MESSAGE send: " .. why(serr))
    end
    log("   -> MESSAGE %s (RP-MR %d, %d octets) via %s:%d", impu, mr, #rpdu, h, p)
    mt.timer = loop:after(MT_T_MS, function()
        mt.timer = nil
        mt_finish(mt, false, "no RP-ACK within " .. MT_T_MS .. " ms")
    end)
end

-- ---- the mobile-originated leg ----------------------------------------

-- Tell the submitting UE what became of its message: a new out-of-dialog
-- MESSAGE carrying RP-ACK, or RP-ERROR with a cause (TS 24.341 §5.3.2.4).
local function send_mo_report(mo, ok, cause, report_tpdu)
    local rpdu
    local okb, err
    if ok then
        okb, rpdu = pcall(sms.ack, sms.DIR_SC_TO_MS, mo.mr, report_tpdu or "")
    else
        okb, rpdu = pcall(sms.error, sms.DIR_SC_TO_MS, mo.mr,
                          cause or sms.RP_CAUSE_TEMPORARY_FAILURE, "")
    end
    if not okb then
        log("   !! cannot build the MO report: %s", why(rpdu))
        return
    end
    local h, p = mt_target(mo.from, mo.host, mo.port)
    local wire = build_message(mo.from_impu, PSI, mo.from_impu, rpdu, nil)
    local sok, serr = pcall(function() sock:sendto(wire, h, p) end)
    if not sok then
        log("   !! MO report send failed: %s", why(serr))
        return
    end
    log("   -> MESSAGE %s (%s, RP-MR %d) via %s:%d", mo.from_impu,
        ok and "RP-ACK" or ("RP-ERROR " .. tostring(cause)), mo.mr, h, p)
end

local function mo_finish(mo, ok, cause, report_tpdu)
    if mo.done then return end
    mo.done = true
    if mo.timer then loop:cancel(mo.timer); mo.timer = nil end
    mo_pending[mo.key] = nil
    if ok then stats.mo_ok = stats.mo_ok + 1
    else stats.mo_fail = stats.mo_fail + 1 end
    send_mo_report(mo, ok, cause, report_tpdu)
end

-- Forward declaration: the SGd side is set up after the SIP side.
local sgd = { conn = nil, up = false }
local sgd_submit

-- A MESSAGE arrived carrying an RPDU from a UE.
local function on_mo(req, host, port)
    local okp, rp = pcall(sms.parse_rpdu, req.body, sms.DIR_MS_TO_SC)
    if not okp then
        stats.bad_body = stats.bad_body + 1
        log("   !! unparseable RPDU from %s:%d: %s", host, port, why(rp))
        return respond(req, 400, "Bad Request", host, port)
    end

    -- RP-ACK / RP-ERROR from a UE is the answer to a delivery WE sent, not
    -- a submission. It is matched by RP-MR because it arrives out of
    -- dialog, in its own MESSAGE (TS 24.341 §5.3.2.6).
    if rp.type == sms.RP_T_ACK or rp.type == sms.RP_T_ERROR then
        respond(req, 200, "OK", host, port)
        local mt = mt_by_mr[rp.mr]
        if not mt then
            stats.ignored = stats.ignored + 1
            return vlog("%s with RP-MR %d matches no delivery", rp:type_name(), rp.mr)
        end
        if rp.type == sms.RP_T_ACK then return mt_finish(mt, true) end
        return mt_finish(mt, false, ("RP-ERROR %d (%s)"):format(rp.cause,
                                                               rp:cause_name()))
    end

    if rp.type == sms.RP_T_SMMA then
        -- "Memory available again": a real gateway would alert the SC so
        -- it retries its waiting-message store. There is nothing stored
        -- here, so acknowledge and say so.
        respond(req, 200, "OK", host, port)
        local mr = rp.mr
        local from = msisdn_of(req)
        local h, p = mt_target(from, host, port)
        local okb, rpdu = pcall(sms.ack, sms.DIR_SC_TO_MS, mr, "")
        if okb then
            local impu = impu_of(from) or req:header("From")
            pcall(function()
                sock:sendto(build_message(impu, PSI, impu, rpdu, nil), h, p)
            end)
        end
        return log("   <- RP-SMMA from %s -- acknowledged (no store to retry)",
                   from or "?")
    end

    if rp.type ~= sms.RP_T_DATA or not rp:has_tpdu() then
        stats.bad_body = stats.bad_body + 1
        return respond(req, 400, "Bad Request", host, port)
    end

    local okt, sub = pcall(function() return rp:tpdu() end)
    if not okt or sub.type ~= sms.T_SUBMIT then
        stats.bad_body = stats.bad_body + 1
        log("   !! RP-DATA whose TPDU is not an SMS-SUBMIT (%s)",
            okt and sub:type_name() or why(sub))
        respond(req, 202, "Accepted", host, port)
        return
    end

    stats.mo_in = stats.mo_in + 1
    local from, src = msisdn_of(req)
    local to = sub.addr.digits
    -- Remember where this subscriber submits from, so a delivery can reach
    -- it when there is no S-CSCF to route through (see mt_target).
    if from then seen[from] = { host = host, port = port, at = now() } end
    local okx, text = pcall(function() return sub:text() end)
    log("   <- MESSAGE submit %s -> %s (%s%s) from %s:%d",
        from or "?", sub.addr:display(),
        sub:binary() and ("%d octets of 8-bit data"):format(#sub.user_data)
                     or ("%q"):format(okx and text or "?"),
        sub.srr and ", SRR" or "", host, port)
    if from and VERBOSE then vlog("originator taken from %s", src) end

    -- TS 24.341 §5.3.2.4: the submit is answered 202 Accepted, and the
    -- relay-layer report follows later in its own MESSAGE.
    respond(req, 202, "Accepted", host, port)

    local mo = {
        key = ("%s/%d"):format(req:call_id(), rp.mr),
        mr = rp.mr, from = from, to = to,
        from_impu = impu_of(from) or req:header("From"):match("<(.-)>") or
                    req:header("From"),
        tpdu = rp.user_data, srr = sub.srr,
        host = host, port = port, t0 = now(), done = false,
    }
    mo_pending[mo.key] = mo
    mo.timer = loop:after(MO_T_MS, function()
        mo.timer = nil
        mo_finish(mo, false, sms.RP_CAUSE_TEMPORARY_FAILURE)
    end)

    if MODE == "loopback" then
        -- No SC and no Diameter: be the service centre. The payload is
        -- copied verbatim, so what the recipient decodes is byte-for-byte
        -- what the sender encoded.
        local okc, deliver_tpdu = pcall(sms.deliver_from_submit, mo.tpdu,
                                        from or SC_ADDR, 0, 0, false)
        if not okc then
            log("   !! loopback conversion failed: %s", why(deliver_tpdu))
            return mo_finish(mo, false, sms.RP_CAUSE_SEMANTIC_ERROR)
        end
        -- The submit is acknowledged as soon as this gateway has taken
        -- responsibility for it, which is what a store-and-forward SC
        -- does — not when the recipient answers.
        mo_finish(mo, true)
        return deliver(deliver_tpdu, to, host, port, function(ok, detail)
            if not ok then vlog("loopback delivery to %s failed: %s", to, detail) end
        end)
    end

    -- SGd: submit to the service centre.
    if not sgd.up then
        log("   !! no SGd connection to %s:%d -- refusing the submit",
            SMSC_HOST, SMSC_PORT)
        return mo_finish(mo, false, sms.RP_CAUSE_NETWORK_OUT_OF_ORDER)
    end
    sgd_submit(mo)
end

-- ---- SIP receive ------------------------------------------------------

local function on_sip_readable()
    while true do
        local ok, dg = pcall(function() return sock:recv(-1) end)
        if not ok then return log("   !! recv error: %s", why(dg)) end
        if dg.timed_out then return end

        local okp, m = pcall(sip.parse, dg.data)
        if not okp then
            vlog("ignoring an unparseable %d-byte datagram from %s:%d",
                 #dg.data, dg.host, dg.port)
        elseif m.request then
            if m.method == sip.MESSAGE then
                local ct = m:header("Content-Type"):lower()
                if ct:find("vnd.3gpp.sms", 1, true) then
                    on_mo(m, dg.host, dg.port)
                else
                    stats.ignored = stats.ignored + 1
                    log("   ?? MESSAGE with Content-Type %q -- 415", ct)
                    respond(m, 415, "Unsupported Media Type", dg.host, dg.port)
                end
            elseif m.method == sip.OPTIONS then
                respond(m, 200, "OK", dg.host, dg.port)
            else
                stats.ignored = stats.ignored + 1
                vlog("ignoring a %s request", m.method_name)
                respond(m, 405, "Method Not Allowed", dg.host, dg.port)
            end
        else
            -- A response to a MESSAGE we sent. 2xx means the UE (or the
            -- core) took it; the RP-ACK that actually confirms delivery
            -- comes later, in its own MESSAGE.
            local mt = mt_by_callid[m:call_id()]
            if mt then
                if m.status >= 200 and m.status < 300 then
                    vlog("%d %s for the delivery to %s", m.status, m.reason, mt.to)
                    mt.accepted = now()
                elseif m.status >= 300 then
                    mt_finish(mt, false, ("%d %s"):format(m.status, m.reason))
                end
            elseif m.status >= 300 then
                vlog("%d %s for a MESSAGE we no longer track", m.status, m.reason)
            end
        end
    end
end

-- ---- SGd side ---------------------------------------------------------

local dseq = { sess = 0, hbh = 0x7000, e2e = 0x7000 }
local function next_session()
    dseq.sess = dseq.sess + 1
    return ("%s;%d;%d"):format(ORIGIN_HOST, math.floor(now() / 1000), dseq.sess)
end
local function next_ids()
    dseq.hbh = dseq.hbh + 1
    dseq.e2e = dseq.e2e + 1
    return dseq.hbh, dseq.e2e
end

local ofr_pending = {}   -- hbh -> mo

local function sgd_send(wire)
    if not sgd.conn then return false, "no connection" end
    local ok, err = pcall(function() sgd.conn:send(wire, 1000) end)
    if not ok then return false, why(err) end
    return true
end

local function sgd_request(cmd)
    local hbh, e2e = next_ids()
    local b = diam.Builder():request(cmd, APP_SGD):ids(hbh, e2e):proxiable()
        :put_str(diam.AVP_SESSION_ID, next_session())
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :end_group()
        :put_u32(diam.AVP_AUTH_SESSION_STATE,
                 diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
        :put_str(diam.AVP_DESTINATION_REALM, DEST_REALM)
    return b, hbh
end

-- OFR (MO-Forward-Short-Message-Request, TS 29.338 §6.3.1). SM-RP-UI
-- carries the TPDU, not the RPDU: the relay layer stops here.
sgd_submit = function(mo)
    local b, hbh = sgd_request(diam.CMD_MO_FORWARD_SHORT_MESSAGE)
    b:put_str(diam.AVP_SC_ADDRESS, SC_ADDR, V3GPP)
     :put_str(diam.AVP_USER_NAME, mo.from or "")
     :put_str(diam.AVP_SM_RP_UI, mo.tpdu, V3GPP)
     :put_u32(diam.AVP_OFR_FLAGS, 0, V3GPP)
    local wire = b:done()
    local ok, err = sgd_send(wire)
    if not ok then
        log("   !! OFR send failed: %s", err)
        return mo_finish(mo, false, sms.RP_CAUSE_NETWORK_OUT_OF_ORDER)
    end
    stats.ofr = stats.ofr + 1
    ofr_pending[hbh] = mo
    log("   -> OFR %s -> %s (%d octets of TPDU)", mo.from or "?", mo.to,
        #mo.tpdu)
end

local function on_ofa(m)
    local mo = ofr_pending[m.hbh]
    ofr_pending[m.hbh] = nil
    local rc = ou32(m, diam.AVP_RESULT_CODE)
    if not mo then
        return vlog("OFA %s matches no submit", tostring(rc or "?"))
    end
    if rc == RC_OK then
        stats.ofa_ok = stats.ofa_ok + 1
        -- The SC may return an SMS-SUBMIT-REPORT, which becomes the
        -- RP-ACK's optional payload so the UE gets the SC's timestamp.
        local report = ostr(m, diam.AVP_SM_RP_UI, V3GPP)
        log("   <- OFA 2001 for %s -> %s (%d ms)", mo.from or "?", mo.to,
            now() - mo.t0)
        return mo_finish(mo, true, nil, report)
    end
    stats.ofa_fail = stats.ofa_fail + 1
    -- Map the Diameter refusal onto an RP cause the UE understands
    -- (TS 23.040 §11.3 maps between the two layers; these are the cases
    -- an SC actually returns).
    local cause = sms.RP_CAUSE_TEMPORARY_FAILURE
    if rc == 5030 then cause = sms.RP_CAUSE_UNKNOWN_SUB          -- UNKNOWN_SESSION_ID
    elseif rc == 5012 then cause = sms.RP_CAUSE_TEMPORARY_FAILURE -- UNABLE_TO_COMPLY
    elseif rc == 3004 then cause = sms.RP_CAUSE_CONGESTION        -- TOO_BUSY
    elseif rc == 5003 then cause = sms.RP_CAUSE_TRANSFER_REJECTED end
    log("   <- OFA %s for %s -> RP-ERROR %d (%s)", tostring(rc or "?"),
        mo.to, cause, sms.rp_cause_name(cause))
    mo_finish(mo, false, cause)
end

-- TFR in: the SC is delivering. SM-RP-UI is the SMS-DELIVER TPDU; the
-- recipient comes from its TP-DA (authoritative) and User-Name is the
-- fallback.
local function on_tfr(m)
    stats.tfr = stats.tfr + 1
    local tpdu = ostr(m, diam.AVP_SM_RP_UI, V3GPP)
    local uname = ostr(m, diam.AVP_USER_NAME)

    local function answer(rc, fcause)
        local b = diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
        if m.proxiable then b:proxiable() end
        b:put_str(diam.AVP_SESSION_ID, ostr(m, diam.AVP_SESSION_ID) or "")
            :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
                :put_u32(diam.AVP_VENDOR_ID, V3GPP)
                :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
            :end_group()
            :put_u32(diam.AVP_AUTH_SESSION_STATE,
                     diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
            :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
            :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
            :put_u32(diam.AVP_RESULT_CODE, rc)
        if fcause then
            b:put_u32(diam.AVP_SM_DELIVERY_FAILURE_CAUSE, fcause, V3GPP)
        end
        sgd_send(b:done())
    end

    if not tpdu then
        log("   <- TFR with no SM-RP-UI -> UNABLE_TO_COMPLY")
        return answer(diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY)
    end
    local okp, del = pcall(sms.parse_tpdu, tpdu, sms.DIR_SC_TO_MS)
    if not okp or (del.type ~= sms.T_DELIVER and
                   del.type ~= sms.T_STATUS_REPORT) then
        log("   <- TFR whose SM-RP-UI is not a DELIVER or STATUS-REPORT (%s)",
            okp and del:type_name() or why(del))
        return answer(diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY)
    end

    -- TP-DA is on a SUBMIT, not a DELIVER — a DELIVER carries TP-OA (the
    -- sender). The recipient therefore has to come from the Diameter
    -- level, which is exactly what User-Name is for.
    local to = uname
    if not to or to == "" then
        log("   <- TFR with no User-Name to deliver to -> UNABLE_TO_COMPLY")
        return answer(diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY)
    end
    log("   <- TFR %s -> %s (%s)", del.addr:display(), to, del:type_name())

    deliver(tpdu, to, SCSCF_HOST, SCSCF_PORT, function(ok, detail)
        if ok then return answer(RC_OK) end
        vlog("delivery failed (%s), answering TFA with a failure cause", detail)
        -- SM-Enumerated-Delivery-Failure-Cause 1 is "equipment protocol
        -- error", the closest thing to "the handset never answered".
        answer(diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY, 1)
    end)
end

-- ---- SGd connection ---------------------------------------------------

local sgd_dial

local function sgd_cer()
    local hbh, e2e = next_ids()
    local ip = net.if_addr4(os.getenv("IPSMGW_IFACE") or "eth0")
    if ip == "" then ip = "127.0.0.1" end
    local wire = diam.Builder()
        :request(diam.CMD_CAPABILITIES_EXCHANGE, diam.APP_BASE)
        :ids(hbh, e2e)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
        :put_addr4(diam.AVP_HOST_IP_ADDRESS, ip)
        :put_u32(diam.AVP_VENDOR_ID, V3GPP)
        :put_str(diam.AVP_PRODUCT_NAME, "pro2call-ipsmgw")
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :end_group()
        :put_u32(diam.AVP_SUPPORTED_VENDOR_ID, V3GPP)
        :put_u32(diam.AVP_FIRMWARE_REVISION, 1)
        :done()
    sgd_send(wire)
end

local function sgd_drop(reason)
    if sgd.conn then
        pcall(function() loop:del_fd(sgd.conn:fd()) end)
        pcall(function() sgd.conn:close() end)
    end
    sgd.conn, sgd.up, sgd.rxbuf = nil, false, ""
    -- Every submit still waiting on this connection is now hopeless.
    for hbh, mo in pairs(ofr_pending) do
        ofr_pending[hbh] = nil
        mo_finish(mo, false, sms.RP_CAUSE_NETWORK_OUT_OF_ORDER)
    end
    log("   -- SGd connection to %s:%d lost (%s); redialling",
        SMSC_HOST, SMSC_PORT, reason or "?")
    loop:after(2000, sgd_dial)
end

local function sgd_dispatch(frame)
    local ok, m = pcall(diam.parse, frame)
    if not ok then
        return log("   !! unparseable %d-byte SGd message: %s", #frame, why(m))
    end
    if m.request then
        if m.cmd == diam.CMD_MT_FORWARD_SHORT_MESSAGE then return on_tfr(m) end
        if m.cmd == diam.CMD_DEVICE_WATCHDOG then
            return sgd_send(diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
                :put_u32(diam.AVP_RESULT_CODE, RC_OK)
                :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
                :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM):done())
        end
        if m.cmd == diam.CMD_DISCONNECT_PEER then
            sgd_send(diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
                :put_u32(diam.AVP_RESULT_CODE, RC_OK)
                :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
                :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM):done())
            return sgd_drop("DPR")
        end
        log("   ?? unhandled SGd request %d (%s)", m.cmd, m:name())
        return
    end
    if m.cmd == diam.CMD_CAPABILITIES_EXCHANGE then
        local rc = ou32(m, diam.AVP_RESULT_CODE)
        if rc == RC_OK then
            sgd.up = true
            log("   == SGd up to %s (%s)",
                ostr(m, diam.AVP_ORIGIN_HOST) or SMSC_HOST,
                ostr(m, diam.AVP_PRODUCT_NAME) or "?")
        else
            log("   !! CEA said %s -- dropping", tostring(rc or "?"))
            sgd_drop("CEA " .. tostring(rc))
        end
        return
    end
    if m.cmd == diam.CMD_MO_FORWARD_SHORT_MESSAGE then return on_ofa(m) end
    vlog("ignoring %s answer", m:name())
end

local function sgd_readable()
    while true do
        local ok, d = pcall(function() return sgd.conn:recv(-1) end)
        if not ok then return sgd_drop("recv: " .. why(d)) end
        if d.closed then return sgd_drop("peer closed") end
        if d.timed_out then break end
        sgd.rxbuf = sgd.rxbuf .. d.data
    end
    while #sgd.rxbuf >= 20 do
        local b = sgd.rxbuf
        local mlen = b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
        if mlen < 20 then return sgd_drop("bad Message Length " .. mlen) end
        if #b < mlen then return end
        sgd.rxbuf = b:sub(mlen + 1)
        sgd_dispatch(b:sub(1, mlen))
        if not sgd.conn then return end
    end
end

sgd_dial = function()
    local ok, c = pcall(net.stream_connect, SMSC_HOST, SMSC_PORT,
                        SMSC_PROTO_ID, 3000)
    if not ok then
        log("   -- cannot reach the SC at %s:%d/%s (%s); retrying",
            SMSC_HOST, SMSC_PORT, SMSC_PROTO, why(c))
        return loop:after(2000, sgd_dial)
    end
    sgd.conn, sgd.rxbuf, sgd.up = c, "", false
    loop:add_fd(c:fd(), net.NET_RD, sgd_readable)
    log("   ++ SGd connected to %s:%d/%s", SMSC_HOST, SMSC_PORT, SMSC_PROTO)
    sgd_cer()
end

local function sgd_watchdog()
    if sgd.up then
        local hbh, e2e = next_ids()
        sgd_send(diam.Builder()
            :request(diam.CMD_DEVICE_WATCHDOG, diam.APP_BASE):ids(hbh, e2e)
            :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
            :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
            :done())
    end
    loop:after(DWR_MS, sgd_watchdog)
end

-- ---- periodic line ----------------------------------------------------

local STATS_MS = tonumber(os.getenv("IPSMGW_STATS_MS") or "5000")
local function tick()
    local t = now()
    local win = (t - stats.win0) / 1000
    log("== MO %d in / %d ok / %d failed | MT %d out / %d ok / %d failed | SGd %s OFR=%d OFA=%d/%d TFR=%d | ignored %d bad-body %d (%.0fs)",
        stats.mo_in, stats.mo_ok, stats.mo_fail,
        stats.mt_out, stats.mt_ok, stats.mt_fail,
        MODE == "loopback" and "off" or (sgd.up and "up" or "down"),
        stats.ofr, stats.ofa_ok, stats.ofa_fail, stats.tfr,
        stats.ignored, stats.bad_body, win)
    stats.win0 = t
    loop:after(STATS_MS, tick)
end

-- ---- run --------------------------------------------------------------

if MODE ~= "sgd" and MODE ~= "loopback" then
    io.stderr:write(("IPSMGW_MODE must be sgd or loopback, not %q\n"):format(MODE))
    os.exit(2)
end

local ok, s = pcall(net.UdpSocket, BIND, PORT)
if not ok then
    io.stderr:write(("cannot bind %s:%d: %s\n"):format(BIND, PORT, why(s)))
    os.exit(1)
end
sock = s
MY_ADDR = local_addr()
loop:add_fd(sock:fd(), net.NET_RD, on_sip_readable)
-- Batch the answers: a burst of submits is answered without entering the
-- kernel between datagrams (see net.UdpSocket:tx_loop).
pcall(function() sock:tx_loop(loop, net.NET_RD) end)

log("== IP-SM-GW emulator ready (%s mode)", MODE)
log("   SIP listen     %s:%d (advertising %s)", BIND, PORT, MY_ADDR)
log("   PSI            %s", PSI)
log("   SC address     %s", SC_ADDR)
log("   realm          %s", REALM)
if SCSCF ~= "" then
    log("   MT via         %s:%d (S-CSCF)", SCSCF_HOST, SCSCF_PORT)
else
    local n = 0
    for _ in pairs(ADDRS) do n = n + 1 end
    log("   MT via         %s", n > 0
        and ("%d pinned UE address(es), then whoever last submitted"):format(n)
        or "whoever last submitted (no S-CSCF and no IPSMGW_ADDR set)")
end
if next(MAP) then
    local n = 0
    for _ in pairs(MAP) do n = n + 1 end
    log("   MSISDN map     %d explicit entr%s", n, n == 1 and "y" or "ies")
else
    log("   MSISDN map     digits -> %s", impu_of("<digits>") or "?")
end
if MODE == "sgd" then
    log("   SGd peer       %s:%d/%s", SMSC_HOST, SMSC_PORT, SMSC_PROTO)
    log("   Origin-Host    %s", ORIGIN_HOST)
    sgd_dial()
    loop:after(DWR_MS, sgd_watchdog)
else
    log("   SGd            disabled (loopback: submits become deliveries here)")
end

loop:after(STATS_MS, tick)
local rok, rerr = pcall(function() loop:run() end)
if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n"); os.exit(1) end
