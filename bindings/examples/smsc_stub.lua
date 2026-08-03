#!/usr/bin/env lua
--
-- smsc_stub.lua — a Service Centre (SMSC) emulator on the SGd interface
-- (3GPP TS 29.338), the side an IP-SM-GW talks Diameter to. It listens
-- where the real SMSC does; bindings/examples/ipsmgw.lua connects in and
-- this script answers, so an SMS goes end to end with no real SMSC.
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so \
--     [SMSC_PORT=3870] [SMSC_PROTO=tcp|sctp] [SMSC_REALM=...] \
--     [SMSC_ADDR=+123456789] [SMSC_FORWARD=1] [SMSC_DELAY_MS=0] \
--     [SMSC_OFA_RESULT=2001] [SMSC_TFA_EXPECT_MS=20000] [SMSC_VERBOSE=1] \
--     lua smsc_stub.lua
--
-- What it speaks:
--   * Diameter base peer protocol — CER/CEA (advertising SGd, app
--     16777313, vendor 3GPP), DWR/DWA, DPR/DPA.
--   * SGd mobile originated — OFR/OFA (MO-Forward-Short-Message): the
--     IP-SM-GW submits, this accepts (or refuses, on demand).
--   * SGd mobile terminated — TFR/TFA (MT-Forward-Short-Message): this
--     originates the delivery, the IP-SM-GW answers.
--   * SGd alerting — ALR/ALA (Alert-Service-Centre), answered so a
--     retry-after-alert flow does not stall.
--
-- Store and forward is the point: every accepted MO submit is turned
-- into an MT delivery for its own TP-DA and pushed back out as a TFR on
-- the connection it arrived on (RFC 6733 connections are bidirectional,
-- so the peer that dialled us is also our route to the serving node).
-- The conversion keeps TP-PID, TP-DCS, TP-UDHI and TP-UD byte for byte —
-- sms.deliver_from_submit does that — which is what makes an end-to-end
-- "what arrived equals what was sent" assertion meaningful rather than a
-- test of the codec against itself.
--
-- Two simplifications, stated so nobody mistakes them for the real thing:
--
--   * A real SMS-GMSC asks the HSS for routing information first
--     (Send-Routing-Info-for-SM over S6c) to learn the recipient's IMSI
--     and serving node. There is one serving node here — whoever
--     connected — so the SRR/SRA round trip is skipped and the TFR goes
--     back down the same connection.
--   * TFR's User-Name is therefore the recipient's MSISDN (the TP-DA
--     out of the submitted TPDU), not the IMSI a real SMSC would have
--     learned from the SRA. ipsmgw.lua resolves the recipient from the
--     TPDU's TP-DA anyway, which is authoritative, and falls back to
--     User-Name.
--
-- SM-RP-UI carries the *TPDU*, not the RPDU (TS 29.338 §7.3.4) — the
-- relay layer terminates at the IP-SM-GW. Getting that boundary wrong is
-- the single most likely reason an SGd interop attempt fails, so it is
-- asserted here rather than assumed: a submit whose SM-RP-UI does not
-- parse as an SMS-SUBMIT is refused with a named cause.
--
-- One net.Loop drives a listening TCP (or SCTP) socket, exactly as
-- cx_hss.lua does: each accepted connection is a peer whose byte stream
-- is de-framed by the Diameter header's Message Length and dispatched by
-- command code.

local net  = require("net")  -- event loop + listening stream socket
local diam = require("diam") -- Diameter codec + SGd/S6c dictionary
local sms  = require("sms")  -- TPDU codec (store-and-forward conversion)

-- ---- configuration ----------------------------------------------------

local BIND    = os.getenv("SMSC_BIND") or "0.0.0.0"
local PORT    = tonumber(os.getenv("SMSC_PORT") or "3870")
local PROTO   = (os.getenv("SMSC_PROTO") or "tcp"):lower()
local REALM   = os.getenv("SMSC_REALM") or "mnc01.mcc001.3gppnetwork.org"
local VERBOSE = (os.getenv("SMSC_VERBOSE") or "0") ~= "0"

local ORIGIN_HOST  = os.getenv("SMSC_ORIGIN_HOST") or ("smsc.epc." .. REALM)
local ORIGIN_REALM = os.getenv("SMSC_ORIGIN_REALM") or ("epc." .. REALM)

-- The SC address this centre answers on; it lands in TP-OA-adjacent
-- places and in the SC-Address AVP of a TFR.
local SC_ADDR = os.getenv("SMSC_ADDR") or "+123456789"

-- Store and forward, or accept and drop. Off is useful for measuring the
-- MO direction alone.
local FORWARD = (os.getenv("SMSC_FORWARD") or "1") ~= "0"
-- Delay between accepting a submit and pushing the delivery out, so a
-- store-and-forward hop can be given a realistic cost (0 = immediate).
local DELAY_MS = tonumber(os.getenv("SMSC_DELAY_MS") or "0")
-- What OFA says. 2001 is DIAMETER_SUCCESS; set anything else to exercise
-- the IP-SM-GW's failure path (it should turn it into an RP-ERROR).
local OFA_RESULT = tonumber(os.getenv("SMSC_OFA_RESULT") or "2001")
-- How long a pushed TFR may go unanswered before it is counted lost.
local TFA_EXPECT_MS = tonumber(os.getenv("SMSC_TFA_EXPECT_MS") or "20000")

local PROTO_ID = (PROTO == "sctp") and net.PROTO_SCTP or net.PROTO_TCP

local V3GPP    = diam.VENDOR_3GPP
local APP_SGD  = diam.APP_SGD
local RC_OK    = diam.RESULT_CODE_DIAMETER_SUCCESS
local RC_NOCOMP = diam.RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY

local HOST_IP = net.if_addr4(os.getenv("SMSC_IFACE") or "eth0")
if HOST_IP == "" then HOST_IP = "127.0.0.1" end

-- ---- little helpers ---------------------------------------------------

local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end
local function log(fmt, ...) io.write(("%s\n"):format(fmt:format(...))); io.flush() end
local function vlog(fmt, ...) if VERBOSE then log("      " .. fmt, ...) end end

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

local now = net.now_ms
local stats = {
    total = 0, by_cmd = {}, start = now(), win0 = now(), win_total = 0,
    submitted = 0, refused = 0, forwarded = 0, delivered = 0,
    tfa_failed = 0, tfa_lost = 0, malformed = 0, reports = 0,
}
local function count(name)
    stats.total = stats.total + 1
    stats.win_total = stats.win_total + 1
    stats.by_cmd[name] = (stats.by_cmd[name] or 0) + 1
end

-- ---- Diameter builders -------------------------------------------------

local function base_answer(m)
    return diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
        :put_u32(diam.AVP_RESULT_CODE, RC_OK)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
end

-- SGd answer preamble (TS 29.338 §6.3): Session-Id echoed, the
-- Vendor-Specific-Application-Id group, stateless, our identity.
local function sgd_answer(m)
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
    return b
end

-- ---- session ids and hop-by-hop for requests WE originate --------------

local seq = { sess = 0, hbh = 0x5000, e2e = 0x5000 }
local function next_session()
    seq.sess = seq.sess + 1
    return ("%s;%d;%d"):format(ORIGIN_HOST, math.floor(now() / 1000), seq.sess)
end
local function next_ids()
    seq.hbh = seq.hbh + 1
    seq.e2e = seq.e2e + 1
    return seq.hbh, seq.e2e
end

-- ---- pending deliveries (TFR out, waiting for TFA) --------------------

local pending = {}   -- hbh -> { peer, msisdn, at, timer }

-- ---- command handlers -------------------------------------------------

local function on_cer(m, peer)
    peer.origin_host = ostr(m, diam.AVP_ORIGIN_HOST) or peer.origin_host
    peer.origin_realm = ostr(m, diam.AVP_ORIGIN_REALM) or peer.origin_realm
    log("   <- CER from %s (%s)", peer.origin_host or "?", peer.addr)
    return base_answer(m)
        :put_addr4(diam.AVP_HOST_IP_ADDRESS, HOST_IP)
        :put_u32(diam.AVP_VENDOR_ID, V3GPP)
        :put_str(diam.AVP_PRODUCT_NAME, "pro2call-smsc-stub")
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :end_group()
        :put_u32(diam.AVP_SUPPORTED_VENDOR_ID, V3GPP)
        :put_u32(diam.AVP_FIRMWARE_REVISION, 1)
        :done()
end

local function on_dwr(m) return base_answer(m):done() end

local function on_dpr(m, peer)
    log("   <- DPR from %s -- closing", peer.origin_host or peer.addr)
    peer.closing = true
    return base_answer(m):done()
end

-- Forward-declared: push_delivery originates a TFR, on_ofr schedules it, and
-- push_report follows a delivered message when TP-SRR asked for a report.
local push_delivery, push_report

-- OFR -> OFA. The submit's TPDU is in SM-RP-UI (§7.3.4); parse it so a
-- malformed submit is refused with a cause rather than silently stored,
-- then (when forwarding) turn it into a delivery for its own TP-DA.
local function on_ofr(m, peer)
    local tpdu  = ostr(m, diam.AVP_SM_RP_UI, V3GPP)
    local imsi  = ostr(m, diam.AVP_USER_NAME)
    local scadr = ostr(m, diam.AVP_SC_ADDRESS, V3GPP)
    local flags = ou32(m, diam.AVP_OFR_FLAGS, V3GPP) or 0

    if not tpdu then
        stats.malformed = stats.malformed + 1
        log("   <- OFR from %s with no SM-RP-UI -> UNABLE_TO_COMPLY", imsi or "?")
        return sgd_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_NOCOMP):done()
    end

    local okp, sub = pcall(sms.parse_tpdu, tpdu, sms.DIR_MS_TO_SC)
    if not okp or sub.type ~= sms.T_SUBMIT then
        stats.malformed = stats.malformed + 1
        log("   <- OFR from %s: SM-RP-UI is not an SMS-SUBMIT (%s) -> refused",
            imsi or "?", okp and sub:type_name() or why(sub))
        -- TP-FCS "TPDU not supported" is the honest cause here.
        return sgd_answer(m)
            :put_u32(diam.AVP_RESULT_CODE, RC_NOCOMP)
            :put_u32(diam.AVP_SM_DELIVERY_FAILURE_CAUSE, 0, V3GPP)
            :done()
    end

    stats.submitted = stats.submitted + 1
    local to = sub.addr:display()
    local okt, text = pcall(function() return sub:text() end)
    log("   <- OFR %s -> %s (%s, %s, mr=%d%s)  [%s]",
        imsi or "?", to,
        sub:binary() and ("%d octets of 8-bit data"):format(#sub.user_data)
                     or ("%q"):format(okt and text or "?"),
        sub:alphabet() == sms.ALPHA_UCS2 and "UCS2" or "GSM7",
        sub.mr, sub.srr and ", SRR" or "", scadr or SC_ADDR)
    if flags ~= 0 then vlog("OFR-Flags 0x%x", flags) end

    if OFA_RESULT ~= RC_OK then
        stats.refused = stats.refused + 1
        log("   -> OFA %d (SMSC_OFA_RESULT)", OFA_RESULT)
        return sgd_answer(m):put_u32(diam.AVP_RESULT_CODE, OFA_RESULT):done()
    end

    -- Accepted. §7.3.4 lets OFA carry an SMS-SUBMIT-REPORT in SM-RP-UI;
    -- the IP-SM-GW turns it into the RP-ACK's optional payload, so the
    -- submitting UE gets the SC's timestamp for the message.
    local report = sms.Tpdu()
    report.type = sms.T_SUBMIT_REPORT
    local ans = sgd_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_OK)
    local okr, rbytes = pcall(function() return report:encode() end)
    if okr then ans:put_str(diam.AVP_SM_RP_UI, rbytes, V3GPP) end

    if FORWARD then
        -- Deliver it back out. The submitted TPDU is captured by value,
        -- so the conversion happens on the timer rather than now.
        local from = imsi or SC_ADDR
        if DELAY_MS > 0 then
            peer.loop:after(DELAY_MS, function()
                push_delivery(peer, tpdu, from, to, sub.srr, sub.mr)
            end)
        else
            push_delivery(peer, tpdu, from, to, sub.srr, sub.mr)
        end
    end
    return ans:done()
end

-- TFA: the serving node's answer to a delivery we pushed.
local function on_tfa(m, peer)
    local p = pending[m.hbh]
    if p then
        pending[m.hbh] = nil
        if p.timer then peer.loop:cancel(p.timer) end
    end
    local rc = ou32(m, diam.AVP_RESULT_CODE)
    local xr
    if m:has(diam.AVP_EXPERIMENTAL_RESULT) then
        local g = m:find(diam.AVP_EXPERIMENTAL_RESULT)
        if g:has_child(diam.AVP_EXPERIMENTAL_RESULT_CODE) then
            xr = g:child(diam.AVP_EXPERIMENTAL_RESULT_CODE):u32()
        end
    end
    if rc == RC_OK then
        stats.delivered = stats.delivered + 1
        log("   <- TFA 2001 for %s (%s)", p and p.msisdn or "?",
            p and ("%d ms"):format(now() - p.at) or "unmatched")
        -- TP-SRR was set on the submit, so the SC now reports the outcome
        -- back to the originator (TS 23.040 §9.2.3.4). It travels as another
        -- MT delivery whose TPDU is an SMS-STATUS-REPORT, addressed to the
        -- sender — which is why `from` and `to` swap roles here.
        if p and p.srr then push_report(peer, p) end
    else
        stats.tfa_failed = stats.tfa_failed + 1
        local fc = ou32(m, diam.AVP_SM_DELIVERY_FAILURE_CAUSE, V3GPP)
        log("   <- TFA %s%s for %s%s", tostring(rc or "?"),
            xr and (" (experimental %d)"):format(xr) or "",
            p and p.msisdn or "?",
            fc and (" cause %d"):format(fc) or "")
    end
end

-- ALR -> ALA. A serving node sends this when a subscriber the SC could
-- not reach becomes available again; a real SC would then retry the
-- messages in its waiting-message store. There is no store here, so this
-- is answered and noted.
local function on_alr(m)
    local who = ostr(m, diam.AVP_USER_NAME)
    local reason = ou32(m, diam.AVP_ALERT_REASON, V3GPP)
    log("   <- ALR %s (reason %s) -> ALA", who or "?", tostring(reason or "?"))
    return sgd_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_OK):done()
end

-- ---- originate a delivery ---------------------------------------------

-- TFR (MT-Forward-Short-Message-Request, TS 29.338 §6.3.2). Sent on the
-- connection the submit arrived on: RFC 6733 connections are
-- bidirectional, and the peer that dialled us is the serving node.
push_delivery = function(peer, submit_tpdu, from, to, srr, mr)
    if not peer.conn or peer.closing then return end

    -- The SC's job (TS 23.040 §10): SUBMIT -> DELIVER with the
    -- originator's address and the SC's timestamp, and the payload copied
    -- verbatim so what arrives is byte-identical to what was sent.
    local okc, deliver = pcall(sms.deliver_from_submit, submit_tpdu, from, 0, 0,
                               false)
    if not okc then
        log("   !! cannot turn the submit into a delivery: %s", why(deliver))
        return
    end

    local hbh, e2e = next_ids()
    local wire = diam.Builder()
        :request(diam.CMD_MT_FORWARD_SHORT_MESSAGE, APP_SGD)
        :ids(hbh, e2e)
        :proxiable()
        :put_str(diam.AVP_SESSION_ID, next_session())
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :end_group()
        :put_u32(diam.AVP_AUTH_SESSION_STATE,
                 diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
        :put_str(diam.AVP_DESTINATION_HOST, peer.origin_host or "")
        :put_str(diam.AVP_DESTINATION_REALM, peer.origin_realm or ORIGIN_REALM)
        -- A real SMSC puts the IMSI it learned from an SRA here; see the
        -- header comment. The recipient is also in the TPDU's TP-DA,
        -- which is what ipsmgw.lua actually resolves on.
        :put_str(diam.AVP_USER_NAME, (to:gsub("^%+", "")))
        :put_str(diam.AVP_SC_ADDRESS, SC_ADDR, V3GPP)
        :put_str(diam.AVP_SM_RP_UI, deliver, V3GPP)   -- the TPDU, not the RPDU
        :put_u32(diam.AVP_SM_RP_MTI, diam.SM_RP_MTI_SM_DELIVER, V3GPP)
        :put_u32(diam.AVP_TFR_FLAGS, 0, V3GPP)
        :done()

    local sok, serr = pcall(function() peer.conn:send(wire, 1000) end)
    if not sok then
        log("   !! TFR send failed to %s: %s", peer.addr, why(serr))
        return
    end
    stats.forwarded = stats.forwarded + 1
    -- Remember what a status report would need: TS 23.040 §9.2.2.3 puts the
    -- RECIPIENT in the report's TP-RA and sends the report to the ORIGINATOR,
    -- so both addresses have to survive until the TFA comes back.
    local p = { peer = peer, msisdn = to, at = now(),
                srr = srr, mr = mr, from = from, to = to }
    pending[hbh] = p
    p.timer = peer.loop:after(TFA_EXPECT_MS, function()
        if pending[hbh] then
            pending[hbh] = nil
            stats.tfa_lost = stats.tfa_lost + 1
            log("   !! no TFA for %s within %d ms", to, TFA_EXPECT_MS)
        end
    end)
    log("   -> TFR %s -> %s (%d octets of TPDU)", from, to, #deliver)
end

-- The SMS-STATUS-REPORT an SC returns when the submit had TP-SRR. TP-RA is
-- the recipient of the original message and TP-MR echoes the submit's, which
-- is how the originating UE knows which of its messages this is about.
push_report = function(peer, p)
    if not peer.conn or peer.closing then return end
    local okr, report = pcall(sms.status_report_tpdu, p.to, p.mr or 0, 0, 0, 0, 0)
    if not okr then
        log("   !! cannot build the status report: %s", why(report))
        return
    end

    local hbh, e2e = next_ids()
    local wire = diam.Builder()
        :request(diam.CMD_MT_FORWARD_SHORT_MESSAGE, APP_SGD)
        :ids(hbh, e2e)
        :proxiable()
        :put_str(diam.AVP_SESSION_ID, next_session())
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_SGD)
        :end_group()
        :put_u32(diam.AVP_AUTH_SESSION_STATE,
                 diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
        :put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
        :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
        :put_str(diam.AVP_DESTINATION_HOST, peer.origin_host or "")
        :put_str(diam.AVP_DESTINATION_REALM, peer.origin_realm or ORIGIN_REALM)
        -- Back to whoever submitted it.
        :put_str(diam.AVP_USER_NAME, ((p.from or ""):gsub("^%+", "")))
        :put_str(diam.AVP_SC_ADDRESS, SC_ADDR, V3GPP)
        :put_str(diam.AVP_SM_RP_UI, report, V3GPP)
        :put_u32(diam.AVP_SM_RP_MTI, diam.SM_RP_MTI_SM_STATUS_REPORT, V3GPP)
        :put_u32(diam.AVP_TFR_FLAGS, 0, V3GPP)
        :done()

    local sok, serr = pcall(function() peer.conn:send(wire, 1000) end)
    if not sok then
        log("   !! status report send failed: %s", why(serr))
        return
    end
    stats.reports = (stats.reports or 0) + 1
    pending[hbh] = { peer = peer, msisdn = p.from, at = now() }
    log("   -> TFR status report for %s (TP-MR %d, delivered)", p.from,
        p.mr or 0)
end

local HANDLERS = {
    [diam.CMD_CAPABILITIES_EXCHANGE]      = { name = "CER", fn = on_cer },
    [diam.CMD_DEVICE_WATCHDOG]            = { name = "DWR", fn = on_dwr },
    [diam.CMD_DISCONNECT_PEER]            = { name = "DPR", fn = on_dpr },
    [diam.CMD_MO_FORWARD_SHORT_MESSAGE]   = { name = "OFR", fn = on_ofr },
    [diam.CMD_ALERT_SERVICE_CENTRE]       = { name = "ALR", fn = on_alr },
}

-- Answers we care about (a TFR is ours, so its answer comes back here).
local ANSWERS = {
    [diam.CMD_MT_FORWARD_SHORT_MESSAGE] = { name = "TFA", fn = on_tfa },
}

-- ---- connection handling ----------------------------------------------

local loop = net.Loop()
local peers = {}

local function drop(peer)
    local fd = peer.conn:fd()
    if peers[fd] then
        peers[fd] = nil
        pcall(function() loop:del_fd(fd) end)
        peer.conn:close()
        peer.conn = nil
        log("   -- peer %s disconnected", peer.origin_host or peer.addr)
    end
end

local function dispatch(peer, frame)
    local ok, m = pcall(diam.parse, frame)
    if not ok then
        log("   !! unparseable %d-byte message from %s: %s", #frame, peer.addr, why(m))
        return
    end
    if not m.request then
        local a = ANSWERS[m.cmd]
        if a then count(a.name); pcall(a.fn, m, peer)
        else vlog("ignoring %s answer", m:name()) end
        return
    end
    local h = HANDLERS[m.cmd]
    if not h then
        log("   ?? unhandled command %d (%s) from %s", m.cmd, m:name(), peer.addr)
        local ans = sgd_answer(m):put_u32(diam.AVP_RESULT_CODE, RC_NOCOMP):done()
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
        if not wok then
            log("   !! send failed to %s: %s", peer.addr, why(werr))
            return drop(peer)
        end
    end
    if peer.closing then drop(peer) end
end

local function frame_stream(peer)
    while #peer.rxbuf >= 20 do
        local b = peer.rxbuf
        local mlen = b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
        if mlen < 20 then
            log("   !! bad Message Length %d from %s -- dropping", mlen, peer.addr)
            return drop(peer)
        end
        if #b < mlen then return end
        peer.rxbuf = b:sub(mlen + 1)
        dispatch(peer, b:sub(1, mlen))
        if not peer.conn or not peers[peer.conn:fd()] then return end
    end
end

local function on_readable(peer)
    while true do
        local ok, d = pcall(function() return peer.conn:recv(-1) end)
        if not ok then
            log("   !! recv error from %s: %s", peer.addr, why(d))
            return drop(peer)
        end
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
            conn = c, rxbuf = "", loop = loop,
            addr = ("%s:%d"):format(c:peer_host(), c:peer_port()),
        }
        peers[c:fd()] = peer
        loop:add_fd(c:fd(), net.NET_RD, function() on_readable(peer) end)
        log("   ++ connection from %s", peer.addr)
    end
end

-- ---- periodic throughput line -----------------------------------------

local STATS_MS = tonumber(os.getenv("SMSC_STATS_MS") or "5000")
local function tick()
    local t = now()
    local win = (t - stats.win0) / 1000
    local rate = win > 0 and (stats.win_total / win) or 0
    local parts = {}
    for _, k in ipairs({ "CER", "DWR", "DPR", "OFR", "TFA", "ALR" }) do
        if stats.by_cmd[k] then parts[#parts + 1] = ("%s=%d"):format(k, stats.by_cmd[k]) end
    end
    log("== %d msg total (%.0f/s last %.0fs) | %s | MO %d ok %d refused | MT %d sent %d delivered %d failed %d lost",
        stats.total, rate, win, table.concat(parts, " "),
        stats.submitted, stats.refused,
        stats.forwarded, stats.delivered, stats.tfa_failed, stats.tfa_lost)
    if stats.reports > 0 then
        log("   status reports sent: %d", stats.reports)
    end
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

log("== SGd/SMSC emulator ready")
log("   listen         %s:%d/%s", BIND, PORT, PROTO)
log("   Origin-Host    %s", ORIGIN_HOST)
log("   Origin-Realm   %s", ORIGIN_REALM)
log("   SC-Address     %s", SC_ADDR)
log("   Host-IP        %s", HOST_IP)
log("   store+forward  %s%s", FORWARD and "on" or "off",
    (FORWARD and DELAY_MS > 0) and (" (%d ms delay)"):format(DELAY_MS) or "")
if OFA_RESULT ~= RC_OK then
    log("   OFA Result-Code %d (refusing every submit)", OFA_RESULT)
end

loop:after(STATS_MS, tick)
local rok, rerr = pcall(function() loop:run() end)
if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n"); os.exit(1) end
