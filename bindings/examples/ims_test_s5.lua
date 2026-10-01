#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] [IMS_SUBS=N] lua ims_test_s5.lua
--
-- The whole UE side of a VoLTE deployment against a live core: N subscribers
-- (IMS_SUBS, default 1) raise their own PDN connection over S5/S8 and then run,
-- concurrently on one net.Loop, every phase a handset runs — registration, the
-- reg-event subscription, calls between pairs of them with real RTP, and SMS
-- over IMS. Each subscriber's IMSI is incremented from IMS_IMSI while the USIM
-- keys stay shared, a load layout where the HSS provisions the IMSI range with
-- one key set.
--
-- bindings/examples/ims_test_gm.lua is this same registration over Gm alone,
-- with no PDN connection under it. Running it first is what makes a failure
-- here readable: when registration fails there and here, the fault is in the
-- IMS or the USIM keys; when it fails only here, it is the PGW, the datapath or
-- the bearer.
--
-- Everything here is orchestration: reading a subscriber through its GTP-C
-- access (ims/access.lua) and then, once it has an address and a P-CSCF, through
-- every phase a handset runs (ims/regflow.lua and beside it). Each module's
-- header explains what it does and why it does it that way:
--
--   ims/cfg.lua        the environment: PLMN, realm, IMSI range, keys, timers
--   ims/ue.lua         one subscriber: identities, protected ports, SPIs, FSMs
--   ims/access.lua     the S5/S8 access: GTP-C, the eBPF GTP-U datapath, TFTs
--   ims/register.lua   the REGISTER and the IMS-AKA credentials
--   ims/regflow.lua    the exchange: REGISTER -> 401 -> SAs (ipsec.Esp) ->
--                      REGISTER -> 200
--   ims/sipio.lua      the UE socket: send, drain, count, preloaded Route
--   ims/wire.lua       the shared Builder and the header readers
--   ims/reg_event.lua  the RFC 3680 subscription phase, with its own report
--   ims/call_phase.lua the call phase and its media, with its own report
--   ims/sms_phase.lua  SMS over IMS (TS 24.341), with its own report
--   ims/log.lua        banners, summary lines, the per-subscriber trace
--   ims/stats.lua      distributions, stage tallies, the kernel's ESP counters
--
-- A phase is switchable (IMS_REG_EVENT, IMS_CALL, IMS_SMS) and separately
-- measured; offered load is the independent variable throughout (CALL_CPS,
-- SMS_MPS, REG_EVENT_RPS, an unramped registration burst), and every report is
-- distributions rather than means, because a mean hides the knee.
--
-- Installing ESP SAs, the transparent UE socket, the PAA route and the media
-- sockets all need CAP_NET_ADMIN; each kernel op degrades to a reported line
-- when refused.

-- The modules this shares with ims_test_gm.lua live in ims/ beside this file.
-- Make them requirable however the script was invoked (the C modules keep
-- coming from LUA_CPATH).
package.path = ((arg and arg[0] or ""):match("^(.*)[/\\]") or ".") .. "/?.lua;" .. package.path

local net = require("net")   -- event loop + UDP socket + DNS + interface/route
local sip = require("sip")   -- the method constants the dispatcher reads
local sms = require("sms")   -- SMS over IP: the Contact feature tag

local cfg      = require("ims.cfg")
local log      = require("ims.log")
local stats_   = require("ims.stats")
local ue       = require("ims.ue")
local sipio    = require("ims.sipio")
local register = require("ims.register")
local regflow  = require("ims.regflow")
local access     = require("ims.access")
local reg_event  = require("ims.reg_event")
local call_phase = require("ims.call_phase")
local sms_phase  = require("ims.sms_phase")

-- TS 24.341 §5.3.2.2: this UE does SMS over IP, so every REGISTER it sends says
-- so on its Contact — not only when the SMS phase is enabled, because in a real
-- network MT routing depends on the registered contact's capabilities.
register.contact_params = sms.FEATURE_TAG

-- ---- configuration ------------------------------------------------------
--
-- IMS_MCC / IMS_MNC / IMS_REALM, IMS_IMSI, IMS_SUBS, IMS_K / IMS_OPC,
-- IMS_EXPIRES, IMS_DEREG, IMS_ABANDON, IMS_IPSEC,
-- SIP_T_MS, IMS_VERBOSE, IMS_DUMP, CALL_URI, IMS_MSISDN_* — is read by
-- ims/cfg.lua; PGW_IP, SGW_IP, IMS_APN, GTP_T3_MS, GTP_N3, GTPU_IFACE,
-- GTPU_INNER_IFACE, GTPU_INNER_MTU by ims/access.lua; and each phase's own
-- knobs by the phase module that uses them.

-- ---- the run ------------------------------------------------------------

local function run()
    local loop = net.Loop()
    local now  = net.now_ms

    -- Both ends formatted the way ims/ue.lua does it, so the numbers below are
    -- the numbers the subscribers actually carry (IMS_IMSI may be short).
    local first_imsi, last_imsi = ue.imsi(1), ue.imsi(cfg.nsubs)
    log.banner(("IMS over S5/S8 — %d subscriber(s)"):format(cfg.nsubs))
    log.line("IMSI range", ("%s .. %s (shared keys)"):format(first_imsi, last_imsi))
    log.line("MSISDN range", ("+%s .. +%s  (+%s + last %d IMSI digits)")
        :format(cfg.msisdn_of(first_imsi), cfg.msisdn_of(last_imsi),
                cfg.msisdn_cc, cfg.msisdn_digits))

    local subs = {}
    local stats = {
        tx = 0, rx = 0, sess = 0, regs = 0, protected = 0, sa_fail = 0,
        start = now(),                        -- run start (before any Create Session)
        pkt_last = nil, sess_last = nil, reg_last = nil,
        latency = {},                         -- per-subscriber registration time
    }
    local io_ = sipio.new(stats)

    -- forward declarations for the mutually-referring pieces: finish() needs
    -- flow before flow exists, access needs dispatch before the phases that
    -- build dispatch exist, and next_phase needs itself (it recurses).
    local flow, acc, dispatch, next_phase
    local pending, grace = cfg.nsubs, nil

    -- A subscriber reached a terminal state; when the last one does, wait a
    -- little for late Create Bearer Requests, then run the phases.
    local function finish(sub)
        if sub.done then return end
        sub.done = true
        flow.disarm(sub)
        pending = pending - 1
        if pending > 0 then return end
        if grace then return end
        grace = loop:after(3000, function()
            grace = nil
            next_phase(1)
        end)
    end

    flow = regflow.new{
        loop = loop, io = io_, stats = stats, subs = subs,
        on_terminal = finish,
        -- Registration is only half of what the 200 OK carries: the identities
        -- the network associated with it, and the Service-Route without which
        -- nothing after it can originate a request, are read by regflow itself.
        -- What is left is to say so.
        on_registered = function(sub, m)
            log.slog(sub, "<- 200 OK", ("registered at P-CSCF %s"):format(sub.pcscf or "?"))
            if not cfg.verbose then return end
            log.slog(sub, "Service-Route", #sub.svc_route > 0
                and table.concat(sub.svc_route, " ")
                or  "absent -- this subscriber cannot originate a call")
            log.slog(sub, "P-Associated-URI", #sub.assoc > 0
                and table.concat(sub.assoc, " ")
                or  "absent -- the registered IMPU is all this UE is known by")
        end,
        -- Every response is evidence the downlink works; say which bearer it came
        -- down, since a reply that never arrives looks identical to one the
        -- datapath dropped.
        on_response = function(sub, m) acc.report_rx(sub, tostring(m.status)) end,
    }

    -- The GTP-C/GTP-U access: Create Session per subscriber, the eBPF datapath
    -- and its TFTs, the PAA and P-CSCF-MTU routes, the transparent UE socket.
    -- See ims/access.lua's header for what it owns and why.
    acc = access.new{
        loop = loop, io = io_, stats = stats, subs = subs, flow = flow,
        dispatch = function(sub, m) return dispatch(sub, m) end,
        on_ready   = flow.first_register,   -- a fresh subscriber is attached
        on_fail    = flow.fail,             -- Create Session rejected/timed out/incomplete
        media_bearer = call_phase.bearer,             -- MEDIA_BEARER: "auto" or "default"
        rtcp_bearer   = call_phase.MEDIA.rtcp_bearer,  -- MEDIA_RTCP_BEARER
    }

    -- ---- the phases ----
    --
    -- Each is a module with its own knobs, flow and report; they see the loop,
    -- the UE sockets and the subscriber list, and the call phase additionally
    -- gets the one datapath hook it needs (its media 5-tuple is only known from
    -- the SDP, so the TFTs for it are programmed as each call negotiates).
    local pctx = { loop = loop, io = io_, subs = subs, media = acc.media }
    local regevp = reg_event.new(pctx)
    local callp  = call_phase.new(pctx)
    local smsp   = sms_phase.new(pctx)

    -- The order a handset does them in (TS 24.229 §5.1.1.3, at the 200 OK), and
    -- the reason the subscription goes first: its NOTIFY is a terminating
    -- request, so if it does not arrive the MT INVITE that follows has the same
    -- problem and this phase has already named it.
    local PHASES = {
        { on = reg_event.on,  p = regevp },
        { on = call_phase.on, p = callp },
        { on = sms_phase.on,  p = smsp },
    }

    -- The de-REGISTERs are fire-and-forget (regflow does not await their 200), so
    -- give them a moment to egress and be processed before the bearers go away.
    local function begin_deregister()
        if flow.deregister() == 0 then return acc.teardown() end
        loop:after(1500, acc.teardown)
    end

    next_phase = function(i)
        while PHASES[i] and not PHASES[i].on do i = i + 1 end
        if not PHASES[i] then
            -- Everything is measured: release the IMS registrations (so the
            -- P-CSCF reaps their ESP SAs), then the PDN connections.
            if cfg.dereg then return begin_deregister() end
            return acc.teardown()
        end
        PHASES[i].p.begin(function() next_phase(i + 1) end)
    end

    -- ---- SIP dispatch ----
    --
    -- One socket per UE carries every phase (with one protected port in both
    -- roles the P-CSCF delivers terminating requests to the same port), so the
    -- method — and for a response the CSeq method — says which layer owns an
    -- inbound message. No phase flag anywhere.
    dispatch = function(sub, m)
        if cfg.verbose then
            log.slog(sub, "<- SIP", m.request
                and ("%s %s"):format(m.method_name, m.uri)
                or  ("%d %s"):format(m.status, m.reason))
        end
        if m.request then
            -- A MESSAGE creates no dialog (RFC 3428 §4), so the SMS layer sorts
            -- it out from the RPDU in the body; a NOTIFY is this UE's own
            -- registration state, inside the dialog its SUBSCRIBE opened.
            if m.method == sip.MESSAGE then return smsp.request(sub, m) end
            if m.method == sip.NOTIFY  then return regevp.request(sub, m) end
            return callp.request(sub, m)
        end
        local okc, cs = pcall(function() return m:cseq() end)
        if okc and cs.method == sip.REGISTER  then return flow.handle(sub, m) end
        if okc and cs.method == sip.MESSAGE   then return smsp.response(sub, m) end
        if okc and cs.method == sip.SUBSCRIBE then return regevp.response(sub, m) end
        return callp.response(sub, m)
    end

    -- ---- the attach burst, then the loop ----

    stats.burst = acc.attach_burst()

    -- One dispatcher for every socket and timer until the last subscriber is
    -- terminal (registered, rejected or timed out), the phases have run and the
    -- PDN connections are torn down.
    local rok, rerr = pcall(function() loop:run() end)

    stats.gtp_tx = acc.tx_stats()
    stats.sip_tx = { sent = 0, calls = 0, blocked = 0, dropped = 0, socks = 0 }
    local function tx_add(t, s)
        t.sent    = t.sent + s:tx_sent()
        t.calls   = t.calls + s:tx_calls()
        t.blocked = t.blocked + s:tx_blocked()
        t.dropped = t.dropped + s:tx_dropped()
    end
    for _, sub in ipairs(subs) do
        if sub.sock and sub.sock:tx_queued() then
            stats.sip_tx.socks = stats.sip_tx.socks + 1
            tx_add(stats.sip_tx, sub.sock)
        end
    end

    -- The media figures are read once the loop has stopped, so late media
    -- (rtpengine teardown lag) is in the counts.
    callp.collect()

    -- Datapath counters, read now (see access.collect_dp) so acc.cleanup()
    -- below cannot invalidate what they are keyed on; acc.dp_report() prints
    -- them later, alongside the rest of the run's summary.
    acc.collect_dp()

    -- ---- teardown that needs no loop ----
    --
    -- Our own kernel state first (while the addresses are still meaningful),
    -- the access's (media filters, PAA route, P-CSCF MTU route), then the
    -- sockets.
    flow.release_sas()
    acc.cleanup()
    flow.close_sockets()
    if not rok then io.stderr:write("loop error: " .. log.why(rerr) .. "\n") end
    return subs, stats, { regev = regevp, call = callp, sms = smsp }, acc
end

-- main
local t0 = net.now_ms()
local subs, stats, phase, acc = run()
local elapsed = (net.now_ms() - t0) / 1000

-- ---- registration ---------------------------------------------------------
--
-- Tally registrations and, for the rest, the stage each subscriber reached when
-- it gave up: session setup (GTP-C Create Session), the initial REGISTER / 401
-- challenge, or authentication (AKA verify + the authenticated REGISTER / 200).
local STAGES = {
    { key = "session",  label = "session setup (GTP-C)" },
    { key = "register", label = "REGISTER / 401 challenge" },
    { key = "auth",     label = "authentication / 200 OK" },
    { key = "other",    label = "other / incomplete" },
}
local ok, abandoned, tally = 0, 0, {}
for _, sub in ipairs(subs) do
    if sub.registered then
        ok = ok + 1
    elseif sub.abandoned then
        abandoned = abandoned + 1
    else
        stats_.fail(tally, sub.fail_stage or "other", sub.err or "unknown")
    end
end

-- Teardown accounting: Delete Session responses received / PDN connections
-- established.
local est, torn = 0, 0
for _, sub in ipairs(subs) do
    if sub.pgw_ctrl_teid then est = est + 1; if sub.del_ok then torn = torn + 1 end end
end

log.banner(("Summary: %d / %d subscriber(s) registered over S5/S8 in %.2fs")
    :format(ok, #subs, elapsed))
if est > 0 then
    log.line("sessions torn down", ("%d / %d (Delete Session)"):format(torn, est))
end
if ok > 0 then
    log.line("IPsec", ("%d of %d registration(s) rode ESP"):format(stats.protected, ok))
end
if stats.sa_fail > 0 then
    log.line("", "the kernel refused SA/policy installs -- run with CAP_NET_ADMIN")
end
if abandoned > 0 then
    log.line("abandoned", ("%d / %d at the 401 (IMS_ABANDON=1)"):format(abandoned, #subs))
    log.line("", "the P-CSCF now holds a pending contact and an IPsec tunnel for each,")
    log.line("", "which only their own expiry removes")
end
if ok + abandoned < #subs then
    log.line("failed", tostring(#subs - ok - abandoned))
    stats_.stages(STAGES, tally, 28)
end

-- ---- the access ----------------------------------------------------------

acc.dp_report()

stats_.xfrm_report()

-- ---- the phases ----------------------------------------------------------
--
-- Each phase reports itself, in the order it ran: validity first, then the
-- per-hop latencies as distributions.
phase.regev.report()
phase.call.report()
phase.sms.report()

-- ---- throughput ----------------------------------------------------------
--
-- Per-second rates for the load. Each rate is measured from the first Create
-- Session Request to the last event of its kind, so the 3s grace + teardown
-- don't dilute the active-burst figures; the phases rate themselves over their
-- own windows for the same reason.
log.banner("Throughput (rates from first Create Session Request)")
local sess_r, sess_w = stats_.per_s(stats.sess, stats.sess_last, stats.start)
local reg_r,  reg_w  = stats_.per_s(stats.regs, stats.reg_last, stats.start)
log.line("sessions created", ("%d in %.2fs  ->  %.1f/s"):format(stats.sess, sess_w, sess_r))
log.line("SIP packets sent", ("%d  ->  %.1f/s")
    :format(stats.tx, stats_.per_s(stats.tx, stats.pkt_last, stats.start)))
log.line("SIP packets received", ("%d  ->  %.1f/s")
    :format(stats.rx, stats_.per_s(stats.rx, stats.pkt_last, stats.start)))
log.line("registrations", ("%d in %.2fs  ->  %.1f/s"):format(stats.regs, reg_w, reg_r))
local d = stats_.summarize(stats.latency)
log.line("registration latency", d
    and ("p50 %dms  p95 %dms  max %dms  (min %dms, n=%d)")
        :format(d.p50, d.p95, d.max, d.min, d.n)
    or  "no samples")
phase.regev.throughput()
phase.call.throughput()
if stats.burst then
    local b = stats.burst
    log.line("Create Session burst", ("%d request(s) offered in %dms, on the wire in %dms  ->  %.0f/s")
        :format(b.n, b.offer, b.total, b.n / math.max(b.total, 1) * 1000))
end
phase.sms.throughput()

-- A run passes when every subscriber registered, every subscription it opened
-- was confirmed by a document describing that subscriber's own registration,
-- every call it actually placed was answered, and every message it sent arrived
-- with its content intact. A phase that was switched off, or had no eligible
-- pair (IMS_SUBS=1), is not held against the run — but a message that arrived
-- corrupted is, and so is a reg-info document that described the wrong state,
-- because those are the failures those phases exist to catch.
--
-- Under IMS_ABANDON the outcome asked for is a challenge walked away from, so
-- that is what every subscriber has to reach instead; a registration that
-- completed anyway means the knob did not take.
local reached = cfg.abandon and abandoned or ok
os.exit((reached == #subs and phase.regev.ok() and phase.call.ok() and phase.sms.ok())
        and 0 or 1)
