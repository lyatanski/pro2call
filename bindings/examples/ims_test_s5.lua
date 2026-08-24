#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] [IMS_SUBS=N] lua ims_test_s5.lua
--
-- Attaches N IMS subscribers over S5/S8 and registers each with the IMS,
-- concurrently, on one net.Loop. IMS_SUBS (default 1) sets the count; each
-- subscriber gets its own PDN connection in the PGW (its own Create
-- Session, control/user TEIDs, PAA and SIP registration) with the IMSI
-- incremented from IMS_IMSI and the SAME USIM keys (IMS_K / IMS_OPC) — a
-- load layout where the HSS provisions the IMSI range with one key set.
--
-- Each subscriber's SIP is driven by the sip module's registration dialog:
-- a `sip.Registration` (RFC 3261 §10 / TS 24.229 §5.1) composed with a
-- `sip.AuthChallenge` (§22 digest) and a per-REGISTER `sip.Transaction`
-- (§17.1.2) — the caller feeds each machine the parsed traffic and reads
-- back the state, so there is no hand-rolled phase variable. The flow per
-- subscriber:
--   1. REGISTER (unprotected, UDP:5060) with a Security-Client offer.
--   2. 401 with the AKA challenge (RAND||AUTN) and the P-CSCF's
--      Security-Server (its SPIs and protected ports).
--   3. Verify AUTN, derive CK/IK, install four transport-mode ESP SAs
--      (ealg=null — integrity-only ESP, see security_client below).
--   4. REGISTER (protected, ESP) to the P-CSCF's protected server port with
--      the AKAv1-MD5 digest and a Security-Verify; then 200 OK.
--   5. SUBSCRIBE to the reg event package (RFC 3680) of its own public
--      identity, and the NOTIFY back carrying the registration state the
--      network holds for it.
--
-- That last step is the half of TS 24.229 §5.1.1.3 no REGISTER exchange
-- covers: the subscription is what carries de-registration and
-- network-initiated re-authentication back to the handset, so a core that
-- registers UEs and never notifies them looks perfectly healthy right up to
-- the day it has something to tell them. It earns its place here twice over.
-- The NOTIFY is the first *terminating* request a UE receives, so the
-- P-CSCF's inbound SA is exercised — and the shared-protected-port fault
-- described below found — before any call depends on it; and the reginfo
-- body lists the implicit registration set, which says whether the number
-- the call phase is about to dial is an identity of the callee at all.
-- IMS_REG_EVENT=0 skips the phase.
--
-- Once registration settles the subscribers call each other: pairs 1<->2,
-- 3<->4, ... where the odd index originates (MO) and the even one terminates
-- (MT). Both ends of a pair live in this process on the same net.Loop and the
-- same monotonic clock, which is what makes the call-setup decomposition below
-- possible with no clock synchronisation at all: t2-t0 is a true one-way core
-- latency, not half a round trip. Per leg the flow is
--
--   MO --INVITE (Route: orig, SDP offer)--> P-CSCF -> S-CSCF -> ... -> MT
--   MT --180 Ringing--> ... --> MO,  then after CALL_ANSWER_MS a 200 OK with
--   the answer SDP; MO ACKs, media runs for CALL_HOLD_MS, MO sends BYE.
--
-- The callee is dialled by NUMBER: the Request-URI and To of that INVITE are
-- the tel URI of its MSISDN (CALL_URI=tel, the default) — what a handset does,
-- and one more link of the chain under test rather than assumed, because the
-- number only routes if the HSS returned it as a public identity of the
-- callee's subscription, so the terminating side has to resolve
-- MSISDN -> IMPU -> registered contact. The numbers are derived from the IMSI
-- (see "the subscriber's number" below) and bindings/examples/cx_hss.lua
-- derives the same ones; CALL_URI=sip dials the registered sip IMPU instead,
-- which is what to fall back to against an HSS that has no MSISDNs for the
-- range.
--
-- The dialog layer is the sip module's own: a `sip.Dialog` (RFC 3261 §12) per
-- call with `sip.Transaction(INVITE_CLIENT)` on the MO side and
-- `INVITE_SERVER` on the MT side, fed the traffic and read back for state —
-- the same discipline the registration code uses.
--
-- The bodies are the sdp module's: sdp.offer builds the audio offer and the
-- answer, sdp.parse reads the rewritten one back. Two rules it applies so
-- this file does not have to — a media-level c= overrides the session-level
-- one (RFC 8866 §5.7, and rtpengine emits both), and m= port 0 is a rejected
-- stream (RFC 3264 §6) rather than a silent zero port — are exactly the two
-- that otherwise send media to the wrong host and look like a network fault.
--
-- Media is relayed by the IMS (the S-CSCF drives rtpengine on the INVITE and
-- on the reply carrying SDP), so each UE's RTP peer is rtpengine, learnt from
-- the rewritten SDP. CALL_MEDIA calls carry real RTP (rtp.Stream on the same
-- loop, sourced from the UE's PAA); the rest are signalling only, because at
-- 50 pps per stream and 4 streams per call the tool itself — one thread
-- crossing SWIG per packet — becomes the bottleneck long before the system
-- under test does. Two measurements come out of the phase:
--
--   * call setup time, decomposed per segment (post-dial delay, session setup,
--     each transit direction separately, media cut-through, release) reported
--     as p50/p95/p99/max rather than means, since the mean hides the knee;
--   * call quality per direction — loss/jitter from our own receive stats,
--     the peer's view of our uplink from RTCP report blocks, RTT from their
--     lsr/dlsr, and a G.107 MOS *estimate* computed from those packet
--     statistics (no audio is decoded, so it is not PESQ/POLQA).
--
-- GTP-U user plane (eBPF): with CAP_BPF + CAP_NET_ADMIN and an eBPF build
-- the datapath is loaded once and shared. Set $GTPU_IFACE (the S5/S8-U
-- interface) and $GTPU_INNER_IFACE (the access side) to attach the TC
-- programs. Each subscriber's SIP rides its default bearer, steered by two
-- TFTs (UDP:5060 for the plain REGISTER, ESP for the protected one). Both
-- filters carry the UE's own PAA as the inner-source match, so several
-- subscribers registering to the ONE P-CSCF stay on their own bearers
-- (without the source key their ESP filters — proto 50, no ports, same
-- P-CSCF dst — would collide). The P-CSCF address comes from the Create
-- Session Response PCO (TS 24.008 container 0x000C); the 401/200 return
-- down the same bearer's decap entry and the kernel decrypts the protected
-- ones. Media gets two more TFTs per UE (RTP and RTCP toward rtpengine),
-- programmed per call at answer time — rtpengine's port is only known from the
-- SDP answer, so they cannot be pre-programmed at attach — and homed on the
-- dedicated bearer the Create Bearer Request brings (MEDIA_BEARER), falling
-- back to the default bearer and re-homing if the bearer arrives later.
--
-- Installing ESP SAs and the transparent UE socket needs CAP_NET_ADMIN;
-- each kernel op degrades to a reported line when refused.
--

local gtp   = require("gtp")   -- GTPv2-C + typed messages + PLMN/ULI/PCO helpers
local net   = require("net")   -- event loop + UDP socket + DNS + interface/route
local sip   = require("sip")   -- codec + Registration / AuthChallenge / Transaction / Dialog FSMs
local ipsec = require("ipsec") -- Milenage (aka_verify) + AKAv1-MD5 digest + Xfrm
local rtp   = require("rtp")   -- RTP/RTCP media session on the same net.Loop
local sdp   = require("sdp")   -- SDP codec: the audio offer and the answer's media
local sms   = require("sms")   -- SMS codec: the TPDU and RP layers in a MESSAGE body

-- ---- configuration ----------------------------------------------------

local pgw_host = os.getenv("PGW_IP")   or "smf"        -- PGW/SMF: a name or a literal IP
local sgw_ip   = os.getenv("SGW_IP")   or "0.0.0.0"    -- auto-derived from GTPU_IFACE when unset
local apn      = os.getenv("IMS_APN")  or "ims"
local mcc      = os.getenv("IMS_MCC")  or "001"        -- serving PLMN (matches the IMSI
local mnc      = os.getenv("IMS_MNC")  or "01"         -- and the mnc01.mcc001 core realm)
local base_imsi = os.getenv("IMS_IMSI") or "001010000000001"
local NSUBS    = math.max(1, math.floor(tonumber(os.getenv("IMS_SUBS") or "1") or 1))

-- Home network domain (TS 23.003); the MNC is zero-padded to three digits.
local function mnc3(n) return (#n == 2) and ("0" .. n) or n end
local ims_realm = os.getenv("IMS_REALM")
    or ("ims.mnc%s.mcc%s.3gppnetwork.org"):format(mnc3(mnc), mcc)

-- ---- the subscriber's number (MSISDN) ---------------------------------
--
-- These subscribers are generated from an IMSI range, so their number is
-- derived rather than provisioned: an E.164 country code (IMS_MSISDN_CC)
-- followed by the last IMS_MSISDN_DIGITS digits of the IMSI.
-- bindings/examples/cx_hss.lua applies the SAME rule to the SAME two
-- variables and returns the number as a public identity in the profile it
-- hands the S-CSCF, which is what makes a call dialled by number reach the
-- callee — see CALL.uri. Against a real HSS, set these to match the MSISDNs
-- it provisions for the IMSI range, or CALL_URI=sip to dial the sip IMPU and
-- leave numbers out of it altogether.
local MSISDN_CC     = (os.getenv("IMS_MSISDN_CC") or "+99"):gsub("^%+", "")
local MSISDN_DIGITS = tonumber(os.getenv("IMS_MSISDN_DIGITS") or "10") or 10

local function msisdn_of(imsi)
    local tail = (MSISDN_DIGITS > 0) and imsi:sub(-MSISDN_DIGITS) or imsi
    return MSISDN_CC .. tail
end

-- GTP-C retransmission (TS 29.274 §7.6): 1s T3-RESPONSE, up to 3 sends. The
-- 1s default is more aggressive than the spec's 3s, which shows at scale — a
-- 1000-wide Create Session burst queues behind a single-threaded PGW/SMF, so
-- a request can still be in progress when T3 fires and the retransmission
-- reaches a transaction the PGW considers open (open5gs logs
-- `ogs_gtp_xact_update_rx() failed`). Raise GTP_T3_MS to give the PGW the
-- full T3-RESPONSE window.
local T3_MS = tonumber(os.getenv("GTP_T3_MS") or "1000")
local N3    = tonumber(os.getenv("GTP_N3") or "3")
local SIP_T_MS   = tonumber(os.getenv("SIP_T_MS") or "5000")  -- SIP response deadline per registration step
local AUTH_CAP   = 2           -- give up after this many 401 challenges
local REG_EXPIRES = tonumber(os.getenv("IMS_EXPIRES") or "600000") -- ~7 days
local DEREG = (os.getenv("IMS_DEREG") or "1") ~= "0"

-- ---- registration-state subscription (RFC 3680 / TS 24.229 §5.1.1.3) ---
--
-- The reg event package: after the 200 OK the UE SUBSCRIBEs to the
-- registration state of its own public identity and the S-CSCF NOTIFYs it
-- with a reginfo document. See the header for why this is worth a phase of
-- its own rather than a line in the registration one.
--
-- The knobs are named REG_EVENT_*, not SUBS_*: IMS_SUBS is the subscriber
-- COUNT, and two knobs a letter apart meaning "how many UEs" and "the reg
-- event" would be read as each other sooner or later.
local REGEV = {
    on = (os.getenv("IMS_REG_EVENT") or "1") ~= "0",
    -- RFC 3680 §5 leaves the default to the notifier; one hour is what a UE
    -- asks for and is long enough that nothing expires inside a run. The
    -- S-CSCF may grant less (its own subscription_max_expires), which is
    -- reported rather than argued with.
    expires = tonumber(os.getenv("REG_EVENT_EXPIRES") or "3600"),
    t_ms    = tonumber(os.getenv("REG_EVENT_T_MS") or "10000"),  -- per-subscription deadline
    -- Offered subscribe rate, like CALL_CPS: the independent variable of an
    -- experiment, NOT a remedy for failures. 0 (the default) is a single
    -- burst, consistent with the deliberately unramped registration side.
    rps     = tonumber(os.getenv("REG_EVENT_RPS") or "0"),
}

-- ---- call phase -------------------------------------------------------
--
-- Two axes that must not be conflated: how many calls are placed (the
-- signalling load) and how many of them carry RTP (the media load). Per call
-- the datapath sees 4 streams x 50 pps = 200 packets/s, and this tool does the
-- sends and receives for all of them on one single-threaded Lua loop, crossing
-- SWIG per packet — so full-rate media on every call saturates the *tool*
-- first, and a saturated tool inflates its own setup-time marks while still
-- printing plausible numbers. Hence: many calls with CALL_MEDIA=0 to measure
-- setup time under load, a few calls with media to measure quality, or media
-- on a sampled subset to measure quality while load is applied.
--
-- The knobs live in two tables rather than as a dozen loose locals because Lua
-- 5.1 caps a function at 60 upvalues and run() was already close to it — and
-- because the grouping reads better anyway.
local CALL = {
    on    = (os.getenv("IMS_CALL") or "1") ~= "0",  -- run the phase at all
    pairs = tonumber(os.getenv("CALL_PAIRS") or ""), -- nil = every eligible pair
    -- How the callee is addressed — the Request-URI and the To of the INVITE.
    -- A handset dials a number, so "tel" (tel:+<msisdn>, RFC 3966) is the
    -- default and the thing worth exercising: it only works if the HSS
    -- returned that number as a public identity, so the whole
    -- MSISDN -> IMPU -> registered contact chain is under test rather than
    -- assumed. The alternatives are for when it is not the chain being
    -- measured: "phone" is the sip:+<msisdn>@<realm>;user=phone form
    -- (TS 23.003 §13.4) for a core that will not route a tel: Request-URI,
    -- and "sip" dials the sip IMPU the UE registered, which needs no number
    -- anywhere.
    uri = (os.getenv("CALL_URI") or "tel"):lower(),
    -- Offered call arrival rate: the independent variable of the experiment —
    -- a knee cannot be found without being able to set the offered rate. It is
    -- NOT a remedy for failures; 0 (the default) is a single burst, consistent
    -- with the deliberately unramped registration side.
    cps       = tonumber(os.getenv("CALL_CPS") or "0"),
    answer_ms = tonumber(os.getenv("CALL_ANSWER_MS") or "200"),   -- MT ring hold
    hold_ms   = tonumber(os.getenv("CALL_HOLD_MS") or "2000"),    -- talk time
    t_ms      = tonumber(os.getenv("CALL_T_MS") or "10000"),      -- per-step deadline
    -- How many calls carry RTP. A small sample by default; -1 = all of them.
    media     = tonumber(os.getenv("CALL_MEDIA") or "1"),
    -- Which bearer carries media: "auto" uses the dedicated bearer once the
    -- Create Bearer Request brings one (re-homing if it arrives after the
    -- answer), "default" keeps media on the default bearer — worth having,
    -- because a UPF whose dedicated-bearer uplink PDR carries an SDF filter
    -- that does not match our negotiated 5-tuple drops the uplink outright.
    bearer    = os.getenv("MEDIA_BEARER") or "auto",
}
-- Caught at startup rather than at the first INVITE: an unrecognised value
-- would otherwise silently fall through to one of the three forms and the run
-- would report the wrong thing as measured.
if CALL.uri ~= "tel" and CALL.uri ~= "phone" and CALL.uri ~= "sip" then
    io.stderr:write(("CALL_URI=%q is not one of tel|phone|sip\n"):format(CALL.uri))
    os.exit(2)
end
local MEDIA = {
    pt       = tonumber(os.getenv("MEDIA_PT") or "0"),        -- 0 = G.711 PCMU
    rate     = tonumber(os.getenv("MEDIA_RATE") or "8000"),   -- codec clock
    ptime_ms = tonumber(os.getenv("MEDIA_PTIME_MS") or "20"), -- packetisation
    -- RFC 3550 §6.2 wants a minimum RTCP interval of 5 s; 1 s here is a
    -- deliberate lab choice, because a 2 s call at 5 s would produce no usable
    -- report series at all. Do not "fix" this to the spec value without also
    -- lengthening the calls.
    rtcp_ms  = tonumber(os.getenv("RTCP_MS") or "1000"),
    -- Which bearer carries RTCP. The dedicated bearer's PCC rule on this stack
    -- describes only the RTP 5-tuple, so RTCP on it is dropped by the UPF as an
    -- "Off-filter G-PDU" — and RTCP is where the peer's view of OUR uplink
    -- comes from (loss, jitter) plus the round trip, so losing it costs a whole
    -- measurement axis. The default bearer's uplink PDR is catch-all, so RTCP
    -- rides it by default; the reports still describe the RTP path, only the
    -- RTT reflects the bearer the reports themselves travelled. Set
    -- MEDIA_RTCP_BEARER=media to keep both on one bearer, as a UE would.
    rtcp_bearer = os.getenv("MEDIA_RTCP_BEARER") or "default",
    -- Each subscriber's RTP port plus its RTCP port (RFC 3550 §11 wants
    -- port + 1), so the stride is 4: room to spare, clear of the SIP ports.
    port_base = 40000,
}

-- ---- SMS phase --------------------------------------------------------
--
-- SMS over IMS (TS 24.341): the UE puts an RPDU (TS 24.011) carrying a TPDU
-- (TS 23.040) in the body of a SIP MESSAGE with Content-Type
-- application/vnd.3gpp.sms. The path is UE -> P-CSCF -> S-CSCF -> (iFC)
-- IP-SM-GW -> ... -> IP-SM-GW -> S-CSCF -> P-CSCF -> UE, so a delivered
-- message exercises the same terminating routing an MT INVITE does — plus
-- the ISC leg and, in SGd mode, a Diameter round trip to the SC.
--
-- The gateway is bindings/examples/ipsmgw.lua and the service centre
-- bindings/examples/smsc_stub.lua. Nothing here assumes either: with
-- SMS_DIRECT=1 the UE addresses the gateway itself, which proves the codec
-- and the emulator without needing the S-CSCF's iFC to fire (the plan's
-- fallback, and the right first step when MT never arrives).
--
-- The phase is orthogonal to the call phase: IMS_CALL=0 IMS_SMS=1 measures
-- SMS alone, both together measures them in sequence.
local SMS = {
    on = (os.getenv("IMS_SMS") or "0") ~= "0",
    -- Messages per submitting subscriber. The default walks the whole
    -- content matrix once, which is the interesting run; a number larger
    -- than the matrix repeats it.
    per_sub = tonumber(os.getenv("SMS_PER_SUB") or ""),
    pairs   = tonumber(os.getenv("SMS_PAIRS") or ""),   -- nil = every eligible pair
    -- Offered submit rate, like CALL_CPS: 0 is a single burst, consistent
    -- with the deliberately unramped registration side.
    mps  = tonumber(os.getenv("SMS_MPS") or "0"),
    t_ms = tonumber(os.getenv("SMS_T_MS") or "20000"),  -- per-message deadline
    -- Ask for a status report. It costs an extra MT MESSAGE per message and
    -- only the SC can produce one, so it is off unless asked for.
    srr  = (os.getenv("SMS_SRR") or "0") ~= "0",
    -- Where a submit is addressed. The service centre PSI by default, which
    -- is what a UE does; SMS_DIRECT=1 sends to SMS_GW_HOST:SMS_GW_PORT and
    -- skips the core entirely.
    sc_uri  = os.getenv("SMS_SC_URI") or "",
    sc_addr = os.getenv("SMS_SC_ADDR") or "+123456789",
    direct  = (os.getenv("SMS_DIRECT") or "0") ~= "0",
    gw_host = os.getenv("SMS_GW_HOST") or "",
    gw_port = tonumber(os.getenv("SMS_GW_PORT") or "5065"),
}

-- The content matrix. Each entry is submitted and the received text is
-- compared byte for byte with what was sent, which is the assertion that
-- finds the UDH fill-bit and TP-UDL-units bugs and the one thing a
-- hand-typed alphabet table cannot fake. `alpha` nil means let the codec
-- choose (GSM 7-bit when it fits, UCS2 otherwise), as a handset does.
--
-- SMS_MATRIX=gsm7,ucs2 restricts it by name; SMS_MATRIX=off sends the
-- first entry only, for a pure-throughput run where the payload is noise.
-- The non-ASCII text is written as literal UTF-8 bytes, NOT as \u{...}:
-- Lua 5.1 has no \u escape and silently drops the backslash, so
-- "5\u{20AC}" would become the eight ASCII characters "5u{20AC}". The
-- round-trip assertion would still pass — both ends mangle it the same
-- way — while never exercising the extension table or a surrogate pair,
-- which is precisely the coverage this matrix exists for.
local SMS_MATRIX = {
    { name = "gsm7",   text = "IMS SMS test 1234567890" },
    { name = "ext",    text = "cost 5€: {a|b} ~ [x] \\y" },
    { name = "accent", text = "èéùìòÇØÅßÉ¤¡§¿ÄÖÑÜàäöñü" },
    { name = "ucs2",   text = "Привет, мир — SMS over IMS" },
    { name = "emoji",  text = "delivered 🙂👍 ok" },
    { name = "binary", text = "\0\1\2\3\127\255\0\254", alpha = "8bit" },
    { name = "full",   text = string.rep("A", 160) },       -- exactly 160 septets
    { name = "concat", text = string.rep("concatenated 1234567890 ", 18) },
}

-- Per-event logging. The trace is ~18 lines per subscriber at ~1.6 us of
-- unbuffered write each, so past a few hundred subscribers the tool spends
-- a serious fraction of a core describing the run rather than driving it —
-- and far more of one against a terminal than a pipe. IMS_VERBOSE=1 forces
-- the trace on, =0 forces it off; unset keeps it on only for a small run,
-- where following one subscriber step by step is the point of the tool.
-- The per-run summary and the phase banners print either way.
local VERBOSE_MAX_SUBS = 20
local VERBOSE
do
    local v = os.getenv("IMS_VERBOSE")
    if v then VERBOSE = v ~= "0" else VERBOSE = NSUBS <= VERBOSE_MAX_SUBS end
end
-- Batch the writes that remain: banner() flushes, so a crash loses at most
-- the current phase.
io.stdout:setvbuf("full", 65536)

local IPPROTO_UDP    = 17      -- unprotected REGISTER: plain UDP toward the P-CSCF
local IPPROTO_ESP    = 50      -- protected traffic: ESP (IMS-AKA IPsec, TS 33.203)
local PCSCF_SIP_PORT = 5060    -- IMS signalling bearer TFT: SIP toward the P-CSCF

-- Per-subscriber resources, spaced by the zero-based index so concurrent
-- subscribers never collide: the S5/S8-U TEIDs (default + dedicated), the
-- UE's protected client/server ports, and its two inbound ESP SPIs.
local S5_UP_TEID_BASE = 0x200
local PORT_UC_BASE, PORT_US_BASE = 5088, 5090
local SPI_BASE = 0x2001

-- USIM secret (raw 16-byte hex). Defaults are 3GPP TS 35.207 Milenage Test
-- Set 1; override IMS_K / IMS_OPC for a real USIM (OPc used directly, no OP
-- derivation). Shared by every subscriber.
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end

local K   = unhex(os.getenv("IMS_K")  or "3919F39741B626604B4BACE23ACFB094")
local OPc = unhex(os.getenv("IMS_OPC") or "177FAD988A964A3AD0421B4693257056")

-- ---- little helpers ---------------------------------------------------

local function banner(t) print(("\n== %s"):format(t)); io.stdout:flush() end

-- IMS_DUMP=1 prints every call-phase message, both directions, as text. Route
-- sets, tags and Record-Route ordering are what call routing turns on, and
-- reasoning about them from a summary line is guesswork; this is off by default
-- because at any real subscriber count it is far more output than the trace.
local DUMP_ON = (os.getenv("IMS_DUMP") or "0") ~= "0"
local function dump(what, wire)
    if not DUMP_ON then return end
    print(("\n--- %s (%d bytes)"):format(what, #wire))
    io.write((wire:gsub("\r\n", "\n")))
    io.stdout:flush()
end
local function line(k, v) print(("   %-24s %s"):format(k, v)) end
local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end

-- Prefix a log line with the subscriber index when running more than one.
-- Silent unless VERBOSE: the per-subscriber trace is the first thing to go
-- at scale. Call sites whose arguments are themselves expensive to build
-- (hex(), string.format over several fields) test VERBOSE themselves, since
-- Lua evaluates them before this function is entered.
local function slog(sub, k, v)
    if not VERBOSE then return end
    line(NSUBS > 1 and ("[%d] %s"):format(sub.i, k) or k, v)
end

-- Run a kernel op (ESP SA / policy install), turning a CAP_NET_ADMIN
-- rejection into one reported line rather than aborting the run.
local function attempt(sub, what, fn)
    local ok, err = pcall(fn)
    slog(sub, what, ok and "ok" or ("skipped (" .. why(err) .. ")"))
    return ok
end

-- Feed one of the sip module's machines, but only while it can still move.
--
-- A machine in its terminal state is not something to hide: fsm_act()
-- (task/src/fsm.c) warns "fsm: already in the terminal state" and the facade
-- turns the FSM_E_FINAL into an exception, so a bare pcall around the feed
-- swallows the error and leaves one unexplained WARN line per call on stderr.
-- Every event that reaches a terminal machine here is one it is CORRECT to
-- drop, so the guard belongs at the feed, not around it:
--
--   * the ACK for a 2xx is its OWN transaction (RFC 3261 §17.2.1) — sending the
--     200 OK ended the INVITE server transaction and handed retransmission to
--     the TU, so the ACK that follows has no transaction left to move. This is
--     the one that fires on every answered call;
--   * a retransmitted 200 OK, or a BYE that crosses our own, arrives at a
--     dialog or client transaction we have already torn down.
--
-- Transaction and Dialog both answer terminated(). The registration machines
-- call that state failed() and are only ever fed while the subscriber is live
-- (handle_sip returns early once it is done), so they keep their own path.
-- The method is taken as a value rather than wrapped in a closure: these run
-- once per message, and pcall(m.recv, m, msg) allocates nothing.
local function feed_ev(m, ev)
    if m and not m:terminated() then pcall(m.event, m, ev) end
end
local function feed_msg(m, msg)
    if m and not m:terminated() then pcall(m.recv, m, msg) end
end

-- Resolve a host name to an IPv4 literal via the net module's own resolver
-- (a dotted quad passes through unchanged). No external tools.
local function resolve(name)
    local ok, res = pcall(function() return net.Resolver():resolve4(name) end)
    assert(ok, ("cannot resolve PGW host name %q: %s"):format(name, why(res)))
    return res
end

-- ---- per-subscriber identity ------------------------------------------

-- IMSI i = base + (i-1) (< 2^53, so exact as a double), 15 digits; IMPU/IMPI
-- and the number follow from it. Keys stay shared, so the HSS must provision
-- this range.
--
-- `dial` is how OTHER subscribers address this one (CALL.uri): the tel URI of
-- its number, that number's sip;user=phone form, or its sip IMPU. It is a
-- separate field from impu on purpose — the UE keeps identifying *itself* by
-- the IMPU it registered (From, P-Preferred-Identity, the RTCP CNAME), which
-- is the identity the P-CSCF matches its registration on, while the number is
-- only ever a destination.
local function make_sub(i)
    local idx  = i - 1
    local imsi = ("%015.0f"):format(tonumber(base_imsi) + idx)
    local impu = ("sip:%s@%s"):format(imsi, ims_realm)
    local msisdn = msisdn_of(imsi)
    local tel   = ("tel:+%s"):format(msisdn)
    local phone = ("sip:+%s@%s;user=phone"):format(msisdn, ims_realm)
    return {
        i = i, idx = idx,
        imsi = imsi,
        impu = impu,
        impi = ("%s@%s"):format(imsi, ims_realm),
        msisdn = msisdn,
        dial = (CALL.uri == "sip") and impu
               or (CALL.uri == "phone") and phone
               or tel,
        up_teid  = S5_UP_TEID_BASE + idx * 0x10,       -- default bearer S5/S8-U TEID
        ded_teid = S5_UP_TEID_BASE + idx * 0x10 + 1,   -- dedicated (media) bearer TEID
        port_uc  = PORT_UC_BASE + idx * 4,             -- UE protected client port
        -- The UE advertises ONE protected port in both roles (see
        -- security_client); port_us stays in the layout so the per-subscriber
        -- port stride is unchanged and nothing collides.
        port_us  = PORT_US_BASE + idx * 4,             -- reserved, not bound
        media_port = MEDIA.port_base + idx * 4,        -- UE RTP port (RTCP on +1)
        spi_uc   = SPI_BASE + idx * 2,                 -- UE inbound SPIs (client / server)
        spi_us   = SPI_BASE + idx * 2 + 1,
        reg  = sip.Registration(), auth = sip.AuthChallenge(),
        -- One transaction machine per subscriber, re-armed with restart()
        -- for each REGISTER (each is its own transaction, §17.1.2) rather
        -- than a fresh machine — and so a fresh allocation — per request.
        txn  = sip.Transaction(sip.NON_INVITE_CLIENT),
        cseq = 0, attempts = 0,
        ue_addr = nil, pcscf = nil, pgw_ctrl_teid = nil,
        sig_teid = nil, remote_addr = nil, rx0 = nil,
        sock = nil, timer = nil, ch = nil,
        registered = false, done = false, paa_added = false, err = nil,
        stage = "session", fail_stage = nil,   -- how far it got / where it gave up
        sess = nil, deleted = false, del_ok = false,  -- GTP-C session + teardown state
        -- Call phase. svc_route is the Service-Route from the REGISTER 200 OK,
        -- mirrored into the INVITE's Route — without it the P-CSCF classifies
        -- the INVITE as terminating and mis-routes it. Terminating requests
        -- arrive on `sock` too: the UE advertises one protected port in both
        -- roles, so there is no second socket to bind.
        svc_route = nil,
        -- The non-barred identities the 200 OK associated with this
        -- registration, in the order the network listed them — see
        -- associated_uris(). `impu` above is what the UE registered; this is
        -- what the network calls it afterwards, and the two differ whenever
        -- the registered IMPU is the barred temporary one.
        assoc = nil,
        -- Reg event (RFC 3680): the subscription this UE opens on its own
        -- IMPU once registered. Kept on the subscriber, not only in the
        -- phase's own list, because the subscription outlives the phase — the
        -- NOTIFY that reports its de-registration arrives at teardown.
        regev = nil, regev_cseq = 0,
        def_bearer = nil, ded_bearer = nil,  -- default / dedicated (Create Bearer)
        media_tft = nil,                     -- {bearer=, tuples={...}} once programmed
        call = nil,                          -- the call this subscriber is in
        -- SMS phase. sms_wait is what this subscriber is expected to receive
        -- (deliveries are matched against it by content, not arrival order);
        -- sms_groups reassembles the parts of a concatenated message, keyed by
        -- its concatenation reference; sms_cseq is the CSeq of the MESSAGE
        -- requests it originates, a separate sequence from the calls' because
        -- they are separate dialogs.
        sms_wait = nil, sms_groups = nil, sms_cseq = 0,
    }
end

-- ---- SIP message building (RFC 3261 / TS 24.229) ----------------------

-- The challenge's qop is a quoted list (kamailio defaults to "auth,auth-int");
-- pick one token. Only "auth" is computed here (HA2 = MD5(method:uri)); fall
-- back to no-qop (RFC 2069) rather than claim a mode we do not compute.
local function pick_qop(list)
    if not list then return nil end
    for tok in list:gmatch("[%w%-]+") do
        if tok == "auth" then return "auth" end
    end
    return nil
end

-- The UE's Security-Client offer (RFC 3329 / TS 33.203): its two inbound
-- SPIs, its protected ports and the ESP algorithms.
--
-- ealg=null: confidentiality is OPTIONAL in TS 33.203 (§6.3, Annex I — only
-- integrity is mandatory), so the SAs run ESP-NULL. Integrity still covers
-- every protected message with IK, the SPI/port plumbing is unchanged, and
-- the SIP stays readable in a capture while the kernel skips the cipher.
-- kamailio's ims_ipsec_pcscf maps this offer to the kernel's cipher_null;
-- it is the only ealg we offer, so it is the one it must select.
--
-- port-c and port-s are deliberately the SAME port here, which is what makes
-- terminating requests (the MT INVITE, a BYE from the far end) reach the UE at
-- all. TS 33.203 §6.3 pairs them the other way — SA1 is
-- {UE client port <-> P-CSCF server port}, SA2 is {UE server port <-> P-CSCF
-- client port} — and kamailio's ims_ipsec_pcscf creates exactly those two
-- outbound SAs. But when it forwards a terminating request it sends from its
-- protected CLIENT port to the UE's protected CLIENT port, a pairing neither SA
-- covers, so its own kernel drops the packet before it ever reaches the access
-- network. Confirmed from the P-CSCF's side: XfrmOutNoStates climbs once per
-- INVITE retransmission and `ip xfrm monitor` reports
--
--   acquire ... sel src <pcscf> dst <ue> proto udp sport <p_port_c> dport <port_uc>
--
-- With one UE port in both roles, SA2 becomes {UE port <-> P-CSCF client port}
-- and that is precisely the flow it uses, so the drop disappears — while SA1
-- still carries the REGISTER exchange exactly as before. A P-CSCF that follows
-- §6.3 strictly is unaffected: it would simply send to the same port.
local function security_client(sub)
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(sub.spi_uc, sub.spi_us, sub.port_uc, sub.port_uc)
end

-- The Authorization value (AKAv1-MD5 Digest). `realm` MUST be the one from
-- the challenge: the S-CSCF recomputes HA1 with the realm it reads back
-- here, so header-realm == computed-realm always; the digest-uri stays the
-- home domain (= Request-URI). An empty nonce/response advertises IMS-AKA on
-- the first REGISTER.
local function authz_hdr(sub, realm, nonce, response, qopset)
    local a = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(sub.impi, realm, ims_realm, nonce or "", response or "")
    if qopset then
        a = a .. (',qop=%s,nc=%s,cnonce="%s"'):format(qopset.qop, qopset.nc, qopset.cnonce)
    end
    return a
end

-- Build the UE's IMS REGISTER. Via/Contact carry the UE's PAA at its
-- protected client port; a fresh transaction per REGISTER keys the branch
-- and From-tag on the CSeq, the Call-ID is stable across the pair.
-- One Builder for the whole run: request() re-inits the write buffer, so
-- successive messages cannot bleed into each other and each REGISTER costs
-- no allocation for the buffer it is written into. Safe because the script
-- is single-threaded and never has two messages half-built at once.
local BUILDER = sip.Builder()

local function build_register(sub, authz, sec_name, sec_hdr, expires)
    local b = BUILDER
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(sub.ue_addr, sub.port_uc, sub.imsi, sub.cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(sub.impu, sub.imsi, sub.cseq))
        :header(sip.H_TO, ("<%s>"):format(sub.impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(sub.imsi, sub.ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(sub.cseq))
        -- TS 24.341 §5.3.2.2: a UE that does SMS over IP says so with the
        -- +g.3gpp.smsip feature tag on its Contact. In a real network MT
        -- routing depends on it — the IP-SM-GW checks the registered
        -- contact's capabilities before choosing IP delivery over the
        -- circuit-switched fallback — so it goes on every REGISTER, not
        -- only when the SMS phase is enabled. The ims stack's own test
        -- client sends it too (ims/images/test/src/sip.py).
        :header(sip.H_CONTACT, expires == 0
                and ("<sip:%s:%d>;expires=0"):format(sub.ue_addr, sub.port_uc)   -- de-REGISTER: bind removal
                or  ("<sip:%s:%d>;%s"):format(sub.ue_addr, sub.port_uc, sms.FEATURE_TAG))
        :header_u32(sip.H_EXPIRES, expires or REG_EXPIRES)
        :header(sip.H_AUTHORIZATION, authz)
    if sec_hdr then b:header_name(sec_name, sec_hdr) end
    return b:done()
end

-- Parse the 401: the AKA challenge from WWW-Authenticate (nonce is
-- base64(RAND||AUTN)) and, when present, the P-CSCF's Security-Server.
local function parse_challenge(msg)
    local wa = msg:header("WWW-Authenticate")
    assert(wa ~= "", "401 without WWW-Authenticate")
    local nonce = sip.auth_param(wa, "nonce")
    assert(nonce ~= "", "401 WWW-Authenticate without nonce")
    local blob = sip.b64decode(nonce)
    assert(#blob >= 32, "AKA nonce shorter than RAND||AUTN")
    local realm = sip.auth_param(wa, "realm")
    local ss = msg:header("Security-Server")
    ss = ss ~= "" and ss or nil
    return {
        nonce = nonce, rand = blob:sub(1, 16), autn = blob:sub(17, 32),
        realm = realm ~= "" and realm or ims_realm,
        qop   = pick_qop(sip.auth_param(wa, "qop")),
        ss_raw   = ss,
        p_spi_c  = ss and tonumber(sip.auth_param(ss, "spi-c")),
        p_spi_s  = ss and tonumber(sip.auth_param(ss, "spi-s")),
        p_port_c = ss and tonumber(sip.auth_param(ss, "port-c")),
        p_port_s = ss and tonumber(sip.auth_param(ss, "port-s")),
    }
end

-- ---- the reg event package (RFC 3680, TS 24.229 §5.1.1.3) -------------
--
-- The phase's three helpers hang off REGEV rather than standing as three
-- more file-scope locals, for the reason the CALL/MEDIA knobs are grouped:
-- Lua 5.1 caps a function at 60 upvalues and run() sits at that cap, so
-- three loose locals would be three of them. They are attached here rather
-- than beside the knobs because the first needs BUILDER, declared above.

-- The UE's SUBSCRIBE to the registration state of its own public identity:
-- Request-URI, To and From are all its IMPU, and the Event/Accept pair is
-- what makes it a reg subscription rather than any other package —
-- kamailio's can_subscribe_to_reg() reads the Event header and answers
-- anything else with 489 Bad Event.
--
-- It is an out-of-dialog ORIGINATING request, so it carries what an INVITE
-- carries: the P-CSCF's own URI marked `orig` ahead of the Service-Route
-- (see build_invite for why the marking has to be on that first entry, and
-- what happens when it is not), and the Contact this UE registered — the
-- P-CSCF matches usrloc on it in pcscf_is_registered() before it lets an
-- originating request through at all.
function REGEV.build(sub, u, expires)
    local pport = (sub.ch and sub.ch.ss_raw and sub.ch.p_port_s) or PCSCF_SIP_PORT
    local b = BUILDER:request(sip.SUBSCRIBE, sub.impu)
    b:header(sip.H_ROUTE, ("<sip:orig@%s:%d;lr>"):format(sub.pcscf, pport))
    for _, r in ipairs(sub.svc_route or {}) do b:header(sip.H_ROUTE, r) end
    b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s"):format(sub.ue_addr, sub.port_uc, u.branch))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s"):format(sub.impu, u.from_tag))
        :header(sip.H_TO, ("<%s>"):format(sub.impu))
        :header(sip.H_CALL_ID, u.call_id)
        :header(sip.H_CSEQ, ("%d SUBSCRIBE"):format(u.cseq))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(sub.ue_addr, sub.port_uc))
        :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(sub.impu))
        :header(sip.H_EVENT, "reg")
        :header(sip.H_ACCEPT, "application/reginfo+xml")
        :header_u32(sip.H_EXPIRES, expires)
    return b:done()
end

-- One attribute out of an XML start tag. The leading %s is not decoration:
-- without it "state" would also match the tail of any attribute name ending
-- in it, and a pattern that quietly reads the wrong attribute is worse than
-- one that reads none.
local function xattr(s, k) return s:match('%s' .. k .. '%s*=%s*"([^"]*)"') end

-- The reg event's body (RFC 3680 §5.1, application/reginfo+xml): one
-- <registration> per public identity of the implicit registration set, each
-- listing the contacts bound to it. Read with patterns rather than an XML
-- parser, and deliberately so — the document is machine-generated, flat and
-- attribute-only, and the two things asserted from it (is this identity
-- active, is our own contact among its bindings) are two attributes and one
-- element. A parser would be a dependency for no more information.
--
-- Chunked at each opening tag rather than matched as
-- <registration>...</registration>, so an identity carrying no contacts —
-- which a notifier is free to write self-closed — is still counted rather
-- than silently skipped, and a missing identity is exactly the finding this
-- phase exists to make.
function REGEV.parse(body)
    local out, pos = {}, 1
    while true do
        local s = body:find("<registration", pos, true)
        if not s then break end
        local e = body:find("<registration", s + 13, true) or (#body + 1)
        local chunk = body:sub(s, e - 1)
        local head  = chunk:match("^<registration([^>]*)") or ""
        local r = { aor = xattr(head, "aor") or "", state = xattr(head, "state") or "",
                    contacts = {} }
        for c in chunk:gmatch("<contact(.-)</contact>") do
            r.contacts[#r.contacts + 1] = {
                state = xattr(c, "state") or "", event = xattr(c, "event") or "",
                uri   = c:match("<uri>%s*(.-)%s*</uri>") or "",
            }
        end
        out[#out + 1] = r
        pos = e
    end
    return out
end

-- Two URIs naming the same identity: compared case-insensitively and without
-- their parameters, so the tel URI this run dials and the one the HSS
-- provisioned are the same identity even when one carries a phone-context
-- (RFC 3966 §3) and the other does not.
function REGEV.same_id(a, b)
    local function norm(u)
        local s = (u or ""):lower()
        s = s:gsub("%s+", "")
        s = s:gsub("[;>].*$", "")
        s = s:gsub("^<", "")
        return s
    end
    return norm(a) == norm(b)
end

-- ---- call signalling (RFC 3261 §12/§13, TS 24.229 §5.1) ---------------

-- The dialog's route set is the Record-Route list: in the order it appeared
-- for the side that received the request (the MT), reversed for the side that
-- received the response (the MO) — RFC 3261 §12.1. Record-Route values are
-- always name-addr, so pulling every <...> out in order copes with both one
-- header per hop and several hops folded into one comma-separated value,
-- without a splitter that has to know a comma inside <> is not a separator.
local function route_set(m, reverse)
    local out  = {}
    local vals = m:header_values("Record-Route")
    for i = 0, vals:size() - 1 do
        for uri in vals[i]:gmatch("<[^>]*>") do out[#out + 1] = uri end
    end
    if reverse then
        for i = 1, math.floor(#out / 2) do
            out[i], out[#out - i + 1] = out[#out - i + 1], out[i]
        end
    end
    return out
end

-- The dialog's remote target: the far end's Contact URI.
local function contact_uri(m)
    local c = m:header("Contact")
    if c == "" then return nil end
    return c:match("<([^>]*)>") or c:match("^%s*([^;%s]+)")
end

-- The Service-Route the S-CSCF returned in the REGISTER 200 OK. Mirroring it
-- into the INVITE's Route is NOT optional: both CSCFs pick the originating
-- path on the Route URI ("sip:orig@..." / "sip:mo@..."), so an INVITE without
-- it is classified as *terminating* and fails in a way that looks like a
-- routing bug in the core (proxy.cfg / serving.cfg request_route).
local function service_route(m)
    local out  = {}
    local vals = m:header_values("Service-Route")
    for i = 0, vals:size() - 1 do
        for uri in vals[i]:gmatch("<[^>]*>") do out[#out + 1] = uri end
    end
    return out
end

-- The identities the REGISTER 200 OK associated with this registration
-- (TS 24.229 §5.1.1.1A), bare — no angle brackets, so they compare as
-- identities rather than as routes.
--
-- This matters because the UE here has no ISIM. It registers with a TEMPORARY
-- public user identity derived from the IMSI (TS 23.003 §13.4B), and that one
-- is provisioned BARRED: good for the REGISTER and for nothing else. The
-- identities the network will actually talk about are the non-barred ones it
-- returns here — with open5gs's HSS, sip:<msisdn>@<realm> and tel:<msisdn>
-- (hss_cx_download_user_data). Both CSCF sides filter on that flag: kamailio
-- builds this header from the unbarred identities (build_p_associated_uri) and
-- builds a reg-info document from the same set, so a UE that only ever knows
-- its own IMPU cannot recognise its own registration state.
local function associated_uris(m)
    local out  = {}
    local vals = m:header_values("P-Associated-URI")
    for i = 0, vals:size() - 1 do
        for uri in vals[i]:gmatch("<([^>]*)>") do out[#out + 1] = uri end
    end
    return out
end

-- The MO's INVITE, from its protected client port. No Require/Supported: with
-- both ends ours, advertising 100rel would oblige PRACK handling and session
-- timers a refresh cycle, and neither buys a measurement (see the header).
local function build_invite(c)
    local mo = c.mo
    -- The dialled address (CALL.uri): by default the callee's tel URI, so the
    -- Request-URI carries a number and the core has to resolve it through the
    -- HSS profile to the callee's registered contact.
    local b  = BUILDER:request(sip.INVITE, c.callee)
    -- TS 24.229 §5.1.2A.1: the preloaded Route of an initial request is the
    -- P-CSCF's own URI — at its protected server port, since IPsec is in use —
    -- followed by the Service-Route values, in order.
    --
    -- The `orig` user on that first entry is what makes the P-CSCF take its
    -- originating path, and it is easy to get wrong: loose_route() strips the
    -- topmost Route when it names the P-CSCF itself, and the classification
    -- (proxy.cfg:101) then reads the URI that was *stripped* — not the one left
    -- behind. So the marking has to be on the P-CSCF's own entry: an INVITE
    -- carrying the Service-Route alone, or a bare <sip:pcscf:port;lr>, leaves
    -- nothing to match and the request takes the *terminating* path, which
    -- fails looking exactly like a routing bug in the core. Normally the
    -- P-CSCF supplies this entry itself by prepending its own Service-Route
    -- value (pcscf_force_service_routes, commented out in this stack), so the
    -- UE synthesises it from the P-CSCF address the PCO gave it.
    local pport = (mo.ch and mo.ch.ss_raw and mo.ch.p_port_s) or PCSCF_SIP_PORT
    b:header(sip.H_ROUTE, ("<sip:orig@%s:%d;lr>"):format(mo.pcscf, pport))
    for _, r in ipairs(mo.svc_route) do b:header(sip.H_ROUTE, r) end
    b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s"):format(mo.ue_addr, mo.port_uc, c.branch))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, c.from_hdr)
        :header(sip.H_TO, c.to_hdr)
        :header(sip.H_CALL_ID, c.call_id)
        :header(sip.H_CSEQ, ("%d INVITE"):format(c.cseq))
        -- The INVITE must come from the registered contact: the P-CSCF matches
        -- usrloc on aor/received_port (pcscf_is_registered), so this is the
        -- same PAA:port_uc the protected REGISTER left from, over the same SA.
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(mo.ue_addr, mo.port_uc))
        -- The P-CSCF checks this against the registration and re-asserts it as
        -- P-Asserted-Identity (proxy.cfg route[MORIG]) — so it stays the sip
        -- IMPU this UE registered even when it dials a number: the caller's
        -- own tel URI is an alias of the same subscription, and asserting an
        -- alias is only accepted if the P-CSCF learnt it from P-Associated-URI,
        -- which turns a working call into a 403 on some stacks for nothing.
        :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(mo.impu))
        :header(sip.H_ALLOW, "INVITE, ACK, CANCEL, BYE")
    -- No Security-Verify: RFC 3329 §2.2 wants it on the request that follows
    -- the Security-Server offer — the authenticated REGISTER, which does carry
    -- it — and the ~110 bytes it costs here come back amplified in the
    -- terminating INVITE the callee has to receive (see build_in_dialog).
    b:header(sip.H_CONTENT_TYPE, "application/sdp")
    return b:done(c.offer)
end

-- A response from `me` to `req`. Via order matters and Record-Route must be
-- echoed in the order received — that is how the far end learns its route set
-- for the ACK and the BYE. The To tag is added only when the request has none
-- (a mid-dialog request already carries it).
local function build_response(c, me, req, status, reason, body)
    local b    = BUILDER:response(status, reason)
    local vias = req:header_values("Via")
    for i = 0, vias:size() - 1 do b:header(sip.H_VIA, vias[i]) end
    local rrs = req:header_values("Record-Route")
    for i = 0, rrs:size() - 1 do b:header(sip.H_RECORD_ROUTE, rrs[i]) end
    local to = req:header("To")
    if not to:find(";tag=", 1, true) then to = to .. ";tag=" .. c.to_tag end
    b:header(sip.H_FROM, req:header("From"))
        :header(sip.H_TO, to)
        :header(sip.H_CALL_ID, req:header("Call-ID"))
        :header(sip.H_CSEQ, req:header("CSeq"))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(me.ue_addr, me.port_uc))
    if body then b:header(sip.H_CONTENT_TYPE, "application/sdp") end
    return b:done(body or "")
end

-- ---- the downlink size budget ------------------------------------------
--
-- Everything the network sends to a UE crosses GTP-U, which adds 36 bytes
-- (outer IPv4 + UDP + GTP header). On a 1500-byte path that leaves 1464 bytes
-- for the packet the P-CSCF emits — and a G-PDU that would exceed the MTU does
-- not arrive: the outer packet is fragmented and the decap cannot classify a
-- fragment that carries no GTP header, so both halves are lost. Measured on
-- this stack, downlink packets of 1452 bytes arrive and 1480 do not.
--
-- The tool only controls one term of that sum — the size of the requests it
-- sends, since the proxies then add ~500 bytes of Record-Route, P-Charging-*,
-- P-Asserted-Identity and Via to whatever it emitted. So the call messages are
-- deliberately lean: short tags/branches/Call-ID, no Contact where it is
-- optional, no Security-Verify outside the REGISTER that RFC 3329 §2.2 asks
-- for it in. Without that, an 882-byte ACK came back as a 1480-byte downlink
-- and vanished, which looks exactly like the far end ignoring the request.
--
-- The uplink half of the same sum is not about message size at all — it is a
-- route MTU, so the kernel fragments before the datapath's TC hook rather than
-- losing the packet at it. See set_pcscf_mtu in run().
--
-- An ACK or a BYE from the MO goes to the dialog's remote target through its
-- route set, with the local/remote URI+tag pair as the 200 OK settled it. The
-- ACK for a 2xx is its own transaction, hence its own branch; the ACK for a
-- non-2xx belongs to the INVITE transaction and reuses the INVITE's branch
-- (and needs no route set — it goes where the INVITE went).
local function build_in_dialog(c, method, mname, cseq, branch, route)
    local mo = c.mo
    local b  = BUILDER:request(method, c.target or c.callee)
    for _, r in ipairs(route or {}) do b:header(sip.H_ROUTE, r) end
    b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s"):format(mo.ue_addr, mo.port_uc, branch))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, c.from_hdr)
        :header(sip.H_TO, c.to_hdr)
        :header(sip.H_CALL_ID, c.call_id)
        :header(sip.H_CSEQ, ("%d %s"):format(cseq, mname))
        -- Contact is optional in ACK and BYE, but this P-CSCF's originating
        -- path needs it: without it pcscf_is_registered() does not find the
        -- registration and answers the BYE with "403 Forbidden - You must
        -- register first with a S-CSCF", even though the INVITE that opened the
        -- dialog from the same port passed the same check.
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(mo.ue_addr, mo.port_uc))
    return b:done()
end

-- Answer with a payload type the offer actually listed (RFC 3264 §6): keep
-- ours when it is on offer, else take the offer's first. Returns the type
-- plus the codec name and clock to echo back — for a dynamic type there is
-- no static name to fall back on, so the answer takes them from the offer's
-- own a=rtpmap rather than claiming PCMU and playing noise.
local function answer_pt(stream)
    local pt = MEDIA.pt
    if stream and not stream:has_pt(pt) and stream:pt_count() > 0 then
        local first = stream:pt_at(0)
        if first >= 0 then pt = first end
    end
    if pt == MEDIA.pt then return pt, MEDIA.codec, MEDIA.rate end
    -- A type we did not offer: echo the offer's own a=rtpmap so the answer
    -- names the codec the peer meant, falling back to the RFC 3551 static
    -- assignment when the offer left it implicit.
    if stream:has_rtpmap(pt) then
        local r = stream:rtpmap(pt)
        return pt, r.enc, r.clock
    end
    local enc, clock = sdp.pt_encoding(pt), sdp.pt_clock(pt)
    if enc ~= "" then return pt, enc, clock end
    return MEDIA.pt, MEDIA.codec, MEDIA.rate  -- nothing nameable; keep ours
end

-- The encoding name a=rtpmap carries. A static payload type names itself
-- (RFC 3551 §6), so the default needs no knob; a dynamic one (96..127) has
-- no assignment to borrow and must be named, because offering it as PCMU
-- negotiates cleanly and then plays noise. Caught here, at startup, rather
-- than as an exception from the first INVITE.
MEDIA.codec = os.getenv("MEDIA_CODEC") or sdp.pt_encoding(MEDIA.pt)
if MEDIA.codec == "" then
    io.stderr:write(("MEDIA_PT=%d is a dynamic payload type; set MEDIA_CODEC " ..
                     "(and MEDIA_RATE) to the encoding it stands for\n")
                    :format(MEDIA.pt))
    os.exit(2)
end

-- One packetisation interval of payload. G.711 is one byte per sample, so at
-- 8 kHz / 20 ms this is the canonical 160-byte packet; for another codec the
-- size is only nominal (nothing decodes it) while the timestamp step stays
-- right, which is what the receiver's jitter estimate is computed from.
MEDIA.samples = math.max(1, math.floor(MEDIA.rate * MEDIA.ptime_ms / 1000))
MEDIA.payload = ("\170"):rep(MEDIA.samples)

-- Kernel ESP error counters. Everything here rides transport-mode ESP, and a
-- packet the kernel refuses — no matching SA, a selector that misses the
-- inbound policy — is dropped in complete silence: the tool sees exactly what
-- it sees when the network never sent anything at all. These counters tell the
-- two apart, so they are worth the four lines. Only non-zero rows are reported.
local function xfrm_errors()
    local f = io.open("/proc/net/xfrm_stat")
    if not f then return nil end
    local out = {}
    for l in f:lines() do
        local k, v = l:match("^(%S+)%s+(%d+)")
        if k and tonumber(v) > 0 then out[#out + 1] = ("%s=%d"):format(k, tonumber(v)) end
    end
    f:close()
    return out
end

-- ---- distributions ----------------------------------------------------

-- Report distributions, not means: the mean hides the knee, which is the whole
-- reason for measuring setup time against offered load.
local function summarize(t)
    local n = #t
    if n == 0 then return nil end
    local s = {}
    for i = 1, n do s[i] = t[i] end
    table.sort(s)
    local sum = 0
    for i = 1, n do sum = sum + s[i] end
    local function q(p) return s[math.max(1, math.min(n, math.ceil(p * n)))] end
    return { n = n, min = s[1], p50 = q(0.50), p95 = q(0.95), p99 = q(0.99),
             max = s[n], mean = sum / n }
end

-- A listening-quality ESTIMATE from packet statistics alone — an ITU-T G.107
-- (E-model) simplification. No audio is decoded, so this is NOT PESQ/POLQA:
-- it is the right tool for "did quality degrade as load rose" and the wrong
-- one for a verdict on a codec. Printed labelled as an estimate for that
-- reason.
local function mos_estimate(delay_ms, loss_pct)
    local d  = math.max(0, delay_ms or 0)
    local Id = 0.024 * d                              -- delay impairment
    if d > 177.3 then Id = Id + 0.11 * (d - 177.3) end -- interactivity knee
    local p  = math.max(0, loss_pct or 0) / 100
    local Ie = 30 * math.log(1 + 15 * p)   -- G.711 + packet-loss concealment
    local R  = 93.2 - Id - Ie
    if R <= 0 then return 1.0 end
    if R >= 100 then return 4.5 end
    local mos = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
    return math.max(1.0, math.min(4.5, mos))
end

-- Install the four transport-mode ESP SAs and steering policies (TS 33.203
-- Annex I: IK integrity-protects; encryption with CK is optional and we
-- negotiated ealg=null, so the cipher is cipher_null with a zero-length key
-- and CK goes unused). Keyed by the receiver's SPI; the UE-side SPIs/ports
-- and PAA are per-subscriber so a shared Xfrm handle keeps every
-- subscriber's SAs distinct.
local function establish_sas(xfrm, sub, ch, keys)
    local function esp_sa(src, dst, spi, reqid)
        local sa = ipsec.Sa()
        sa.src, sa.dst, sa.spi = src, dst, spi
        sa.proto, sa.mode, sa.reqid = ipsec.PROTO_ESP, ipsec.TRANSPORT, reqid
        sa.enc_alg,  sa.enc_key  = "ecb(cipher_null)", ""
        sa.auth_alg, sa.auth_key = "hmac(sha1)",       keys.ik
        return sa
    end
    local function esp_policy(dir, src, dst, sport, dport, reqid)
        local p = ipsec.Policy()
        p.src, p.dst = src, dst
        p.sel_proto, p.sport, p.dport = IPPROTO_UDP, sport, dport
        p.dir, p.action = dir, ipsec.ALLOW
        p.has_tmpl, p.tmpl_reqid = true, reqid
        p.tmpl_proto, p.tmpl_mode = ipsec.PROTO_ESP, ipsec.TRANSPORT
        return p
    end
    local ue, pcscf = sub.ue_addr, sub.pcscf
    local sas = {
        esp_sa(ue, pcscf, ch.p_spi_s, ch.p_spi_s),
        esp_sa(ue, pcscf, ch.p_spi_c, ch.p_spi_c),
        esp_sa(pcscf, ue, sub.spi_uc, sub.spi_uc),
        esp_sa(pcscf, ue, sub.spi_us, sub.spi_us),
    }
    -- One UE port in both roles (see security_client): SA1 carries the
    -- REGISTER exchange with the P-CSCF's protected server port, SA2 carries
    -- terminating requests and their responses with its protected client port.
    local pols = {
        esp_policy(ipsec.DIR_OUT, ue, pcscf, sub.port_uc, ch.p_port_s, ch.p_spi_s),
        esp_policy(ipsec.DIR_OUT, ue, pcscf, sub.port_uc, ch.p_port_c, ch.p_spi_c),
        esp_policy(ipsec.DIR_IN,  pcscf, ue, ch.p_port_s, sub.port_uc, sub.spi_uc),
        esp_policy(ipsec.DIR_IN,  pcscf, ue, ch.p_port_c, sub.port_uc, sub.spi_us),
    }
    -- hex() of a 16-byte key: build it only if it will be printed.
    if VERBOSE then
        slog(sub, "ESP keys", ("enc=null auth(IK)=%s"):format(hex(keys.ik)))
    end
    for j, sa in ipairs(sas) do
        attempt(sub, ("ESP SA %d (spi %#x)"):format(j, sa.spi), function() xfrm:sa_add(sa) end)
    end
    for j, p in ipairs(pols) do
        attempt(sub, ("ESP policy %d (%s)"):format(j, p.dir == ipsec.DIR_OUT and "out" or "in"),
                function() xfrm:policy_add(p) end)
    end
end

-- ---- the run ----------------------------------------------------------

local function run()
    -- Fill the SGW address from the GTP-U interface when left at any-address;
    -- 0.0.0.0 gives an invalid outer source and F-TEID address.
    local gtpu_ifname = os.getenv("GTPU_IFACE") or "eth0"
    local inner_name  = os.getenv("GTPU_INNER_IFACE") or "eth0"
    -- The MTU put on the route toward the P-CSCF: 1500 less the 36 bytes of
    -- GTP-U the datapath adds. See set_pcscf_mtu below; 0 leaves routing
    -- untouched.
    local inner_mtu   = tonumber(os.getenv("GTPU_INNER_MTU") or "1464") or 1464
    local sgw_auto = false
    if sgw_ip == "0.0.0.0" then
        local ip = net.if_addr4(gtpu_ifname)
        if ip ~= "" then sgw_ip, sgw_auto = ip, true end
    end

    local pgw_ip = resolve(pgw_host)
    banner(("GTPv2-C — %d subscriber(s) over S5/S8: SGW %s -> PGW %s")
        :format(NSUBS, sgw_ip, pgw_ip))
    if sgw_auto then line("SGW address", ("%s (auto from %s)"):format(sgw_ip, gtpu_ifname)) end
    if pgw_ip ~= pgw_host then line("PGW address", ("%s -> %s"):format(pgw_host, pgw_ip)) end
    -- Both ends formatted the way make_sub does it, so the numbers below are
    -- the numbers the subscribers actually carry (IMS_IMSI may be short).
    local first_imsi = ("%015.0f"):format(tonumber(base_imsi))
    local last_imsi  = ("%015.0f"):format(tonumber(base_imsi) + NSUBS - 1)
    line("IMSI range", ("%s .. %s (shared keys)"):format(base_imsi, last_imsi))
    -- The numbers the call phase dials, and the rule that produced them, so a
    -- mismatch with the HSS side is visible before the first INVITE.
    line("MSISDN range", ("+%s .. +%s  (+%s + last %d IMSI digits)")
        :format(msisdn_of(first_imsi), msisdn_of(last_imsi), MSISDN_CC, MSISDN_DIGITS))

    local loop = net.Loop()
    local ok, ep = pcall(gtp.Endpoint, loop, sgw_ip)     -- binds sgw_ip:2123 (GTP-C)
    if not ok then
        io.stderr:write(("cannot bind GTP-C on %s:2123: %s\n"):format(sgw_ip, why(ep)))
        os.exit(1)
    end
    ep:set_t3_ms(T3_MS)
    ep:set_n3(N3)
    ep:set_tx_loop(true)

    -- ---- shared GTP-U datapath (loaded once) ----
    local up
    if gtp.UserPlane.supported() then
        local gi = net.if_index(gtpu_ifname)
        local ii = net.if_index(inner_name)
        local cfg = gtp.UserPlaneConfig()
        cfg.pin_dir        = ""        -- a fresh datapath each run
        cfg.local_v4       = sgw_ip    -- outer source for encapsulated uplink
        cfg.uplink_ifindex = gi
        local made, obj = pcall(gtp.UserPlane, cfg)
        if made then
            up = obj
            if gi ~= 0 or ii ~= 0 then
                local aok, aerr = pcall(function() up:attach(gi, ii) end)
                line("GTP-U datapath", aok
                    and ("attached (gtpu=%s inner=%s)"):format(gi ~= 0 and gtpu_ifname or "-", inner_name)
                    or  ("attach failed: " .. why(aerr)))
            else
                line("GTP-U datapath", "loaded (set GTPU_IFACE/GTPU_INNER_IFACE to attach TC)")
            end
        else
            line("GTP-U datapath", "unavailable (" .. why(obj) .. ")")
        end
    else
        line("GTP-U datapath", "unsupported (non-eBPF build or missing CAP_BPF/CAP_NET_ADMIN)")
    end

    local xfrm                         -- shared ipsec.Xfrm handle (SAs distinct per subscriber)
    local subs, by_imsi, by_teid = {}, {}, {}
    local pending, grace = NSUBS, nil
    local dpending, tguard = 0, nil     -- outstanding Delete Session txns (teardown)

    -- Throughput counters over the run. Each rate (reported in the summary) is
    -- measured from the first Create Session Request (stats.start) to the last
    -- event of its kind, so the 3s grace + teardown don't dilute the active
    -- burst. Packets are the tool's SIP signalling datagrams (REGISTER /
    -- responses / de-REGISTER) driven over the loop; sessions are accepted
    -- Create Session Responses; registrations are 200 OKs.
    local now = net.now_ms
    local stats = {
        tx = 0, rx = 0, sess = 0, regs = 0,   -- counts
        start = now(),                        -- run start (before any Create Session)
        pkt_last = nil, sess_last = nil, reg_last = nil,   -- last-event timestamps
    }
    local function mark_pkt() stats.pkt_last = now() end
    -- Bump a count in a keyed tally (failure stage, SIP status, RP cause).
    local function sbump(t, k) t[k] = (t[k] or 0) + 1 end

    -- ---- call phase state ----
    local calls, by_callid = {}, {}
    local cpending, cguard = 0, nil
    local cstats = {
        pairs_total = 0, eligible = 0, attempted = 0, answered = 0, released = 0,
        media_calls = 0, first_invite = nil, last_answer = nil,
        by_status = {},                       -- final-response counts, non-2xx
        stage = {},                           -- where a failed call died
        kpi = { pdd = {}, sst = {}, sst_net = {}, mo_transit = {}, mt_transit = {},
                answer = {}, cut = {}, release = {} },
        media = { streams = 0, calls = 0, zero = 0, early = 0, late = 0, no_reports = 0,
                  unconnected = 0,   -- streams opened for a call that never answered
                  tx = 0, rx = 0, tx_err = 0, tx_why = nil,
                  dl_loss = {}, dl_jitter = {}, ul_loss = {}, ul_jitter = {},
                  exp_loss = {}, rtt = {}, mos = {} },
    }

    -- ---- SMS phase state ----
    -- Messages in flight, keyed both ways: by the Call-ID of the MESSAGE we
    -- sent (to match its 202/4xx) and by RP-MR (to match the RP-ACK, which
    -- comes back in a NEW out-of-dialog MESSAGE, TS 24.341 §5.3.2.4 — so
    -- there is no dialog to match it against).
    local msgs, msg_by_callid, msg_by_mr = {}, {}, {}
    -- A status report arrives AFTER its message has settled — that is the
    -- point of TP-SRR: the SC reports once the recipient actually has the
    -- message, which is later than the RP-ACK that closed the submit. So the
    -- correlation for it has to outlive msg_by_mr, which msg_finish clears.
    local rep_by_mr = {}
    local mpending, mguard = 0, nil
    local sstats = {
        pairs_total = 0, eligible = 0,
        attempted = 0, accepted = 0, acked = 0, delivered = 0, verified = 0,
        orphans = 0,                          -- deliveries matching no submit
        first_submit = nil, last_delivery = nil,
        reports = 0,                          -- status reports received
        by_cause = {},                        -- RP-ERROR cause -> count
        by_status = {},                       -- non-2xx SIP finals
        stage = {},                           -- where a failed message died
        mismatch = {},                        -- matrix name -> count
        by_matrix = {},                       -- matrix name -> { sent, ok }
        kpi = { accept = {}, ack = {}, transit = {}, deliver_ok = {},
                report = {}, total = {} },
    }

    -- ---- reg-event phase state ----
    -- Subscriptions are keyed by the Call-ID of the SUBSCRIBE that opened
    -- them, which is what both the 200 OK and every NOTIFY of that dialog
    -- carry. The index is NOT cleared when the phase ends: the S-CSCF sends
    -- one more NOTIFY when the registration goes away, and matching it is how
    -- the run can say the UE was told about its own de-registration.
    local regev_by_callid = {}
    local upending, uguard = 0, nil
    local ustats = {
        eligible = 0, attempted = 0, accepted = 0, notified = 0, verified = 0,
        terminated = 0,          -- NOTIFYs saying the registration is gone
        orphans = 0,             -- NOTIFYs matching no subscription of ours
        first = nil, last = nil,
        by_status = {},          -- non-2xx finals for the SUBSCRIBE
        stage = {},              -- where a subscription died, and why
        states = {},             -- Subscription-State token -> count
        identities = {},         -- identities per reg-info document
        dialable = 0,            -- documents listing the address the call phase dials
        kpi = { accept = {}, notify = {}, ack = {} },
    }

    -- Per-subscriber SIP deadline over the shared loop.
    local function disarm(sub) if sub.timer then loop:cancel(sub.timer); sub.timer = nil end end
    local function arm(sub, ms, fn) disarm(sub); sub.timer = loop:after(ms, function() sub.timer = nil; fn() end) end

    -- Advance a subscriber's three machines for a REGISTER we are sending.
    --
    -- The events are injected directly rather than derived from the message.
    -- `sub.reg:send(sip.parse(wire))` reads better, but it re-parses the wire
    -- we just built — a full parse, a string copy per header, and a deep copy
    -- across the binding — purely so the codec can tell us which transition
    -- we are making. We already know: the script decided it. So this mirrors
    -- sip::Registration::send()'s own mapping for an outbound REGISTER, keyed
    -- on the same registration state. `dereg` picks DEREGISTER over REFRESH
    -- for the Expires:0 teardown REGISTER.
    local REG_SEND_EV = {
        [sip.RS_IDLE]       = sip.RE_SEND,   -- first REGISTER
        [sip.RS_CHALLENGED] = sip.RE_AUTH,   -- the authenticated retry
    }
    local function feed_sent_register(sub, dereg)
        local ev = REG_SEND_EV[sub.reg:state()]
        if not ev and sub.reg:registered() then
            ev = dereg and sip.RE_DEREGISTER or sip.RE_REFRESH
        end
        -- Anything else (a REGISTER already in flight) is a retransmission and
        -- moves no machine — exactly what Registration::send() does with it.
        if ev then pcall(function() sub.reg:event(ev) end) end
        pcall(function() sub.auth:event(sip.AE_SEND) end)
        -- Each REGISTER is its own transaction (§17.1.2): re-arm, then send.
        pcall(function() sub.txn:restart():event(sip.TE_SEND_REQUEST) end)
    end

    -- forward declarations for the mutually-referring phase steps
    local begin_registration, on_sip_readable, handle_sip, on_401, on_registered
    local begin_teardown, begin_deregister, del_done
    local dispatch_sip, begin_calls, after_calls, call_request, call_response
    local begin_sms, after_sms, sms_request, sms_response
    local begin_regev, after_regev, regev_request, regev_response

    -- A subscriber reached a terminal state; when the last one does, wait a
    -- little for late Create Bearer Requests, then stop the loop.
    local function finish(sub)
        if sub.done then return end
        sub.done = true
        disarm(sub)
        pending = pending - 1
        if pending > 0 then return end
        if grace then return end
        -- All subscribers terminal: wait briefly for late Create Bearer Requests,
        -- then subscribe to the reg event and place the calls; when they settle,
        -- release the IMS registrations (de-REGISTER, so the P-CSCF reaps their
        -- ESP SAs) and tear the PDN connections down (Delete Session).
        --
        -- The subscription goes first because that is the order a UE does it in
        -- (TS 24.229 §5.1.1.3, at the 200 OK) and because its NOTIFY is a
        -- terminating request: if it does not arrive, the MT INVITE that follows
        -- has the same problem and this phase has already named it.
        grace = loop:after(3000, function()
            grace = nil
            if REGEV.on then begin_regev() else after_regev() end
        end)
    end
    after_regev = function()
        if CALL.on then begin_calls() else after_calls() end
    end
    after_calls = function()
        if SMS.on then begin_sms() else after_sms() end
    end
    after_sms = function()
        if DEREG then begin_deregister() else begin_teardown() end
    end
    local function fail(sub, msg)
        sub.err = msg
        sub.fail_stage = sub.stage       -- snapshot the stage reached at give-up
        slog(sub, "result", "FAILED: " .. msg)
        finish(sub)
    end
    local function succeed(sub, m)
        sub.registered = true
        sub.stage = "done"
        stats.regs = stats.regs + 1; stats.reg_last = now()
        -- Capture the Service-Route here, at the one message that carries it:
        -- the call phase cannot originate without it (see service_route()). No
        -- fallback is invented when it is absent — an INVITE with a guessed
        -- Route would fail as "mis-routed by the core" and hide the real cause.
        sub.svc_route = service_route(m)
        if VERBOSE then
            slog(sub, "Service-Route", #sub.svc_route > 0
                and table.concat(sub.svc_route, " ")
                or  "absent -- this subscriber cannot originate a call")
        end
        -- Captured at the same message and for the same reason: it is the one
        -- place the network says which identities this registration owns, and
        -- the reg-event phase has nothing to compare a reg-info document
        -- against without it.
        sub.assoc = associated_uris(m)
        if VERBOSE then
            slog(sub, "P-Associated-URI", #sub.assoc > 0
                and table.concat(sub.assoc, " ")
                or  "absent -- the registered IMPU is all this UE is known by")
        end
        slog(sub, "result", ("registered at P-CSCF %s"):format(sub.pcscf or "?"))
        finish(sub)
    end

    -- One Delete Session transaction resolved (response, timeout or send failure);
    -- when the last one settles, stop the loop.
    del_done = function(sub, ok, note)
        if sub.deleted then return end
        sub.deleted, sub.del_ok = true, ok and true or false
        if note then slog(sub, "Delete Session", note) end
        dpending = dpending - 1
        if dpending <= 0 then
            if tguard then loop:cancel(tguard); tguard = nil end
            loop:stop()
        end
    end

    -- Release the IMS registrations before dropping the bearers. Each registered
    -- UE sends one protected REGISTER with Expires:0 over its established ESP SA
    -- (Security-Verify + the same Authorization as the successful REGISTER; the
    -- S-CSCF de-registers an already-registered IMPU with Expires:0 without a
    -- fresh challenge). This drives the P-CSCF's explicit contact-removal path,
    -- which destroys the ESP SAs — unlike contact expiry, which it does not reap.
    -- Fire-and-forget (we don't await the 200), then give it a moment before the
    -- bearers go away so the de-REGISTERs actually egress and get processed.
    begin_deregister = function()
        local dr = {}
        for _, s in ipairs(subs) do
            if s.registered and s.sock and s.ch and s.authz then dr[#dr + 1] = s end
        end
        if #dr == 0 then return begin_teardown() end
        banner(("De-REGISTER — releasing %d registration(s) so the P-CSCF reaps their IPsec SAs"):format(#dr))
        for _, s in ipairs(dr) do
            s.cseq = s.cseq + 1
            local protected = s.ch.ss_raw and s.ch.p_spi_s and s.ch.p_port_s
            local dport = protected and s.ch.p_port_s or PCSCF_SIP_PORT
            local wire = build_register(s, s.authz,
                                        protected and "Security-Verify" or nil, s.ch.ss_raw, 0)
            feed_sent_register(s, true)   -- REGISTERED -> DEREGISTERING
            local ok, err = pcall(function() s.sock:sendto(wire, s.pcscf, dport) end)
            if ok then stats.tx = stats.tx + 1; mark_pkt() end
            slog(s, "-> de-REGISTER", ok
                and ("Expires:0 -> %s:%d (release SAs)"):format(s.pcscf, dport)
                or  ("send failed: " .. why(err)))
        end
        loop:after(1500, begin_teardown)
    end

    -- Teardown: send a Delete Session Request for every established PDN connection
    -- and wait for the responses (T3/N3 retransmission), so the PGW/SMF frees each
    -- session-pool entry instead of leaking it until timeout. Ramped like the attach.
    begin_teardown = function()
        local del = {}
        for _, s in ipairs(subs) do
            -- Skip a PDN connection the network already told us it released
            -- (Delete Bearer with a linked EBI): asking again only earns a
            -- "context not found" and muddies the teardown tally.
            if s.sess and s.pgw_ctrl_teid and not s.pdn_gone then del[#del + 1] = s end
        end
        if #del == 0 then return loop:stop() end
        banner(("Delete Session Requests — tearing down %d PDN connection(s)"):format(#del))
        dpending = #del
        -- overall deadline so a lost response cannot hang teardown forever
        tguard = loop:after(#del + T3_MS * N3 + 2000,
                            function() tguard = nil; loop:stop() end)
        for i, s in ipairs(del) do
            local dok, derr = pcall(function() s.sess:delete_session() end)
            if dok then
                slog(s, "-> Delete Session Req", ("linked EBI -> PGW ctrl TEID %#x"):format(s.pgw_ctrl_teid))
            else
                del_done(s, false, "send failed: " .. why(derr))
            end
        end
    end

    -- Steer a subscriber's SIP onto its default bearer with two TFTs (UDP for
    -- the plain REGISTER, ESP for the protected one). ue_saddr = the UE's PAA
    -- is the inner-source match that keeps concurrent subscribers registering
    -- to the one P-CSCF on their own bearers; add_filter also installs the
    -- shared decap entry so the 401/200 return down this bearer.
    local function program_filter(sub, tun)
        sub.sig_teid    = tun.local_teid
        sub.remote_addr = tun.remote_addr
        -- Kept whole, not just the TEID: media filters need the same bearer
        -- fields, and this is the fallback when no dedicated bearer shows up.
        sub.def_bearer  = { ebi = tun.ebi, local_teid = tun.local_teid,
                            remote_teid = tun.remote_teid,
                            remote_addr = tun.remote_addr }
        if not up then return end
        if not (sub.pcscf and tun.remote_addr and tun.remote_addr ~= "") then
            slog(sub, "GTP-U filter", "not programmed (missing P-CSCF/peer address)")
            return
        end
        local function add_tft(proto, ue_port, label)
            local t = gtp.Tunnel()
            t.local_teid, t.remote_teid = tun.local_teid, tun.remote_teid
            t.ebi, t.ue_addr, t.remote_addr = tun.ebi, sub.pcscf, tun.remote_addr
            local f = gtp.TrafficFilter()
            f.tunnel, f.proto, f.ue_port = t, proto, ue_port
            f.ue_saddr = sub.ue_addr                 -- inner source = this UE (concurrency key)
            local pok, perr = pcall(function() up:add_filter(f) end)
            slog(sub, "GTP-U filter", pok
                and ("EBI %d %s  TEID %#x/%#x @ %s  proto %d src %s -> %s%s")
                    :format(tun.ebi, label, tun.local_teid, tun.remote_teid, tun.remote_addr,
                            proto, sub.ue_addr, sub.pcscf, ue_port > 0 and (":" .. ue_port) or "")
                or  ("EBI %d %s add_filter failed: %s"):format(tun.ebi, label, why(perr)))
        end
        add_tft(IPPROTO_UDP, PCSCF_SIP_PORT, "SIP")  -- unprotected REGISTER
        add_tft(IPPROTO_ESP, 0,              "ESP")  -- protected traffic
    end

    -- Make the UE PAA locally deliverable (net.addr_add adds <PAA>/32 to lo,
    -- RTNETLINK) so the decapped downlink whose inner dst is the PAA reaches
    -- the transparent UE socket. Best-effort, only with the datapath up.
    local function add_paa_route(sub)
        if not (up and sub.ue_addr and sub.ue_addr:match("^%d+%.%d+%.%d+%.%d+$")) then return end
        local ok, err = pcall(function() net.addr_add("lo", sub.ue_addr, 32) end)
        sub.paa_added = ok
        slog(sub, "PAA local route", ok
            and ("%s/32 dev lo"):format(sub.ue_addr)
            or  ("could not add %s/32 (need CAP_NET_ADMIN?): %s"):format(sub.ue_addr, why(err)))
    end

    -- ---- the uplink size budget: the route MTU toward the P-CSCF ----
    --
    -- The other half of the sum the "downlink size budget" comment above
    -- describes, seen from this end. A UE's signalling rides transport-mode
    -- ESP to the P-CSCF and the datapath then adds 36 bytes of GTP-U at TC
    -- egress — where nothing can fragment, because a TC program cannot split
    -- a packet. So a datagram that fits the 1500-byte link before
    -- encapsulation and not after is dropped there, and the only trace of it
    -- is one number in this run's own summary ("datapath drops ... no
    -- neighbour 2").
    --
    -- It lands on exactly one message: the 200 OK answering an MT INVITE,
    -- which carries the SDP answer plus the dialog's whole route set — 5
    -- Record-Route and 6 Via, since a call between two subscribers of one
    -- core crosses P-CSCF -> S-CSCF -> I-CSCF -> S-CSCF -> P-CSCF — so ~1470
    -- bytes of SIP, 1513 with UDP and the ESP overhead, 1549 encapsulated.
    -- The MO gets its 180 and then nothing, and the call is reported as
    -- failed after ringing with the answer never on the wire.
    --
    -- The fix is to make the kernel fragment *before* the hook: the route to
    -- the P-CSCF carries the MTU that is actually available, so the ESP
    -- datagram leaves as two G-PDUs that both fit and the P-CSCF reassembles
    -- them. Only that route is touched — the interface MTU has to stay 1500,
    -- since the encapsulated packets themselves go out at up to that size.
    --
    -- One /32 per P-CSCF, installed once and removed at teardown (the less
    -- specific route it shadows is left in place, so this adds and removes a
    -- route rather than rewriting the container's routing). The dev is
    -- $GTPU_INNER_IFACE, not $GTPU_IFACE: encap attaches to the *inner*
    -- interface's TC egress (gtpu_ebpf_attach), so that is the path a UE
    -- packet has to take to be encapsulated at all, and the only one whose
    -- MTU decides whether it survives. The two are the same interface on a
    -- single-NIC deployment. Only with the datapath up: without GTP-U there
    -- is no encapsulation to make room for and the interface MTU is already
    -- the truth.
    --
    -- Attempted (so a refusal is reported once, not once per subscriber) and
    -- installed (what teardown removes) are separate: 400 subscribers share
    -- one P-CSCF and one route.
    local mtu_routes, mtu_tried = {}, {}
    local function set_pcscf_mtu(sub)
        if not (up and inner_mtu > 0 and sub.pcscf) then return end
        if mtu_tried[sub.pcscf] then return end
        mtu_tried[sub.pcscf] = true
        local r = net.Route()
        r.dst, r.prefixlen, r.dev, r.mtu = sub.pcscf, 32, inner_name, inner_mtu
        local ok, err = pcall(function() net.route_add(r) end)
        if ok then mtu_routes[sub.pcscf] = r end
        line("P-CSCF route MTU", ok
            and ("%s/32 dev %s mtu %d (GTP-U leaves 1500-36)"):format(sub.pcscf, inner_name, inner_mtu)
            or  ("could not set %d toward %s (need CAP_NET_ADMIN?): %s — an answered call's 200 OK will not fit")
                :format(inner_mtu, sub.pcscf, why(err)))
    end

    -- Confirm a downlink reply arrived through the decap entry.
    local function report_rx(sub, what)
        if not (up and sub.sig_teid and sub.rx0) then return end
        local drx = up:stats(sub.sig_teid).rx_pkts - sub.rx0.rx_pkts
        if drx > 0 then
            slog(sub, "GTP-U decap", ("%s via downlink (rx +%d on TEID %#x)"):format(what, drx, sub.sig_teid))
        end
    end

    -- ---- media steering: TFTs learnt from the SDP, per call ----
    --
    -- rtpengine's address and port are only known once the SDP has been
    -- rewritten and come back, so media filters are late-bound per call — they
    -- cannot be pre-programmed at attach the way the SIP ones are. Two per UE
    -- (RTP, and RTCP on the next port), each carrying the UE's own PAA as the
    -- inner-source match: that is what keeps many UEs talking to the ONE
    -- rtpengine on their own bearers, exactly as it does for the one P-CSCF.
    local function apply_media_tfts(sub, op, only)
        if not (up and sub.media_tft) then return end
        for _, t in ipairs(sub.media_tft.tuples) do
            local bearer = t.bearer
            if bearer and (only == nil or only == t.follows_media) then
                local tun = gtp.Tunnel()
                tun.local_teid, tun.remote_teid = bearer.local_teid, bearer.remote_teid
                tun.ebi, tun.ue_addr, tun.remote_addr = bearer.ebi, t.addr, bearer.remote_addr
                local f = gtp.TrafficFilter()
                f.tunnel, f.proto, f.ue_port = tun, t.proto, t.port
                f.ue_saddr = sub.ue_addr
                local pok, perr = pcall(function()
                    if op == "del" then up:del_filter(f) else up:add_filter(f) end
                end)
                -- A failed delete is expected and harmless: several filters
                -- share one bearer's decap entry, and removing the first takes
                -- that entry with it, so the rest have nothing left to unhook.
                if not pok and op ~= "del" and VERBOSE then
                    slog(sub, "media filter", ("%s %s %s:%d failed: %s")
                        :format(op, t.label, t.addr, t.port, why(perr)))
                end
            end
        end
    end

    -- Which bearer media rides. "auto" prefers the dedicated bearer the Create
    -- Bearer Request brought, since that is what the Rx->Gx->Create Bearer
    -- chain exists for; "default" forces the default bearer, which is worth
    -- having because a UPF whose dedicated-bearer uplink PDR carries an SDF
    -- filter that does not match our negotiated 5-tuple drops the uplink.
    local function media_bearer(sub)
        if CALL.bearer ~= "default" and sub.ded_bearer and not sub.ded_released then
            return sub.ded_bearer, "dedicated"
        end
        return sub.def_bearer, "default"
    end

    local function program_media_tfts(sub, addr, port)
        if not (up and addr and port and port > 0) then return end
        local bearer, kind = media_bearer(sub)
        if not bearer then return end
        local rtcp_on_media = MEDIA.rtcp_bearer == "media"
        local rtcp_bearer   = rtcp_on_media and bearer or sub.def_bearer
        sub.media_tft = { kind = kind, tuples = {
            { proto = IPPROTO_UDP, addr = addr, port = port, label = "RTP",
              bearer = bearer, follows_media = true },
            { proto = IPPROTO_UDP, addr = addr, port = port + 1, label = "RTCP",
              bearer = rtcp_bearer, follows_media = rtcp_on_media },
        } }
        apply_media_tfts(sub, "add")
        slog(sub, "media on bearer", ("%s (EBI %d, TEID %#x) -> %s:%d, RTCP on the %s bearer")
            :format(kind, bearer.ebi or 0, bearer.local_teid or 0, addr, port,
                    rtcp_on_media and kind or "default"))
    end

    -- The Create Bearer Request and the SDP answer race. If the bearer is
    -- known when the media 5-tuple is learnt, the filters go straight onto it;
    -- otherwise they went onto the default bearer and are re-homed here. Which
    -- bearer each call's media actually landed on is reported either way —
    -- "media on the default bearer" is a legitimate finding, not something to
    -- hide.
    local function rehome_media(sub)
        if not (up and sub.media_tft and sub.ded_bearer) then return end
        if CALL.bearer == "default" or sub.ded_released then return end
        local cur
        for _, t in ipairs(sub.media_tft.tuples) do
            if t.follows_media then cur = t.bearer break end
        end
        if not cur or cur.local_teid == sub.ded_bearer.local_teid then return end
        apply_media_tfts(sub, "del", true)
        for _, t in ipairs(sub.media_tft.tuples) do
            if t.follows_media then t.bearer = sub.ded_bearer end
        end
        sub.media_tft.kind = "dedicated (re-homed)"
        apply_media_tfts(sub, "add", true)
        slog(sub, "media re-homed", ("onto the dedicated bearer (EBI %d, TEID %#x)")
            :format(sub.ded_bearer.ebi or 0, sub.ded_bearer.local_teid or 0))
    end

    -- ---- media: one rtp.Stream per leg, on the shared loop ----
    --
    -- Sourced from the UE's PAA with a non-local bind (IP_FREEBIND +
    -- IP_TRANSPARENT), like the SIP socket: the RTP that leaves must carry the
    -- address the SDP advertises, or the UPF drops it as spoofed.
    local function open_media(c, sub, role)
        local ok, s = pcall(rtp.Stream, loop, sub.ue_addr, sub.media_port, true)
        if not ok then
            slog(sub, "media session", ("cannot bind %s:%d: %s")
                :format(sub.ue_addr, sub.media_port, why(s)))
            return nil, nil
        end
        local st = { role = role, rx = 0, tx = 0, tx_err = 0, first = nil, last = nil,
                     early = 0, late = 0, reports = 0, ul_lost = nil, ul_jitter = {} }
        pcall(function()
            s:set_payload_type(MEDIA.pt)
            s:set_clock_rate(MEDIA.rate)
            s:set_rtcp_interval(MEDIA.rtcp_ms)
            s:set_cname(sub.impu)
        end)
        -- Report blocks the peer wrote about US are the only measurement of our
        -- uplink there is; they arrive on either an SR (rtpengine sends media,
        -- so it sends SRs) or an RR, so both paths feed the same collector.
        local function note(reports)
            st.reports = st.reports + 1
            for _, r in ipairs(reports) do
                if r.ssrc == s:ssrc() then
                    st.ul_lost = r.packets_lost
                    st.ul_frac = r.fraction_lost
                    st.ul_jitter[#st.ul_jitter + 1] = r.jitter / (MEDIA.rate / 1000)
                end
            end
        end
        s:set_handler({
            on_rtp = function()
                local t = now()
                st.rx = st.rx + 1
                st.first = st.first or t
                st.last  = t
                -- Media cut-through is measured at the originating side: the
                -- first packet the caller actually hears (t8 - t6).
                if role == "mo" and not c.t.t8 then c.t.t8 = t end
                -- Media before the answer is early/leaked media; media after
                -- our BYE is rtpengine teardown lag. Both are counted rather
                -- than folded into the loss figures.
                if not c.answered_at then st.early = st.early + 1 end
                if c.released_at then st.late = st.late + 1 end
            end,
            on_sender_report   = function(_, _, reports) note(reports) end,
            on_receiver_report = function(_, reports) note(reports) end,
        })
        return s, st
    end

    -- A send that fails is recorded, not swallowed: "no RTP arrived" and "the
    -- kernel refused every send" look identical in the receive statistics, and
    -- only one of them is a network problem.
    local function media_send(c, s, st)
        if not (s and st) then return end
        local ok, err = pcall(function() s:send(MEDIA.payload, MEDIA.samples) end)
        if ok then st.tx = (st.tx or 0) + 1 else
            st.tx_err = (st.tx_err or 0) + 1
            st.tx_why = st.tx_why or why(err)
        end
    end

    local function media_tick(c)
        c.media_timer = nil
        if c.media_stop then return end
        if c.mo_ready then media_send(c, c.sess_mo, c.mstat_mo) end
        if c.mt_ready then media_send(c, c.sess_mt, c.mstat_mt) end
        c.media_timer = loop:after(MEDIA.ptime_ms, function() media_tick(c) end)
    end

    -- One timer per call, not per stream: it feeds both directions, which
    -- halves the timer churn on the loop that also has to measure itself.
    local function start_media(c)
        if c.media_timer or c.media_stop then return end
        if not (c.sess_mo or c.sess_mt) then return end
        media_tick(c)
    end

    -- Stop sending and tell the peer (RTCP BYE, so rtpengine releases its ports
    -- rather than holding them for its 60 s timeout). The sessions stay open:
    -- packets still arriving are the late-media count.
    local function stop_media(c)
        c.media_stop = true
        if c.media_timer then loop:cancel(c.media_timer); c.media_timer = nil end
        if c.sess_mo then pcall(function() c.sess_mo:bye("call cleared") end) end
        if c.sess_mt then pcall(function() c.sess_mt:bye("call cleared") end) end
    end

    -- ---- call lifecycle ----

    -- Identifiers are kept SHORT on purpose, and it is not cosmetic: see the
    -- note on the downlink size budget above build_in_dialog(). Uniqueness is
    -- still guaranteed — the call index is unique within the run and the UE
    -- address within the pool, and every message of the call carries both.
    local function make_call(n, mo, mt, with_media)
        local c = {
            n = n, mo = mo, mt = mt, media = with_media, cseq = 1,
            call_id  = ("c%d@%s"):format(n, mo.ue_addr),
            from_tag = ("o%d"):format(n),
            to_tag   = ("t%d"):format(n),
            branch   = ("z9hG4bK%d"):format(n),
            -- The dialog and transaction machines the sip module already
            -- carries: fed the traffic and read back for state, so the call
            -- phase has no hand-rolled state variable either.
            dlg_mo = sip.Dialog(), dlg_mt = sip.Dialog(),
            txn_mo = sip.Transaction(sip.INVITE_CLIENT),
            txn_mt = sip.Transaction(sip.INVITE_SERVER),
            route_mo = {}, route_mt = {},
            t = {}, stage = "invite",
        }
        -- From identifies the caller (its registered IMPU); To is the address
        -- dialled, which by default is the callee's number and not an identity
        -- this process ever registered. The far end matches the call on the
        -- Call-ID, so it does not have to recognise the form.
        c.callee   = mt.dial
        c.from_hdr = ("<%s>;tag=%s"):format(mo.impu, c.from_tag)
        c.to_hdr   = ("<%s>"):format(c.callee)
        return c
    end

    local function carm(c, ms, fn)
        if c.timer then loop:cancel(c.timer) end
        c.timer = loop:after(ms, function() c.timer = nil; fn() end)
    end

    -- The MO always talks from its protected client port to the P-CSCF's
    -- protected SERVER port (the pair the outbound ESP policy covers, and the
    -- one usrloc has for the contact). The MT answers from its protected
    -- SERVER port to the P-CSCF's protected CLIENT port — the reverse tunnel
    -- the P-CSCF's ipsec_forward() delivers terminating requests through.
    local function pcscf_port(sub, role)
        local ch = sub.ch
        if not (ch and ch.ss_raw) then return PCSCF_SIP_PORT end
        if role == "mt" then return ch.p_port_c or PCSCF_SIP_PORT end
        return ch.p_port_s or PCSCF_SIP_PORT
    end

    local function send_call(sub, sock, role, wire, what)
        local port = pcscf_port(sub, role)
        dump(("[%d] -> %s"):format(sub.i, what), wire)
        local ok, err = pcall(function() sock:sendto(wire, sub.pcscf, port) end)
        if ok then
            stats.tx = stats.tx + 1; mark_pkt()
            if VERBOSE then
                slog(sub, "-> " .. what, ("%dB -> %s:%d"):format(#wire, sub.pcscf, port))
            end
        else
            slog(sub, "-> " .. what, "send failed: " .. why(err))
        end
        return ok
    end

    -- Setup-time KPIs from the marks. Every figure is a difference of two
    -- readings of ONE monotonic clock taken in this process, so the one-way
    -- transit figures carry no clock skew — that is the whole point of putting
    -- both UEs in one process, and nothing else in the setup can measure them.
    local function record_kpis(c)
        local t, k = c.t, cstats.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.pdd,        "t0", "t4")   -- post-dial delay: what a user hears as ringing
        push(k.sst,        "t0", "t6")   -- session setup time: the headline number
        push(k.mo_transit, "t0", "t2")   -- MO -> MT through the core, one way
        push(k.mt_transit, "t3", "t4")   -- the return path, independently
        push(k.answer,     "t5", "t6")   -- the 200 OK path, independently
        push(k.cut,        "t6", "t8")   -- media cut-through: answer to audio
        push(k.release,    "t9", "t10")  -- BYE round trip
        -- SST with our own deliberate ring hold removed, so CALL.answer_ms does
        -- not sit inside the headline figure.
        if t.t0 and t.t6 and t.t3 and t.t5 then
            k.sst_net[#k.sst_net + 1] = (t.t6 - t.t0) - (t.t5 - t.t3)
        end
    end

    local function call_finish(c)
        if c.done then return end
        c.done = true
        if c.timer then loop:cancel(c.timer); c.timer = nil end
        stop_media(c)
        record_kpis(c)
        cpending = cpending - 1
        if cpending <= 0 then
            if cguard then loop:cancel(cguard); cguard = nil end
            after_calls()
        end
    end

    -- A failed call is attributed to the stage it died at — invite, ringing,
    -- answered, media or release — exactly as a failed registration is.
    local function call_fail(c, msg, status)
        if c.done then return end
        -- Name the cause when the stack's protected-port sharing explains it
        -- (see begin_calls), instead of filing another "no ringing".
        if c.port_clash and c.stage == "invite" then
            msg = msg .. " (P-CSCF protected port shared with the caller)"
        end
        c.err, c.fail_stage = msg, c.stage
        if status then cstats.by_status[status] = (cstats.by_status[status] or 0) + 1 end
        local t = cstats.stage[c.stage]
        if not t then t = { n = 0, reasons = {} }; cstats.stage[c.stage] = t end
        t.n = t.n + 1
        t.reasons[msg] = (t.reasons[msg] or 0) + 1
        slog(c.mo, "call", ("%d FAILED at %s: %s"):format(c.n, c.stage, msg))
        call_finish(c)
    end

    -- MO: the far end answered. Learn the dialog's remote target, route set and
    -- To (with the tag the answer settled), point our media at whatever the
    -- rewritten SDP says, ACK, and hold the call up for CALL.hold_ms.
    local function on_answered(c, m)
        c.t.t6 = now()
        c.answered_at = c.t.t6
        c.stage = "answered"
        cstats.answered = cstats.answered + 1
        cstats.last_answer = c.t.t6
        c.to_hdr  = m:header("To")
        c.target  = contact_uri(m) or c.callee
        c.route_mo = route_set(m, true)

        if c.media and c.sess_mo then
            -- s.addr is the resolved one: rtpengine emits a session-level c=
            -- AND a media-level c=, and the media one is the relay (RFC 8866
            -- §5.7). The sdp module applies that rule, so this reads one
            -- field; s:rejected() is the port-0 case (RFC 3264 §6).
            local okp, a = pcall(sdp.parse, m.body)
            local s = okp and a:has_audio() and a:audio() or nil
            if s and not s:rejected() and s.addr ~= "" then
                program_media_tfts(c.mo, s.addr, s.port)
                local sok = pcall(function() c.sess_mo:set_peer(s.addr, s.port) end)
                c.mo_ready = sok
                if VERBOSE then
                    slog(c.mo, "media peer", ("%s:%d (pt %s)"):format(s.addr, s.port,
                        s:pt_count() > 0 and tostring(s:pt_at(0)) or "-"))
                end
            else
                slog(c.mo, "media", okp and "answer carries no usable audio stream"
                                        or ("cannot parse the answer SDP: " .. why(a)))
            end
        end

        local wire = build_in_dialog(c, sip.ACK, "ACK", c.cseq, c.branch .. "-ack", c.route_mo)
        c.t.t7 = now()
        send_call(c.mo, c.mo.sock, "mo", wire, "ACK")
        start_media(c)

        c.stage = "media"
        carm(c, CALL.hold_ms, function()
            -- Always BYE: rtpengine holds a port pair per call for its 60 s
            -- timeout, so a run that walks away from calls exhausts its
            -- 30000-40000 range instead of failing anything visibly.
            c.stage = "release"
            c.t.t9  = now()
            c.released_at = c.t.t9
            stop_media(c)
            local bye = build_in_dialog(c, sip.BYE, "BYE", c.cseq + 1,
                                        c.branch .. "-bye", c.route_mo)
            feed_ev(c.dlg_mo, sip.DE_TERMINATE)
            send_call(c.mo, c.mo.sock, "mo", bye, "BYE")
            carm(c, CALL.t_ms, function()
                -- No 200 to our BYE: released as far as we are concerned, but
                -- recorded as such rather than as an answered-and-released call.
                slog(c.mo, "call", ("%d no 200 to the BYE"):format(c.n))
                call_finish(c)
            end)
        end)
    end

    -- MT: answer the INVITE we are holding, with the SDP answer.
    local function send_answer(c)
        if c.done or not c.mt_req then return end
        local mt = c.mt
        local body = sdp.offer{ addr = mt.ue_addr, port = mt.media_port,
                                pt = c.mt_pt or MEDIA.pt,
                                codec = c.mt_codec or MEDIA.codec,
                                rate = c.mt_rate or MEDIA.rate,
                                ptime = MEDIA.ptime_ms }
        local wire = build_response(c, mt, c.mt_req, 200, "OK", body)
        -- The 2xx ends the INVITE server transaction (§17.2.1); the ACK that
        -- follows is a transaction of its own, which is why call_request feeds
        -- it through feed_msg rather than into this machine.
        feed_ev(c.txn_mt, sip.TE_SEND_2XX)
        feed_ev(c.dlg_mt, sip.DE_CONFIRM)
        c.t.t5 = now()
        send_call(mt, mt.sock, "mt", wire, "200 OK (answer)")
        -- A UE starts sending as it answers; the MO starts at its ACK, so
        -- t8 - t6 measures answer-to-audio across the relay, not our own delay.
        c.mt_ready = c.sess_mt ~= nil
        start_media(c)
    end

    -- MT: an INVITE arrived on the protected server port.
    local function on_invite(sub, c, m)
        c.t.t2 = now()
        c.stage = "ringing"
        feed_msg(c.txn_mt, m)
        feed_msg(c.dlg_mt, m)
        c.mt_req   = m                    -- what the responses must echo back
        c.route_mt = route_set(m, false)

        if c.media and c.sess_mt then
            local okp, o = pcall(sdp.parse, m.body)
            local s = okp and o:has_audio() and o:audio() or nil
            if s and not s:rejected() and s.addr ~= "" then
                c.mt_pt, c.mt_codec, c.mt_rate = answer_pt(s)
                program_media_tfts(sub, s.addr, s.port)
                c.mt_ready = false        -- armed at the answer
                local sok = pcall(function() c.sess_mt:set_peer(s.addr, s.port) end)
                if not sok then slog(sub, "media", "cannot point the session at the offer") end
                if VERBOSE then
                    slog(sub, "media peer", ("%s:%d (pt %d %s/%d)")
                        :format(s.addr, s.port, c.mt_pt, c.mt_codec, c.mt_rate))
                end
            else
                slog(sub, "media", okp and "offer carries no usable audio stream"
                                       or ("cannot parse the offer SDP: " .. why(o)))
            end
        end

        -- 180 now (that is what the MO's post-dial delay measures), 200 OK
        -- after the deliberate ring hold.
        local ring = build_response(c, sub, m, 180, "Ringing")
        feed_ev(c.txn_mt, sip.TE_SEND_1XX)
        feed_ev(c.dlg_mt, sip.DE_EARLY)
        c.t.t3 = now()
        send_call(sub, sub.sock, "mt", ring, "180 Ringing")
        loop:after(CALL.answer_ms, function() send_answer(c) end)
    end

    -- Incoming requests: the MT INVITE and its ACK, plus a BYE from whichever
    -- end releases first. Both arrive on the protected server port.
    call_request = function(sub, m, which)
        local c = by_callid[m:call_id()]
        if m.method == sip.INVITE then
            if not c then
                return slog(sub, "call", "INVITE for an unknown Call-ID; ignored")
            end
            if c.t.t2 then return end            -- retransmission; already ringing
            return on_invite(sub, c, m)
        elseif m.method == sip.ACK then
            -- Absorbed by the transaction only when a non-2xx final left one
            -- alive (Completed -ACK-> Confirmed). After a 2xx there is nothing
            -- to absorb it — see feed_msg.
            if c then feed_msg(c.txn_mt, m) end
            return
        elseif m.method == sip.BYE then
            -- Answer it whoever we are; then this call is over for us.
            -- Answer from this UE's protected port, back to whichever P-CSCF
            -- port the request came from: a BYE we receive is terminating for
            -- us, so it came from the P-CSCF's protected client port.
            local sock = sub.sock
            local role = (c and sub == c.mt) and "mt" or "mt"
            local wire = build_response(c or { to_tag = "x", mt = sub }, sub, m, 200, "OK")
            send_call(sub, sock, role, wire, "200 OK (BYE)")
            if c and not c.done then
                feed_msg(sub == c.mt and c.dlg_mt or c.dlg_mo, m)
                if not c.released_at then c.released_at = now() end
                cstats.released = cstats.released + 1
                stop_media(c)
                call_finish(c)
            end
            return
        elseif m.method == sip.CANCEL then
            if c then call_fail(c, "cancelled by the network", nil) end
            return
        elseif m.method == sip.MESSAGE then
            -- A MESSAGE creates no dialog (RFC 3428 §4), so there is no
            -- Call-ID to match it against: the SMS layer sorts it out from
            -- the RPDU in the body.
            return sms_request(sub, m, which)
        elseif m.method == sip.NOTIFY then
            -- The reg event package: this UE's own registration state, inside
            -- the dialog its SUBSCRIBE opened — so it IS matched by Call-ID,
            -- just not against a call.
            return regev_request(sub, m)
        end
        if VERBOSE then
            slog(sub, "call", ("ignoring in-dialog %s"):format(m.method_name))
        end
    end

    -- Responses to what the MO sent: the INVITE's provisionals and final, and
    -- the 200 to our BYE.
    call_response = function(sub, m)
        local c = by_callid[m:call_id()]
        if not c then
            -- Never drop SIP silently: a response for a Call-ID we do not know
            -- is either a stray retransmission or a real bug, and telling the
            -- two apart from the outside is impossible without saying so.
            if VERBOSE then
                slog(sub, "call", ("%d %s for an unknown Call-ID"):format(m.status, m.reason))
            end
            return
        end
        local okc, cs = pcall(function() return m:cseq() end)
        local meth = okc and cs.method or sip.M_UNKNOWN

        if meth == sip.BYE then
            if m.status >= 200 and not c.done then
                c.t.t10 = now()
                cstats.released = cstats.released + 1
                call_finish(c)
            end
            return
        end
        if meth ~= sip.INVITE or c.done then return end

        feed_msg(c.txn_mo, m)
        feed_msg(c.dlg_mo, m)

        if m.status == 100 then
            c.t.t1 = c.t.t1 or now()
            return
        elseif m.status > 100 and m.status < 200 then
            if not c.t.t4 then
                c.t.t4 = now()
                if VERBOSE then
                    slog(sub, "<- " .. tostring(m.status), ("%s (dialog %s)")
                        :format(m.reason, c.dlg_mo:state_name()))
                end
            end
            carm(c, CALL.t_ms, function() call_fail(c, "no final response after ringing") end)
            return
        elseif m.status >= 200 and m.status < 300 then
            if c.t.t6 then return end            -- 200 retransmission
            return on_answered(c, m)
        end

        -- Any other final: ACK it (the ACK for a non-2xx belongs to the INVITE
        -- transaction, so it reuses its branch and needs no route set) and
        -- record where the network said no.
        c.to_hdr = m:header("To")
        local ack = build_in_dialog(c, sip.ACK, "ACK", c.cseq, c.branch, nil)
        send_call(c.mo, c.mo.sock, "mo", ack, "ACK (non-2xx)")
        call_fail(c, ("%d %s"):format(m.status, m.reason), m.status)
    end

    -- One socket carries both phases, so the CSeq method says which layer owns
    -- an inbound message: registration responses go to the registration
    -- machines, everything else to the call layer. No phase flag, and the call
    -- code needs no second socket set.
    dispatch_sip = function(sub, m, which)
        if VERBOSE then
            slog(sub, "<- SIP on " .. which, m.request
                and ("%s %s"):format(m.method_name, m.uri)
                or  ("%d %s"):format(m.status, m.reason))
        end
        if m.request then return call_request(sub, m, which) end
        local okc, cs = pcall(function() return m:cseq() end)
        if okc and cs.method == sip.REGISTER then return handle_sip(sub, m) end
        if okc and cs.method == sip.MESSAGE then return sms_response(sub, m) end
        if okc and cs.method == sip.SUBSCRIBE then return regev_response(sub, m) end
        return call_response(sub, m)
    end

    -- ---- the reg-event phase (RFC 3680, TS 24.229 §5.1.1.3) --------------
    --
    -- One subscription per registered UE, to its own registration state, with
    -- every hop timed:
    --
    --   t0  SUBSCRIBE   to its own IMPU, through the Service-Route
    --   t1  200 OK      the S-CSCF accepted the subscription
    --   t2  NOTIFY      the reg-info document: the state the network holds
    --   t3  200 OK      our answer to it (RFC 6665 §4.4.1 — a notifier that
    --                   gets none tears the subscription down again)
    --
    -- t0 and t2 are readings of ONE monotonic clock in this process, so t2-t0
    -- is a true one-way figure, exactly as the call and SMS phases' transit
    -- figures are.
    --
    -- The 200 OK and the NOTIFY race, and both orders happen: kamailio's
    -- ims_registrar_scscf sends the first NOTIFY from inside
    -- subscribe_to_reg(), so it can overtake the reply it was triggered by.
    -- Neither is treated as the other's precondition — the record settles when
    -- both are in, and the deadline names whichever is missing.

    -- One unit of outstanding work per subscription, plus the scheduler's own
    -- sentinel — see mdec() for why a spaced run needs it.
    local function udec()
        upending = upending - 1
        if upending > 0 then return end
        if uguard then loop:cancel(uguard); uguard = nil end
        after_regev()
    end

    -- A failed subscription is attributed to the hop it died at and to the
    -- reason within it, the way a failed call and a failed registration are —
    -- "no NOTIFY" and "a NOTIFY describing somebody else's registration" are
    -- both `reginfo` stage failures and nothing like the same fault.
    local function regev_finish(u, ok, stage, detail)
        if u.done then return end
        u.done = true
        if u.timer then loop:cancel(u.timer); u.timer = nil end
        -- regev_by_callid keeps its entry on purpose: the subscription lives
        -- on past the phase and its last NOTIFY arrives at de-registration.
        if not ok then
            local t = ustats.stage[stage or "unknown"]
            if not t then t = { n = 0, reasons = {} }; ustats.stage[stage or "unknown"] = t end
            t.n = t.n + 1
            sbump(t.reasons, detail or "unknown")
            slog(u.sub, "reg-event", ("subscription FAILED at %s: %s")
                :format(stage or "?", detail or "?"))
        end
        udec()
    end

    local function uarm(u)
        if u.timer then loop:cancel(u.timer) end
        u.timer = loop:after(REGEV.t_ms, function()
            u.timer = nil
            -- Name the furthest hop that DID happen: "the S-CSCF never took
            -- the subscription" and "it took it and never notified" are
            -- different faults with different fixes.
            local stage, detail
            if not u.t.t1 then stage, detail = "accept", "no 200 OK for the SUBSCRIBE"
            elseif not u.t.t2 then stage, detail = "notify", "subscribed, but no NOTIFY ever came"
            else stage, detail = "unknown", "both hops completed but the subscription never settled"
            end
            regev_finish(u, false, stage, detail)
        end)
    end

    local function regev_settle(u)
        if u.done or not (u.t.t1 and u.t.t2) then return end
        local t, k = u.t, ustats.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.accept, "t0", "t1")   -- SUBSCRIBE -> 200 OK
        push(k.notify, "t0", "t2")   -- SUBSCRIBE -> the state, one clock
        push(k.ack,    "t2", "t3")   -- our own turnaround on the NOTIFY
        ustats.last = t.t2
        regev_finish(u, true)
    end

    -- Everything a reg-info document has to say before the subscription
    -- counts: one of this UE's own identities is registered, and one of the
    -- contacts bound to it is the contact this UE registered. Anything less
    -- means the core is telling the UE a registration state that is not the
    -- one it is in — which is the whole reason to ask.
    --
    -- The dialled address is checked at the same time but never failed on: it
    -- is the call phase's precondition, not this one's, and reporting it here
    -- is what turns a later "404 for the number" from a mystery into a
    -- provisioning line that was visible before the first INVITE.
    local function check_reginfo(u, m)
        local sub = u.sub
        local ct  = m:header("Content-Type"):lower()
        if not ct:find("reginfo+xml", 1, true) then
            return false, ("NOTIFY body is %s, not application/reginfo+xml")
                :format(ct ~= "" and ct or "typeless")
        end
        local regs = REGEV.parse(m.body)
        if #regs == 0 then
            return false, ("reg-info carries no <registration> element (%d bytes)")
                :format(#m.body)
        end
        u.identities = #regs
        -- "This UE's own identity" is a SET, not the one URI it registered:
        -- the registered IMPU first, then everything the 200 OK associated
        -- with it. Without an ISIM the registered IMPU is the temporary,
        -- barred one and the network deliberately never names it in a
        -- reg-info document, so matching on it alone fails a core for being
        -- correct — which is the opposite of what this phase is for.
        --
        -- Only the matching moves. The SUBSCRIBE still goes to sub.impu and
        -- still asserts sub.impu, because that pairing is the one the S-CSCF
        -- can authorise: can_subscribe_to_reg() accepts the asserted identity
        -- either as the presentity's own AOR or as an *unbarred* entry in its
        -- service profile, and the temporary IMPU is neither of those for an
        -- associated presentity. Subscribing to the associated identity while
        -- asserting the registered one is a 403.
        local own = { sub.impu }
        for _, a in ipairs(sub.assoc or {}) do own[#own + 1] = a end
        local mine
        for _, id in ipairs(own) do
            for _, r in ipairs(regs) do
                if REGEV.same_id(r.aor, id) then mine = r; break end
            end
            if mine then break end
        end
        for _, r in ipairs(regs) do
            if REGEV.same_id(r.aor, sub.dial) and r.state == "active" then u.dialable = true end
        end
        if not mine then
            local names = {}
            for _, r in ipairs(regs) do names[#names + 1] = r.aor end
            return false, ("reg-info names %s, none of this UE's own identities (%s)")
                :format(#names > 0 and table.concat(names, ",") or "nothing",
                        table.concat(own, ","))
        end
        u.aor = mine.aor
        u.state = mine.state
        if mine.state ~= "active" then
            return false, ("reg-info says this identity is %q, not active"):format(mine.state)
        end
        -- The binding, matched on address:port rather than on the whole URI:
        -- the S-CSCF may hand back the contact with parameters of its own
        -- (received, expires, the +g.3gpp.smsip feature tag) and none of them
        -- change which socket the binding points at.
        local want = ("%s:%d"):format(sub.ue_addr, sub.port_uc)
        for _, c in ipairs(mine.contacts) do
            if c.uri:find(want, 1, true) then u.event = c.event; return true end
        end
        return false, ("this identity is registered, but to %d other contact(s), not %s")
            :format(#mine.contacts, want)
    end

    -- A NOTIFY arrived on a UE's socket: the network's view of that UE's own
    -- registration. Answer the SIP hop first, then read the body — a notifier
    -- that gets no 200 OK terminates the subscription, and a run that fails
    -- the body check would then also have broken the thing it was measuring.
    regev_request = function(sub, m)
        local u  = regev_by_callid[m:call_id()]
        local t2 = now()
        -- Answered even when it matches nothing we track: 481 would tell the
        -- S-CSCF to drop a subscription that is most likely ours (a NOTIFY
        -- that overtook its own 200 OK), and an unmatched one is counted
        -- below rather than turned into a teardown.
        send_call(sub, sub.sock, "mt",
                  build_response({ to_tag = (u and u.from_tag) or ("r%d"):format(sub.i) },
                                 sub, m, 200, "OK"),
                  "200 OK (NOTIFY)")
        local t3 = now()

        local ss    = m:header("Subscription-State"):lower()
        local state = ss:match("^%s*([%w%-]+)") or "?"
        if not u then
            ustats.orphans = ustats.orphans + 1
            return slog(sub, "reg-event",
                ("NOTIFY (%s) for a subscription this run does not track"):format(state))
        end
        sbump(ustats.states, state)

        -- A later state change on a subscription that has already been
        -- measured. At teardown this is the S-CSCF telling the UE its
        -- registration is gone — the half of the reg event that only a
        -- de-REGISTER exercises, and the one a UE actually needs.
        if u.done then
            if state == "terminated" then
                ustats.terminated = ustats.terminated + 1
                slog(sub, "reg-event", ("NOTIFY: subscription terminated (%s)")
                    :format(sip.auth_param(ss, "reason") ~= "" and sip.auth_param(ss, "reason")
                            or "no reason given"))
            else
                slog(sub, "reg-event", ("NOTIFY: %s (state change after the phase)"):format(state))
            end
            return
        end

        -- A NOTIFY we have already read: answered above (the notifier is
        -- retransmitting because it wants one), counted once. The S-CSCF may
        -- also send a legitimate second document before the phase settles —
        -- the first one is the measurement, so this is the same decision.
        if u.t.t2 then return end
        u.t.t2, u.t.t3 = t2, t3
        ustats.notified = ustats.notified + 1
        local okb, detail = check_reginfo(u, m)
        if not okb then return regev_finish(u, false, "reginfo", detail) end
        ustats.verified = ustats.verified + 1
        ustats.identities[#ustats.identities + 1] = u.identities
        if u.dialable then ustats.dialable = ustats.dialable + 1 end
        if VERBOSE then
            slog(sub, "reg-event", ("%s as %s, %d identity(ies), contact %s after %d ms")
                :format(u.state, u.aor ~= "" and u.aor or "?", u.identities,
                        u.event ~= "" and u.event or "bound", t2 - u.t.t0))
        end
        regev_settle(u)
    end

    -- The reply to the SUBSCRIBE. 200 and 202 both create the subscription
    -- (RFC 6665 §4.1.2.1); anything else means there is none.
    regev_response = function(sub, m)
        local u = regev_by_callid[m:call_id()]
        if not u then
            if m.status >= 300 then
                sbump(ustats.by_status, m.status)
                slog(sub, "reg-event", ("%d %s for a subscription we no longer track")
                    :format(m.status, m.reason))
            end
            return
        end
        if m.status < 200 then return end
        if m.status >= 300 then
            sbump(ustats.by_status, m.status)
            return regev_finish(u, false, "accept", ("%d %s"):format(m.status, m.reason))
        end
        if u.t.t1 then return end                     -- retransmitted final
        u.t.t1 = now()
        ustats.accepted = ustats.accepted + 1
        -- What the notifier granted, which may be less than we asked for.
        u.granted = tonumber(m:header("Expires"))
        if VERBOSE then
            slog(sub, "reg-event", ("%d %s after %d ms (expires %s)")
                :format(m.status, m.reason, u.t.t1 - u.t.t0,
                        u.granted and tostring(u.granted) or "unstated"))
        end
        regev_settle(u)
    end

    begin_regev = function()
        -- A SUBSCRIBE is an originating request, so it needs exactly what an
        -- INVITE needs: a live registration and the Service-Route to send it
        -- through. The denominator stays every subscriber, so a registration
        -- failure cannot turn into a perfect subscription rate.
        local list = {}
        for _, s in ipairs(subs) do
            if s.registered and s.sock and #(s.svc_route or {}) > 0 then
                ustats.eligible = ustats.eligible + 1
                list[#list + 1] = s
            end
        end
        if #list == 0 then
            banner(("Reg-event — none sent (%d/%d subscriber(s) eligible; a SUBSCRIBE needs a registered UE with a Service-Route)")
                :format(ustats.eligible, #subs))
            return after_regev()
        end
        banner(("Reg-event — %d of %d subscriber(s) subscribing to their own registration state%s")
            :format(#list, #subs,
                    REGEV.rps > 0 and (" at %.1f sub/s"):format(REGEV.rps) or " in one burst"))
        line("event package", ("reg (RFC 3680), Expires: %d, Accept: application/reginfo+xml")
            :format(REGEV.expires))

        local spacing = REGEV.rps > 0 and math.floor(1000 / REGEV.rps) or 0
        local function subscribe(sub)
            sub.regev_cseq = sub.regev_cseq + 1
            -- Short identifiers for the same reason the call phase uses them
            -- (see the downlink size budget): the reg-info NOTIFY is the
            -- largest thing the network sends a UE outside a call, and every
            -- byte of the dialog id comes back inside it.
            local u = {
                sub = sub, cseq = sub.regev_cseq,
                call_id  = ("r%d@%s"):format(sub.i, sub.ue_addr),
                from_tag = ("r%d"):format(sub.i),
                branch   = ("z9hG4bKr%d-%d"):format(sub.i, sub.regev_cseq),
                identities = 0, dialable = false, state = "", event = "",
                aor = "",   -- which of the UE's identities the document named
                t = {}, done = false,
            }
            sub.regev = u
            regev_by_callid[u.call_id] = u
            upending = upending + 1
            ustats.attempted = ustats.attempted + 1
            u.t.t0 = now()
            ustats.first = ustats.first or u.t.t0
            if send_call(sub, sub.sock, "mo", REGEV.build(sub, u, REGEV.expires),
                         ("SUBSCRIBE (reg, %s)"):format(sub.impu)) then
                uarm(u)
            else
                regev_finish(u, false, "send", "SUBSCRIBE send failed")
            end
        end

        -- Overall deadline so a lost NOTIFY cannot hang the run.
        uguard = loop:after(spacing * #list + REGEV.t_ms + 2000, function()
            uguard = nil
            for _, u in pairs(regev_by_callid) do
                if not u.done then regev_finish(u, false, "guard", "reg-event phase deadline") end
            end
            if upending > 0 then upending = 0; after_regev() end
        end)

        upending = 1                      -- the scheduler's sentinel; see mdec()
        if spacing > 0 then
            for i, s in ipairs(list) do loop:after((i - 1) * spacing, function() subscribe(s) end) end
            loop:after((#list - 1) * spacing + 1, udec)
        else
            for _, s in ipairs(list) do subscribe(s) end
            udec()
        end
    end

    -- ---- the call phase ----
    begin_calls = function()
        -- Structural pairs: 1<->2, 3<->4, ... A pair is eligible only when BOTH
        -- ends registered, and the denominator stays the structural count —
        -- silently shrinking it would turn a registration failure into a
        -- perfect call-success rate.
        cstats.pairs_total = math.floor(#subs / 2)
        local list = {}
        for p = 1, cstats.pairs_total do
            local mo, mt = subs[2 * p - 1], subs[2 * p]
            local ready = mo.registered and mt.registered
                and mo.sock and mt.sock and #(mo.svc_route or {}) > 0
            if ready then
                cstats.eligible = cstats.eligible + 1
                if not CALL.pairs or #list < CALL.pairs then
                    list[#list + 1] = { mo = mo, mt = mt }
                end
            end
        end
        if #list == 0 then
            banner(("Calls — none placed (%d/%d pair(s) eligible; a call needs BOTH ends registered with a Service-Route)")
                :format(cstats.eligible, cstats.pairs_total))
            return after_calls()
        end

        local nmedia = CALL.media < 0 and #list or math.min(CALL.media, #list)
        cstats.media_calls = nmedia
        banner(("Calls — %d of %d eligible pair(s) (%d structural), %d carrying RTP%s")
            :format(#list, cstats.eligible, cstats.pairs_total, nmedia,
                    CALL.cps > 0 and (" at %.1f call/s"):format(CALL.cps) or " in one burst"))
        -- What is actually dialled, spelled out: a run that fails because the
        -- HSS profile carries no such identity is otherwise indistinguishable
        -- from a routing fault, and this is the line that tells them apart.
        line("dialled address", ("%s   (CALL_URI=%s%s)"):format(
            list[1].mt.dial, CALL.uri,
            CALL.uri == "sip" and "" or ", needs the number in the HSS profile"))

        cpending = #list
        local spacing = CALL.cps > 0 and math.floor(1000 / CALL.cps) or 0
        -- Overall deadline so a lost 200 OK cannot hang the run.
        cguard = loop:after(spacing * #list + CALL.t_ms + CALL.hold_ms + 5000, function()
            cguard = nil
            for _, c in ipairs(calls) do
                if not c.done then call_fail(c, "call phase deadline", nil) end
            end
            if cpending > 0 then cpending = 0; after_calls() end
        end)

        for i, p in ipairs(list) do
            local c = make_call(i, p.mo, p.mt, i <= nmedia)
            calls[i] = c
            by_callid[c.call_id] = c
            p.mo.call, p.mt.call = c, c
            -- The P-CSCF hands out protected port pairs from a pool sized by
            -- ims_ipsec_pcscf's ipsec_max_connections (default 2), and shares
            -- them between UEs once it runs out — the pairs even overlap
            -- ((5062,5063) then (5063,5064)). When the MO's protected SERVER
            -- port is also the MT's protected CLIENT port, this P-CSCF sends
            -- the terminating INVITE from the wrong pair: it matches no ESP
            -- policy for the callee, so it leaves unprotected (or not at all)
            -- and the callee never rings. Flag it up front, so the failure is
            -- attributed to a stack that is under-provisioned for concurrent
            -- UEs rather than looking like a core routing bug.
            if p.mo.ch and p.mt.ch and p.mo.ch.p_port_s
               and p.mo.ch.p_port_s == p.mt.ch.p_port_c then
                c.port_clash = true
                cstats.port_clash = (cstats.port_clash or 0) + 1
                slog(p.mo, "protected ports", ("call %d shares P-CSCF port %d (MO server = MT client); raise ipsec_max_connections")
                    :format(i, p.mo.ch.p_port_s))
            end
            local function fire()
                if c.media then
                    c.sess_mo, c.mstat_mo = open_media(c, p.mo, "mo")
                    c.sess_mt, c.mstat_mt = open_media(c, p.mt, "mt")
                    c.media = (c.sess_mo ~= nil) and (c.sess_mt ~= nil)
                end
                c.offer = sdp.offer{ addr = p.mo.ue_addr, port = p.mo.media_port,
                                     pt = MEDIA.pt, codec = MEDIA.codec,
                                     rate = MEDIA.rate, ptime = MEDIA.ptime_ms }
                local wire = build_invite(c)
                feed_ev(c.txn_mo, sip.TE_SEND_REQUEST)
                c.t.t0 = now()
                cstats.first_invite = cstats.first_invite or c.t.t0
                cstats.attempted = cstats.attempted + 1
                if send_call(p.mo, p.mo.sock, "mo", wire,
                             ("INVITE (call %d -> %s)"):format(i, c.callee)) then
                    -- The message names what did arrive, so "the core never
                    -- answered" and "the core answered but the callee never
                    -- rang" are not reported as the same failure.
                    carm(c, CALL.t_ms, function()
                        call_fail(c, c.t.t1 and "no ringing after 100 Trying"
                                            or  "no response to the INVITE")
                    end)
                else
                    call_fail(c, "INVITE send failed", nil)
                end
            end
            if spacing > 0 then loop:after((i - 1) * spacing, fire) else fire() end
        end
    end

    -- ---- the SMS phase ----------------------------------------------------
    --
    -- One message is a chain of hops, and each is timed:
    --
    --   t0  submit        MESSAGE(RP-DATA / SMS-SUBMIT) to the SC address
    --   t1  202 Accepted  the IP-SM-GW took responsibility (TS 24.341 §5.3.2.4)
    --   t2  MT MESSAGE    the recipient receives RP-DATA / SMS-DELIVER
    --   t3  200 OK        the recipient's SIP hop for that delivery
    --   t4  RP-ACK out    the recipient's relay-layer acknowledgement
    --   t5  RP-ACK in     the gateway's report back to the sender
    --   t6  report        the SMS-STATUS-REPORT, when TP-SRR was set
    --
    -- t0 and t2 are readings of ONE monotonic clock in THIS process, so
    -- t2-t0 is a true one-way core latency carrying no clock skew — the same
    -- property the call phase's mo_transit has, and the reason both ends of
    -- every pair live in one process.
    --
    -- Nothing new is needed on the datapath: SMS is signalling and rides the
    -- ESP TFT the protected REGISTER already installed. That is asserted
    -- rather than assumed — the phase counts its own datagrams through the
    -- same mark_pkt() the registration does, so a message that never left
    -- shows up as a send failure and not as a silent timeout.

    local SMS_SC_URI = SMS.sc_uri ~= "" and SMS.sc_uri
                       or ("sip:smsc@" .. ims_realm)

    local ALPHA = { gsm7 = sms.ALPHA_GSM7, ucs2 = sms.ALPHA_UCS2,
                    ["8bit"] = sms.ALPHA_8BIT }

    -- The matrix, filtered by SMS_MATRIX and repeated to per_sub length.
    local function sms_plan()
        local want = os.getenv("SMS_MATRIX")
        local base = {}
        if want == "off" then
            base[1] = SMS_MATRIX[1]
        elseif want and want ~= "" then
            local keep = {}
            for n in want:gmatch("[^,]+") do keep[n:gsub("%s", "")] = true end
            for _, it in ipairs(SMS_MATRIX) do
                if keep[it.name] then base[#base + 1] = it end
            end
            if #base == 0 then base[1] = SMS_MATRIX[1] end
        else
            for _, it in ipairs(SMS_MATRIX) do base[#base + 1] = it end
        end
        local n = SMS.per_sub or #base
        local out = {}
        for i = 1, n do out[i] = base[(i - 1) % #base + 1] end
        return out
    end

    -- Where a submit goes, and from which port. Direct mode skips the core
    -- entirely (proving the codec and the gateway without the S-CSCF's iFC);
    -- otherwise it is an originating request exactly like the INVITE, which
    -- means the P-CSCF's own URI marked `orig` ahead of the Service-Route —
    -- see build_invite for why the marking has to be on that first entry.
    local function build_sms_message(sub, ruri, body, cseq, br)
        local b = BUILDER:request(sip.MESSAGE, ruri)
        if not SMS.direct then
            local pport = (sub.ch and sub.ch.ss_raw and sub.ch.p_port_s)
                          or PCSCF_SIP_PORT
            b:header(sip.H_ROUTE, ("<sip:orig@%s:%d;lr>"):format(sub.pcscf, pport))
            for _, r in ipairs(sub.svc_route or {}) do b:header(sip.H_ROUTE, r) end
        end
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s"):format(
                                sub.ue_addr, sub.port_uc, br))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, ("<%s>;tag=%s-m%d"):format(sub.impu, sub.imsi, cseq))
            :header(sip.H_TO, ("<%s>"):format(ruri))
            :header(sip.H_CALL_ID, ("sms-%s-%d@%s"):format(sub.imsi, cseq, sub.ue_addr))
            :header(sip.H_CSEQ, ("%d MESSAGE"):format(cseq))
            :header(sip.H_CONTACT, ("<sip:%s:%d>;%s"):format(
                                       sub.ue_addr, sub.port_uc, sms.FEATURE_TAG))
            :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(sub.impu))
            :header(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)
        return b:done(body)
    end

    local function send_sms(sub, wire, what)
        if SMS.direct then
            dump(("[%d] -> %s"):format(sub.i, what), wire)
            local ok, err = pcall(function()
                sub.sock:sendto(wire, SMS.gw_host, SMS.gw_port)
            end)
            if ok then
                stats.tx = stats.tx + 1; mark_pkt()
                if VERBOSE then
                    slog(sub, "-> " .. what, ("%dB -> %s:%d (direct)"):format(
                                                 #wire, SMS.gw_host, SMS.gw_port))
                end
            else
                slog(sub, "-> " .. what, "send failed: " .. why(err))
            end
            return ok
        end
        return send_call(sub, sub.sock, "mo", wire, what)
    end

    -- Out-of-dialog answer to a MESSAGE we received. A MESSAGE creates no
    -- dialog (RFC 3428 §4), so there is no route set to echo and no to-tag
    -- to remember — just the RFC 3261 §8.2.6 fields, from this UE's
    -- protected server port back to the P-CSCF's protected client port.
    local function sms_respond(sub, req, status, reason)
        local b    = BUILDER:response(status, reason)
        local vias = req:header_values("Via")
        for i = 0, vias:size() - 1 do b:header(sip.H_VIA, vias[i]) end
        local to = req:header("To")
        if not to:find(";tag=", 1, true) then
            to = to .. (";tag=%s-r"):format(sub.imsi)
        end
        b:header(sip.H_FROM, req:header("From"))
            :header(sip.H_TO, to)
            :header(sip.H_CALL_ID, req:header("Call-ID"))
            :header(sip.H_CSEQ, req:header("CSeq"))
            :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(sub.ue_addr, sub.port_uc))
        local wire = b:done()
        if SMS.direct then
            pcall(function() sub.sock:sendto(wire, SMS.gw_host, SMS.gw_port) end)
            stats.tx = stats.tx + 1; mark_pkt()
        else
            send_call(sub, sub.sock, "mt", wire, ("%d %s (MESSAGE)"):format(status, reason))
        end
    end

    -- One counter for "work still outstanding", decremented by a finished
    -- message AND by the scheduler releasing its own sentinel. Without the
    -- sentinel a spaced run (SMS_MPS>0) would end the phase the moment its
    -- FIRST message settled, because the rest had not been issued yet and
    -- the count was legitimately zero.
    local function mdec()
        mpending = mpending - 1
        if mpending > 0 then return end
        if mguard then loop:cancel(mguard); mguard = nil end
        after_sms()
    end

    local function msg_finish(msg, ok, stage, detail)
        if msg.done then return end
        msg.done = true
        if msg.timer then loop:cancel(msg.timer); msg.timer = nil end
        msg_by_callid[msg.call_id] = nil
        msg_by_mr[msg.mr_key] = nil
        if not ok then
            sbump(sstats.stage, stage or "unknown")
            slog(msg.mo, "sms", ("message %d (%s) FAILED at %s: %s"):format(
                                    msg.i, msg.item.name, stage or "?",
                                    detail or "?"))
        end
        mdec()
    end

    local function marm(msg)
        if msg.timer then loop:cancel(msg.timer) end
        msg.timer = loop:after(SMS.t_ms, function()
            msg.timer = nil
            -- Name the furthest hop that DID happen, so "the gateway never
            -- answered" and "the gateway answered but the recipient never got
            -- it" are not reported as the same failure.
            local stage, detail
            if not msg.t.t1 then stage, detail = "accept", "no 202 for the submit"
            elseif not msg.t.t2 then stage, detail = "transit", "accepted, but never delivered"
            elseif not msg.t.t4 then stage, detail = "mt_ack", "delivered, but the recipient never acknowledged"
            elseif not msg.t.t5 then stage, detail = "mo_ack", "delivered, but no RP-ACK came back to the sender"
            else stage, detail = "unknown", "every hop completed but the message never settled" end
            msg_finish(msg, false, stage, detail)
        end)
    end

    -- Record a message as fully accounted for: the recipient has it and the
    -- sender has been told. A status report, when asked for, is a separate
    -- (later) event and does not hold the message open.
    local function msg_settle(msg)
        local t, k = msg.t, sstats.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.accept,     "t0", "t1")
        push(k.transit,    "t0", "t2")   -- MO submit -> MT deliver, one clock
        push(k.deliver_ok, "t2", "t3")
        push(k.total,      "t0", "t4")
        push(k.ack,        "t0", "t5")
        -- No status-report figure here: it arrives after the message has
        -- settled, so the report branch records it directly (see rep_by_mr).
        if t.t2 then sstats.last_delivery = t.t2 end
        msg_finish(msg, true)
    end

    -- Everything a delivered message has to satisfy before it counts. The
    -- text comparison is the point of the whole phase: a byte difference
    -- here is a codec bug (the septet alignment, the length units, an
    -- alphabet mapping) that no amount of successful signalling reveals.
    local function verify(msg, got)
        local m = sstats.by_matrix[msg.item.name]
        if not m then m = { sent = 0, ok = 0 }; sstats.by_matrix[msg.item.name] = m end
        if got == msg.text then
            m.ok = m.ok + 1
            sstats.verified = sstats.verified + 1
            return true
        end
        sbump(sstats.mismatch, msg.item.name)
        slog(msg.mt, "sms", ("content MISMATCH (%s): sent %d bytes, received %d"):format(
                                msg.item.name, #msg.text, #got))
        return false
    end

    -- A DELIVER arrived at `sub`. Returns the message record this delivery
    -- belongs to, plus — once every part of a concatenated message is in —
    -- the reassembled text and the list of records to verify against it.
    --
    -- A concatenated message is N SIP MESSAGEs, each with its own 202 and its
    -- own RP-ACK, so N records are outstanding and all N have to settle. Only
    -- the last part can be verified, because only then is there a whole text
    -- to compare — so the verification is applied to every member at that
    -- point. Counting the group as one message instead would make `submitted`
    -- and `delivered` disagree by the part count.
    local function match_delivery(sub, tpdu, text)
        local wait = sub.sms_wait
        if not wait or #wait == 0 then return nil, nil, nil end

        if tpdu:has_concat() then
            local c     = tpdu:concat()
            local group = sub.sms_groups[c.ref]
            if not group then return nil, nil, nil end
            local member = group.members[c.seq]
            if not group.parts[c.seq] then
                group.parts[c.seq] = text
                group.got = group.got + 1
            end
            if group.got < group.total then return member, nil, nil end
            sub.sms_groups[c.ref] = nil
            for _, m in ipairs(group.members) do
                for i, w in ipairs(wait) do
                    if w == m then table.remove(wait, i); break end
                end
            end
            return member, table.concat(group.parts, "", 1, group.total),
                   group.members
        end

        -- Single part: match on the content, so a corrupted body becomes a
        -- mismatch rather than a misattributed success.
        for i, m in ipairs(wait) do
            if not m.group and m.text == text then
                table.remove(wait, i)
                return m, text, { m }
            end
        end
        -- Nothing matched: attribute it to the oldest outstanding single-part
        -- message so the difference is counted rather than lost.
        for i, m in ipairs(wait) do
            if not m.group then
                table.remove(wait, i)
                return m, text, { m }
            end
        end
        return nil, nil, nil
    end

    -- A MESSAGE request arrived on a UE's socket. It is either a delivery to
    -- this UE, a relay-layer report about something this UE sent, or a status
    -- report; the RPDU says which, and the direction is SC -> MS in all three
    -- cases because everything reaching a UE comes from the network side.
    sms_request = function(sub, req, which)
        local ct = req:header("Content-Type"):lower()
        if not ct:find("vnd.3gpp.sms", 1, true) then
            slog(sub, "sms", ("MESSAGE with Content-Type %q -- 415"):format(ct))
            return sms_respond(sub, req, 415, "Unsupported Media Type")
        end

        local okp, rp = pcall(sms.parse_rpdu, req.body, sms.DIR_SC_TO_MS)
        if not okp then
            slog(sub, "sms", "unparseable RPDU: " .. why(rp))
            return sms_respond(sub, req, 400, "Bad Request")
        end

        -- The gateway's report about a message THIS UE submitted.
        if rp.type == sms.RP_T_ACK or rp.type == sms.RP_T_ERROR then
            sms_respond(sub, req, 200, "OK")
            local msg = msg_by_mr[("%d:%d"):format(sub.i, rp.mr)]
            if not msg then
                return slog(sub, "sms", ("%s RP-MR %d matches no submit"):format(
                                            rp:type_name(), rp.mr))
            end
            if rp.type == sms.RP_T_ERROR then
                sbump(sstats.by_cause, rp.cause)
                return msg_finish(msg, false, "rp_error",
                                  ("RP-ERROR %d (%s)"):format(rp.cause, rp:cause_name()))
            end
            sstats.acked = sstats.acked + 1
            msg.t.t5 = now()
            slog(sub, "sms", ("RP-ACK for message %d (%s) after %d ms"):format(
                                 msg.i, msg.item.name, msg.t.t5 - msg.t.t0))
            -- The sender is satisfied. The recipient may already have
            -- acknowledged (the gateway is a store-and-forward hop, so the
            -- order is not fixed); settle once both are in.
            if msg.t.t4 then msg_settle(msg) end
            return
        end

        if rp.type ~= sms.RP_T_DATA or not rp:has_tpdu() then
            return sms_respond(sub, req, 400, "Bad Request")
        end

        local okt, tpdu = pcall(function() return rp:tpdu() end)
        if not okt then
            slog(sub, "sms", "unparseable TPDU: " .. why(tpdu))
            return sms_respond(sub, req, 400, "Bad Request")
        end

        -- A status report: the SC saying what became of a submitted message.
        if tpdu.type == sms.T_STATUS_REPORT then
            sms_respond(sub, req, 200, "OK")
            local ack = sms.ack(sms.DIR_MS_TO_SC, rp.mr)
            sub.sms_cseq = (sub.sms_cseq or 0) + 1
            send_sms(sub, build_sms_message(sub, SMS_SC_URI, ack, sub.sms_cseq,
                          ("z9hG4bK-smsr-%s-%d"):format(sub.imsi, sub.sms_cseq)),
                     "MESSAGE (RP-ACK for a status report)")
            sstats.reports = sstats.reports + 1
            local msg = rep_by_mr[("%d:%d"):format(sub.i, tpdu.mr)]
            if msg then
                -- Recorded straight into the distribution: the message has
                -- already settled, so msg_settle will not run again.
                local k = sstats.kpi.report
                k[#k + 1] = now() - msg.t.t0
                if not tpdu:delivered() then
                    sbump(sstats.stage, "report_failed")
                    slog(sub, "sms", ("status report for message %d says %s"):format(
                                         msg.i, tpdu:status_name()))
                else
                    slog(sub, "sms", ("status report for message %d: %s"):format(
                                         msg.i, tpdu:status_name()))
                end
            else
                slog(sub, "sms", ("status report TP-MR %d: %s"):format(
                                     tpdu.mr, tpdu:status_name()))
            end
            return
        end

        if tpdu.type ~= sms.T_DELIVER then
            slog(sub, "sms", ("ignoring a delivered %s"):format(tpdu:type_name()))
            return sms_respond(sub, req, 200, "OK")
        end

        -- A delivery. Answer the SIP hop first, then the relay layer.
        local t2 = now()
        sms_respond(sub, req, 200, "OK")
        local t3 = now()
        sstats.delivered = sstats.delivered + 1

        local okx, text = pcall(function() return tpdu:text() end)
        if not okx then
            slog(sub, "sms", "undecodable user data: " .. why(text))
            text = ""
        end

        -- RP-ACK back towards the SC: a NEW out-of-dialog MESSAGE from this
        -- UE (TS 24.341 §5.3.2.6), not a body on the 200 OK.
        local ack = sms.ack(sms.DIR_MS_TO_SC, rp.mr)
        sub.sms_cseq = (sub.sms_cseq or 0) + 1
        local br = ("z9hG4bK-smsa-%s-%d"):format(sub.imsi, sub.sms_cseq)
        local sent = send_sms(sub, build_sms_message(sub, SMS_SC_URI, ack,
                                                     sub.sms_cseq, br),
                              ("MESSAGE (RP-ACK, RP-MR %d)"):format(rp.mr))
        local t4 = sent and now() or nil

        local msg, whole, members = match_delivery(sub, tpdu, text)
        if not msg then
            sstats.orphans = sstats.orphans + 1
            return slog(sub, "sms",
                ("delivery from %s matches no submit (%d bytes)")
                :format(tpdu.addr:display(), #text))
        end

        -- Timestamp the part that actually arrived, whichever it is.
        msg.t.t2, msg.t.t3, msg.t.t4 = msg.t.t2 or t2, t3, t4
        if not whole then
            if VERBOSE then
                local c = tpdu:concat()
                slog(sub, "sms", ("part %d/%d of reference %d in"):format(
                                     c.seq, c.total, c.ref))
            end
            return
        end

        slog(sub, "sms", ("delivered message %d (%s) from %s in %d ms"):format(
                             msg.i, msg.item.name, tpdu.addr:display(),
                             t2 - msg.t.t0))
        -- The whole text exists now, so every record in the group is verified
        -- against it and settles as soon as its own RP-ACK is in.
        for _, m in ipairs(members) do
            verify(m, whole)
            if m.t.t5 then msg_settle(m) end
        end
    end

    -- Responses to a MESSAGE we sent: the 202 for a submit, or the 200 for an
    -- RP-ACK we relayed (which needs no bookkeeping).
    sms_response = function(sub, m)
        local msg = msg_by_callid[m:call_id()]
        if not msg then
            if m.status >= 300 then
                sbump(sstats.by_status, m.status)
                slog(sub, "sms", ("%d %s for a MESSAGE we no longer track"):format(
                                     m.status, m.reason))
            end
            return
        end
        if m.status < 200 then return end          -- a provisional, if any
        if m.status >= 300 then
            sbump(sstats.by_status, m.status)
            return msg_finish(msg, false, "accept",
                              ("%d %s"):format(m.status, m.reason))
        end
        if msg.t.t1 then return end                -- retransmitted 202
        msg.t.t1 = now()
        sstats.accepted = sstats.accepted + 1
        slog(sub, "sms", ("%d %s for message %d (%s) after %d ms"):format(
                             m.status, m.reason, msg.i, msg.item.name,
                             msg.t.t1 - msg.t.t0))
    end

    begin_sms = function()
        -- Structural pairs, as in the call phase: 1<->2, 3<->4, ... The odd
        -- index submits, the even index receives. The denominator stays the
        -- structural count, so a registration failure cannot turn into a
        -- perfect SMS success rate.
        sstats.pairs_total = math.floor(#subs / 2)
        local list = {}
        for p = 1, sstats.pairs_total do
            local mo, mt = subs[2 * p - 1], subs[2 * p]
            local ready = mo.registered and mt.registered and mo.sock and mt.sock
                and (SMS.direct or #(mo.svc_route or {}) > 0)
            if ready then
                sstats.eligible = sstats.eligible + 1
                if not SMS.pairs or #list < SMS.pairs then
                    list[#list + 1] = { mo = mo, mt = mt }
                end
            end
        end

        local plan = sms_plan()
        if #list == 0 then
            banner(("SMS — none sent (%d/%d pair(s) eligible; a message needs BOTH ends registered%s)")
                :format(sstats.eligible, sstats.pairs_total,
                        SMS.direct and "" or " with a Service-Route"))
            return after_sms()
        end

        local names = {}
        for _, it in ipairs(plan) do names[#names + 1] = it.name end
        banner(("SMS — %d of %d eligible pair(s) (%d structural), %d message(s) each%s")
            :format(#list, sstats.eligible, sstats.pairs_total, #plan,
                    SMS.mps > 0 and (" at %.1f msg/s"):format(SMS.mps) or " in one burst"))
        line("destination", SMS.direct
            and ("%s:%d (direct, bypassing the core)"):format(SMS.gw_host, SMS.gw_port)
            or SMS_SC_URI)
        line("content", table.concat(names, " "))
        if SMS.srr then line("status reports", "requested (TP-SRR)") end

        -- Build the work list first, so the deadline can be sized from it.
        local work = {}
        for _, p in ipairs(list) do
            p.mt.sms_wait   = p.mt.sms_wait or {}
            p.mt.sms_groups = p.mt.sms_groups or {}
            for _, item in ipairs(plan) do
                work[#work + 1] = { mo = p.mo, mt = p.mt, item = item }
            end
        end

        if SMS.direct and SMS.gw_host == "" then
            banner("SMS — SMS_DIRECT=1 needs SMS_GW_HOST; skipping the phase")
            return after_sms()
        end

        local spacing = SMS.mps > 0 and math.floor(1000 / SMS.mps) or 0
        mpending = 0
        local mr_seq = 0

        -- One submit, possibly split into several messages.
        local function submit(w, idx)
            local mo, mt, item = w.mo, w.mt, w.item
            local alpha = item.alpha and ALPHA[item.alpha] or sms.ALPHA_AUTO

            -- The recipient's number in TP-DA. Deliberately the IMSI digits
            -- and NOT mt.msisdn: an SMS is resolved by the IP-SM-GW, not by
            -- the HSS profile, and ipsmgw.lua's default rule turns the digits
            -- it is given straight back into sip:<digits>@<realm> — which is
            -- the IMPU this run registered, so nothing has to be provisioned
            -- or configured. The MSISDN form works too, but only once the
            -- gateway is told to produce the matching identity: run it with
            -- IPSMGW_TEL=1 (sip:+<digits>@<realm>;user=phone, the alias
            -- cx_hss.lua puts in the profile) and set `to` to mt.msisdn.
            local to = mt.imsi

            local okp, parts = pcall(function()
                mr_seq = mr_seq + 1
                local args = { to = to, text = item.text, sc = SMS.sc_addr,
                               alphabet = alpha, srr = SMS.srr,
                               mr = mr_seq % 256 }
                return sms.parts(sms.submit_parts(args, mr_seq % 65536, false))
            end)
            if not okp then
                banner(("SMS — cannot build %q: %s"):format(item.name, why(parts)))
                return
            end

            -- A multi-part message needs a record the recipient can find by
            -- concatenation reference, holding every part's message record so
            -- all of them settle when the last part arrives.
            local group = nil
            if #parts > 1 then
                group = { ref = mr_seq % 65536, total = #parts, got = 0,
                          parts = {}, members = {} }
                mt.sms_groups[group.ref] = group
            end
            for pi, rpdu in ipairs(parts) do
                mo.sms_cseq = (mo.sms_cseq or 0) + 1
                local mr = (mr_seq + pi - 1) % 256
                local br = ("z9hG4bK-sms-%s-%d"):format(mo.imsi, mo.sms_cseq)
                local wire = build_sms_message(mo, SMS_SC_URI, rpdu, mo.sms_cseq, br)
                local msg = {
                    i = idx, mo = mo, mt = mt, item = item,
                    text = item.text, group = group,
                    mr = mr, mr_key = ("%d:%d"):format(mo.i, mr),
                    call_id = ("sms-%s-%d@%s"):format(mo.imsi, mo.sms_cseq, mo.ue_addr),
                    t = {}, done = false,
                }
                msgs[#msgs + 1] = msg
                msg_by_callid[msg.call_id] = msg
                msg_by_mr[msg.mr_key] = msg
                rep_by_mr[msg.mr_key] = msg
                mt.sms_wait[#mt.sms_wait + 1] = msg
                if group then group.members[pi] = msg end
                mpending = mpending + 1
                sstats.attempted = sstats.attempted + 1
                local mm = sstats.by_matrix[item.name]
                if not mm then mm = { sent = 0, ok = 0 }; sstats.by_matrix[item.name] = mm end
                mm.sent = mm.sent + 1

                msg.t.t0 = now()
                sstats.first_submit = sstats.first_submit or msg.t.t0
                if send_sms(mo, wire, ("MESSAGE submit %d/%d (%s -> %s)"):format(
                                          pi, #parts, item.name, to)) then
                    marm(msg)
                else
                    msg_finish(msg, false, "send", "MESSAGE send failed")
                end
            end
        end

        -- Overall deadline so a lost report cannot hang the run.
        mguard = loop:after(spacing * #work + SMS.t_ms + 5000, function()
            mguard = nil
            for _, msg in ipairs(msgs) do
                if not msg.done then
                    msg_finish(msg, false, "guard", "SMS phase deadline")
                end
            end
            if mpending > 0 then mpending = 0; after_sms() end
        end)

        -- The sentinel: one unit of outstanding work standing for "not every
        -- submit has been issued yet". Released after the last one, so a
        -- message that settles before its successors are even scheduled
        -- cannot end the phase early.
        mpending = 1
        if spacing > 0 then
            for i, w in ipairs(work) do
                loop:after((i - 1) * spacing, function() submit(w, i) end)
            end
            loop:after((#work - 1) * spacing + 1, mdec)
        else
            for i, w in ipairs(work) do submit(w, i) end
            mdec()
        end
    end

    -- Send `wire` and feed it to the subscriber's three FSMs in lock-step.
    local function send_register(sub, wire, label, dport, dereg)
        feed_sent_register(sub, dereg)
        local sok, serr = pcall(function() sub.sock:sendto(wire, sub.pcscf, dport) end)
        if not sok then return fail(sub, "REGISTER send: " .. why(serr)) end
        stats.tx = stats.tx + 1; mark_pkt()
        if VERBOSE then
            slog(sub, "-> REGISTER", ("%s, %dB -> %s:%d"):format(label, #wire, sub.pcscf, dport))
        end
        arm(sub, SIP_T_MS, function() fail(sub, "timed out awaiting a SIP response") end)
    end

    -- ---- SIP receive: drain the socket, drive the FSMs, dispatch ----
    -- `which` is the port the datagram came in on: "uc" is the protected client
    -- port (our own requests' responses), "us" the protected server port (what
    -- the P-CSCF delivers terminating requests to).
    on_sip_readable = function(sub, sock, which)
        while true do
            local dg = sock:recv(-1)
            if dg.timed_out then return end
            stats.rx = stats.rx + 1; mark_pkt()
            local okp, m = pcall(sip.parse, dg.data)
            if okp and not m.request and pcall(function() return m:cseq() end) then
                -- registration traffic has its own trace; dump the call phase
                if m:cseq().method ~= sip.REGISTER then
                    dump(("[%d] <- response"):format(sub.i), dg.data)
                end
            elseif okp then
                dump(("[%d] <- request"):format(sub.i), dg.data)
            end
            if okp then dispatch_sip(sub, m, which)
            else slog(sub, "SIP", "ignoring unparseable datagram") end
        end
    end

    handle_sip = function(sub, m)
        if sub.done then return end   -- ignore late replies once terminal
        disarm(sub)
        pcall(function() sub.txn:recv(m) end)
        pcall(function() sub.auth:recv(m) end)
        local ok = pcall(function() sub.reg:recv(m) end)  -- classifies 401 / 2xx / fail
        if not ok then
            slog(sub, "SIP", ("ignoring %s in state %s"):format(m.status or "?", sub.reg:state_name()))
            return
        end
        report_rx(sub, tostring(m.status))
        if sub.reg:state() == sip.RS_CHALLENGED then
            sub.attempts = sub.attempts + 1
            if sub.attempts > AUTH_CAP then
                pcall(function() sub.auth:event(sip.AE_GIVE_UP) end)
                return fail(sub, "authentication failed (repeated 401)")
            end
            on_401(sub, m)
        elseif sub.reg:registered() then
            slog(sub, "<- 200 OK", "registered")
            succeed(sub, m)
        elseif sub.reg:failed() then
            fail(sub, ("registration rejected: %d %s"):format(m.status, m.reason))
        end
    end

    -- Round 2: verify the AKA challenge, derive RES/CK/IK; with a
    -- Security-Server raise the ESP SAs and send the protected REGISTER (the
    -- kernel ESP-wraps it, egressing as proto 50) with a Security-Verify.
    -- Without one, fall back to an unprotected authenticated REGISTER.
    on_401 = function(sub, m401)
        sub.stage = "auth"           -- challenged; now authenticating toward 200 OK
        local okc, ch = pcall(parse_challenge, m401)
        if not okc then return fail(sub, "cannot parse 401 challenge: " .. why(ch)) end
        sub.ch = ch
        if VERBOSE then
            slog(sub, "<- 401", ("IMS-AKA challenge (RAND %s)"):format(hex(ch.rand)))
        end

        local okv, keys = pcall(function() return ipsec.aka_verify(K, OPc, ch.rand, ch.autn) end)
        if not okv then return fail(sub, "AKA AUTN verification failed: " .. why(keys)) end
        if VERBOSE then
            slog(sub, "AUTN verified", ("SQN %s, RES %s"):format(hex(keys.sqn), hex(keys.res)))
        end

        sub.cseq = sub.cseq + 1
        local nc, cnonce = "00000001", hex(ipsec.md5(sub.imsi .. tostring(sub.cseq)):sub(1, 8))
        local response = ipsec.aka_digest(sub.impi, ch.realm, keys.res, "REGISTER",
                                          "sip:" .. ims_realm, ch.nonce, nc, cnonce, ch.qop or "")
        local authz = authz_hdr(sub, ch.realm, ch.nonce, response,
                                ch.qop and { qop = ch.qop, nc = nc, cnonce = cnonce })
        sub.authz = authz            -- kept for the Expires:0 de-REGISTER on teardown

        local dport, sec_name, sec_hdr = PCSCF_SIP_PORT, nil, nil
        if ch.ss_raw and ch.p_spi_s and ch.p_port_s then
            if not xfrm then xfrm = ipsec.Xfrm() end
            slog(sub, "P-CSCF ports", ("client %s / server %d, SPIs %#x/%#x")
                :format(ch.p_port_c or 0, ch.p_port_s, ch.p_spi_c or 0, ch.p_spi_s))
            establish_sas(xfrm, sub, ch, keys)
            dport, sec_name, sec_hdr = ch.p_port_s, "Security-Verify", ch.ss_raw
        else
            slog(sub, "Security-Server", "absent -- unprotected authenticated REGISTER")
        end

        local reg2 = build_register(sub, authz, sec_name, sec_hdr)
        send_register(sub, reg2, sec_hdr and "AKAv1-MD5 over ESP" or "AKAv1-MD5 (digest only)", dport)
    end

    -- Round 1: make the PAA deliverable, prime the neighbour table, bind the
    -- transparent UE socket and send the unprotected REGISTER.
    begin_registration = function(sub)
        if not (sub.pcscf and sub.ue_addr) then
            return fail(sub, "no P-CSCF/UE address from Create Session")
        end
        add_paa_route(sub)
        set_pcscf_mtu(sub)

        -- encap resolves the outer L2 with bpf_fib_lookup (reads the neighbour
        -- table, never ARPs); a throwaway datagram warms the peer's entry.
        if sub.remote_addr then
            local prime = net.UdpSocket("0.0.0.0", 0)
            pcall(function() prime:sendto("x", sub.remote_addr, 2152) end)
            prime:close()
        end

        -- The REGISTER's inner source must be the PAA (not the SGW/outer
        -- source), so bind a non-local transparent socket (IP_FREEBIND +
        -- IP_TRANSPARENT) that also receives the 401/200 returned to the PAA.
        -- Needs CAP_NET_ADMIN; falls back to the SGW source (which the UPF
        -- drops as spoofed) when refused.
        local okb, s = pcall(function()
            return net.UdpSocket(sub.ue_addr, sub.port_uc, false, true)
        end)
        if okb then
            sub.sock = s
            slog(sub, "UE SIP socket", ("%s:%d (UE PAA, transparent)"):format(sub.ue_addr, sub.port_uc))
        else
            sub.sock = net.UdpSocket("0.0.0.0", 0)
            slog(sub, "UE SIP socket", ("SGW source (UE PAA bind refused: %s); no reply can return"):format(why(s)))
        end
        loop:add_fd(sub.sock:fd(), net.NET_RD, function() on_sip_readable(sub, sub.sock, "uc") end)
        -- Put this UE's output on the loop (queue now, batched sendmmsg from
        -- the loop). NET_RD is the fd's steady-state interest above, which the
        -- queue restores after adding NET_WR to ride out a full send buffer.
        sub.sock:tx_loop(loop, net.NET_RD)

        -- No second socket: with one protected port in both roles (see
        -- security_client) the P-CSCF delivers terminating requests to this
        -- same port, so the MT INVITE and any BYE from the far end arrive here
        -- and the dispatcher sorts them out by CSeq method.

        if up and sub.sig_teid then sub.rx0 = up:stats(sub.sig_teid) end

        sub.cseq = sub.cseq + 1
        sub.stage = "register"       -- driving the initial REGISTER / 401 exchange
        local reg1 = build_register(sub, authz_hdr(sub, ims_realm, "", ""),
                                    "Security-Client", security_client(sub))
        send_register(sub, reg1, "unprotected", PCSCF_SIP_PORT)
    end

    -- The EBI we assign the dedicated (media) bearer when the network asks for
    -- one, and quote back when it asks us to delete it.
    local DED_EBI = 6

    ep:set_handler({
        -- The PGW answered a Create Session: read the PAA and P-CSCF; kick off
        -- registration after on_user_plane has programmed the filters (it runs
        -- right after this handler), giving the primed neighbour time to resolve.
        on_create_session_response = function(sess, rsp)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
                return fail(sub, ("Create Session rejected, cause %d"):format(rsp.cause))
            end
            stats.sess = stats.sess + 1; stats.sess_last = now()
            sub.pgw_ctrl_teid = sess:remote_teid()
            if rsp.has_paa then sub.ue_addr = rsp.paa.addr4 end
            if rsp.pco and #rsp.pco > 0 then
                local p = gtp.pco_pcscf_v4(rsp.pco)
                sub.pcscf = p ~= "" and p or nil
            end
            if VERBOSE then
                slog(sub, "<- Create Session Resp", ("PAA %s, P-CSCF %s"):format(sub.ue_addr or "?", sub.pcscf or "none"))
            end
            arm(sub, 200, function() begin_registration(sub) end)
        end,

        -- One per bearer F-TEID in the accepted response (the default bearer):
        -- steer the subscriber's uplink SIP onto it.
        on_user_plane = function(sess, tun)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            slog(sub, "user plane (S5/S8-U)", ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
            program_filter(sub, tun)
        end,

        -- Network-initiated dedicated bearer (§7.2.3): accept it with a typed
        -- Create Bearer Response addressed to the subscriber's PGW control TEID
        -- (correlated by the request's header TEID = our control TEID). This is
        -- the media bearer the Rx->Gx->Create Bearer chain exists to build, so
        -- it is recorded and media is homed (or re-homed) onto it.
        on_create_bearer_request = function(req, host, port)
            local sub = by_teid[req.teid]
            local pgw_u
            if req.bearers:size() > 0 then
                local fts = req.bearers[0].fteids
                if fts:size() > 0 then pgw_u = fts[0].fteid end
            end
            -- A subscriber gets MORE than one of these: the PCRF installs a
            -- rule at registration and another for the call's actual media, so
            -- a second request arrives with its own PGW TEID and its own SDF.
            -- Each therefore needs its OWN EBI and UE-side TEID — answering
            -- both with EBI 6 and one TEID leaves us steering media onto the
            -- first bearer while the network runs the media rule on the second,
            -- which the UPF then rejects uplink ("Off-filter G-PDU") and
            -- delivers downlink on a TEID we have no decap entry for. The
            -- per-subscriber TEID stride is 0x10, so +n stays inside it.
            local n   = (sub and (sub.ded_n or 0) + 1) or 1
            local ebi = DED_EBI + n - 1
            local teid = (sub and sub.ded_teid + n - 1) or (S5_UP_TEID_BASE - 1)
            local rbc = gtp.BearerContext()
            rbc.ebi, rbc.cause = ebi, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, teid, sgw_ip
            rbc:add_fteid(2, u)
            if pgw_u then rbc:add_fteid(3, pgw_u) end

            local resp = gtp.CreateBearerResponse()
            resp.teid     = (sub and sub.pgw_ctrl_teid) or 0
            resp.sequence = req.sequence
            resp.cause    = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            resp.pti      = req.pti
            resp:add_bearer(rbc)
            ep:send_create_bearer_response(resp, host, port)
            if sub then
                sub.ded_n = n
                slog(sub, "<> Create Bearer", ("seq %d, EBI %d accepted (media #%d, TEID %#x)")
                    :format(req.sequence, ebi, n, teid))
                -- The newest dedicated bearer is the one the call's media rule
                -- lives on, so it becomes the media home; re-home anything
                -- already programmed elsewhere. The Create Bearer Request and
                -- the SDP answer race, and both orders have to work.
                sub.ded_bearer = {
                    ebi = ebi, local_teid = teid,
                    remote_teid = pgw_u and pgw_u.teid or 0,
                    remote_addr = (pgw_u and pgw_u.addr4 ~= "" and pgw_u.addr4)
                                  or sub.remote_addr,
                }
                rehome_media(sub)
            end
        end,

        -- A Delete Session Request was answered: this PDN connection is torn down.
        on_delete_session_response = function(sess, rsp)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            slog(sub, "<- Delete Session Resp", ("cause %d"):format(rsp.cause))
            del_done(sub, true)
        end,

        -- The other half of the dedicated bearer's life. When a call clears,
        -- the P-CSCF tears its Rx session down, the PCRF removes the PCC rule
        -- over Gx and the SMF sends us a Delete Bearer Request — which the
        -- endpoint has no typed message for, so it arrives here as raw bytes.
        --
        -- Answering it matters beyond tidiness: ignore it and the SMF retries,
        -- keeps the bearer half-removed and leaves the session in a state where
        -- the NEXT run's Create Session comes back with PDRs the UPF then
        -- rejects ("Send Error Indication"), so that run gets no downlink at
        -- all and every registration times out for no visible reason. One
        -- response per request costs nothing and keeps the stack clean between
        -- runs. Hand-encoded because a GTPv2 response with a Cause and a linked
        -- EBI is 20 bytes and the alternative is a typed message pair in the
        -- gtp facade for this one path.
        on_message = function(mt, wire, host, port)
            if mt ~= gtp.GTP2_MT_DELETE_BEARER_REQUEST then return end
            if #wire < 12 then return end
            local function be(s, i, n)      -- big-endian read, Lua 5.1 safe
                local v = 0
                for k = i, i + n - 1 do v = v * 256 + s:byte(k) end
                return v
            end
            local function u16(v) return string.char(math.floor(v / 256) % 256, v % 256) end
            local function u24(v)
                return string.char(math.floor(v / 65536) % 256,
                                   math.floor(v / 256) % 256, v % 256)
            end
            local function u32(v)
                return string.char(math.floor(v / 16777216) % 256,
                                   math.floor(v / 65536) % 256,
                                   math.floor(v / 256) % 256, v % 256)
            end
            -- The request's header TEID is our control TEID, exactly as the
            -- Create Bearer Request's is, so the same index correlates it.
            local sub = by_teid[be(wire, 5, 4)]
            local seq = be(wire, 9, 3)

            -- Walk the request's IEs: type(1) length(2) spare/instance(1) value.
            local function ies_of(body, from)
                local out, i = {}, from
                while i + 3 <= #body do
                    local len = be(body, i + 1, 2)
                    out[#out + 1] = { t = body:byte(i), v = body:sub(i + 4, i + 3 + len) }
                    i = i + 4 + len
                end
                return out
            end
            -- Which bearers: a Bearer Context (93) per bearer, each carrying its
            -- EBI (73) — or a bare linked EBI (73) at the top level, which per
            -- TS 29.274 §7.2.9.2 means the whole PDN connection goes away. The
            -- two need different answers: quoting a linked EBI back when only
            -- one bearer was asked about tells the SMF the PDN connection is
            -- gone, and our own Delete Session then comes back "context not
            -- found" (cause 64) instead of accepted.
            local ebis, whole_pdn = {}, false
            for _, ie in ipairs(ies_of(wire, 13)) do
                if ie.t == 93 then
                    for _, inner in ipairs(ies_of(ie.v, 1)) do
                        if inner.t == 73 and #inner.v >= 1 then
                            ebis[#ebis + 1] = inner.v:byte(1) % 16
                        end
                    end
                elseif ie.t == 73 then
                    whole_pdn = true
                end
            end

            local ies = string.char(2) .. u16(2) .. string.char(0) ..     -- Cause
                        string.char(gtp.GTP2_CAUSE_REQUEST_ACCEPTED, 0)
            for _, ebi in ipairs(ebis) do
                local inner = string.char(73) .. u16(1) .. string.char(0) ..
                              string.char(ebi) ..
                              string.char(2) .. u16(2) .. string.char(0) ..
                              string.char(gtp.GTP2_CAUSE_REQUEST_ACCEPTED, 0)
                ies = ies .. string.char(93) .. u16(#inner) .. string.char(0) .. inner
            end
            local rsp = string.char(0x48, gtp.GTP2_MT_DELETE_BEARER_RESPONSE) ..
                        u16(8 + #ies) .. u32((sub and sub.pgw_ctrl_teid) or 0) ..
                        u24(seq) .. string.char(0) .. ies
            local ok, err = pcall(function() ep:send_raw(rsp, host, port) end)
            if sub then
                -- The bearer is gone, so media must not stay steered onto it;
                -- the default bearer is always there to fall back to.
                if sub.ded_bearer then
                    for _, e in ipairs(ebis) do
                        if e == sub.ded_bearer.ebi then sub.ded_released = true end
                    end
                end
                if whole_pdn then sub.pdn_gone = true end
                slog(sub, "<> Delete Bearer", ok
                    and ("seq %d, %s released"):format(seq, whole_pdn and "PDN connection"
                         or ("EBI " .. table.concat(ebis, ",")))
                    or  ("seq %d, response failed: %s"):format(seq, why(err)))
            end
        end,

        on_timeout = function(sess, mt)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            if mt == gtp.GTP2_MT_DELETE_SESSION_REQUEST then
                del_done(sub, false, ("no Delete Session response (%d sends)"):format(N3))
            else
                fail(sub, ("PGW did not answer message type %d (after %d sends)"):format(mt, N3))
            end
        end,
    })

    -- Fire off every subscriber's Create Session Request up front; the
    -- endpoint multiplexes the transactions and the callbacks drive each to
    -- registration on the one loop.
    banner("Create Session Requests")

    -- One request, re-filled per subscriber. Everything here is identical for
    -- every UE — the PLMN, ULI and PCO encodings especially, which are three
    -- helper calls returning fresh byte strings — so building a whole message
    -- object per subscriber re-did all of it N times. create_session() copies
    -- the request into the Session it returns, so re-using this one is safe:
    -- nothing downstream keeps a reference to it.
    local CSR = gtp.CreateSessionRequest()
    CSR.apn      = apn
    CSR.rat_type = gtp.GTP2_RAT_EUTRAN
    CSR.pdn_type = gtp.GTP2_PDN_IPV4
    CSR.serving_network = gtp.plmn_encode(mcc, mnc)
    CSR.uli             = gtp.uli_tai_ecgi(mcc, mnc, 0x0001, 0x0000001)
    CSR.has_paa      = true
    CSR.paa.pdn_type = gtp.GTP2_PDN_IPV4
    CSR.paa.addr4    = "0.0.0.0"                     -- request a dynamic IPv4
    CSR.pco = gtp.pco_request_pcscf()                -- ask for the P-CSCF IPv4

    local CSR_C = gtp.Fteid()
    CSR_C.if_type = gtp.GTP2_IF_S5S8C_SGW            -- sender F-TEID: SGW S5/S8-C
    CSR.sender_fteid = CSR_C

    -- The bearer's F-TEID is the one per-subscriber field, so the single
    -- bearer context is rebuilt each time (clear_bearers + add_bearer);
    -- the QoS and EBI on it are constant.
    local CSR_BC = gtp.BearerContext()
    CSR_BC.ebi, CSR_BC.has_qos, CSR_BC.qos.qci = 5, true, 9
    local CSR_U = gtp.Fteid()                        -- bearer F-TEID: SGW S5/S8-U
    CSR_U.if_type, CSR_U.addr4 = gtp.GTP2_IF_S5S8U_SGW, sgw_ip

    -- Point the shared template at one subscriber. Called from inside fire(),
    -- not ahead of it: filling early would let the next subscriber's values
    -- overwrite the template before this one's request left. create_session()
    -- copies what it is given, so one fill-then-send per subscriber is all
    -- that is needed.
    local function fill_csr(sub)
        CSR.imsi   = sub.imsi
        CSR_U.teid = sub.up_teid
        CSR_BC:clear_fteids(); CSR_BC:add_fteid(2, CSR_U)
        CSR:clear_bearers(); CSR:add_bearer(CSR_BC)
        return CSR
    end

    local burst_t0 = now()
    for i = 1, NSUBS do
        local sub = make_sub(i)
        subs[i] = sub
        by_imsi[sub.imsi] = sub

        local sess = ep:create_session(fill_csr(sub), pgw_ip)
        sub.sess = sess
        by_teid[sess:local_teid()] = sub
        if VERBOSE then
            slog(sub, "-> Create Session Req", ("SGW ctrl TEID %#x, IMSI %s"):format(sess:local_teid(), sub.imsi))
        end
    end

    -- How long the attach burst took to leave the client, split into the part
    -- on the caller's path (build + hand off every request) and the part in
    -- the kernel (the endpoint's queue drained with batched sendmmsg — what
    -- the loop would do at the top of its next iteration anyway). With the
    -- direct path the two are the same thing: one sendto per request, inline.
    local offer = now() - burst_t0
    ep:tx_flush()
    stats.burst = { n = NSUBS, offer = offer, total = now() - burst_t0 }

    -- One dispatcher for every socket and timer until the last subscriber is
    -- terminal (registered, rejected or timed out) and the grace elapses.
    local rok, rerr = pcall(function() loop:run() end)

    -- Loop-driven TX accounting, read before the sockets go away. sent/calls
    -- is the batching ratio: datagrams that left per sendmmsg() syscall (1.0 =
    -- one syscall each, as a direct sendto). blocked counts the times the
    -- kernel pushed back and the queue rode it out instead of failing a send.
    local function tx_add(t, s)
        t.sent    = t.sent + s:tx_sent()
        t.calls   = t.calls + s:tx_calls()
        t.blocked = t.blocked + s:tx_blocked()
        t.dropped = t.dropped + s:tx_dropped()
    end
    stats.gtp_tx = { sent = ep:tx_sent(), calls = ep:tx_calls(),
                     blocked = ep:tx_blocked(), dropped = ep:tx_dropped() }
    stats.sip_tx = { sent = 0, calls = 0, blocked = 0, dropped = 0, socks = 0 }
    for _, sub in ipairs(subs) do
        if sub.sock and sub.sock:tx_queued() then
            stats.sip_tx.socks = stats.sip_tx.socks + 1
            tx_add(stats.sip_tx, sub.sock)
        end
    end

    -- ---- media quality, read once the loop has stopped ----
    --
    -- Read here rather than at BYE so late media (rtpengine teardown lag) is
    -- included in the counts. Four independent views per stream, because any
    -- one of them can be the thing that is broken:
    --   1. our own receive stats  — the downlink, as we saw it;
    --   2. the peer's report block — the only measurement of our uplink;
    --   3. RTT from that block's lsr/dlsr;
    --   4. expected-vs-received at a fixed ptime — computed without RTCP at
    --      all, which is what catches "no reports ever arrived" (the shape the
    --      rtpengine routing bug takes) instead of reporting it as no data.
    local M = cstats.media
    for _, c in ipairs(calls) do
        -- A call that never reached its 200 OK still opened both sockets at
        -- INVITE time, and they carried nothing because nothing was ever
        -- negotiated. Those streams are counted APART from the media figures:
        -- folded in, they report a signalling failure as one-way audio, and
        -- when the only call carrying RTP is the one that failed they leave
        -- every quality row reading "no samples" with nothing to say why.
        local connected, counted = c.answered_at ~= nil, 0
        for _, side in ipairs({ { c.sess_mo, c.mstat_mo }, { c.sess_mt, c.mstat_mt } }) do
            local s, st = side[1], side[2]
            if s and st and not connected then
                M.unconnected = M.unconnected + 1
            elseif s and st then
                M.streams = M.streams + 1
                counted = counted + 1
                local ok, sm = pcall(function() return s:stats() end)
                if ok then
                    M.early = M.early + st.early
                    M.late  = M.late + st.late
                    M.tx    = M.tx + sm.tx_packets
                    M.rx    = M.rx + sm.rx_packets
                    M.tx_err = M.tx_err + (st.tx_err or 0)
                    M.tx_why = M.tx_why or st.tx_why
                    if sm.rx_packets == 0 then
                        -- One-way audio: the case loss percentages alone report
                        -- as "no data" rather than as broken.
                        M.zero = M.zero + 1
                    else
                        local recvd = sm.rx_packets
                        local lost  = math.max(0, sm.rx_lost)
                        M.dl_loss[#M.dl_loss + 1] = lost / (recvd + lost) * 100
                        M.dl_jitter[#M.dl_jitter + 1] = sm.rx_jitter / (MEDIA.rate / 1000)
                        -- 4: expected from the elapsed span at a fixed ptime.
                        if st.first and st.last and st.last > st.first then
                            local expect = (st.last - st.first) / MEDIA.ptime_ms + 1
                            M.exp_loss[#M.exp_loss + 1] =
                                math.max(0, (expect - recvd) / expect * 100)
                        end
                    end
                    if sm.rtt_ms >= 0 then M.rtt[#M.rtt + 1] = sm.rtt_ms end
                    if st.reports == 0 then M.no_reports = M.no_reports + 1 end
                    if st.ul_frac then
                        M.ul_loss[#M.ul_loss + 1] = st.ul_frac / 256 * 100
                    end
                    for _, j in ipairs(st.ul_jitter) do
                        M.ul_jitter[#M.ul_jitter + 1] = j
                    end
                    -- MOS from this stream's own numbers: one-way delay taken as
                    -- RTT/2 plus a jitter-buffer allowance of 2*jitter + ptime.
                    if sm.rx_packets > 0 then
                        local jit   = sm.rx_jitter / (MEDIA.rate / 1000)
                        local delay = (sm.rtt_ms >= 0 and sm.rtt_ms / 2 or 0)
                                      + 2 * jit + MEDIA.ptime_ms
                        local lost  = math.max(0, sm.rx_lost)
                        M.mos[#M.mos + 1] =
                            mos_estimate(delay, lost / (sm.rx_packets + lost) * 100)
                    end
                end
            end
        end
        if counted > 0 then M.calls = M.calls + 1 end
    end
    stats.calls = cstats
    if SMS.on then stats.sms = sstats end
    if REGEV.on then stats.regev = ustats end

    -- Datapath counters, read while the datapath is still loaded. Aggregated
    -- over every bearer the run programmed, because the error tallies are the
    -- point: a downlink the network sent on a TEID we never programmed a decap
    -- entry for is counted as err_unknown_teid here and is invisible everywhere
    -- else — the tool would otherwise report it as "the network never answered".
    if up then
        local d = { rx = 0, tx = 0, unknown = 0, malformed = 0, no_neigh = 0, teids = 0 }
        for _, sub in ipairs(subs) do
            for _, b in ipairs({ sub.def_bearer, sub.ded_bearer }) do
                if b and b.local_teid then
                    local oks, s = pcall(function() return up:stats(b.local_teid) end)
                    if oks then
                        d.teids     = d.teids + 1
                        d.rx        = d.rx + s.rx_pkts
                        d.tx        = d.tx + s.tx_pkts
                        d.unknown   = d.unknown + s.err_unknown_teid
                        d.malformed = d.malformed + s.err_malformed
                        d.no_neigh  = d.no_neigh + s.err_tx_no_neigh
                    end
                end
            end
        end
        stats.dp = d
    end

    -- Teardown that needs no loop.
    if xfrm then
        pcall(function() xfrm:flush_policy() end)
        pcall(function() xfrm:flush_sa(ipsec.PROTO_ESP) end)
    end
    -- Media TFTs are per call, so they go before the sockets that used them.
    for _, sub in ipairs(subs) do
        if sub.media_tft then pcall(function() apply_media_tfts(sub, "del") end) end
    end
    for _, sub in ipairs(subs) do
        if sub.sock then
            pcall(function() loop:del_fd(sub.sock:fd()) end)
            sub.sock:close()
        end
        if sub.paa_added then pcall(function() net.addr_del("lo", sub.ue_addr, 32) end) end
    end
    -- The P-CSCF /32 that carried the tunnel MTU; removing it uncovers the
    -- route it shadowed.
    for _, r in pairs(mtu_routes) do pcall(function() net.route_del(r) end) end
    if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n") end
    return subs, stats
end

-- main
local t0 = net.now_ms()
local subs, stats = run()
local elapsed = (net.now_ms() - t0) / 1000

-- Tally registrations and, for the rest, the stage each subscriber reached when
-- it gave up: session setup (GTP-C Create Session), the initial REGISTER / 401
-- challenge, or authentication (AKA verify + the authenticated REGISTER / 200 OK).
local STAGES = {
    { key = "session",  label = "session setup (GTP-C)" },
    { key = "register", label = "REGISTER / 401 challenge" },
    { key = "auth",     label = "authentication / 200 OK" },
    { key = "other",    label = "other / incomplete" },
}
local ok, tally = 0, {}
for _, sub in ipairs(subs) do
    if sub.registered then
        ok = ok + 1
    else
        local k = sub.fail_stage or "other"
        local t = tally[k]
        if not t then t = { n = 0, reasons = {} }; tally[k] = t end
        t.n = t.n + 1
        local r = sub.err or "unknown"
        t.reasons[r] = (t.reasons[r] or 0) + 1
    end
end

-- Teardown accounting: Delete Session responses received / PDN connections established.
local est, torn = 0, 0
for _, sub in ipairs(subs) do
    if sub.pgw_ctrl_teid then est = est + 1; if sub.del_ok then torn = torn + 1 end end
end

banner(("Summary: %d / %d subscriber(s) registered over S5/S8 in %.2fs"):format(ok, #subs, elapsed))
if est > 0 then line("sessions torn down", ("%d / %d (Delete Session)"):format(torn, est)) end
if ok < #subs then
    line("failed", tostring(#subs - ok))
    for _, s in ipairs(STAGES) do
        local t = tally[s.key]
        if t then
            print(("     %-28s %d"):format(s.label, t.n))
            -- distinct reasons within the stage, most frequent first
            local rs = {}
            for r, n in pairs(t.reasons) do rs[#rs + 1] = { r = r, n = n } end
            table.sort(rs, function(a, b) return a.n > b.n end)
            for _, e in ipairs(rs) do print(("        %-45s %d"):format(e.r, e.n)) end
        end
    end
end

-- ---- the call phase: validity first, then setup time, then quality --------

local cs = stats.calls

if stats.dp then
    local d = stats.dp
    banner(("GTP-U datapath (aggregate over %d programmed bearer(s))"):format(d.teids))
    line("decap / encap", ("rx %d pkt, tx %d pkt"):format(d.rx, d.tx))
    if d.unknown + d.malformed + d.no_neigh > 0 then
        line("datapath drops", ("unknown TEID %d, malformed %d, no neighbour %d")
            :format(d.unknown, d.malformed, d.no_neigh))
        if d.unknown > 0 then
            line("", "a G-PDU arrived on a TEID with no decap entry -- most likely a")
            line("", "bearer we accepted in signalling but never steered.")
        end
    end
end

do
    local xe = xfrm_errors()
    if xe and #xe > 0 then
        banner("Kernel ESP drops (non-zero /proc/net/xfrm_stat counters)")
        line("xfrm", table.concat(xe, "  "))
        line("", "a packet counted here was refused by our own kernel, not lost")
        line("", "in the network -- check the SA/policy selectors for that port.")
    end
end

-- Every distribution prints the same way, and always with its n: a percentile
-- over three samples is not a percentile, and the reader has to be able to see
-- that.
local function dist(s, unit, fmt)
    if not s then return "no samples" end
    fmt = fmt or "%.0f"
    return (("p50 " .. fmt .. "  p95 " .. fmt .. "  p99 " .. fmt .. "  max " .. fmt .. " %s  (n=%d)")
        :format(s.p50, s.p95, s.p99, s.max, unit, s.n))
end

-- ---- the registration-state subscription ----------------------------------
--
-- Validity first, as in the SMS phase: a subscription that was accepted and
-- notified but whose document describes some other registration state is a
-- failure, and a louder one than a subscription that was refused outright.
local us = stats.regev
if us and us.attempted > 0 then
    banner(("Reg-event — %d confirmed / %d subscribed (%d of %d subscriber(s) eligible)")
        :format(us.verified, us.attempted, us.eligible, #subs))
    line("accepted (200 OK)", ("%d  (%.1f%%)")
        :format(us.accepted, us.accepted / us.attempted * 100))
    line("notified (reg-info)", ("%d  (%.1f%%)")
        :format(us.notified, us.notified / us.attempted * 100))
    -- The implicit registration set as the network sees it. This is the line
    -- that says, before any INVITE, whether the callee's number is an identity
    -- of the callee's subscription at all.
    local ids = summarize(us.identities)
    if ids then
        line("identities per UE", dist(ids, "", "%.0f"))
    end
    if us.verified > 0 and CALL.uri ~= "sip" then
        line("dialled form present", ("%d / %d reg-info document(s) list it")
            :format(us.dialable, us.verified))
        if us.dialable < us.verified then
            line("", "the address the call phase dials is not among the identities the")
            line("", "HSS returned for these subscribers, so a call to it will come back")
            line("", "404/604 from the I-CSCF or 480 from the S-CSCF -- the same cause the")
            line("", "call phase reports as DIALLED NUMBER UNRESOLVED, with the two fixes.")
        end
    end
    if us.terminated > 0 then
        line("de-registration told", ("%d UE(s) were NOTIFYed that their registration ended")
            :format(us.terminated))
    end
    if us.orphans > 0 then
        line("UNMATCHED NOTIFYs", ("%d — arrived for no subscription of ours"):format(us.orphans))
    end
    if next(us.states) then
        local st = {}
        for s, n in pairs(us.states) do st[#st + 1] = ("%s %d"):format(s, n) end
        table.sort(st)
        line("subscription states", table.concat(st, "  "))
    end

    local REGEV_STAGES = {
        { key = "send",    label = "SUBSCRIBE send failed" },
        { key = "accept",  label = "no 200 OK for the SUBSCRIBE" },
        { key = "notify",  label = "subscribed, never notified" },
        { key = "reginfo", label = "notified, but the state was not this UE's" },
        { key = "guard",   label = "reg-event phase deadline" },
        { key = "unknown", label = "other" },
    }
    local nfail = 0
    for _, t in pairs(us.stage) do nfail = nfail + t.n end
    if nfail > 0 then
        line("failed", tostring(nfail))
        for _, s in ipairs(REGEV_STAGES) do
            local t = us.stage[s.key]
            if t then
                print(("     %-45s %d"):format(s.label, t.n))
                local rs = {}
                for r, n in pairs(t.reasons) do rs[#rs + 1] = { r = r, n = n } end
                table.sort(rs, function(a, b) return a.n > b.n end)
                for _, e in ipairs(rs) do print(("        %-45s %d"):format(e.r, e.n)) end
            end
        end
    end
    if next(us.by_status) then
        local st = {}
        for s, n in pairs(us.by_status) do st[#st + 1] = { s = s, n = n } end
        table.sort(st, function(a, b) return a.n > b.n end)
        for _, e in ipairs(st) do
            print(("     SIP %-40s %d"):format(("%d %s"):format(
                e.s, sip.status_phrase(e.s)), e.n))
        end
        if us.by_status[489] then
            line("", "489 Bad Event: the S-CSCF does not serve the reg package here.")
            line("", "kamailio needs ims_registrar_scscf and a route[SUBSCRIBE] that")
            line("", "calls can_subscribe_to_reg()/subscribe_to_reg(\"location\").")
        end
    end
    -- Accepted but never notified has one cause that is invisible from here
    -- and worth naming, because it is a property of the path rather than of
    -- the core: the reg-info document is the largest thing the network sends
    -- a UE outside a call, and a downlink that does not fit the tunnel is
    -- lost whole (see the downlink size budget above build_in_dialog).
    if us.stage.notify then
        line("", "a subscription accepted and never notified may be a NOTIFY that did")
        line("", "not fit: with 36 bytes of GTP-U on a 1500-byte path the reg-info")
        line("", "document plus its headers is the first downlink big enough to be")
        line("", "fragmented, and a fragment carries no GTP header to classify.")
    end

    banner("Reg-event latency (percentiles, not means — a mean hides the knee)")
    line("SUBSCRIBE -> 200 OK", dist(summarize(us.kpi.accept), "ms"))
    line("SUBSCRIBE -> NOTIFY", dist(summarize(us.kpi.notify), "ms"))
    line("NOTIFY -> our 200 OK", dist(summarize(us.kpi.ack), "ms"))
    if summarize(us.kpi.notify) then
        print("   SUBSCRIBE -> NOTIFY is a true one-way figure: both marks are readings")
        print("   of ONE monotonic clock in this process, so no skew is in it.")
    end
end

if cs and cs.pairs_total > 0 then
    banner(("Call setup — %d answered / %d attempted (%d of %d structural pair(s) eligible)")
        :format(cs.answered, cs.attempted, cs.eligible, cs.pairs_total))
    if cs.attempted > 0 then
        line("ASR (answer/seizure)", ("%.1f%%"):format(cs.answered / cs.attempted * 100))
    end
    line("calls released (BYE)", tostring(cs.released))
    if cs.port_clash and cs.port_clash > 0 then
        line("SHARED P-CSCF PORTS", ("%d call(s): the MO's protected server port is also the")
            :format(cs.port_clash))
        line("", "MT's protected client port, so the P-CSCF sends the terminating")
        line("", "INVITE from the wrong pair. Raise ims_ipsec_pcscf's")
        line("", "ipsec_max_connections to the concurrent UE count and restart it.")
    end

    -- Failure attribution: where a call died, the same way a registration's
    -- stage is reported above.
    local CALL_STAGES = {
        { key = "invite",   label = "INVITE / no response" },
        { key = "ringing",  label = "ringing / no answer" },
        { key = "answered", label = "answered / ACK" },
        { key = "media",    label = "media / talk time" },
        { key = "release",  label = "release (BYE)" },
    }
    for _, s in ipairs(CALL_STAGES) do
        local t = cs.stage[s.key]
        if t then
            print(("     %-28s %d"):format(s.label, t.n))
            local rs = {}
            for r, n in pairs(t.reasons) do rs[#rs + 1] = { r = r, n = n } end
            table.sort(rs, function(a, b) return a.n > b.n end)
            for _, e in ipairs(rs) do print(("        %-45s %d"):format(e.r, e.n)) end
        end
    end

    local KPIS = {
        { k = "pdd",        label = "post-dial delay  t4-t0" },
        { k = "sst",        label = "session setup    t6-t0" },
        { k = "sst_net",    label = "  ... less our ring hold" },
        { k = "mo_transit", label = "MO->MT transit   t2-t0" },
        { k = "mt_transit", label = "MT->MO return    t4-t3" },
        { k = "answer",     label = "answer transit   t6-t5" },
        { k = "cut",        label = "media cut-through t8-t6" },
        { k = "release",    label = "release delay    t10-t9" },
    }
    for _, e in ipairs(KPIS) do
        local s = summarize(cs.kpi[e.k])
        if s then line(e.label, dist(s, "ms")) end
    end
    if summarize(cs.kpi.mo_transit) then
        line("", "(transit figures are true one-way latencies: both UEs share this")
        line("", " process's monotonic clock, so there is no skew to correct for)")
    end

    -- Failure counts by SIP status, most frequent first.
    local by_st = {}
    for st, n in pairs(cs.by_status) do by_st[#by_st + 1] = { st = st, n = n } end
    table.sort(by_st, function(a, b) return a.n > b.n end)
    for _, e in ipairs(by_st) do
        line(("failed %d %s"):format(e.st, sip.status_phrase(e.st)), tostring(e.n))
    end

    -- A number the HSS profile does not carry is its own failure, and an easy
    -- one to misread: the I-CSCF answers 404 (no such public identity) or the
    -- S-CSCF 480 (the identity exists but nothing is registered against it)
    -- while registration, IPsec and the datapath all look healthy. Name it,
    -- with both fixes, whenever a number was dialled and those came back.
    if CALL.uri ~= "sip"
       and (cs.by_status[404] or cs.by_status[604] or cs.by_status[480]) then
        line("DIALLED NUMBER UNRESOLVED", ("the callee was addressed as %s")
            :format(subs[2] and subs[2].dial or ("a " .. CALL.uri .. " URI")))
        line("", "the HSS must return that number as a public identity of the")
        line("", "callee's subscription: cx_hss.lua does (HSS_MSISDN, and the")
        line("", "same IMS_MSISDN_CC / IMS_MSISDN_DIGITS as here), a real HSS")
        line("", "needs the MSISDN provisioned for the IMSI range. CALL_URI=phone")
        line("", "dials the sip;user=phone form instead if the core will not route")
        line("", "a tel: Request-URI, CALL_URI=sip dials the sip IMPU and needs no")
        line("", "number at all.")
    end

    -- ---- media quality ----
    local M = cs.media
    if M.streams > 0 then
        banner(("Media quality — %d stream(s) over %d of %d call(s) carrying RTP  [%s, %d ms, RTCP %d ms]")
            :format(M.streams, M.calls, cs.media_calls,
                    MEDIA.pt == 0 and "G.711 PCMU" or ("payload type " .. MEDIA.pt),
                    MEDIA.ptime_ms, MEDIA.rtcp_ms))
        line("packets sent / received", ("%d / %d"):format(M.tx, M.rx))
        if M.tx_err > 0 then
            line("SEND FAILURES", ("%d packet(s) never left the socket: %s")
                :format(M.tx_err, tostring(M.tx_why)))
        end
        line("downlink loss (ours)",  dist(summarize(M.dl_loss), "%", "%.2f"))
        line("downlink jitter",       dist(summarize(M.dl_jitter), "ms", "%.2f"))
        line("uplink loss (peer RR)", dist(summarize(M.ul_loss), "%", "%.2f"))
        line("uplink jitter (RR)",    dist(summarize(M.ul_jitter), "ms", "%.2f"))
        line("round trip (lsr/dlsr)", dist(summarize(M.rtt), "ms", "%.2f"))
        line("expected-vs-received",  dist(summarize(M.exp_loss), "%", "%.2f"))
        -- Labelled at the point of printing, so the number cannot be re-read
        -- later as a decoded-audio score.
        line("MOS (G.107 estimate)",  dist(summarize(M.mos), "", "%.2f"))
        line("", "MOS is estimated from packet statistics only -- no audio is")
        line("", "decoded, so it is not PESQ/POLQA.")
        if M.zero > 0 then
            line("ONE-WAY AUDIO", ("%d of %d stream(s) received nothing at all")
                :format(M.zero, M.streams))
        end
        if M.unconnected > 0 then
            line("streams not counted", ("%d belonged to call(s) that never answered")
                :format(M.unconnected))
        end
        if M.no_reports > 0 then
            line("no RTCP received", ("%d stream(s) -- uplink figures come from fewer streams")
                :format(M.no_reports))
        end
        if M.early > 0 then line("early media", ("%d packet(s) before the 200 OK"):format(M.early)) end
        if M.late > 0 then line("late media", ("%d packet(s) after the BYE (relay teardown lag)"):format(M.late)) end
    elseif M.unconnected > 0 then
        -- The distinction that matters: nothing was measured because no call
        -- carrying RTP ever connected. Said plainly here, because the
        -- alternative — a page of "no samples" — reads as a media fault.
        banner(("Media quality — nothing to measure: every RTP call failed before the answer (%d stream(s))")
            :format(M.unconnected))
        line("", "the sockets opened at INVITE time and no SDP was ever negotiated,")
        line("", "so no RTP was expected. The cause is in the call-failure")
        line("", "attribution above, not in the media path.")
    elseif cs.media_calls > 0 then
        banner("Media quality — no stream opened (media sockets need CAP_NET_ADMIN for the PAA source)")
    end
end

-- ---- the SMS phase --------------------------------------------------------
--
-- Validity first (did the content survive), then the per-hop latencies. The
-- percentiles are reported rather than means for the same reason the call
-- phase reports them: a mean hides the knee, and the knee is the finding.
local ss = stats.sms
if ss and ss.pairs_total > 0 then
    banner(("SMS — %d delivered / %d submitted (%d of %d structural pair(s) eligible)")
        :format(ss.delivered, ss.attempted, ss.eligible, ss.pairs_total))
    if ss.attempted > 0 then
        line("delivery rate", ("%.1f%%"):format(ss.delivered / ss.attempted * 100))
        line("accepted (202)", ("%d  (%.1f%%)"):format(
            ss.accepted, ss.accepted / ss.attempted * 100))
        line("acknowledged (RP-ACK)", ("%d  (%.1f%%)"):format(
            ss.acked, ss.acked / ss.attempted * 100))
    end
    if ss.reports > 0 then line("status reports", tostring(ss.reports)) end
    if ss.orphans > 0 then
        line("UNMATCHED deliveries", ("%d — arrived but match no submit"):format(
            ss.orphans))
    end

    -- Content integrity: the assertion the whole phase exists for. A byte
    -- difference is a codec bug — the UDH septet alignment, the TP-UDL units,
    -- an alphabet mapping — and no amount of successful signalling reveals it.
    local nmis = 0
    for _, n in pairs(ss.mismatch) do nmis = nmis + n end
    if next(ss.by_matrix) then
        local names = {}
        for n in pairs(ss.by_matrix) do names[#names + 1] = n end
        table.sort(names)
        local parts = {}
        for _, n in ipairs(names) do
            local m = ss.by_matrix[n]
            parts[#parts + 1] = ("%s %d/%d"):format(n, m.ok, m.sent)
        end
        line("content verified", table.concat(parts, "  "))
    end
    if nmis > 0 then
        line("CONTENT MISMATCHES", ("%d — the received text differs from what was sent")
            :format(nmis))
        for n, c in pairs(ss.mismatch) do
            print(("     %-28s %d"):format(n, c))
        end
    end

    -- Failure attribution: the furthest hop each failed message reached.
    local SMS_STAGES = {
        { key = "send",     label = "MESSAGE send failed" },
        { key = "accept",   label = "no 202 for the submit" },
        { key = "rp_error", label = "refused (RP-ERROR)" },
        { key = "transit",  label = "accepted, never delivered" },
        { key = "mt_ack",   label = "delivered, recipient never acknowledged" },
        { key = "mo_ack",   label = "delivered, no RP-ACK to the sender" },
        { key = "report_failed", label = "status report says not delivered" },
        { key = "guard",    label = "SMS phase deadline" },
        { key = "unknown",  label = "other" },
    }
    local nfail = 0
    for _, n in pairs(ss.stage) do nfail = nfail + n end
    if nfail > 0 then
        line("failed", tostring(nfail))
        for _, s in ipairs(SMS_STAGES) do
            local n = ss.stage[s.key]
            if n then print(("     %-45s %d"):format(s.label, n)) end
        end
    end
    if next(ss.by_cause) then
        local cs2 = {}
        for c, n in pairs(ss.by_cause) do cs2[#cs2 + 1] = { c = c, n = n } end
        table.sort(cs2, function(a, b) return a.n > b.n end)
        for _, e in ipairs(cs2) do
            print(("     RP-ERROR %-36s %d"):format(sms.rp_cause_name(e.c), e.n))
        end
    end
    if next(ss.by_status) then
        local st = {}
        for s, n in pairs(ss.by_status) do st[#st + 1] = { s = s, n = n } end
        table.sort(st, function(a, b) return a.n > b.n end)
        for _, e in ipairs(st) do
            print(("     SIP %-40s %d"):format(("%d %s"):format(
                e.s, sip.status_phrase(e.s)), e.n))
        end
    end

    local k = ss.kpi
    banner("SMS latency (percentiles, not means — a mean hides the knee)")
    line("submit -> 202 Accepted", dist(summarize(k.accept), "ms"))
    line("submit -> MT delivery",  dist(summarize(k.transit), "ms"))
    line("delivery -> 200 OK",     dist(summarize(k.deliver_ok), "ms"))
    line("submit -> recipient ACK", dist(summarize(k.total), "ms"))
    line("submit -> sender RP-ACK", dist(summarize(k.ack), "ms"))
    if #k.report > 0 then
        line("submit -> status report", dist(summarize(k.report), "ms"))
    end
    print("   submit -> MT delivery is a true one-way core latency: both marks are")
    print("   readings of ONE monotonic clock in this process, so no skew is in it.")
end

-- Throughput: per-second rates for the load. Each rate is measured from the
-- first Create Session Request (stats.start) to the last event of its kind, so
-- the 3s grace + teardown don't dilute the active-burst figures. per_s returns
-- the rate and the window it was computed over (0/0 when nothing happened).
local function per_s(n, last)
    if n == 0 or not last then return 0, 0 end
    local w = (last - stats.start) / 1000
    if w <= 0 then return 0, 0 end
    return n / w, w
end
local sess_r, sess_w = per_s(stats.sess, stats.sess_last)
local reg_r,  reg_w  = per_s(stats.regs, stats.reg_last)
local tx_r = per_s(stats.tx, stats.pkt_last)
local rx_r = per_s(stats.rx, stats.pkt_last)
banner("Throughput (rates from first Create Session Request)")
line("sessions created",     ("%d in %.2fs  ->  %.1f/s"):format(stats.sess, sess_w, sess_r))

line("SIP packets sent",     ("%d  ->  %.1f/s"):format(stats.tx, tx_r))
line("SIP packets received", ("%d  ->  %.1f/s"):format(stats.rx, rx_r))

line("registrations",        ("%d in %.2fs  ->  %.1f/s"):format(stats.regs, reg_w, reg_r))

-- Subscriptions get their own window too (first SUBSCRIBE to last NOTIFY), so
-- the registration burst before them does not dilute the figure.
if us and us.attempted > 0 and us.first then
    local w = ((us.last or us.first) - us.first) / 1000
    line("subscriptions", w > 0
        and ("%d confirmed in %.2fs  ->  %.1f/s"):format(us.verified, w, us.verified / w)
        or  ("%d confirmed (single burst, under one clock tick)"):format(us.verified))
end

-- Calls are rated over their own window (first INVITE to last answer) so the
-- registration phase that precedes them does not dilute the figure, exactly as
-- the rates above exclude the grace and teardown.
if cs and cs.attempted > 0 then
    local w = ((cs.last_answer or cs.first_invite) - cs.first_invite) / 1000
    line("calls attempted",  ("%d  (%d answered, %d released)")
        :format(cs.attempted, cs.answered, cs.released))
    line("calls answered",   w > 0
        and ("%d in %.2fs  ->  %.1f/s"):format(cs.answered, w, cs.answered / w)
        or  ("%d (single burst, under one clock tick)"):format(cs.answered))
end

if stats.burst then
    local b = stats.burst
    line("Create Session burst", ("%d request(s) offered in %dms, on the wire in %dms  ->  %.0f/s")
        :format(b.n, b.offer, b.total, b.n / math.max(b.total, 1) * 1000))
end

if ss and ss.attempted > 0 and ss.first_submit then
    local w = ((ss.last_delivery or ss.first_submit) - ss.first_submit) / 1000
    line("messages submitted", ("%d  (%d delivered, %d verified)")
        :format(ss.attempted, ss.delivered, ss.verified))
    line("messages delivered", w > 0
        and ("%d in %.2fs  ->  %.1f/s"):format(ss.delivered, w, ss.delivered / w)
        or  ("%d (single burst, under one clock tick)"):format(ss.delivered))
end

-- A run passes when every subscriber registered, every subscription it opened
-- was confirmed by a document describing that subscriber's own registration,
-- every call it actually placed was answered, and every message it sent
-- arrived with its content intact. A phase that was switched off, or had no
-- eligible pair (IMS_SUBS=1), is not held against the run — but a message that
-- arrived corrupted is, and so is a reg-info document that described the wrong
-- state, because those are the failures those phases exist to catch.
local calls_ok = not cs or cs.attempted == 0 or cs.answered == cs.attempted
local sms_ok = not ss or ss.attempted == 0
    or (ss.delivered == ss.attempted and ss.verified == ss.attempted)
local regev_ok = not us or us.attempted == 0 or us.verified == us.attempted
os.exit((ok == #subs and regev_ok and calls_ok and sms_ok) and 0 or 1)
