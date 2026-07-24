#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] [IMS_SUBS=N] \
--     lua ims_test_s5.lua
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
--   3. Verify AUTN, derive CK/IK, install four transport-mode ESP SAs.
--   4. REGISTER (protected, ESP) to the P-CSCF's protected server port with
--      the AKAv1-MD5 digest and a Security-Verify; then 200 OK.
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
-- ones. The dedicated bearer from a Create Bearer Request is accepted but
-- not probed.
--
-- Installing ESP SAs and the transparent UE socket needs CAP_NET_ADMIN;
-- each kernel op degrades to a reported line when refused.
--

local gtp   = require("gtp")   -- GTPv2-C + typed messages + PLMN/ULI/PCO helpers
local net   = require("net")   -- event loop + UDP socket + DNS + interface/route
local sip   = require("sip")   -- codec + Registration / AuthChallenge / Transaction FSMs
local ipsec = require("ipsec") -- Milenage (aka_verify) + AKAv1-MD5 digest + Xfrm

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

local T3_MS, N3  = 1000, 3     -- GTP-C retransmission: 1s T3-RESPONSE, up to 3 sends
local SIP_T_MS   = 5000        -- SIP response deadline per registration step
local AUTH_CAP   = 2           -- give up after this many 401 challenges

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

local function banner(t) print(("\n== %s"):format(t)) end
local function line(k, v) print(("   %-24s %s"):format(k, v)) end
local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end

-- Prefix a log line with the subscriber index when running more than one.
local function slog(sub, k, v) line(NSUBS > 1 and ("[%d] %s"):format(sub.i, k) or k, v) end

-- Run a kernel op (ESP SA / policy install), turning a CAP_NET_ADMIN
-- rejection into one reported line rather than aborting the run.
local function attempt(sub, what, fn)
    local ok, err = pcall(fn)
    slog(sub, what, ok and "ok" or ("skipped (" .. why(err) .. ")"))
    return ok
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
-- follow from it. Keys stay shared, so the HSS must provision this range.
local function make_sub(i)
    local idx  = i - 1
    local imsi = ("%015.0f"):format(tonumber(base_imsi) + idx)
    return {
        i = i, idx = idx,
        imsi = imsi,
        impu = ("sip:%s@%s"):format(imsi, ims_realm),
        impi = ("%s@%s"):format(imsi, ims_realm),
        up_teid  = S5_UP_TEID_BASE + idx * 0x10,       -- default bearer S5/S8-U TEID
        ded_teid = S5_UP_TEID_BASE + idx * 0x10 + 1,   -- dedicated (media) bearer TEID
        port_uc  = PORT_UC_BASE + idx * 4,             -- UE protected client port
        port_us  = PORT_US_BASE + idx * 4,             -- UE protected server port
        spi_uc   = SPI_BASE + idx * 2,                 -- UE inbound SPIs (client / server)
        spi_us   = SPI_BASE + idx * 2 + 1,
        reg  = sip.Registration(), auth = sip.AuthChallenge(),
        cseq = 0, attempts = 0,
        ue_addr = nil, pcscf = nil, pgw_ctrl_teid = nil,
        sig_teid = nil, remote_addr = nil, rx0 = nil,
        sock = nil, timer = nil, txn = nil, ch = nil,
        registered = false, done = false, paa_added = false, err = nil,
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
-- SPIs, its protected client/server ports and the ESP algorithms.
local function security_client(sub)
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(sub.spi_uc, sub.spi_us, sub.port_uc, sub.port_us)
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
local function build_register(sub, authz, sec_name, sec_hdr)
    local b = sip.Builder()
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(sub.ue_addr, sub.port_uc, sub.imsi, sub.cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(sub.impu, sub.imsi, sub.cseq))
        :header(sip.H_TO, ("<%s>"):format(sub.impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(sub.imsi, sub.ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(sub.cseq))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(sub.ue_addr, sub.port_uc))
        :header_u32(sip.H_EXPIRES, 600000)
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

-- Install the four transport-mode ESP SAs and steering policies (TS 33.203
-- Annex I: IK integrity-protects, CK encrypts). Keyed by the receiver's SPI;
-- the UE-side SPIs/ports and PAA are per-subscriber so a shared Xfrm handle
-- keeps every subscriber's SAs distinct.
local function establish_sas(xfrm, sub, ch, keys)
    local function esp_sa(src, dst, spi, reqid)
        local sa = ipsec.Sa()
        sa.src, sa.dst, sa.spi = src, dst, spi
        sa.proto, sa.mode, sa.reqid = ipsec.PROTO_ESP, ipsec.TRANSPORT, reqid
        sa.enc_alg,  sa.enc_key  = "cbc(aes)",   keys.ck
        sa.auth_alg, sa.auth_key = "hmac(sha1)", keys.ik
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
    local pols = {
        esp_policy(ipsec.DIR_OUT, ue, pcscf, sub.port_uc, ch.p_port_s, ch.p_spi_s),
        esp_policy(ipsec.DIR_OUT, ue, pcscf, sub.port_us, ch.p_port_c, ch.p_spi_c),
        esp_policy(ipsec.DIR_IN,  pcscf, ue, ch.p_port_s, sub.port_uc, sub.spi_uc),
        esp_policy(ipsec.DIR_IN,  pcscf, ue, ch.p_port_c, sub.port_us, sub.spi_us),
    }
    slog(sub, "ESP keys", ("enc(CK)=%s auth(IK)=%s"):format(hex(keys.ck), hex(keys.ik)))
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
    line("IMSI range", ("%s .. %s (shared keys)"):format(base_imsi, ("%015.0f"):format(tonumber(base_imsi) + NSUBS - 1)))

    local loop = net.Loop()
    local ok, ep = pcall(gtp.Endpoint, loop, sgw_ip)     -- binds sgw_ip:2123 (GTP-C)
    if not ok then
        io.stderr:write(("cannot bind GTP-C on %s:2123: %s\n"):format(sgw_ip, why(ep)))
        os.exit(1)
    end
    ep:set_t3_ms(T3_MS)
    ep:set_n3(N3)

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

    -- Per-subscriber SIP deadline over the shared loop.
    local function disarm(sub) if sub.timer then loop:cancel(sub.timer); sub.timer = nil end end
    local function arm(sub, ms, fn) disarm(sub); sub.timer = loop:after(ms, function() sub.timer = nil; fn() end) end

    -- forward declarations for the mutually-referring phase steps
    local begin_registration, on_sip_readable, handle_sip, on_401, on_registered

    -- A subscriber reached a terminal state; when the last one does, wait a
    -- little for late Create Bearer Requests, then stop the loop.
    local function finish(sub)
        if sub.done then return end
        sub.done = true
        disarm(sub)
        pending = pending - 1
        if pending > 0 then return end
        if grace then return end
        grace = loop:after(3000, function() grace = nil; loop:stop() end)
    end
    local function fail(sub, msg)
        sub.err = msg
        slog(sub, "result", "FAILED: " .. msg)
        finish(sub)
    end
    local function succeed(sub)
        sub.registered = true
        slog(sub, "result", ("registered at P-CSCF %s"):format(sub.pcscf or "?"))
        finish(sub)
    end

    -- Steer a subscriber's SIP onto its default bearer with two TFTs (UDP for
    -- the plain REGISTER, ESP for the protected one). ue_saddr = the UE's PAA
    -- is the inner-source match that keeps concurrent subscribers registering
    -- to the one P-CSCF on their own bearers; add_filter also installs the
    -- shared decap entry so the 401/200 return down this bearer.
    local function program_filter(sub, tun)
        sub.sig_teid    = tun.local_teid
        sub.remote_addr = tun.remote_addr
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

    -- Confirm a downlink reply arrived through the decap entry.
    local function report_rx(sub, what)
        if not (up and sub.sig_teid and sub.rx0) then return end
        local drx = up:stats(sub.sig_teid).rx_pkts - sub.rx0.rx_pkts
        if drx > 0 then
            slog(sub, "GTP-U decap", ("%s via downlink (rx +%d on TEID %#x)"):format(what, drx, sub.sig_teid))
        end
    end

    -- Send `wire` and feed it to the subscriber's three FSMs in lock-step.
    local function send_register(sub, wire, label, dport)
        local m = sip.parse(wire)
        sub.txn = sip.Transaction(sip.NON_INVITE_CLIENT)
        pcall(function() sub.reg:send(m); sub.auth:send(m); sub.txn:send(m) end)
        local sok, serr = pcall(function() sub.sock:sendto(wire, sub.pcscf, dport) end)
        if not sok then return fail(sub, "REGISTER send: " .. why(serr)) end
        slog(sub, "-> REGISTER", ("%s, %dB -> %s:%d"):format(label, #wire, sub.pcscf, dport))
        arm(sub, SIP_T_MS, function() fail(sub, "timed out awaiting a SIP response") end)
    end

    -- ---- SIP receive: drain the socket, drive the FSMs, dispatch ----
    on_sip_readable = function(sub)
        while true do
            local dg = sub.sock:recv(-1)
            if dg.timed_out then return end
            local okp, m = pcall(sip.parse, dg.data)
            if okp then handle_sip(sub, m)
            else slog(sub, "SIP", "ignoring unparseable datagram") end
        end
    end

    handle_sip = function(sub, m)
        disarm(sub)
        pcall(function() if sub.txn then sub.txn:recv(m) end end)
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
            succeed(sub)
        elseif sub.reg:failed() then
            fail(sub, ("registration rejected: %d %s"):format(m.status, m.reason))
        end
    end

    -- Round 2: verify the AKA challenge, derive RES/CK/IK; with a
    -- Security-Server raise the ESP SAs and send the protected REGISTER (the
    -- kernel ESP-wraps it, egressing as proto 50) with a Security-Verify.
    -- Without one, fall back to an unprotected authenticated REGISTER.
    on_401 = function(sub, m401)
        local okc, ch = pcall(parse_challenge, m401)
        if not okc then return fail(sub, "cannot parse 401 challenge: " .. why(ch)) end
        sub.ch = ch
        slog(sub, "<- 401", ("IMS-AKA challenge (RAND %s)"):format(hex(ch.rand)))

        local okv, keys = pcall(function() return ipsec.aka_verify(K, OPc, ch.rand, ch.autn) end)
        if not okv then return fail(sub, "AKA AUTN verification failed: " .. why(keys)) end
        slog(sub, "AUTN verified", ("SQN %s, RES %s"):format(hex(keys.sqn), hex(keys.res)))

        sub.cseq = sub.cseq + 1
        local nc, cnonce = "00000001", hex(ipsec.md5(sub.imsi .. tostring(sub.cseq)):sub(1, 8))
        local response = ipsec.aka_digest(sub.impi, ch.realm, keys.res, "REGISTER",
                                          "sip:" .. ims_realm, ch.nonce, nc, cnonce, ch.qop or "")
        local authz = authz_hdr(sub, ch.realm, ch.nonce, response,
                                ch.qop and { qop = ch.qop, nc = nc, cnonce = cnonce })

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
            slog(sub, "registration", "skipped (no P-CSCF/UE address)")
            return finish(sub)
        end
        add_paa_route(sub)

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
        loop:add_fd(sub.sock:fd(), net.NET_RD, function() on_sip_readable(sub) end)

        if up and sub.sig_teid then sub.rx0 = up:stats(sub.sig_teid) end

        sub.cseq = sub.cseq + 1
        local reg1 = build_register(sub, authz_hdr(sub, ims_realm, "", ""),
                                    "Security-Client", security_client(sub))
        send_register(sub, reg1, "unprotected", PCSCF_SIP_PORT)
    end

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
            sub.pgw_ctrl_teid = sess:remote_teid()
            if rsp.has_paa then sub.ue_addr = rsp.paa.addr4 end
            if rsp.pco and #rsp.pco > 0 then
                local p = gtp.pco_pcscf_v4(rsp.pco)
                sub.pcscf = p ~= "" and p or nil
            end
            slog(sub, "<- Create Session Resp", ("PAA %s, P-CSCF %s"):format(sub.ue_addr or "?", sub.pcscf or "none"))
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
        -- (correlated by the request's header TEID = our control TEID). It is a
        -- media bearer, so it is reported but not programmed/probed.
        on_create_bearer_request = function(req, host, port)
            local sub = by_teid[req.teid]
            local pgw_u
            if req.bearers:size() > 0 then
                local fts = req.bearers[0].fteids
                if fts:size() > 0 then pgw_u = fts[0].fteid end
            end
            local NEW_EBI = 6
            local rbc = gtp.BearerContext()
            rbc.ebi, rbc.cause = NEW_EBI, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, (sub and sub.ded_teid) or (S5_UP_TEID_BASE - 1), sgw_ip
            rbc:add_fteid(2, u)
            if pgw_u then rbc:add_fteid(3, pgw_u) end

            local resp = gtp.CreateBearerResponse()
            resp.teid     = (sub and sub.pgw_ctrl_teid) or 0
            resp.sequence = req.sequence
            resp.cause    = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            resp.pti      = req.pti
            resp:add_bearer(rbc)
            ep:send_create_bearer_response(resp, host, port)
            if sub then slog(sub, "<> Create Bearer", ("seq %d, EBI %d accepted (media)"):format(req.sequence, NEW_EBI)) end
        end,

        on_timeout = function(sess, mt)
            local sub = by_imsi[sess:imsi()]
            if sub then fail(sub, ("PGW did not answer message type %d (after %d sends)"):format(mt, N3)) end
        end,
    })

    -- Fire off every subscriber's Create Session Request up front; the
    -- endpoint multiplexes the transactions and the callbacks drive each to
    -- registration on the one loop.
    banner("Create Session Requests")
    for i = 1, NSUBS do
        local sub = make_sub(i)
        subs[i] = sub
        by_imsi[sub.imsi] = sub

        local req = gtp.CreateSessionRequest()
        req.imsi     = sub.imsi
        req.apn      = apn
        req.rat_type = gtp.GTP2_RAT_EUTRAN
        req.pdn_type = gtp.GTP2_PDN_IPV4
        req.serving_network = gtp.plmn_encode(mcc, mnc)
        req.uli             = gtp.uli_tai_ecgi(mcc, mnc, 0x0001, 0x0000001)
        req.has_paa      = true
        req.paa.pdn_type = gtp.GTP2_PDN_IPV4
        req.paa.addr4    = "0.0.0.0"                 -- request a dynamic IPv4
        req.pco = gtp.pco_request_pcscf()            -- ask for the P-CSCF IPv4

        local c = gtp.Fteid()
        c.if_type = gtp.GTP2_IF_S5S8C_SGW            -- sender F-TEID: SGW S5/S8-C
        req.sender_fteid = c

        local bc = gtp.BearerContext()
        bc.ebi, bc.has_qos, bc.qos.qci = 5, true, 9
        local u = gtp.Fteid()                        -- bearer F-TEID: SGW S5/S8-U
        u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, sub.up_teid, sgw_ip
        bc:add_fteid(2, u)
        req:add_bearer(bc)

        local sess = ep:create_session(req, pgw_ip)
        by_teid[sess:local_teid()] = sub
        slog(sub, "-> Create Session Req", ("SGW ctrl TEID %#x, IMSI %s"):format(sess:local_teid(), sub.imsi))
    end

    -- One dispatcher for every socket and timer until the last subscriber is
    -- terminal (registered, rejected or timed out) and the grace elapses.
    local rok, rerr = pcall(function() loop:run() end)

    -- Teardown that needs no loop.
    if xfrm then
        pcall(function() xfrm:flush_policy() end)
        pcall(function() xfrm:flush_sa(ipsec.PROTO_ESP) end)
    end
    for _, sub in ipairs(subs) do
        if sub.sock then
            pcall(function() loop:del_fd(sub.sock:fd()) end)
            sub.sock:close()
        end
        if sub.paa_added then pcall(function() net.addr_del("lo", sub.ue_addr, 32) end) end
    end
    if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n") end
    return subs
end

-- main
local subs = run()
local ok = 0
for _, sub in ipairs(subs) do if sub.registered then ok = ok + 1 end end
banner(("Summary: %d / %d subscriber(s) registered over S5/S8"):format(ok, #subs))
os.exit(ok == #subs and 0 or 1)
