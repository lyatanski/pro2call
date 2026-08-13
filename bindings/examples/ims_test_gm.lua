#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PCSCF_IP=pcscf] [IMS_SUBS=N] lua ims_test_gm.lua
--
-- IMS registration over Gm with IMS-AKA and IPsec, and nothing else: N
-- subscribers (IMS_SUBS, default 1) register with the P-CSCF concurrently on one
-- net.Loop, straight over the access network — no GTP tunnel under them, no
-- calls, no SMS, no reg-event subscription.
--
-- bindings/examples/ims_test_s5.lua is this same registration carried over an
-- S5/S8 PDN connection, plus every phase that follows it. Keeping the Gm leg on
-- its own is what makes it the first probe to run against a stack: when it
-- fails, the fault is in the IMS (P-CSCF / I-CSCF / S-CSCF / HSS) or in the USIM
-- keys, because there is no PGW, no eBPF datapath and no bearer in the path to
-- be the other explanation — and ims_test_s5.lua's registration failures can
-- only be read as core faults once this one passes.
--
-- The flow per subscriber (RFC 3261 §10, TS 24.229 §5.1, TS 33.203 §6.1/§6.3):
--
--   1. REGISTER (unprotected, UDP:5060) with an empty AKAv1-MD5 Authorization
--      that advertises IMS-AKA, and a Security-Client offer carrying the UE's
--      two inbound SPIs, its protected ports and the ESP algorithms.
--   2. 401 with the AKA challenge (nonce = base64(RAND||AUTN)) and the P-CSCF's
--      Security-Server (its SPIs and protected ports).
--   3. Verify AUTN against the USIM secret, derive RES/CK/IK, install the four
--      transport-mode ESP SAs and the policies that steer traffic onto them.
--   4. REGISTER (protected, ESP) from the UE's protected client port to the
--      P-CSCF's protected server port, carrying the AKAv1-MD5 digest computed
--      from RES and a Security-Verify; then 200 OK.
--   5. IMS_DEREG=1 (the default) releases the binding with an Expires:0
--      REGISTER over the same SA. That is what makes the P-CSCF destroy its half
--      of the IPsec state — contact expiry does not reap it, and a stack left
--      holding SAs from earlier runs registers fewer UEs on each one.
--
-- The SIP is driven by the sip module's own machines: a `sip.Registration`
-- (§10) composed with a `sip.AuthChallenge` (§22 digest) and a per-REGISTER
-- `sip.Transaction` (§17.1.2), fed the traffic and read back for state — the
-- same composition sip_register.lua walks offline, so there is no hand-rolled
-- phase variable here either.
--
-- The UE's source address is a real address of this host (IMS_UE_IP, by default
-- the first IPv4 address of IMS_UE_IFACE): over Gm the P-CSCF replies to the
-- address it received the REGISTER from, so that address has to be routable
-- back here. Subscribers share it and are separated by port and SPI, so one
-- container address carries all of them.
--
-- Installing ESP SAs needs CAP_NET_ADMIN. Each kernel op degrades to a reported
-- line when refused, and since an unprotected "protected" REGISTER is dropped by
-- the P-CSCF the summary names the missing capability rather than reporting a
-- plain registration failure.
--
-- One stack-side failure mode is worth naming here, because from the UE side it
-- is indistinguishable from a dead core: a P-CSCF that hands out an SPI it has
-- used before WITHOUT having deleted the old SA (kamailio's ims_ipsec_pcscf logs
-- `clean_sa(): Error sending delete SAs command via netlink socket` when its
-- delete path fails) is left holding a state — the kernel keys one by
-- destination and SPI, so the old one answers for the new offer — whose replay
-- window has already advanced. Our fresh SA starts at sequence 1, so its kernel
-- discards the protected REGISTER as a replay, silently, before kamailio ever
-- sees it. The signature is exact: the ESP packet is on the wire, nothing comes
-- back, OUR xfrm counters are all zero, and the P-CSCF's own
-- XfrmInStateSeqError climbs — `docker exec <pcscf> grep -v " 0$"
-- /proc/net/xfrm_stat`. Restarting the P-CSCF clears it; there is nothing the UE
-- side can do about it, which is why the summary points at it rather than
-- pretending otherwise.

local net   = require("net")   -- event loop + UDP socket + DNS + interface helpers
local sip   = require("sip")   -- codec + Registration / AuthChallenge / Transaction FSMs
local ipsec = require("ipsec") -- Milenage (aka_verify) + AKAv1-MD5 digest + Xfrm

-- ---- configuration ----------------------------------------------------

local pcscf_host     = os.getenv("PCSCF_IP")   or "pcscf"   -- a name or a literal IP
local PCSCF_SIP_PORT = tonumber(os.getenv("PCSCF_PORT") or "5060")
local mcc            = os.getenv("IMS_MCC")    or "001"     -- serving PLMN (matches the IMSI
local mnc            = os.getenv("IMS_MNC")    or "01"      -- and the mnc01.mcc001 core realm)
local base_imsi      = os.getenv("IMS_IMSI")   or "001010000000001"
local NSUBS          = math.max(1, math.floor(tonumber(os.getenv("IMS_SUBS") or "1") or 1))

-- Home network domain (TS 23.003); the MNC is zero-padded to three digits.
local function mnc3(n) return (#n == 2) and ("0" .. n) or n end
local ims_realm = os.getenv("IMS_REALM")
    or ("ims.mnc%s.mcc%s.3gppnetwork.org"):format(mnc3(mnc), mcc)

local SIP_T_MS    = tonumber(os.getenv("SIP_T_MS") or "5000")      -- deadline per REGISTER step
local AUTH_CAP    = 2                                             -- give up after this many 401s
local REG_EXPIRES = tonumber(os.getenv("IMS_EXPIRES") or "600000")
local DEREG       = (os.getenv("IMS_DEREG") or "1") ~= "0"

-- IMS_IPSEC=1 (the default) treats a 401 without a Security-Server as a
-- failure: this test exists to exercise IMS-AKA *with* IPsec, and a P-CSCF that
-- offers no SAs would otherwise let the run report a clean pass for a
-- registration that never negotiated any security at all. =0 permits the
-- digest-only fallback, for a core with ipsec turned off.
local REQUIRE_IPSEC = (os.getenv("IMS_IPSEC") or "1") ~= "0"

-- The UE's own address: a real address of this host, since the P-CSCF answers
-- whatever it received the REGISTER from. IMS_UE_IP overrides it (an address
-- this host does not own is bound with IP_FREEBIND + IP_TRANSPARENT, which then
-- needs the reply routed back here by something else).
local ue_iface = os.getenv("IMS_UE_IFACE") or "eth0"
local ue_addr  = os.getenv("IMS_UE_IP")
if not ue_addr or ue_addr == "" then ue_addr = net.if_addr4(ue_iface) end
if not ue_addr or ue_addr == "" then
    io.stderr:write(("no IPv4 address on %q: set IMS_UE_IP or IMS_UE_IFACE\n"):format(ue_iface))
    os.exit(2)
end

-- Per-subscriber resources, spaced by the zero-based index so concurrent
-- subscribers sharing the one UE address never collide: the UE's protected
-- client/server ports and its two inbound ESP SPIs.
local PORT_UC_BASE, PORT_US_BASE = 5088, 5090
local SPI_BASE = 0x2001

local IPPROTO_UDP = 17         -- the ESP policies' inner selector: SIP over UDP

-- USIM secret (raw 16-byte hex). Defaults are 3GPP TS 35.207 Milenage Test
-- Set 1; override IMS_K / IMS_OPC for a real USIM (OPc used directly, no OP
-- derivation). Shared by every subscriber, so the HSS must provision the whole
-- IMSI range with the one key set.
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end

local K   = unhex(os.getenv("IMS_K")   or "3919F39741B626604B4BACE23ACFB094")
local OPc = unhex(os.getenv("IMS_OPC") or "177FAD988A964A3AD0421B4693257056")

-- Per-event logging: ~8 lines per subscriber of unbuffered write, so it is on
-- for a small run (following one subscriber step by step is the point of the
-- tool) and off past that. IMS_VERBOSE=1/0 forces it either way; the summary
-- prints regardless.
local VERBOSE_MAX_SUBS = 20
local VERBOSE
do
    local v = os.getenv("IMS_VERBOSE")
    if v then VERBOSE = v ~= "0" else VERBOSE = NSUBS <= VERBOSE_MAX_SUBS end
end
io.stdout:setvbuf("full", 65536)

-- ---- little helpers ---------------------------------------------------

local function banner(t) print(("\n== %s"):format(t)); io.stdout:flush() end
local function line(k, v) print(("   %-24s %s"):format(k, v)) end
local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end

local function slog(sub, k, v)
    if not VERBOSE then return end
    line(NSUBS > 1 and ("[%d] %s"):format(sub.i, k) or k, v)
end

-- Kernel ESP error counters. A packet the kernel refuses — no matching SA, a
-- selector that misses the inbound policy — is dropped in complete silence, so
-- the tool sees exactly what it sees when the network never replied at all.
-- These counters tell the two apart. Only non-zero rows are reported.
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

-- Report distributions, not means: the mean hides the knee, which is the whole
-- reason for measuring registration latency against a subscriber count.
local function summarize(t)
    local n = #t
    if n == 0 then return nil end
    local s = {}
    for i = 1, n do s[i] = t[i] end
    table.sort(s)
    local function q(p) return s[math.max(1, math.min(n, math.ceil(p * n)))] end
    return { n = n, min = s[1], p50 = q(0.50), p95 = q(0.95), max = s[n] }
end

-- ---- per-subscriber identity ------------------------------------------

-- IMSI i = base + (i-1) (< 2^53, so exact as a double), 15 digits; the IMPU and
-- IMPI follow from it. No MSISDN: nothing here dials anything.
local function make_sub(i)
    local idx  = i - 1
    local imsi = ("%015.0f"):format(tonumber(base_imsi) + idx)
    return {
        i = i,
        imsi = imsi,
        impu = ("sip:%s@%s"):format(imsi, ims_realm),
        impi = ("%s@%s"):format(imsi, ims_realm),
        port_uc = PORT_UC_BASE + idx * 4,   -- UE protected client port
        -- The UE advertises ONE protected port in both roles (see
        -- security_client); port_us stays in the layout so the per-subscriber
        -- port stride is unchanged and nothing collides.
        port_us = PORT_US_BASE + idx * 4,   -- reserved, not bound
        spi_uc  = SPI_BASE + idx * 2,       -- UE inbound SPIs (client / server)
        spi_us  = SPI_BASE + idx * 2 + 1,
        reg  = sip.Registration(), auth = sip.AuthChallenge(),
        -- One transaction machine per subscriber, re-armed with restart() for
        -- each REGISTER (each is its own transaction, §17.1.2) rather than a
        -- fresh machine — and so a fresh allocation — per request.
        txn  = sip.Transaction(sip.NON_INVITE_CLIENT),
        cseq = 0, attempts = 0,
        sock = nil, timer = nil, ch = nil, authz = nil,
        sas = {}, pols = {},                -- installed kernel state, for teardown
        protected = false,                  -- did the REGISTER actually ride ESP
        registered = false, done = false, err = nil,
        stage = "register", fail_stage = nil,
        t0 = nil, reg_ms = nil,
    }
end

-- ---- SIP message building (RFC 3261 / TS 24.229) ----------------------

-- The challenge's qop is a quoted LIST (kamailio's ims_auth defaults to
-- "auth,auth-int"); pick one token. Echoing the list computes the digest over a
-- value that is not a single token AND puts a comma inside the qop parameter,
-- which breaks the S-CSCF's own parse of nc — a repeat 401 with no obvious
-- cause. Only "auth" is computed here (HA2 = MD5(method:uri)); anything else
-- falls back to no-qop (RFC 2069) rather than claiming a mode we do not compute.
local function pick_qop(list)
    if not list then return nil end
    for tok in list:gmatch("[%w%-]+") do
        if tok == "auth" then return "auth" end
    end
    return nil
end

-- The UE's Security-Client offer (RFC 3329 / TS 33.203): its two inbound SPIs,
-- its protected ports and the ESP algorithms.
--
-- ealg=null: confidentiality is OPTIONAL in TS 33.203 (§6.3, Annex I — only
-- integrity is mandatory), so the SAs run ESP-NULL. Integrity still covers every
-- protected message with IK, the SPI/port plumbing is unchanged, and the SIP
-- stays readable in a capture while the kernel skips the cipher. kamailio's
-- ims_ipsec_pcscf maps this offer to the kernel's cipher_null; it is the only
-- ealg we offer, so it is the one it must select.
--
-- port-c and port-s are deliberately the SAME port. TS 33.203 §6.3 pairs them
-- the other way — SA1 {UE client <-> P-CSCF server}, SA2 {UE server <-> P-CSCF
-- client} — and kamailio creates exactly those two, but it then sends
-- terminating requests from its protected CLIENT port to the UE's protected
-- CLIENT port, a pairing neither SA covers, and its own kernel drops them
-- (XfrmOutNoStates climbs, `ip xfrm monitor` shows the acquire). Registration
-- alone would not notice, since the REGISTER exchange rides SA1 either way; the
-- pairing is kept identical to ims_test_s5.lua so that what this test proves
-- about a stack carries over to the one that does place calls.
local function security_client(sub)
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(sub.spi_uc, sub.spi_us, sub.port_uc, sub.port_uc)
end

-- The Authorization value (AKAv1-MD5 Digest). `realm` MUST be the one from the
-- challenge: the S-CSCF recomputes HA1 with the realm it reads back from this
-- header, so header-realm == computed-realm always — a derived home domain that
-- differs from the challenge realm (a two- vs three-digit MNC is the usual one)
-- makes the two HA1s diverge and auth fail with a repeat 401. The digest-uri
-- stays the home domain (= Request-URI). An empty nonce/response advertises
-- IMS-AKA on the first REGISTER.
local function authz_hdr(sub, realm, nonce, response, qopset)
    local a = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(sub.impi, realm, ims_realm, nonce or "", response or "")
    if qopset then
        a = a .. (',qop=%s,nc=%s,cnonce="%s"'):format(qopset.qop, qopset.nc, qopset.cnonce)
    end
    return a
end

-- Build the UE's IMS REGISTER. Via/Contact carry the UE's address at its
-- protected client port; a fresh transaction per REGISTER keys the branch and
-- From-tag on the CSeq, while the Call-ID is stable across the binding's life.
-- One Builder for the whole run: request() re-inits the write buffer, so
-- successive messages cannot bleed into each other and no REGISTER pays for the
-- buffer it is written into. Safe because this is single-threaded and never has
-- two messages half-built at once.
local BUILDER = sip.Builder()

local function build_register(sub, authz, sec_name, sec_hdr, expires)
    local b = BUILDER
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(ue_addr, sub.port_uc, sub.imsi, sub.cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(sub.impu, sub.imsi, sub.cseq))
        :header(sip.H_TO, ("<%s>"):format(sub.impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(sub.imsi, ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(sub.cseq))
        :header(sip.H_CONTACT, expires == 0
                and ("<sip:%s:%d>;expires=0"):format(ue_addr, sub.port_uc)  -- de-REGISTER
                or  ("<sip:%s:%d>"):format(ue_addr, sub.port_uc))
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

-- ---- the ESP SAs (TS 33.203 §6.3, Annex I) ----------------------------

-- Install the four transport-mode ESP SAs and the policies that steer traffic
-- onto them (IK integrity-protects; encryption with CK is optional and we
-- negotiated ealg=null, so the cipher is cipher_null with a zero-length key and
-- CK goes unused). The receiver's SPI keys each SA and doubles as its reqid, so
-- the policy that must use a given SA names it unambiguously even though every
-- subscriber shares the one UE address. What went in is recorded on the
-- subscriber so teardown deletes exactly that and nothing else — flushing the
-- tables instead would take out any other IPsec state in this namespace.
local function establish_sas(xfrm, sub, ch, keys)
    local function esp_sa(src, dst, spi)
        local sa = ipsec.Sa()
        sa.src, sa.dst, sa.spi = src, dst, spi
        sa.proto, sa.mode, sa.reqid = ipsec.PROTO_ESP, ipsec.TRANSPORT, spi
        sa.enc_alg,  sa.enc_key  = "ecb(cipher_null)", ""
        sa.auth_alg, sa.auth_key = "hmac(sha1)",       keys.ik
        return sa
    end
    -- /32 selectors: the policy is this UE's traffic to this P-CSCF on this port
    -- pair, not "anything on those ports", which is what a zero prefix length
    -- would mean to the kernel.
    local function esp_policy(dir, src, dst, sport, dport, reqid)
        local p = ipsec.Policy()
        p.src, p.src_prefix = src, 32
        p.dst, p.dst_prefix = dst, 32
        p.sel_proto, p.sport, p.dport = IPPROTO_UDP, sport, dport
        p.dir, p.action = dir, ipsec.ALLOW
        p.has_tmpl, p.tmpl_reqid = true, reqid
        p.tmpl_proto, p.tmpl_mode = ipsec.PROTO_ESP, ipsec.TRANSPORT
        return p
    end
    local pcscf = sub.pcscf
    local sas = {
        esp_sa(ue_addr, pcscf, ch.p_spi_s),
        esp_sa(ue_addr, pcscf, ch.p_spi_c),
        esp_sa(pcscf, ue_addr, sub.spi_uc),
        esp_sa(pcscf, ue_addr, sub.spi_us),
    }
    -- One UE port in both roles (see security_client): SA1 carries the REGISTER
    -- exchange with the P-CSCF's protected server port, SA2 carries terminating
    -- requests and their responses with its protected client port.
    local pols = {
        esp_policy(ipsec.DIR_OUT, ue_addr, pcscf, sub.port_uc, ch.p_port_s, ch.p_spi_s),
        esp_policy(ipsec.DIR_OUT, ue_addr, pcscf, sub.port_uc, ch.p_port_c, ch.p_spi_c),
        esp_policy(ipsec.DIR_IN,  pcscf, ue_addr, ch.p_port_s, sub.port_uc, sub.spi_uc),
        esp_policy(ipsec.DIR_IN,  pcscf, ue_addr, ch.p_port_c, sub.port_uc, sub.spi_us),
    }
    if VERBOSE then
        slog(sub, "ESP keys", ("enc=null auth(IK)=%s"):format(hex(keys.ik)))
    end
    local failed = 0
    for _, sa in ipairs(sas) do
        local ok, err = pcall(function() xfrm:sa_add(sa) end)
        if ok then
            local id = ipsec.SaId()
            id.dst, id.spi, id.proto = sa.dst, sa.spi, sa.proto
            sub.sas[#sub.sas + 1] = id
        else
            failed = failed + 1
            slog(sub, ("ESP SA (spi %#x)"):format(sa.spi), "skipped (" .. why(err) .. ")")
        end
    end
    for _, p in ipairs(pols) do
        local ok, err = pcall(function() xfrm:policy_add(p) end)
        if ok then
            local id = ipsec.PolicyId()
            id.src, id.src_prefix = p.src, p.src_prefix
            id.dst, id.dst_prefix = p.dst, p.dst_prefix
            id.sel_proto, id.sport, id.dport, id.dir = p.sel_proto, p.sport, p.dport, p.dir
            sub.pols[#sub.pols + 1] = id
        else
            failed = failed + 1
            slog(sub, "ESP policy", "skipped (" .. why(err) .. ")")
        end
    end
    if failed == 0 then
        slog(sub, "IPsec", ("4 SAs + 4 policies, UE %s:%d <-> %s:%d/%d")
            :format(ue_addr, sub.port_uc, pcscf, ch.p_port_s, ch.p_port_c or 0))
    end
    return failed
end

-- Remove what this subscriber installed (the reverse of establish_sas), so a
-- repeated run starts from a clean table and the namespace is left as found.
local function release_sas(xfrm, sub)
    for _, id in ipairs(sub.pols) do pcall(function() xfrm:policy_del(id) end) end
    for _, id in ipairs(sub.sas)  do pcall(function() xfrm:sa_del(id) end) end
    sub.pols, sub.sas = {}, {}
end

-- ---- the run ----------------------------------------------------------

local function run()
    local loop = net.Loop()
    local now  = net.now_ms

    -- Resolve the P-CSCF once, with the net module's own resolver (a dotted quad
    -- passes through unchanged) — no external tools.
    local pcscf
    do
        local ok, res = pcall(function() return net.Resolver():resolve4(pcscf_host) end)
        if not ok then
            io.stderr:write(("cannot resolve P-CSCF %q: %s\n"):format(pcscf_host, why(res)))
            os.exit(2)
        end
        pcscf = res
    end

    local subs = {}
    for i = 1, NSUBS do subs[i] = make_sub(i); subs[i].pcscf = pcscf end

    local stats = { tx = 0, rx = 0, regs = 0, protected = 0, sa_fail = 0,
                    start = now(), reg_last = nil, latency = {} }
    local pending = NSUBS
    local xfrm                              -- opened on the first 401 that offers SAs

    banner(("Gm registration — %d subscriber(s) to P-CSCF %s:%d (%s)")
        :format(NSUBS, pcscf, PCSCF_SIP_PORT, pcscf_host))
    line("UE address", ("%s (ports %d..%d)"):format(ue_addr, PORT_UC_BASE,
                                                    PORT_UC_BASE + (NSUBS - 1) * 4))
    line("home domain", ims_realm)
    line("IMSI range", NSUBS > 1
        and ("%s .. %s"):format(subs[1].imsi, subs[NSUBS].imsi)
        or  subs[1].imsi)

    -- Per-subscriber SIP deadline over the shared loop.
    local function disarm(sub) if sub.timer then loop:cancel(sub.timer); sub.timer = nil end end
    local function arm(sub, ms, fn)
        disarm(sub)
        sub.timer = loop:after(ms, function() sub.timer = nil; fn() end)
    end

    -- Advance a subscriber's three machines for a REGISTER we are sending. The
    -- events are injected rather than derived from the message: re-parsing the
    -- wire we just built, purely so the codec can tell us which transition we
    -- are making, costs a full parse per REGISTER — and we already know, because
    -- this script decided it. The mapping mirrors sip::Registration::send()'s own
    -- for an outbound REGISTER, keyed on the same registration state; `dereg`
    -- picks DEREGISTER over REFRESH for the Expires:0 teardown REGISTER.
    local REG_SEND_EV = {
        [sip.RS_IDLE]       = sip.RE_SEND,   -- first REGISTER
        [sip.RS_CHALLENGED] = sip.RE_AUTH,   -- the authenticated retry
    }
    local function feed_sent_register(sub, dereg)
        local ev = REG_SEND_EV[sub.reg:state()]
        if not ev and sub.reg:registered() then
            ev = dereg and sip.RE_DEREGISTER or sip.RE_REFRESH
        end
        if ev then pcall(function() sub.reg:event(ev) end) end
        pcall(function() sub.auth:event(sip.AE_SEND) end)
        -- Each REGISTER is its own transaction (§17.1.2): re-arm, then send.
        pcall(function() sub.txn:restart():event(sip.TE_SEND_REQUEST) end)
    end

    -- forward declarations for the mutually-referring steps
    local begin_registration, on_sip_readable, handle_sip, on_401
    local begin_deregister

    -- A subscriber reached a terminal state; when the last one does, release the
    -- registrations and stop the loop.
    local function finish(sub)
        if sub.done then return end
        sub.done = true
        disarm(sub)
        pending = pending - 1
        if pending > 0 then return end
        if DEREG then begin_deregister() else loop:stop() end
    end
    local function fail(sub, msg)
        sub.err = msg
        sub.fail_stage = sub.stage       -- snapshot the stage reached at give-up
        slog(sub, "result", "FAILED: " .. msg)
        finish(sub)
    end
    local function succeed(sub)
        sub.registered = true
        sub.stage = "done"
        sub.reg_ms = now() - sub.t0
        stats.regs = stats.regs + 1
        stats.reg_last = now()
        stats.latency[#stats.latency + 1] = sub.reg_ms
        if sub.protected then stats.protected = stats.protected + 1 end
        slog(sub, "result", ("registered in %dms (%s)")
            :format(sub.reg_ms, sub.protected and "over ESP" or "unprotected"))
        finish(sub)
    end

    -- Send `wire` and feed it to the subscriber's three FSMs in lock-step.
    local function send_register(sub, wire, label, dport, dereg)
        feed_sent_register(sub, dereg)
        local sok, serr = pcall(function() sub.sock:sendto(wire, sub.pcscf, dport) end)
        if not sok then return fail(sub, "REGISTER send: " .. why(serr)) end
        stats.tx = stats.tx + 1
        if VERBOSE then
            slog(sub, "-> REGISTER", ("%s, %dB -> %s:%d"):format(label, #wire, sub.pcscf, dport))
        end
        arm(sub, SIP_T_MS, function() fail(sub, "timed out awaiting a SIP response") end)
    end

    -- Release the bindings so the P-CSCF destroys its half of the IPsec state:
    -- one protected REGISTER with Expires:0 over the established SA (the same
    -- Authorization as the successful REGISTER — the S-CSCF de-registers an
    -- already-registered IMPU with Expires:0 without a fresh challenge). Its
    -- explicit contact-removal path is what reaps the SAs; contact expiry is not.
    -- Fire-and-forget, then a moment for them to egress and be processed.
    begin_deregister = function()
        local dr = {}
        for _, s in ipairs(subs) do
            if s.registered and s.sock and s.ch and s.authz then dr[#dr + 1] = s end
        end
        if #dr == 0 then return loop:stop() end
        banner(("De-REGISTER — releasing %d registration(s) so the P-CSCF reaps their IPsec SAs")
            :format(#dr))
        for _, s in ipairs(dr) do
            s.cseq = s.cseq + 1
            -- The Security-Verify goes only on a REGISTER that actually rides an
            -- SA; the header name is passed unconditionally because
            -- build_register keys on the value, and a name with no value would
            -- otherwise depend on which of the two the fallback path left set.
            local dport   = s.protected and s.ch.p_port_s or PCSCF_SIP_PORT
            local sec_hdr = s.protected and s.ch.ss_raw or nil
            local wire    = build_register(s, s.authz, "Security-Verify", sec_hdr, 0)
            feed_sent_register(s, true)   -- REGISTERED -> DEREGISTERING
            local ok, err = pcall(function() s.sock:sendto(wire, s.pcscf, dport) end)
            if ok then stats.tx = stats.tx + 1 end
            slog(s, "-> de-REGISTER", ok
                and ("Expires:0 -> %s:%d"):format(s.pcscf, dport)
                or  ("send failed: " .. why(err)))
        end
        loop:after(1000, function() loop:stop() end)
    end

    -- ---- SIP receive ----
    on_sip_readable = function(sub, sock)
        while true do
            local dg = sock:recv(-1)
            if dg.timed_out then return end
            stats.rx = stats.rx + 1
            local okp, m = pcall(sip.parse, dg.data)
            if not okp then
                slog(sub, "SIP", "ignoring unparseable datagram")
            elseif m.request then
                -- Nothing here subscribes or calls, so no terminating request is
                -- expected; one that arrives anyway is reported, not answered.
                slog(sub, "<- request", ("ignoring %s from %s:%d")
                    :format(m.method_name, dg.host, dg.port))
            else
                handle_sip(sub, m)
            end
        end
    end

    handle_sip = function(sub, m)
        if sub.done then return end   -- ignore late replies once terminal
        disarm(sub)
        pcall(function() sub.txn:recv(m) end)
        pcall(function() sub.auth:recv(m) end)
        local ok = pcall(function() sub.reg:recv(m) end)  -- classifies 401 / 2xx / fail
        if not ok then
            slog(sub, "SIP", ("ignoring %s in state %s")
                :format(tostring(m.status), sub.reg:state_name()))
            return
        end
        if sub.reg:state() == sip.RS_CHALLENGED then
            sub.attempts = sub.attempts + 1
            if sub.attempts > AUTH_CAP then
                pcall(function() sub.auth:event(sip.AE_GIVE_UP) end)
                return fail(sub, "authentication failed (repeated 401)")
            end
            on_401(sub, m)
        elseif sub.reg:registered() then
            succeed(sub)
        elseif sub.reg:failed() then
            fail(sub, ("registration rejected: %d %s"):format(m.status, m.reason))
        end
    end

    -- Round 2: verify the AKA challenge, derive RES/CK/IK, raise the ESP SAs and
    -- send the protected REGISTER (the kernel ESP-wraps it, so it egresses as IP
    -- proto 50) with a Security-Verify echoing the offer we accepted.
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
        sub.authz = authz            -- kept for the Expires:0 de-REGISTER

        local have_ss = ch.ss_raw and ch.p_spi_s and ch.p_port_s
        if not have_ss then
            if REQUIRE_IPSEC then
                return fail(sub, "401 carried no Security-Server (IMS_IPSEC=0 to allow " ..
                                 "an unprotected authenticated REGISTER)")
            end
            slog(sub, "Security-Server", "absent -- unprotected authenticated REGISTER")
            local reg2 = build_register(sub, authz)
            return send_register(sub, reg2, "AKAv1-MD5 (digest only)", PCSCF_SIP_PORT)
        end

        if not xfrm then
            local okx, x = pcall(function() return ipsec.Xfrm() end)
            if not okx then return fail(sub, "cannot open NETLINK_XFRM: " .. why(x)) end
            xfrm = x
        end
        slog(sub, "P-CSCF ports", ("client %s / server %d, SPIs %#x/%#x")
            :format(ch.p_port_c or 0, ch.p_port_s, ch.p_spi_c or 0, ch.p_spi_s))
        local bad = establish_sas(xfrm, sub, ch, keys)
        if bad > 0 then
            -- Without the SAs the "protected" REGISTER leaves in the clear and
            -- the P-CSCF discards it; say so once, here, rather than let it
            -- surface as an unexplained timeout per subscriber.
            stats.sa_fail = stats.sa_fail + 1
            return fail(sub, ("%d of 8 IPsec operations refused (CAP_NET_ADMIN?)"):format(bad))
        end
        sub.protected = true

        local reg2 = build_register(sub, authz, "Security-Verify", ch.ss_raw)
        send_register(sub, reg2, "AKAv1-MD5 over ESP", ch.p_port_s)
    end

    -- Round 1: bind the UE socket and send the unprotected REGISTER.
    begin_registration = function(sub)
        -- The UE's address is normally one this host owns, so a plain bind is
        -- enough. IMS_UE_IP may name one it does not (a simulated PDN address),
        -- and that needs IP_FREEBIND + IP_TRANSPARENT — and CAP_NET_ADMIN.
        local okb, s = pcall(function() return net.UdpSocket(ue_addr, sub.port_uc) end)
        if not okb then
            local okt, t = pcall(function()
                return net.UdpSocket(ue_addr, sub.port_uc, false, true)
            end)
            if not okt then
                return fail(sub, ("cannot bind %s:%d: %s"):format(ue_addr, sub.port_uc, why(s)))
            end
            s = t
            slog(sub, "UE SIP socket", ("%s:%d (non-local source, transparent)")
                :format(ue_addr, sub.port_uc))
        else
            slog(sub, "UE SIP socket", ("%s:%d"):format(ue_addr, sub.port_uc))
        end
        sub.sock = s
        loop:add_fd(sub.sock:fd(), net.NET_RD, function() on_sip_readable(sub, sub.sock) end)
        -- Put this UE's output on the loop (queue now, batched sendmmsg from the
        -- loop). NET_RD is the fd's steady-state interest, which the queue
        -- restores after adding NET_WR to ride out a full send buffer.
        sub.sock:tx_loop(loop, net.NET_RD)

        sub.cseq = sub.cseq + 1
        sub.t0 = now()
        local reg1 = build_register(sub, authz_hdr(sub, ims_realm, "", ""),
                                    "Security-Client", security_client(sub))
        send_register(sub, reg1, "unprotected", PCSCF_SIP_PORT)
    end

    banner("REGISTER — IMS-AKA challenge, ESP SAs, protected REGISTER")
    -- A single burst, deliberately: the offered load is the independent variable
    -- of the experiment, and spacing the REGISTERs would hide the very knee a
    -- registration test is run to find.
    for _, sub in ipairs(subs) do begin_registration(sub) end

    local rok, rerr = pcall(function() loop:run() end)

    -- Teardown: our own kernel state first (while the addresses are still
    -- meaningful), then the sockets.
    if xfrm then
        for _, sub in ipairs(subs) do release_sas(xfrm, sub) end
    end
    for _, sub in ipairs(subs) do
        if sub.sock then
            pcall(function() loop:del_fd(sub.sock:fd()) end)
            sub.sock:close()
        end
    end
    if not rok then io.stderr:write("loop error: " .. why(rerr) .. "\n") end
    return subs, stats
end

-- main
local t0 = net.now_ms()
local subs, stats = run()
local elapsed = (net.now_ms() - t0) / 1000

-- Tally registrations and, for the rest, the stage each subscriber reached when
-- it gave up: the initial REGISTER / 401 challenge, or authentication (AKA
-- verify + ESP SAs + the protected REGISTER / 200 OK).
local STAGES = {
    { key = "register", label = "REGISTER / 401 challenge" },
    { key = "auth",     label = "authentication / 200 OK" },
    { key = "other",    label = "other / incomplete" },
}
local ok, tally, esp_silent = 0, {}, 0
for _, sub in ipairs(subs) do
    if sub.registered then
        ok = ok + 1
    else
        -- A protected REGISTER that got no answer at all: either the P-CSCF
        -- never replied, or one of the two kernels dropped an ESP packet. Ours
        -- reports itself (the xfrm banner below); the P-CSCF's does not, so the
        -- hint has to say where to look. See the header on a reused SPI whose
        -- stale SA rejects our sequence 1 as a replay.
        if sub.protected and (sub.err or ""):find("timed out", 1, true) then
            esp_silent = esp_silent + 1
        end
        local k = sub.fail_stage or "other"
        local t = tally[k]
        if not t then t = { n = 0, reasons = {} }; tally[k] = t end
        t.n = t.n + 1
        local r = sub.err or "unknown"
        t.reasons[r] = (t.reasons[r] or 0) + 1
    end
end

banner(("Summary: %d / %d subscriber(s) registered over Gm in %.2fs"):format(ok, #subs, elapsed))
if ok > 0 then
    line("IPsec", ("%d of %d registration(s) rode ESP"):format(stats.protected, ok))
end
if stats.sa_fail > 0 then
    line("", "the kernel refused SA/policy installs -- run with CAP_NET_ADMIN")
end
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
if esp_silent > 0 then
    line("silent over ESP", ("%d protected REGISTER(s) got no reply at all"):format(esp_silent))
    line("", "with our own xfrm counters clean below, the drop is on the P-CSCF:")
    line("", 'docker exec <pcscf> grep -v " 0$" /proc/net/xfrm_stat -- a climbing')
    line("", "XfrmInStateSeqError is a stale SA on a reused SPI (see the header).")
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

banner("Timing (first REGISTER of a subscriber to its 200 OK)")
local d = summarize(stats.latency)
line("registration latency", d
    and ("p50 %dms  p95 %dms  max %dms  (min %dms, n=%d)"):format(d.p50, d.p95, d.max, d.min, d.n)
    or  "no samples")
-- Rate over the burst itself (first REGISTER to last 200 OK), so the
-- de-REGISTER and teardown do not dilute it.
if stats.regs > 0 and stats.reg_last then
    local w = (stats.reg_last - stats.start) / 1000
    line("registrations", w > 0
        and ("%d in %.2fs  ->  %.1f/s"):format(stats.regs, w, stats.regs / w)
        or  ("%d (single burst, under one clock tick)"):format(stats.regs))
end
line("SIP packets", ("%d sent, %d received"):format(stats.tx, stats.rx))

os.exit(ok == #subs and 0 or 1)
