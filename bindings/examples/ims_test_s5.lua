#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] lua ims_test_s5.lua
--
-- PGW_IP may be a host name (resolved with the net module's DNS resolver)
-- or a literal IP address; it defaults to "smf".
--
-- GTP-U user plane: when the eBPF datapath is available (CAP_BPF +
-- CAP_NET_ADMIN, eBPF build) the script programs each bearer's forwarding
-- entry into it. Set $GTPU_IFACE (the S5/S8-U interface facing the PGW)
-- and $GTPU_INNER_IFACE (the access side) to also attach the TC programs;
-- without them the datapath loads and the tunnels are installed in its
-- map, but no interface is hooked. Without the datapath the tunnels are
-- only reported.
--
-- With both interfaces attached the script drives a full IMS-AKA
-- registration end to end over the encap path (TS 33.203). The P-CSCF
-- address comes from the Create Session Response PCO (TS 24.008 container
-- 0x000C). The flow:
--   1. REGISTER (unprotected, plain UDP:5060) with a Security-Client offer.
--   2. 401 with the AKA challenge (RAND||AUTN) and the P-CSCF's
--      Security-Server (its SPIs and protected ports).
--   3. Verify AUTN, derive CK/IK, install four transport-mode ESP SAs.
--   4. REGISTER (protected, ESP) to the P-CSCF's protected server port with
--      the AKAv1-MD5 digest response and a Security-Verify; then 200 OK.
--
-- IMS signalling rides the default bearer, so both shapes are steered onto
-- it -- the plain REGISTER by a UDP:5060 TFT and everything ESP-protected
-- by a proto-50 TFT (two filters on the one bearer) -- and the UPF routes
-- them to the P-CSCF; the 401/200 come back down the same bearer's decap
-- entry, and the kernel's IPsec decrypts the protected ones. Per-TEID
-- kernel counters confirm the datapath in both directions. The dedicated
-- (media) bearer from the Create Bearer Request is accepted but not probed.
--
-- The USIM secret defaults to a test set; override IMS_K / IMS_OPC (raw
-- 16-byte hex) for a real subscriber. Installing ESP SAs needs
-- CAP_NET_ADMIN; each kernel op degrades to a reported line when refused.
--
-- The whole scenario is a state machine advanced by socket and timer
-- callbacks on one net.Loop, with a single loop:run() at the bottom
-- instead of any blocking recv() or step() pump.
--

local gtp   = require("gtp")   -- GTPv2-C + typed Create Bearer + PLMN/ULI/PCO wire helpers
local net   = require("net")   -- event loop + UDP socket + DNS resolver + interface lookup
local sip   = require("sip")   -- IMS REGISTER builder / parser + auth_param / b64decode
local ipsec = require("ipsec") -- Milenage (aka_verify) + AKAv1-MD5 digest (aka_digest)

-- ---- configuration ----------------------------------------------------

local pgw_host = os.getenv("PGW_IP")   or "smf"              -- PGW/SMF: a name (resolved below) or a literal IP
local sgw_ip   = os.getenv("SGW_IP")   or "0.0.0.0"
local apn      = os.getenv("IMS_APN")  or "ims"
local mcc      = os.getenv("IMS_MCC")  or "001"              -- serving PLMN (matches the IMSI
local mnc      = os.getenv("IMS_MNC")  or "01"               -- and the mnc01.mcc001 core realm)
local imsi     = os.getenv("IMS_IMSI") or "001010000000001"

-- IMS identities for the REGISTER (TS 23.003): the home network domain
-- and the IMPU/IMPI derived from the IMSI. Override with IMS_REALM /
-- IMS_IMPU / IMS_IMPI for a different core; the MNC is zero-padded to
-- three digits as the domain label requires.
local function mnc3(n) return (#n == 2) and ("0" .. n) or n end
local ims_realm = os.getenv("IMS_REALM")
    or ("ims.mnc%s.mcc%s.3gppnetwork.org"):format(mnc3(mnc), mcc)
local impu = os.getenv("IMS_IMPU") or ("sip:%s@%s"):format(imsi, ims_realm)
local impi = os.getenv("IMS_IMPI") or ("%s@%s"):format(imsi, ims_realm)

local S5_UP_TEID = 0x200       -- our (SGW) S5/S8-U downlink tunnel endpoint id
local T3_MS, N3  = 1000, 3     -- GTP-C retransmission: 1s T3-RESPONSE, up to 3 sends
local SIP_T_MS   = 5000        -- SIP response deadline per registration step

local IPPROTO_UDP    = 17      -- unprotected REGISTER: plain UDP toward the P-CSCF
local IPPROTO_ESP    = 50      -- protected traffic: ESP (IMS-AKA IPsec, TS 33.203)
local PCSCF_SIP_PORT = 5060    -- IMS signalling bearer TFT: SIP toward the P-CSCF

-- IMS-AKA IPsec (TS 33.203 / RFC 3329): the UE's protected client/server
-- ports and the SPIs of its two inbound ESP SAs, advertised in the
-- Security-Client offer; the P-CSCF's own ports/SPIs come back in the 401's
-- Security-Server. The protected REGISTER is sent from the client port to
-- the P-CSCF's protected server port and the kernel ESP-wraps it.
local PORT_UC, PORT_US = 5088, 5090
local SPI_UC,  SPI_US  = 0x2001, 0x2002

-- USIM secret (raw 16-byte hex). Defaults are 3GPP TS 35.207 Milenage
-- Test Set 1; override IMS_K / IMS_OP (or IMS_OPC) for a real USIM. Used
-- to answer the 401 AKA challenge (recover RES, the digest password).
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end

local K   = unhex(os.getenv("IMS_K")  or "3919F39741B626604B4BACE23ACFB094")
local OPc = unhex(os.getenv("IMS_OPC") or "177FAD988A964A3AD0421B4693257056")

-- ---- little helpers ---------------------------------------------------

local function banner(t) print(("\n== %s"):format(t)) end
local function line(k, v) print(("   %-22s %s"):format(k, v)) end

-- Strip the leading "context: " a gtp/net Error carries, for one-line logs.
local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end

-- Run a kernel op (ESP SA / policy install), turning a CAP_NET_ADMIN
-- rejection into one reported line rather than aborting the run.
local function attempt(what, fn)
    local ok, err = pcall(fn)
    line(what, ok and "ok" or ("skipped (" .. why(err) .. ")"))
    return ok
end

-- Resolve a host name to an IPv4 literal via the net module's own resolver.
-- resolve4() returns a dotted-quad unchanged and otherwise runs the
-- asynchronous net_dns engine (first A record, /etc/resolv.conf nameserver,
-- throwing on NXDOMAIN or timeout). This wrapper only adds a friendlier
-- error naming the offending host. No external tools.
local function resolve(name)
    local ok, res = pcall(function() return net.Resolver():resolve4(name) end)
    assert(ok, ("cannot resolve PGW host name %q: %s"):format(name, why(res)))
    return res
end

-- The PLMN (gtp.plmn_encode), ULI (gtp.uli_tai_ecgi) and PCO parse/build
-- (gtp.pco_pcscf_v4 / gtp.pco_request_pcscf) wire encoders now live in the
-- gtp module, and the F-TEID / Cause IEs are assembled by the typed Create
-- Bearer Response below -- so none of that byte-arithmetic lives here.

-- ---- IMS-AKA / HTTP Digest (RFC 3310 + RFC 2617) ----------------------

-- base64 decode of the AKA nonce (sip.b64decode) and the AKAv1-MD5 digest
-- (ipsec.aka_digest) are C helpers; only the policy bits stay in Lua.

-- The challenge's qop is a quoted list (kamailio's ims_auth default is
-- "auth,auth-int"); pick a single token for the response. Only "auth" is
-- supported here (HA2 = MD5(method:uri); auth-int would fold the body in),
-- so prefer it and fall back to no-qop (RFC 2069) rather than claim a mode
-- we do not compute. Echoing the whole list would both miscompute the digest
-- and put a comma inside the qop value, which breaks the S-CSCF's header
-- parsing ("qop specified with no nonce count").
local function pick_qop(list)
    if not list then return nil end
    for tok in list:gmatch("[%w%-]+") do
        if tok == "auth" then return "auth" end
    end
    return nil
end

-- The UE's Security-Client offer (RFC 3329 / TS 33.203): its two inbound
-- SPIs, its protected client/server ports, and the integrity (hmac-sha-1-96)
-- and cipher (aes-cbc) algorithms it supports for the ESP SAs.
local function security_client()
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(SPI_UC, SPI_US, PORT_UC, PORT_US)
end

-- The Authorization header value: AKAv1-MD5 Digest. `realm` MUST be the one
-- from the challenge (RFC 2617): the S-CSCF recomputes HA1 with the realm it
-- reads back from this header, so it has to match the realm the digest was
-- computed with — the two can differ from the UE's derived home domain (e.g.
-- a two-digit-MNC realm), which would otherwise fail authentication. An empty
-- nonce/response advertises IMS-AKA on the first (unprotected) REGISTER; the
-- second carries the challenge's nonce and the computed response, plus
-- qop/nc/cnonce when the P-CSCF asked for qop. The digest-uri stays the home
-- domain (= the REGISTER Request-URI), independent of the realm.
local function authz_hdr(realm, nonce, response, qopset)
    local a = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(impi, realm, ims_realm, nonce or "", response or "")
    if qopset then
        a = a .. (',qop=%s,nc=%s,cnonce="%s"'):format(qopset.qop, qopset.nc, qopset.cnonce)
    end
    return a
end

-- Build the UE's IMS REGISTER toward the P-CSCF (TS 24.229 / RFC 3261):
-- the Request-URI is the home domain, Via/Contact carry the UE's own (PAA)
-- address at its protected client port, and `authz` is the AKAv1-MD5
-- credential. Each REGISTER is a fresh non-INVITE transaction, so the branch
-- and the From tag are keyed on the CSeq; the Call-ID is stable across the
-- pair. `sec_name`/`sec_hdr`, when given, add a Security-Client (first
-- REGISTER) or Security-Verify (protected REGISTER) header.
local function build_register(ue_addr, cseq, authz, sec_name, sec_hdr)
    local b = sip.Builder()
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(ue_addr, PORT_UC, imsi, cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(impu, imsi, cseq))
        :header(sip.H_TO, ("<%s>"):format(impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(imsi, ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(cseq))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(ue_addr, PORT_UC))
        :header_u32(sip.H_EXPIRES, 600000)
        :header(sip.H_AUTHORIZATION, authz)
    if sec_hdr then b:header_name(sec_name, sec_hdr) end
    return b:done()
end

-- Parse the 401: the AKA challenge from WWW-Authenticate (nonce is
-- base64(RAND||AUTN); realm/qop steer the digest) and, when present, the
-- P-CSCF's Security-Server (its SPIs and protected ports). ss_raw is kept
-- verbatim so the protected REGISTER can echo it back in Security-Verify.
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
        nonce = nonce,
        rand  = blob:sub(1, 16),
        autn  = blob:sub(17, 32),
        realm = realm ~= "" and realm or ims_realm,
        qop   = pick_qop(sip.auth_param(wa, "qop")),
        ss_raw   = ss,
        p_spi_c  = ss and tonumber(sip.auth_param(ss, "spi-c")),
        p_spi_s  = ss and tonumber(sip.auth_param(ss, "spi-s")),
        p_port_c = ss and tonumber(sip.auth_param(ss, "port-c")),
        p_port_s = ss and tonumber(sip.auth_param(ss, "port-s")),
    }
end

-- Build and install the four transport-mode ESP SAs and their steering
-- policies (TS 33.203 Annex I: IK integrity-protects, CK encrypts). The
-- keys come straight from AKA. Best-effort: each kernel op reports and
-- degrades on a CAP_NET_ADMIN rejection.
local function establish_sas(xfrm, ch, keys, ue_addr, pcscf)
    local function esp_sa(src, dst, spi, reqid)
        local sa = ipsec.Sa()
        sa.src, sa.dst, sa.spi = src, dst, spi
        sa.proto, sa.mode, sa.reqid = ipsec.PROTO_ESP, ipsec.TRANSPORT, reqid
        sa.enc_alg,  sa.enc_key  = "cbc(aes)",   keys.ck   -- confidentiality (CK)
        sa.auth_alg, sa.auth_key = "hmac(sha1)", keys.ik   -- integrity (IK, SHA-1-96)
        return sa
    end
    local function esp_policy(dir, src, dst, sport, dport, reqid)
        local p = ipsec.Policy()
        p.src, p.dst = src, dst
        p.sel_proto, p.sport, p.dport = IPPROTO_UDP, sport, dport   -- UDP selector
        p.dir, p.action = dir, ipsec.ALLOW
        p.has_tmpl, p.tmpl_reqid = true, reqid
        p.tmpl_proto, p.tmpl_mode = ipsec.PROTO_ESP, ipsec.TRANSPORT
        return p
    end
    -- Four SAs keyed by the receiver's SPI: UE->P to the P-CSCF's server and
    -- client ports (outbound), P->UE to the UE's client and server ports
    -- (inbound). reqid = SPI ties each policy to its SA.
    local sas = {
        esp_sa(ue_addr, pcscf, ch.p_spi_s, ch.p_spi_s),
        esp_sa(ue_addr, pcscf, ch.p_spi_c, ch.p_spi_c),
        esp_sa(pcscf, ue_addr, SPI_UC,     SPI_UC),
        esp_sa(pcscf, ue_addr, SPI_US,     SPI_US),
    }
    local pols = {
        esp_policy(ipsec.DIR_OUT, ue_addr, pcscf, PORT_UC, ch.p_port_s, ch.p_spi_s),
        esp_policy(ipsec.DIR_OUT, ue_addr, pcscf, PORT_US, ch.p_port_c, ch.p_spi_c),
        esp_policy(ipsec.DIR_IN,  pcscf, ue_addr, ch.p_port_s, PORT_UC, SPI_UC),
        esp_policy(ipsec.DIR_IN,  pcscf, ue_addr, ch.p_port_c, PORT_US, SPI_US),
    }
    line("ESP keys", ("enc(CK)=%s  auth(IK)=%s"):format(hex(keys.ck), hex(keys.ik)))
    line("UE ports", ("client %d / server %d, SPIs %#x/%#x"):format(PORT_UC, PORT_US, SPI_UC, SPI_US))
    for i, sa in ipairs(sas) do
        attempt(("ESP SA %d (spi %#x)"):format(i, sa.spi), function() xfrm:sa_add(sa) end)
    end
    for i, p in ipairs(pols) do
        attempt(("ESP policy %d (%s)"):format(i, p.dir == ipsec.DIR_OUT and "out" or "in"),
                function() xfrm:policy_add(p) end)
    end
end

-- ---- GTPv2-C over S5/S8 + IMS registration over GTP-U -----------------

local function attach_pdn_over_s5()
    -- Fill the SGW address from the GTP-U interface when it was left at the
    -- any-address: 0.0.0.0 there gives an invalid outer source and S5/S8
    -- F-TEID address, which breaks user-plane addressing and FIB source
    -- selection. The GTP-U interface is the uplink, so its IP is the SGW's.
    local gtpu_ifname = os.getenv("GTPU_IFACE") or "eth0"
    local sgw_auto = false
    if sgw_ip == "0.0.0.0" then
        local ip = net.if_addr4(gtpu_ifname)
        if ip ~= "" then sgw_ip, sgw_auto = ip, true end
    end

    local pgw_ip = resolve(pgw_host)
    banner(("GTPv2-C — PDN connection over S5/S8: SGW %s -> PGW %s")
        :format(sgw_ip, pgw_ip))
    if sgw_auto then
        line("SGW address", ("%s (auto from %s)"):format(sgw_ip, gtpu_ifname))
    end
    if pgw_ip ~= pgw_host then
        line("PGW address", ("%s -> %s"):format(pgw_host, pgw_ip))
    end

    local loop = net.Loop()
    local ok, ep = pcall(gtp.Endpoint, loop, sgw_ip)  -- binds sgw_ip:2123 (GTP-C)
    if not ok then
        io.stderr:write(("cannot bind GTP-C on %s:2123: %s\n"):format(sgw_ip, why(ep)))
        os.exit(1)
    end
    ep:set_t3_ms(T3_MS)
    ep:set_n3(N3)

    -- Cross-phase state, filled by the callbacks and read by later ones.
    local st = {
        err = nil, registered = false, session_up = false, cbr_done = false,
        ue_addr = nil, pcscf = nil, pgw_ctrl_teid = nil,
        sig_teid = nil,          -- default (signalling) bearer TEID, for counters
        rx0 = nil,               -- downlink rx baseline captured at REGISTER time
        peers = {}, bearers = {},
    }

    -- ---- GTP-U user plane (eBPF datapath) ----
    -- Load the datapath when the kernel and privileges allow it; attach its
    -- TC programs to the S5/S8-U and access interfaces when their names are
    -- given. Everything degrades to a log line if the datapath, the caps or
    -- the interfaces are missing, so an unprivileged run still completes.
    local up
    local inner_name = os.getenv("GTPU_INNER_IFACE") or "eth0" -- access side (encap egress)
    if gtp.UserPlane.supported() then
        local gi = net.if_index(gtpu_ifname)       -- S5/S8-U (GTP-U) side; 0 if absent
        local ii = net.if_index(inner_name)        -- access side; 0 if absent
        local cfg = gtp.UserPlaneConfig()
        cfg.pin_dir        = ""        -- no bpffs pinning: a fresh datapath each run
        cfg.local_v4       = sgw_ip    -- outer source address for encapsulated uplink
        cfg.uplink_ifindex = gi
        local made, obj = pcall(gtp.UserPlane, cfg)
        if made then
            up = obj
            if gi ~= 0 or ii ~= 0 then
                local aok, aerr = pcall(function() up:attach(gi, ii) end)
                line("GTP-U datapath", aok
                    and ("attached (gtpu=%s inner=%s)")
                        :format(gi ~= 0 and gtpu_ifname or "-", inner_name or "-")
                    or ("attach failed: " .. why(aerr)))
            else
                line("GTP-U datapath", "loaded (set GTPU_IFACE/GTPU_INNER_IFACE to attach TC)")
            end
        else
            line("GTP-U datapath", "unavailable (" .. why(obj) .. ")")
        end
    else
        line("GTP-U datapath", "unsupported (non-eBPF build or missing CAP_BPF/CAP_NET_ADMIN)")
    end

    -- Steer the UE's SIP toward the P-CSCF onto the default bearer's datapath
    -- entry (local_teid @ our side, remote_teid @ the PGW/UPF). It rides the
    -- bearer in two shapes, so two TFTs are installed on the one bearer: the
    -- initial unprotected REGISTER as plain UDP:5060, and — once the ESP SAs
    -- are up — everything else as ESP (IP proto 50). The encap keys the TX
    -- maps on the inner *destination*, so the P-CSCF fills the Tunnel's
    -- ue_addr (classification address); add_filter also installs the shared
    -- decap (rx) entry keyed on local_teid, so the 401/200 the P-CSCF sends
    -- back decapsulate on that bearer and reach the UE (plain, then ESP which
    -- the kernel decrypts).
    local function program_filter(ebi, local_teid, remote_teid, remote_addr, pcscf)
        if not up then return end
        if not (pcscf and pcscf ~= "" and remote_addr and remote_addr ~= "") then
            line("GTP-U filter", ("EBI %d not programmed (missing P-CSCF/peer address)"):format(ebi))
            return
        end
        local function add_tft(proto, ue_port, label)
            local t = gtp.Tunnel()
            t.local_teid, t.remote_teid = local_teid, remote_teid
            t.ebi, t.ue_addr, t.remote_addr = ebi, pcscf, remote_addr
            local f = gtp.TrafficFilter()
            f.tunnel  = t
            f.proto   = proto
            f.ue_port = ue_port            -- inner dst port; host order, loader htons
            local pok, perr = pcall(function() up:add_filter(f) end)
            line("GTP-U filter", pok
                and ("EBI %d  %s  ul/dl TEID %#x/%#x @ %s  proto %d -> %s%s")
                    :format(ebi, label, local_teid, remote_teid, remote_addr, proto, pcscf,
                            ue_port > 0 and (":" .. ue_port) or "")
                or ("EBI %d %s add_filter failed: %s"):format(ebi, label, why(perr)))
            return pok
        end
        local udp = add_tft(IPPROTO_UDP, PCSCF_SIP_PORT, "SIP")  -- unprotected REGISTER
        local esp = add_tft(IPPROTO_ESP, 0,              "ESP")  -- protected traffic
        if udp or esp then
            st.peers[remote_addr] = true
            st.sig_teid = local_teid   -- default bearer carries the signalling
            st.bearers[#st.bearers + 1] =
                { ebi = ebi, teid = local_teid, kind = "signalling", dst = pcscf }
        end
    end

    -- ---- SIP registration state machine (drives the encap path) ----
    --
    -- One net.Loop carries the GTP-C endpoint (its own socket + N3 timer)
    -- and the UE's SIP socket. The scenario advances by callbacks:
    --
    --   [Create Session Resp] --(filters programmed)--> begin_registration
    --     REGISTER (unprotected)  --401-->  on_401
    --       verify AUTN, derive RES, REGISTER (AKAv1-MD5)  --200-->  on_registered
    --
    -- Each SIP step arms a one-shot deadline (loop:after); the reply
    -- disarms it and the next step re-arms it. GTP-C has the endpoint's N3.
    local sock                 -- UE SIP socket (non-local UE PAA source, protected client port)
    local ue_bound = false     -- did the transparent PAA bind succeed
    local uac, uac2            -- the two RFC 3261 non-INVITE client transactions
    local ch                   -- the parsed 401 challenge
    local xfrm                 -- ipsec.Xfrm handle for the ESP SAs (nil until the 401)
    local sip_state = "idle"   -- which SIP response the socket is waiting for
    local reg_cseq = 0         -- REGISTER CSeq (bumped per request)
    local grace                -- post-200 wait for a late Create Bearer Request
    local paa_route_added = false  -- did we add the UE-PAA local route

    -- forward declarations for the mutually-referring phase steps
    local begin_registration, on_sip_readable, handle_sip, on_401, on_registered

    -- One deadline for the in-flight SIP step.
    local timer
    local function disarm() if timer then loop:cancel(timer); timer = nil end end
    local function arm(ms, on_expire)
        disarm()
        timer = loop:after(ms, function() timer = nil; on_expire() end)
    end
    local function fail(msg)
        st.err = msg; disarm()
        if grace then loop:cancel(grace); grace = nil end
        loop:stop()
    end

    -- Stop the loop once registered; wait briefly first for a late Create
    -- Bearer Request so the dedicated bearer is still accepted.
    local function finish()
        disarm()
        if st.cbr_done then return loop:stop() end
        line("note", "waiting up to 3s for a Create Bearer Request before exit")
        grace = loop:after(3000, function() grace = nil; loop:stop() end)
    end

    -- Send a REGISTER over the UE socket to the P-CSCF at `dport` (5060 for
    -- the unprotected one, the protected server port for the ESP one — the
    -- kernel ESP-wraps that per the OUT policy).
    local function send_register(wire, label, dport)
        local sok, serr = pcall(function() sock:sendto(wire, st.pcscf, dport) end)
        if not sok then return fail(("REGISTER send failed: %s"):format(why(serr))) end
        line("-> REGISTER", ("%s, %d B -> P-CSCF %s:%d"):format(label, #wire, st.pcscf, dport))
    end

    -- Make the UE PAA locally deliverable so the decapped downlink (the
    -- P-CSCF's 401/200, whose inner dst is the PAA) reaches the UE socket.
    -- The rx decap entry hands the inner packet to the local stack, but the
    -- PAA is an address this host does not own, so without a local route the
    -- kernel would try to forward -- and drop -- it. net.addr_add (RTNETLINK
    -- RTM_NEWADDR, the netlink/rtnl module) adds <PAA>/32 to `lo`, which puts
    -- it in the local routing table (delivered whatever interface it arrives
    -- on) without answering ARP for it on the wire -- and needs no external
    -- `ip` tool. Best-effort and only meaningful with the decap datapath up,
    -- so it is attempted only then (needs CAP_NET_ADMIN); the add is
    -- idempotent, degrades to a reported line, and is removed in teardown.
    local function add_paa_route()
        if not (up and st.ue_addr and st.ue_addr:match("^%d+%.%d+%.%d+%.%d+$")) then return end
        local ok, err = pcall(function() net.addr_add("lo", st.ue_addr, 32) end)
        paa_route_added = ok
        line("PAA local route", ok
            and ("%s/32 dev lo (decapsulated downlink now deliverable)"):format(st.ue_addr)
            or  ("could not add %s/32 (need CAP_NET_ADMIN?): %s"):format(st.ue_addr, why(err)))
    end
    local function del_paa_route()
        if paa_route_added then pcall(function() net.addr_del("lo", st.ue_addr, 32) end) end
    end

    -- Confirm a downlink response reached us through the decap entry by
    -- reading the rx counter delta from the baseline taken at REGISTER time.
    local function report_rx(what)
        if not (up and st.sig_teid and st.rx0) then return end
        local a   = up:stats(st.sig_teid)
        local drx = a.rx_pkts - st.rx0.rx_pkts
        if drx > 0 then
            line("GTP-U decap", ("%s arrived via downlink (rx +%d pkt on TEID %#x)")
                :format(what, drx, st.sig_teid))
        end
    end

    -- ---- SIP receive: drain the socket, dispatch by phase ----
    on_sip_readable = function()
        while true do
            local dg = sock:recv(-1)                 -- non-blocking drain of the fd
            if dg.timed_out then return end
            local okp, m = pcall(sip.parse, dg.data)
            if okp then handle_sip(m)
            else line("SIP", "ignoring unparseable datagram") end
        end
    end

    handle_sip = function(m)
        if sip_state == "reg1" then
            disarm()
            if uac then pcall(function() uac:recv(m) end) end
            report_rx("401")
            if m.status == 401 then
                line("<- 401", "IMS-AKA challenge")
                on_401(m)
            elseif m.status == 200 then
                line("<- 200 OK", "registered (no challenge)")
                on_registered(m)
            else
                fail(("expected 401 challenge, got %d %s"):format(m.status, m.reason))
            end
        elseif sip_state == "reg2" then
            disarm()
            if uac2 then pcall(function() uac2:recv(m) end) end
            report_rx("200 OK")
            if m.status == 200 then
                line("<- 200 OK", "registered")
                on_registered(m)
            else
                fail(("registration failed: %d %s"):format(m.status, m.reason))
            end
        end
        -- any other state (done / idle): ignore late datagrams
    end

    -- Round 2: verify the AKA challenge and derive RES/CK/IK; with a
    -- Security-Server, install the ESP SAs and send the protected REGISTER
    -- (ESP, to the P-CSCF's protected server port) carrying the AKAv1-MD5
    -- digest and a Security-Verify. Without one, fall back to an unprotected
    -- authenticated REGISTER (digest only) so a non-IPsec core still works.
    on_401 = function(m401)
        local okc, res = pcall(parse_challenge, m401)
        if not okc then return fail("cannot parse 401 challenge: " .. why(res)) end
        ch = res
        line("RAND", hex(ch.rand)); line("AUTN", hex(ch.autn))

        local okv, keys = pcall(function() return ipsec.aka_verify(K, OPc, ch.rand, ch.autn) end)
        if not okv then return fail("AKA AUTN verification failed: " .. why(keys)) end
        line("AUTN verified", ("SQN %s, RES %s"):format(hex(keys.sqn), hex(keys.res)))

        -- AKAv1-MD5 digest: RES is the password (RFC 3310).
        reg_cseq = reg_cseq + 1
        local nc, cnonce = "00000001", hex(ipsec.md5(imsi .. tostring(reg_cseq)):sub(1, 8))
        local response = ipsec.aka_digest(impi, ch.realm, keys.res, "REGISTER",
                                          "sip:" .. ims_realm, ch.nonce, nc, cnonce,
                                          ch.qop or "")
        local authz = authz_hdr(ch.realm, ch.nonce, response,
                                ch.qop and { qop = ch.qop, nc = nc, cnonce = cnonce })

        -- Protected path when the P-CSCF offered a Security-Server: raise the
        -- ESP SAs, then aim the REGISTER at the protected server port (the
        -- kernel ESP-wraps it, so it egresses as proto 50 and the ESP TFT
        -- steers it) and echo the Security-Server in a Security-Verify.
        local dport, sec_name, sec_hdr = PCSCF_SIP_PORT, nil, nil
        if ch.ss_raw and ch.p_spi_s and ch.p_port_s then
            banner("IPsec — establishing ESP SAs (transport mode)")
            line("P-CSCF ports", ("client %s / server %d, SPIs %#x/%#x")
                :format(ch.p_port_c or 0, ch.p_port_s, ch.p_spi_c or 0, ch.p_spi_s))
            xfrm = ipsec.Xfrm()
            establish_sas(xfrm, ch, keys, st.ue_addr, st.pcscf)
            dport, sec_name, sec_hdr = ch.p_port_s, "Security-Verify", ch.ss_raw
            banner("IMS-AKA registration — protected REGISTER over ESP")
        else
            line("Security-Server", "absent -- unprotected authenticated REGISTER (digest only)")
        end

        local reg2 = build_register(st.ue_addr, reg_cseq, authz, sec_name, sec_hdr)
        uac2 = sip.Transaction(sip.NON_INVITE_CLIENT)
        send_register(reg2, sec_hdr and "AKAv1-MD5 over ESP" or "AKAv1-MD5 (digest only)", dport)
        pcall(function() uac2:send(sip.parse(reg2)) end)
        sip_state = "reg2"
        arm(SIP_T_MS, function() fail("timed out waiting for 200 OK") end)
    end

    -- Registered: the 200 OK closed the second transaction. Report and
    -- wind down (a late Create Bearer Request is still accepted).
    on_registered = function()
        st.registered = true
        sip_state = "done"
        banner("IMS registration complete")
        line("result", ("%s registered at P-CSCF %s"):format(impu, st.pcscf or "?"))
        finish()
    end

    -- Round 1: prime the outer neighbour table, bind the UE PAA socket into
    -- the loop, and send the unprotected REGISTER that advertises IMS-AKA.
    begin_registration = function()
        if not (st.pcscf and st.ue_addr) then
            line("registration", "skipped (no P-CSCF/UE address)")
            return finish()
        end
        banner(("IMS registration — %s -> P-CSCF %s (over GTP-U)"):format(impi, st.pcscf))

        -- Make the PAA locally deliverable before anything can reply, so the
        -- P-CSCF's 401/200 reach the UE socket after the datapath decaps them.
        add_paa_route()

        -- Prime the neighbour table for each PGW/UPF peer. encap resolves
        -- the outer L2 with bpf_fib_lookup, which only *reads* the neighbour
        -- table -- it never triggers ARP -- so on a cold start the peer's
        -- MAC is not yet cached and the first encapsulated packets hit
        -- err_tx_no_neigh. A throwaway datagram makes the kernel resolve it.
        local prime = net.UdpSocket("0.0.0.0", 0)
        for peer in pairs(st.peers) do
            pcall(function() prime:sendto("x", peer, 2152) end)
        end
        prime:close()

        -- The REGISTER must look like uplink traffic *from the UE*: its
        -- inner source has to be the PAA, not the SGW address (which is also
        -- the outer GTP-U source). The SGW does not own the PAA, so open the
        -- socket with a non-local source (the fourth UdpSocket arg ->
        -- IP_FREEBIND + IP_TRANSPARENT): the kernel then binds and *sends*
        -- from an address it does not own, and — because it is bound
        -- transparently — can also *receive* the 401/200 the P-CSCF returns
        -- to the PAA once the datapath decapsulates them. Needs
        -- CAP_NET_ADMIN; falls back to the SGW source (which the UPF then
        -- drops as spoofed, and no reply can return) when it is refused.
        local okb, s = pcall(function()
            return net.UdpSocket(st.ue_addr, PORT_UC, false, true)  -- protected client port
        end)
        if okb then
            sock, ue_bound = s, true
            line("UE SIP socket", ("%s:%d (UE PAA, transparent)"):format(st.ue_addr, PORT_UC))
        else
            sock, ue_bound = net.UdpSocket("0.0.0.0", 0), false
            line("UE SIP socket",
                 ("SGW source (UE PAA bind refused, need CAP_NET_ADMIN: %s); "
                  .. "no reply can return"):format(why(s)))
        end
        loop:add_fd(sock:fd(), net.NET_RD, on_sip_readable)

        -- Baseline the downlink counter so report_rx can show the 401/200
        -- arriving through the decap entry.
        if up and st.sig_teid then st.rx0 = up:stats(st.sig_teid) end

        reg_cseq = reg_cseq + 1
        uac = sip.Transaction(sip.NON_INVITE_CLIENT)
        -- Unprotected REGISTER (plain UDP:5060) advertising IMS-AKA and the
        -- UE's Security-Client offer (realm is the UE's home domain guess).
        local reg1 = build_register(st.ue_addr, reg_cseq, authz_hdr(ims_realm, "", ""),
                                    "Security-Client", security_client())
        send_register(reg1, "unprotected", PCSCF_SIP_PORT)
        pcall(function() uac:send(sip.parse(reg1)) end)
        sip_state = "reg1"
        arm(SIP_T_MS, function() fail("timed out waiting for 401 challenge") end)
    end

    ep:set_handler({
        -- The PGW answered the Create Session: read the cause, the
        -- allocated UE address (PAA), the P-CSCF from the PCO, and the PGW's
        -- control TEID. on_user_plane fires next (same dispatch) to program
        -- the filters, so registration is kicked off on a short timer once
        -- those are in place (and the neighbour table has had time to warm).
        on_create_session_response = function(sess, rsp)
            if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
                st.err = ("Create Session rejected, cause %d"):format(rsp.cause)
                return loop:stop()
            end
            st.pgw_ctrl_teid = sess:remote_teid()  -- to address later responses to the PGW
            if rsp.has_paa then st.ue_addr = rsp.paa.addr4 end
            if rsp.pco and #rsp.pco > 0 then
                local p = gtp.pco_pcscf_v4(rsp.pco)
                st.pcscf = p ~= "" and p or nil
            end
            st.session_up = true
            line("<- Create Session Resp", ("accepted; PGW ctrl TEID %#x"):format(sess:remote_teid()))
            if st.ue_addr then line("PAA (UE address)", st.ue_addr) end
            line("P-CSCF (from PCO)", st.pcscf or "not returned")

            -- Kick off after on_user_plane has programmed the filters (it
            -- runs synchronously right after this handler); ~200ms also lets
            -- the primed neighbour entries resolve before the first encap.
            arm(200, begin_registration)
        end,

        -- One per bearer F-TEID in the accepted response: the PGW's
        -- data-plane endpoint (the default bearer over S5/S8-U). IMS SIP
        -- signalling rides the default bearer, so steer the UE's uplink SIP
        -- toward the P-CSCF onto it with a TFT; add_filter also installs the
        -- decap entry so the P-CSCF's 401/200 come back down the same
        -- bearer. A downlink UE /32 entry is deliberately not programmed --
        -- its destination is the UE, which a real UPF rejects as uplink.
        on_user_plane = function(sess, tun)
            line("user plane (S5/S8-U)",
                 ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                     :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
            if st.pcscf then
                program_filter(tun.ebi, tun.local_teid, tun.remote_teid,
                               tun.remote_addr, st.pcscf)
            else
                line("GTP-U filter",
                     ("EBI %d not programmed (no P-CSCF IPv4 in Create Session PCO)"):format(tun.ebi))
            end
        end,

        -- With the default bearer up the PGW opens a dedicated bearer with
        -- a Create Bearer Request (§7.2.3); accept it and answer with a
        -- typed Create Bearer Response (§7.2.4) addressed to the PGW's
        -- control TEID, echoing the request's sequence.
        on_create_bearer_request = function(req, host, port)
            line("<- Create Bearer Req",
                 ("seq %d; accepting dedicated bearer"):format(req.sequence))

            -- The request's bearer context carries the PGW's S5/S8-U
            -- F-TEID; echo it back so the PGW can correlate the bearer.
            local pgw_u
            if req.bearers:size() > 0 then
                local fts = req.bearers[0].fteids
                if fts:size() > 0 then pgw_u = fts[0].fteid end
            end

            -- Response bearer context: the EBI we allocate for the new
            -- bearer, an accepted cause, our S5/S8-U SGW F-TEID (instance
            -- 2) and the echoed PGW F-TEID (instance 3).
            local NEW_EBI = 6
            local rbc = gtp.BearerContext()
            rbc.ebi   = NEW_EBI
            rbc.cause = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, S5_UP_TEID + 1, sgw_ip
            rbc:add_fteid(2, u)
            if pgw_u then rbc:add_fteid(3, pgw_u) end

            local resp = gtp.CreateBearerResponse()
            resp.teid     = st.pgw_ctrl_teid or 0    -- to the PGW's control TEID
            resp.sequence = req.sequence             -- echo the request's sequence
            resp.cause    = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            resp.pti      = req.pti                   -- echo the PTI (-1 => omitted)
            resp:add_bearer(rbc)

            ep:send_create_bearer_response(resp, host, port)
            line("-> Create Bearer Resp",
                 ("seq %d, EBI %d, cause accepted"):format(req.sequence, NEW_EBI))

            -- The dedicated bearer is a media bearer: the SMF/PCRF installs
            -- its own uplink SDF on the UPF (the negotiated media flow),
            -- which SIP does not match. IMS signalling rides the default
            -- bearer (programmed in on_user_plane), so we accept and report
            -- this bearer but do not program a datapath entry or probe it.
            line("note",
                 ("dedicated bearer EBI %d accepted (media); not programmed/probed"):format(NEW_EBI))
            st.cbr_done = true
            -- If registration already finished, this was the awaited late
            -- bearer: stop now instead of waiting out the grace timer.
            if st.registered then
                if grace then loop:cancel(grace); grace = nil end
                loop:stop()
            end
        end,

        on_timeout = function(sess, mt)
            fail(("PGW did not answer message type %d (after %d sends)"):format(mt, N3))
        end,
    })

    -- Create Session Request: attach the UE's default bearer over S5/S8.
    -- The SGW S5/S8-C sender F-TEID's TEID and address are filled in by
    -- create_session (a fresh control TEID, the endpoint's bound address).
    local req = gtp.CreateSessionRequest()
    req.imsi     = imsi
    req.apn      = apn
    req.rat_type = gtp.GTP2_RAT_EUTRAN
    req.pdn_type = gtp.GTP2_PDN_IPV4

    -- Serving Network (§8.18) and UE Location (§8.21): the PGW treats both
    -- as mandatory on the S5/S8 Create Session. The PLMN matches the IMSI.
    req.serving_network = gtp.plmn_encode(mcc, mnc)
    req.uli             = gtp.uli_tai_ecgi(mcc, mnc, 0x0001, 0x0000001)

    -- PDN Address Allocation (§8.14): offer 0.0.0.0 to request a dynamic
    -- IPv4 address; the PGW returns the one it assigned in its own PAA.
    req.has_paa      = true
    req.paa.pdn_type = gtp.GTP2_PDN_IPV4
    req.paa.addr4    = "0.0.0.0"

    -- Protocol Configuration Options (§8.13): request the IMS P-CSCF IPv4
    -- address (container 0x000C) -- the PGW echoes it back carrying the
    -- address(es) it assigned.
    req.pco = gtp.pco_request_pcscf()

    local c = gtp.Fteid()
    c.if_type = gtp.GTP2_IF_S5S8C_SGW               -- sender F-TEID: SGW S5/S8-C
    req.sender_fteid = c

    local bc = gtp.BearerContext()
    bc.ebi     = 5
    bc.has_qos = true
    bc.qos.qci = 9
    local u = gtp.Fteid()                           -- bearer F-TEID: SGW S5/S8-U
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, S5_UP_TEID, sgw_ip
    bc:add_fteid(2, u)                              -- instance 2 = S5/S8-U SGW slot
    req:add_bearer(bc)

    local sess = ep:create_session(req, pgw_ip)     -- request sent, transaction tracked
    line("-> Create Session Req", ("SGW ctrl TEID %#x, IMSI %s, APN %s")
        :format(sess:local_teid(), imsi, apn))

    -- One dispatcher for every socket and timer in the scenario: the GTP-C
    -- endpoint, the UE's SIP socket, and every deadline. It runs until a
    -- terminal step calls loop:stop() (registered, rejected, or timed out).
    local rok, rerr = pcall(function() loop:run() end)

    -- Teardown that needs no loop: drop the ESP SA state, the SIP socket and
    -- the UE-PAA local route. Runs whether the flow completed or aborted.
    if xfrm then
        attempt("flush ESP policies", function() xfrm:flush_policy() end)
        attempt("flush ESP SAs",      function() xfrm:flush_sa(ipsec.PROTO_ESP) end)
    end
    if sock then
        pcall(function() loop:del_fd(sock:fd()) end)
        sock:close()
    end
    pcall(del_paa_route)
    if not rok then st.err = st.err or why(rerr) end   -- a loop/callback exception

    return { loop = loop, ep = ep, sess = sess, st = st, up = up, ue_addr = st.ue_addr }
end

-- main
local pdn = attach_pdn_over_s5()
if pdn.st.err then
    line("result", pdn.st.err)
    os.exit(1)
end
if pdn.st.registered then
    line("result", "PDN connection + IMS registration complete over S5/S8")
else
    line("result", "PDN connection established over S5/S8 (IMS registration not completed)")
end
