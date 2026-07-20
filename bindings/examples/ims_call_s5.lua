#!/usr/bin/env lua
-- IMS-AKA registration and call from the UE side of the Gm reference
-- point (UE <-> P-CSCF), sent over a real UDP socket so it can be run
-- against a live IMS core. This is the active-client counterpart to a
-- passive probe: it drives one UE through the security-agreement dance
-- that TS 33.203 puts around SIP registration, and installs the IPsec
-- ESP SAs that every message after the challenge rides in.
--
--   1. REGISTER (unprotected) with a Security-Client offer.
--   2. 401 with the AKA challenge (RAND||AUTN in the nonce) and the
--      P-CSCF's Security-Server (its SPIs and protected ports).
--   3. Milenage on the USIM secret: verify AUTN, derive RES, CK, IK.
--   4. Install four transport-mode ESP SAs (TS 33.203 Annex I keys the
--      integrity SA from IK and the AES-CBC SA from CK) plus the
--      policies that steer the protected ports onto them.
--   5. REGISTER (protected) with the AKAv1-MD5 digest response and a
--      Security-Verify; 200 OK. Then an INVITE/BYE, all over the SAs.
--
-- Optionally, given a PGW address, the script first raises the PDN
-- connection that IMS access rides on: acting as the SGW it sends a
-- GTPv2-C Create Session Request to the PGW over S5/S8 (gtp.Endpoint)
-- and registers callbacks for the PGW's responses — the Create Session
-- Response carries the UE address the PGW allocated (PAA) and the PGW's
-- user-plane F-TEID. The session is deleted again during teardown.
--
-- Transport is net.UdpSocket (the transport layer's non-blocking UDP
-- socket); the kernel applies ESP underneath, so the script still sends
-- plain SIP from the UE's protected client port. Crypto is
-- ipsec.aka_* (Milenage) and ipsec.md5. SIP is built/parsed with sip,
-- and a sip.Transaction tracks each RFC 3261 transaction.
--
-- Manipulating SAs needs CAP_NET_ADMIN; each kernel op is wrapped so an
-- unprivileged run reports it "skipped" rather than aborting.
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so lua ims_call_s5.lua \
--       PCSCF_IP [UE_IP] [CALLEE] [PGW_IP]
--
-- PCSCF_IP is required; the script drives one UE against that live
-- P-CSCF over a real UDP socket. If PGW_IP is given (positionally or via
-- $PGW_IP) the S5/S8 Create Session to the PGW runs first; $SGW_IP sets
-- the local GTP-C source (default UE_IP), $IMS_IMSI / $IMS_APN the attach
-- identity (default TS 35.207 test IMSI, APN "ims").

local gtp   = require("gtp")
local net   = require("net")     -- event loop + UDP socket transport
local sip   = require("sip")
local ipsec = require("ipsec")

-- ---- configuration ----------------------------------------------------

local pcscf_ip = arg[1]                       -- P-CSCF IP (required)
local ue_ip    = arg[2] or "127.0.0.1"
local callee   = arg[3] or "bob"
local pgw_ip   = arg[4] or os.getenv("PGW_IP") -- optional: raise the S5/S8 PDN first
local sgw_ip   = os.getenv("SGW_IP") or ue_ip  -- local GTP-C (S5/S8) source address

local REALM = os.getenv("IMS_REALM") or "ims.example.net"
local name  = os.getenv("IMS_USER")  or "alice"
local impi  = name .. "@" .. REALM
local impu  = "sip:" .. name .. "@" .. REALM
local imsi  = os.getenv("IMS_IMSI") or "001010123456789"  -- S5/S8 attach (TS 35.207 test IMSI)
local apn   = os.getenv("IMS_APN")  or "ims"

local PCSCF_SIP_PORT = 5060                   -- unprotected REGISTER lands here
local PORT_UC, PORT_US = 5088, 5090           -- UE protected client / server ports
local SPI_UC, SPI_US   = 0x2001, 0x2002       -- UE's inbound SPIs

-- USIM secret (raw 16-byte hex). Defaults are 3GPP TS 35.207 Milenage
-- Test Set 1; override IMS_K / IMS_OP (or IMS_OPC) for a real USIM.
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end

local K   = unhex(os.getenv("IMS_K")  or "465b5ce8b199b49faa5f0a2ee238a6bc")
local OP  = unhex(os.getenv("IMS_OP") or "cdc202d5123e20f62b6d676ac72cb318")
local OPc = os.getenv("IMS_OPC") and unhex(os.getenv("IMS_OPC")) or ipsec.aka_opc(K, OP)

-- ---- little helpers ---------------------------------------------------

local function banner(t) print(("\n== %s"):format(t)) end
local function line(k, v) print(("   %-22s %s"):format(k, v)) end
local function fsm(label, m) print(("       [fsm] %-28s -> %s"):format(label, m:state_name())) end

-- base64 decode, for the AKA nonce (RAND||AUTN) in the 401 challenge
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64dec(s)
    local map = {}; for i = 1, #B64 do map[B64:byte(i)] = i - 1 end
    local acc, nbits, out = 0, 0, {}
    for i = 1, #s do
        local v = map[s:byte(i)]
        if v then
            acc = (acc << 6) | v; nbits = nbits + 6
            if nbits >= 8 then nbits = nbits - 8; out[#out + 1] = string.char((acc >> nbits) & 0xff) end
        end
    end
    return table.concat(out)
end

-- HTTP Digest AKAv1-MD5 (RFC 3310 + RFC 2617): the RES is the password.
local function md5hex(s) return hex(ipsec.md5(s)) end
local function digest_response(user, realm, res, method, uri, nonce, nc, cnonce, qop)
    local ha1 = md5hex(user .. ":" .. realm .. ":" .. res)
    local ha2 = md5hex(method .. ":" .. uri)
    if qop then
        return md5hex(ha1 .. ":" .. nonce .. ":" .. nc .. ":" .. cnonce .. ":" .. qop .. ":" .. ha2)
    end
    return md5hex(ha1 .. ":" .. nonce .. ":" .. ha2)
end

-- pull one quoted or bare token out of an auth-style header
local function auth_param(hdr, key)
    return hdr:match(key .. '%s*=%s*"([^"]*)"') or hdr:match(key .. '%s*=%s*([^,%s]+)')
end
-- pull one "spi-s=1234" style token out of a Security-* header (';' list)
local function sec_param(hdr, key)
    return hdr:match((key:gsub("%-", "%%-")) .. "=([%w%.]+)")
end

-- run a kernel op, turning a CAP_NET_ADMIN rejection into one line
local function attempt(what, fn)
    local ok, err = pcall(fn)
    if not ok then err = tostring(err):gsub("^.-:%s*", "") end
    print(("       %-30s %s"):format(what, ok and "ok" or ("skipped (" .. err .. ")")))
    return ok
end

-- ---- SIP message construction ----------------------------------------

local seq = 0
local function next_cseq() seq = seq + 1; return seq end

-- The UE's Security-Client offer (RFC 3329 / TS 33.203).
local function security_client()
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(SPI_UC, SPI_US, PORT_UC, PORT_US)
end

local function register(cseq, authz, sec_hdr, sec_name)
    local b = sip.Builder()
        :request(sip.REGISTER, "sip:" .. REALM)
        :header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(ue_ip, PORT_UC, name, cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(impu, name, cseq))
        :header(sip.H_TO, ("<%s>"):format(impu))
        :header(sip.H_CALL_ID, name .. "-reg@" .. ue_ip)
        :header(sip.H_CSEQ, ("%d REGISTER"):format(cseq))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(ue_ip, PORT_UC))
        :header_u32(sip.H_EXPIRES, 600000)
        :header(sip.H_AUTHORIZATION, authz)
    if sec_hdr then b:header_name(sec_name, sec_hdr) end
    return b:done()
end

-- ---- AKA + IPsec ------------------------------------------------------

-- Parse the 401: the AKA challenge from WWW-Authenticate and the
-- P-CSCF's Security-Server. Returns rand, autn, realm, and the P-CSCF
-- security parameters.
local function parse_challenge(msg)
    local wa = msg:header("WWW-Authenticate")
    assert(wa ~= "", "401 without WWW-Authenticate")
    local nonce = auth_param(wa, "nonce")
    local blob  = b64dec(nonce)
    assert(#blob >= 32, "AKA nonce shorter than RAND||AUTN")
    local ss = msg:header("Security-Server")
    assert(ss ~= "", "401 without Security-Server")
    return {
        rand   = blob:sub(1, 16),
        autn   = blob:sub(17, 32),
        realm  = auth_param(wa, "realm") or REALM,
        qop    = auth_param(wa, "qop"),
        p_spi_c = tonumber(sec_param(ss, "spi-c")),
        p_spi_s = tonumber(sec_param(ss, "spi-s")),
        p_port_c = tonumber(sec_param(ss, "port-c")),
        p_port_s = tonumber(sec_param(ss, "port-s")),
    }
end

-- Build (and, given an Xfrm handle, install) the four transport-mode
-- ESP SAs and their steering policies. Keys come straight from AKA:
-- IK integrity-protects, CK encrypts (TS 33.203 Annex I). Returns the
-- P-CSCF protected server port to send protected requests to.
local function establish_sas(xfrm, ch, keys)
    local function esp_sa(src, dst, spi, reqid)
        local sa = ipsec.Sa()
        sa.src, sa.dst, sa.spi = src, dst, spi
        sa.proto, sa.mode, sa.reqid = ipsec.PROTO_ESP, ipsec.TRANSPORT, reqid
        sa.enc_alg,  sa.enc_key  = "cbc(aes)",  keys.ck   -- confidentiality key
        sa.auth_alg, sa.auth_key = "hmac(sha1)", keys.ik   -- integrity key (SHA-1-96)
        return sa
    end
    local function esp_policy(dir, src, dst, sport, dport, reqid)
        local p = ipsec.Policy()
        p.src, p.dst = src, dst
        p.sel_proto, p.sport, p.dport = 17, sport, dport   -- UDP selector
        p.dir, p.action = dir, ipsec.ALLOW
        p.has_tmpl, p.tmpl_reqid = true, reqid
        p.tmpl_proto, p.tmpl_mode = ipsec.PROTO_ESP, ipsec.TRANSPORT
        return p
    end

    -- Four SAs, keyed by the receiver's SPI: UE->P to the P-CSCF server
    -- and client ports (outbound), P->UE to the UE server and client
    -- ports (inbound). reqid = SPI keeps each policy tied to its SA.
    local sas = {
        esp_sa(ue_ip, pcscf_ip, ch.p_spi_s, ch.p_spi_s),   -- UE requests  -> P server port
        esp_sa(ue_ip, pcscf_ip, ch.p_spi_c, ch.p_spi_c),   -- UE responses -> P client port
        esp_sa(pcscf_ip, ue_ip, SPI_UC,     SPI_UC),       -- P responses  -> UE client port
        esp_sa(pcscf_ip, ue_ip, SPI_US,     SPI_US),       -- P requests   -> UE server port
    }
    local pols = {
        esp_policy(ipsec.DIR_OUT, ue_ip, pcscf_ip, PORT_UC, ch.p_port_s, ch.p_spi_s),
        esp_policy(ipsec.DIR_OUT, ue_ip, pcscf_ip, PORT_US, ch.p_port_c, ch.p_spi_c),
        esp_policy(ipsec.DIR_IN,  pcscf_ip, ue_ip, ch.p_port_s, PORT_UC, SPI_UC),
        esp_policy(ipsec.DIR_IN,  pcscf_ip, ue_ip, ch.p_port_c, PORT_US, SPI_US),
    }

    line("ESP keys", ("enc(CK)=%s  auth(IK)=%s"):format(hex(keys.ck), hex(keys.ik)))
    line("UE ports", ("client %d / server %d, SPIs %#x/%#x"):format(PORT_UC, PORT_US, SPI_UC, SPI_US))
    line("P-CSCF ports", ("client %d / server %d, SPIs %#x/%#x")
        :format(ch.p_port_c, ch.p_port_s, ch.p_spi_c, ch.p_spi_s))

    if xfrm then
        for i, sa in ipairs(sas) do attempt(("add SA %d (spi %#x)"):format(i, sa.spi), function() xfrm:sa_add(sa) end) end
        for i, p  in ipairs(pols) do attempt(("add policy %d (%s)"):format(i, p.dir == ipsec.DIR_OUT and "out" or "in"),
                                             function() xfrm:policy_add(p) end) end
    end
    return sas, pols
end

-- ---- GTPv2-C over S5/S8: the PDN connection behind the IMS access ----
--
-- Before any IMS signalling the UE needs a PDN connection: a default EPS
-- bearer and an IP address. In the EPC that is set up over GTPv2-C
-- (TS 29.274) — the SGW sends a Create Session Request to the PGW across
-- S5/S8, and the response carries the address the PGW allocated for the
-- UE (the PAA) plus the PGW's user-plane F-TEID. Here the script plays
-- the SGW: it raises that session first and reports what the PGW handed
-- back, then runs the IMS-AKA registration over Gm as before.
--
-- gtp.Endpoint drives the transaction on its own GTP-C socket over the
-- net_loop (sequence numbers, T3/N3 retransmission, response matching);
-- we register callbacks for the PGW's responses and step the loop until
-- one lands (or the retransmissions time out).

local S5_UP_TEID = 0x200   -- our (SGW) S5/S8-U downlink tunnel endpoint id

-- Step the loop until the in-flight transaction resolves: a response
-- sets st.done, an N3 timeout or a rejection sets st.err. The endpoint's
-- own retransmission timer guarantees step() cannot block forever.
local function pump(loop, st)
    while not (st.done or st.err) do loop:step(-1) end
    assert(not st.err, st.err)
end

-- Raise the UE's PDN connection over S5/S8 and return a handle
-- {loop, ep, sess, st, ue_addr}; the handler reports each PGW response.
local function attach_pdn_over_s5()
    banner(("GTPv2-C — PDN connection over S5/S8: SGW %s -> PGW %s"):format(sgw_ip, pgw_ip))
    local loop = net.Loop()
    local ep   = gtp.Endpoint(loop, sgw_ip)         -- binds sgw_ip:2123 (GTP-C)
    local st   = { done = false, err = nil, ue_addr = nil }

    ep:set_handler({
        -- The PGW answered the Create Session: read the cause, the
        -- allocated UE address (PAA) and the PGW's control TEID.
        on_create_session_response = function(sess, rsp)
            if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
                st.err = ("Create Session rejected, cause %d"):format(rsp.cause)
                return
            end
            if rsp.has_paa then st.ue_addr = rsp.paa.addr4 end
            line("<- Create Session Resp", ("accepted; PGW ctrl TEID %#x"):format(sess:remote_teid()))
            if st.ue_addr then line("PAA (UE address)", st.ue_addr) end
            st.done = true
        end,

        -- One per bearer F-TEID in the accepted response: the PGW's
        -- data-plane endpoint. A real SGW would program its GTP-U
        -- datapath (gtp.UserPlane) here; we just report it.
        on_user_plane = function(sess, tun)
            line("user plane (S5/S8-U)",
                 ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                     :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
        end,

        on_delete_session_response = function(sess, rsp)
            line("<- Delete Session Resp", ("cause %d"):format(rsp.cause))
            st.done = true
        end,

        on_timeout = function(sess, mt)
            st.err = ("PGW did not answer message type %d"):format(mt)
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

    local c = gtp.Fteid()
    c.if_type = gtp.GTP2_IF_S5S8C_SGW               -- sender F-TEID: SGW S5/S8-C
    req.sender_fteid = c

    local bc = gtp.BearerContext()
    bc.ebi     = 5
    bc.has_qos = true
    bc.qos.qci = 9
    local u = gtp.Fteid()                           -- bearer F-TEID: SGW S5/S8-U
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, S5_UP_TEID, sgw_ip
    bc:add_fteid(0, u)
    req:add_bearer(bc)

    local sess = ep:create_session(req, pgw_ip)     -- request sent, transaction tracked
    line("-> Create Session Req", ("SGW ctrl TEID %#x, IMSI %s, APN %s")
        :format(sess:local_teid(), imsi, apn))
    pump(loop, st)

    return { loop = loop, ep = ep, sess = sess, st = st, ue_addr = st.ue_addr }
end

-- ---- online run -------------------------------------------------------

local function recv_msg(sock, timeout_ms, what)
    local d = sock:recv(timeout_ms or 5000)
    assert(not d.timed_out, ("timed out waiting for %s"):format(what or "a response"))
    return sip.parse(d.data), d
end

local function run_online()
    -- Optional: raise the PDN connection over S5/S8 to the PGW first, so
    -- the IMS registration below runs "behind" a real EPC bearer. The
    -- PAA is the address the PGW assigned; the SIP socket still binds
    -- ue_ip (the PGW address may not be configured on this host).
    local pdn
    if pgw_ip then
        pdn = attach_pdn_over_s5()
        if pdn.ue_addr then
            line("note", ("PGW assigned %s; IMS signalling binds %s"):format(pdn.ue_addr, ue_ip))
        end
    end

    banner(("IMS-AKA registration — %s -> P-CSCF %s (Gm)"):format(impi, pcscf_ip))
    local sock = net.UdpSocket(ue_ip, PORT_UC)     -- protected client port
    line("bound", ("%s:%d"):format(ue_ip, sock:local_port()))

    -- Round 1: unprotected REGISTER carrying the Security-Client offer.
    local uac = sip.Transaction(sip.NON_INVITE_CLIENT)
    local reg1 = register(next_cseq(),
        ('Digest username="%s",realm="%s",uri="sip:%s",nonce="",response="",algorithm=AKAv1-MD5')
        :format(impi, REALM, REALM),
        security_client(), "Security-Client")
    sock:sendto(reg1, pcscf_ip, PCSCF_SIP_PORT)
    uac:send(sip.parse(reg1))
    line("-> REGISTER", ("unprotected, %d B"):format(#reg1)); fsm(name .. " UAC", uac)

    local m401 = recv_msg(sock, 5000, "401")
    uac:recv(m401)
    assert(m401.status == 401, ("expected 401, got %d"):format(m401.status))
    line("<- 401", "AKA challenge + Security-Server"); fsm(name .. " UAC", uac)

    -- Round 2: verify the challenge, derive the keys, raise the SAs.
    local ch = parse_challenge(m401)
    line("RAND", hex(ch.rand)); line("AUTN", hex(ch.autn))
    local v = ipsec.aka_verify(K, OPc, ch.rand, ch.autn)   -- throws on MAC failure
    line("AUTN verified", ("SQN %s, RES %s"):format(hex(v.sqn), hex(v.res)))

    banner("IPsec — establishing ESP SAs (transport mode)")
    local xfrm = ipsec.Xfrm()
    establish_sas(xfrm, ch, v)

    -- Round 3: protected REGISTER with the AKAv1-MD5 digest response.
    banner("IMS-AKA registration — protected REGISTER over ESP")
    local cseq = next_cseq()
    local nc, cnonce = "00000001", hex(ipsec.md5(name .. tostring(cseq)):sub(1, 8))
    local resp = digest_response(impi, ch.realm, v.res, "REGISTER",
                                 "sip:" .. REALM, auth_param(m401:header("WWW-Authenticate"), "nonce"),
                                 nc, cnonce, ch.qop)
    local authz = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(impi, ch.realm, REALM, auth_param(m401:header("WWW-Authenticate"), "nonce"), resp)
    if ch.qop then authz = authz .. (',qop=%s,nc=%s,cnonce="%s"'):format(ch.qop, nc, cnonce) end

    local uac2 = sip.Transaction(sip.NON_INVITE_CLIENT)
    local reg2 = register(cseq, authz, security_client() .. "; q=0.1", "Security-Verify")
    sock:sendto(reg2, pcscf_ip, ch.p_port_s)       -- to the protected server port; kernel ESP-wraps it
    uac2:send(sip.parse(reg2))
    line("-> REGISTER", ("protected (ESP), %d B"):format(#reg2)); fsm(name .. " UAC", uac2)

    local m200 = recv_msg(sock, 5000, "200 OK")
    uac2:recv(m200)
    assert(m200.status == 200, ("registration failed: %d %s"):format(m200.status, m200.reason))
    line("<- 200 OK", "registered"); fsm(name .. " UAC", uac2)

    -- A call, protected end to end (media/RTP would ride its own bearer).
    banner(("Call — %s INVITEs %s (over ESP)"):format(name, callee))
    local callee_uri = ("sip:%s@%s"):format(callee, REALM)
    local offer = ("v=0\r\no=%s 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n" ..
                   "m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR/8000\r\n"):format(name, ue_ip, ue_ip)
    local invite = sip.Builder()
        :request(sip.INVITE, callee_uri)
        :header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-call-1"):format(ue_ip, PORT_UC))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=caller-1"):format(impu))
        :header(sip.H_TO, ("<%s>"):format(callee_uri))
        :header(sip.H_CALL_ID, "call-1@" .. ue_ip)
        :header(sip.H_CSEQ, "1 INVITE")
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(ue_ip, PORT_UC))
        :header(sip.H_CONTENT_TYPE, "application/sdp")
        :done(offer)
    local ic = sip.Transaction(sip.INVITE_CLIENT)
    sock:sendto(invite, pcscf_ip, ch.p_port_s)
    ic:send(sip.parse(invite))
    line("-> INVITE", ("SDP offer, %d B"):format(#invite)); fsm(name .. " UAC", ic)

    -- Read provisional/final responses until a final (>=200) arrives.
    local final
    repeat
        local m = recv_msg(sock, 10000, "an INVITE response")
        ic:recv(m)
        line(("<- %d"):format(m.status), m.reason); fsm(name .. " UAC", ic)
        if m.status >= 200 then final = m end
    until final
    if final.status < 300 then
        local ack = sip.Builder()
            :request(sip.ACK, callee_uri)
            :header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-call-ack"):format(ue_ip, PORT_UC))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, ("<%s>;tag=caller-1"):format(impu))
            :header(sip.H_TO, final:header("To"))
            :header(sip.H_CALL_ID, "call-1@" .. ue_ip)
            :header(sip.H_CSEQ, "1 ACK")
            :done()
        sock:sendto(ack, pcscf_ip, ch.p_port_s)
        line("-> ACK", "call up")
    end

    -- Teardown: de-register, then tear the SAs down.
    banner("Teardown")
    local dereg = register(next_cseq(),
        ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(impi, ch.realm, REALM, auth_param(m401:header("WWW-Authenticate"), "nonce"), resp))
    dereg = dereg:gsub("Expires: 600000", "Expires: 0")
    sock:sendto(dereg, pcscf_ip, ch.p_port_s)
    line("-> REGISTER", "de-register (Expires: 0)")
    pcall(function() recv_msg(sock, 3000, "de-register 200") end)
    attempt("flush policies", function() xfrm:flush_policy() end)
    attempt("flush ESP SAs",  function() xfrm:flush_sa(ipsec.PROTO_ESP) end)
    if pdn then
        pdn.st.done, pdn.st.err = false, nil
        pdn.sess:delete_session()                  -- DSReq with the default bearer's EBI
        line("-> Delete Session Req", "S5/S8 PDN teardown")
        pcall(function() pump(pdn.loop, pdn.st) end)
    end
    sock:close()
    print("\nregistration + call complete")
end

-- main
if not pcscf_ip then
    io.stderr:write("usage: ims_call_s5.lua PCSCF_IP [UE_IP] [CALLEE] [PGW_IP]\n")
    os.exit(1)
end
-- run_online()
if pgw_ip then
    pdn = attach_pdn_over_s5()
    if pdn.ue_addr then
        line("note", ("PGW assigned %s; IMS signalling binds %s"):format(pdn.ue_addr, ue_ip))
    end
end
