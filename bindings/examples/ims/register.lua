-- ims/register.lua — the REGISTER, and the IMS-AKA credentials that earn the
-- 200 OK (RFC 3261 §10, TS 24.229 §5.1, TS 33.203 §6.1/§6.3).
--
-- Message building and cryptography only: no sockets, no timers, no state
-- beyond the subscriber passed in. The exchange that uses these is
-- ims/regflow.lua.

local sip   = require("sip")
local ipsec = require("ipsec")
local cfg   = require("ims.cfg")
local wire  = require("ims.wire")

local M = {}

-- Parameters appended to the Contact of a non-de-REGISTER. TS 24.341 §5.3.2.2:
-- a UE that does SMS over IP says so with the +g.3gpp.smsip feature tag, and in
-- a real network MT routing depends on it — the IP-SM-GW checks the registered
-- contact's capabilities before choosing IP delivery over the circuit-switched
-- fallback. A script that can carry SMS sets this (to sms.FEATURE_TAG) for
-- every REGISTER it sends, not only when its SMS phase is enabled; one that
-- cannot leaves it nil rather than advertising a capability it does not have.
M.contact_params = nil

-- ---- the Security-Client offer ----------------------------------------

-- The UE's Security-Client offer (RFC 3329 / TS 33.203): its two inbound SPIs,
-- its protected ports and the ESP algorithms.
--
-- ealg=null: confidentiality is OPTIONAL in TS 33.203 (§6.3, Annex I — only
-- integrity is mandatory), so the SAs run ESP-NULL. Integrity still covers
-- every protected message with IK, the SPI/port plumbing is unchanged, and the
-- SIP stays readable in a capture while the kernel skips the cipher.
-- kamailio's ims_ipsec_pcscf maps this offer to the kernel's cipher_null; it is
-- the only ealg we offer, so it is the one it must select.
--
-- port-c and port-s are deliberately the SAME port, which is what makes
-- terminating requests (an MT INVITE, a BYE from the far end, a reg-event
-- NOTIFY) reach the UE at all. TS 33.203 §6.3 pairs them the other way — SA1 is
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
function M.security_client(sub)
    return ("ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; " ..
            "spi-c=%d; spi-s=%d; port-c=%d; port-s=%d")
        :format(sub.spi_uc, sub.spi_us, sub.port_uc, sub.port_uc)
end

-- ---- the Authorization header -----------------------------------------

-- The Authorization value (AKAv1-MD5 Digest). `realm` MUST be the one from the
-- challenge: the S-CSCF recomputes HA1 with the realm it reads back from this
-- header, so header-realm == computed-realm always — a derived home domain that
-- differs from the challenge realm (a two- vs three-digit MNC is the usual one)
-- makes the two HA1s diverge and auth fail with a repeat 401. The digest-uri
-- stays the home domain (= Request-URI). An empty nonce/response advertises
-- IMS-AKA on the first REGISTER.
function M.authz_hdr(sub, realm, nonce, response, qopset)
    local a = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(sub.impi, realm, cfg.realm, nonce or "", response or "")
    if qopset then
        a = a .. (',qop=%s,nc=%s,cnonce="%s"'):format(qopset.qop, qopset.nc, qopset.cnonce)
    end
    return a
end

-- What the first REGISTER carries: IMS-AKA advertised, nothing computed yet.
function M.advertise(sub) return M.authz_hdr(sub, cfg.realm, "", "") end

-- ---- building the REGISTER --------------------------------------------

-- Via/Contact carry the UE's address at its protected client port; a fresh
-- transaction per REGISTER keys the branch and From-tag on the CSeq, while the
-- Call-ID is stable across the binding's life.
function M.build(sub, authz, sec_name, sec_hdr, expires)
    local contact = ("<sip:%s:%d>"):format(sub.ue_addr, sub.port_uc)
    if expires == 0 then
        contact = contact .. ";expires=0"                       -- bind removal
    elseif M.contact_params then
        contact = contact .. ";" .. M.contact_params
    end
    local b = wire.builder
        :request(sip.REGISTER, "sip:" .. cfg.realm)
        :header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d")
                           :format(sub.ue_addr, sub.port_uc, sub.imsi, sub.cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(sub.impu, sub.imsi, sub.cseq))
        :header(sip.H_TO, ("<%s>"):format(sub.impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(sub.imsi, sub.ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(sub.cseq))
        :header(sip.H_CONTACT, contact)
        :header_u32(sip.H_EXPIRES, expires or cfg.expires)
        :header(sip.H_AUTHORIZATION, authz)
    if sec_hdr then b:header_name(sec_name, sec_hdr) end
    return b:done()
end

-- ---- reading the 401 --------------------------------------------------

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

-- The AKA challenge from WWW-Authenticate (nonce is base64(RAND||AUTN)) and,
-- when present, the P-CSCF's Security-Server (its SPIs and protected ports).
function M.parse_challenge(msg)
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
        realm = realm ~= "" and realm or cfg.realm,
        qop   = pick_qop(sip.auth_param(wa, "qop")),
        ss_raw   = ss,
        p_spi_c  = ss and tonumber(sip.auth_param(ss, "spi-c")),
        p_spi_s  = ss and tonumber(sip.auth_param(ss, "spi-s")),
        p_port_c = ss and tonumber(sip.auth_param(ss, "port-c")),
        p_port_s = ss and tonumber(sip.auth_param(ss, "port-s")),
    }
end

-- Did the P-CSCF offer SAs to raise? Its Security-Server has to name at least
-- the SPI and port the protected REGISTER goes to.
function M.offers_ipsec(ch)
    return (ch.ss_raw and ch.p_spi_s and ch.p_port_s) and true or false
end

-- ---- the credentials --------------------------------------------------

-- Verify AUTN against the USIM secret and derive RES/CK/IK (raises on a MAC or
-- SQN failure, which is what a wrongly provisioned HSS looks like from here).
function M.verify_aka(ch)
    return ipsec.aka_verify(cfg.k, cfg.opc, ch.rand, ch.autn)
end

-- The Authorization for the authenticated REGISTER. The caller has already
-- bumped sub.cseq — the cnonce is derived from it, so the two cannot drift.
function M.digest(sub, ch, keys)
    local nc     = "00000001"
    local cnonce = cfg.hex(ipsec.md5(sub.imsi .. tostring(sub.cseq)):sub(1, 8))
    local response = ipsec.aka_digest(sub.impi, ch.realm, keys.res, "REGISTER",
                                      "sip:" .. cfg.realm, ch.nonce, nc, cnonce,
                                      ch.qop or "")
    return M.authz_hdr(sub, ch.realm, ch.nonce, response,
                       ch.qop and { qop = ch.qop, nc = nc, cnonce = cnonce })
end

return M
