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
-- With both interfaces attached the script drives a full IMS registration
-- end to end over the encap path: a real SIP REGISTER from the UE toward
-- the P-CSCF (whose address the PGW returned in the Create Session
-- Response PCO, TS 24.008 container 0x000C), the P-CSCF's 401 IMS-AKA
-- challenge (RAND||AUTN), the authenticated REGISTER carrying the
-- AKAv1-MD5 digest response, and the 200 OK. IMS signalling rides the
-- default bearer, so the REGISTER is steered onto it (a UDP:5060 TFT) and
-- the UPF routes it to the P-CSCF; the 401/200 come back down the same
-- bearer's decap entry. Per-TEID kernel counters confirm the datapath in
-- both directions (tx on each send, rx on each response). The dedicated
-- (media) bearer from the Create Bearer Request is accepted but not probed.
--
-- IMS-AKA is done at the digest layer only (no IPsec ESP SAs): ESP would
-- turn the inner packet into IP protocol 50, which the UDP:5060 TFT this
-- datapath test verifies would no longer match. The USIM secret defaults
-- to the 3GPP TS 35.207 Milenage test set; override IMS_K / IMS_OP (or
-- IMS_OPC) for a real subscriber.
--
-- The whole scenario is a state machine advanced by socket and timer
-- callbacks on one net.Loop, with a single loop:run() at the bottom
-- instead of any blocking recv() or step() pump.
--

local gtp   = require("gtp")
local net   = require("net")   -- event loop + UDP socket transport + DNS resolver
local sip   = require("sip")   -- IMS REGISTER builder / response parser
local ipsec = require("ipsec") -- Milenage (aka_verify) + md5 for the AKAv1-MD5 digest

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

local IPPROTO_UDP    = 17      -- inner protocol used by the SIP signalling flow
local PCSCF_SIP_PORT = 5060    -- IMS signalling bearer TFT: SIP toward the P-CSCF

local PCO_PCSCF_IPV4 = 0x000c  -- TS 24.008 §10.5.6.3 P-CSCF IPv4 Address container

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

-- Map an interface name to its kernel ifindex through sysfs (the binding
-- exposes no if_nametoindex). Returns nil when the name is unset or the
-- interface is absent, so attach can be skipped cleanly.
local function iface_index(name)
    if not name or name == "" then return nil end
    local f = io.open("/sys/class/net/" .. name .. "/ifindex")
    if not f then return nil end
    local n = tonumber((f:read("*l") or ""):match("%d+"))
    f:close()
    return n
end

-- Read an interface's first IPv4 address through `ip addr` (busybox or
-- iproute2). Returns a dotted-quad or nil. Used to fill SGW_IP from the
-- GTP-U interface so the outer source and the S5/S8 F-TEIDs carry a real
-- address. The name is validated so it cannot smuggle shell syntax.
local function iface_ipv4(name)
    if not name or not name:match("^[%w._-]+$") then return nil end
    local p = io.popen(("ip addr show dev %s 2>/dev/null"):format(name))
    if not p then return nil end
    local out = p:read("*a") or ""; p:close()
    return out:match("inet%s+(%d+%.%d+%.%d+%.%d+)")
end

-- The interface `ip route get <dst>` would send <dst> out of. Used to warn
-- when the P-CSCF would leave via an interface encap is not attached to.
local function route_dev(dst)
    local p = io.popen(("ip route get %s 2>/dev/null"):format(dst))
    if not p then return nil end
    local out = p:read("*a") or ""; p:close()
    return out:match("dev%s+(%S+)")
end

-- Run an `ip ...` command, returning ok and its combined output. `ip` is
-- silent on success, so empty output is the success signal (this reads the
-- same on busybox and iproute2, and needs no version-specific exit-code
-- handling). Used for the best-effort UE-PAA local route below.
local function ip_cmd(args)
    local p = io.popen("ip " .. args .. " 2>&1")
    if not p then return false, "cannot run ip" end
    local out = (p:read("*a") or ""):gsub("%s+$", "")
    p:close()
    return (out == ""), out
end

-- Resolve a host name to an IPv4 literal. A dotted-quad is returned
-- unchanged; otherwise the net module's own asynchronous DNS resolver
-- (net_dns: A/AAAA/SRV/NAPTR over UDP, driven by its private event loop)
-- takes the first A record. net.Resolver() reads /etc/resolv.conf for the
-- nameserver; resolve4() throws on NXDOMAIN or timeout. No external tools.
local function resolve(name)
    if name:match("^%d+%.%d+%.%d+%.%d+$") then return name end
    local ok, res = pcall(function() return net.Resolver():resolve4(name) end)
    assert(ok, ("cannot resolve PGW host name %q: %s"):format(name, why(res)))
    return res
end

-- Encode an MCC/MNC pair into the 3-octet PLMN of TS 24.008 §10.5.1.3,
-- reused by the Serving Network IE (§8.18) and the PLMN inside each ULI
-- field. A two-digit MNC leaves the spare high nibble of octet 2 as 0xF.
-- Nibbles never overlap, so `hi*16 + lo` composes each octet without the
-- 5.3 bitwise operators (this runs under Lua 5.1 / LuaJIT too).
local function plmn(m, n)
    local function d(s, i) return s:byte(i) - 0x30 end
    local n3 = (#n == 3) and d(n, 3) or 0xf
    return string.char(
        d(m, 2) * 16 + d(m, 1),
        n3      * 16 + d(m, 3),
        d(n, 2) * 16 + d(n, 1))
end

-- User Location Information (§8.21): a TAI and an ECGI, each carrying the
-- serving PLMN. Flags 0x18 select TAI (bit 3) and ECGI (bit 4); the two
-- fields follow in the spec's fixed order. TAC is 16-bit, ECI 28-bit (its
-- four spare high bits kept zero). `oct(x, div)` slices byte `div` out of
-- an integer with plain arithmetic, so no 5.3 bitwise operators are used.
local function uli_tai_ecgi(pl, tac, eci)
    local function oct(x, div) return math.floor(x / div) % 256 end
    return string.char(0x18)
        .. pl .. string.char(oct(tac, 256), oct(tac, 1))
        .. pl .. string.char(math.floor(eci / 0x1000000) % 16,
                             oct(eci, 0x10000), oct(eci, 0x100), oct(eci, 1))
end

-- Encode an F-TEID IE value (§8.22) for an IPv4 endpoint: the flags /
-- interface-type octet (V4 bit 0x80 set, interface type in the low six
-- bits), the 32-bit TEID, then the four address octets. Built by hand
-- because the facade only encodes F-TEIDs inside its typed messages, and
-- the Create Bearer Response is assembled from a raw IE tree.
local function fteid_v4(if_type, teid, addr)
    local function oct(x, div) return math.floor(x / div) % 256 end
    local a, b, c, d = addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    return string.char(0x80 + if_type,
                       oct(teid, 0x1000000), oct(teid, 0x10000),
                       oct(teid, 0x100), oct(teid, 1),
                       tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

-- A GTPv2-C Cause IE value (§8.4): the cause octet plus a spare/flags
-- octet (CS/BCE/PCE bits, all zero here).
local function cause_ie(cause) return string.char(cause, 0) end

-- Walk a Protocol Configuration Options field (§8.13 / TS 24.008
-- §10.5.6.3) for the first P-CSCF IPv4 address the PGW returned. Octet 1
-- is the configuration-protocol/flags byte; each container that follows
-- is {id_hi, id_lo, len, len octets}. Container 0x000C carries one or
-- more 4-octet P-CSCF IPv4 addresses. Returns a dotted quad or nil. Plain
-- byte arithmetic only, so it runs under Lua 5.1 / LuaJIT too.
local function pco_pcscf_v4(pco)
    if not pco or #pco < 4 then return nil end
    local i = 2                                   -- skip the flags octet
    while i + 2 <= #pco do
        local id   = pco:byte(i) * 256 + pco:byte(i + 1)
        local len  = pco:byte(i + 2)
        local body = i + 3
        if body + len - 1 > #pco then break end   -- truncated container
        if id == PCO_PCSCF_IPV4 and len >= 4 then
            return ("%d.%d.%d.%d"):format(pco:byte(body), pco:byte(body + 1),
                                          pco:byte(body + 2), pco:byte(body + 3))
        end
        i = body + len
    end
    return nil
end

-- ---- IMS-AKA / HTTP Digest (RFC 3310 + RFC 2617) ----------------------

-- base64 decode, for the AKA nonce (RAND||AUTN) in the 401 challenge.
-- Plain arithmetic (no 5.3 bitwise operators) so it runs under Lua 5.1 /
-- LuaJIT; acc is masked back to its pending low bits each byte, so it
-- never exceeds a double's 53-bit range.
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64dec(s)
    local map = {}; for i = 1, #B64 do map[B64:byte(i)] = i - 1 end
    local acc, nbits, out = 0, 0, {}
    for i = 1, #s do
        local v = map[s:byte(i)]
        if v then
            acc = acc * 64 + v; nbits = nbits + 6      -- acc << 6 | v
            if nbits >= 8 then
                nbits = nbits - 8
                local div = 2 ^ nbits
                out[#out + 1] = string.char(math.floor(acc / div) % 256)  -- (acc >> nbits) & 0xff
                acc = acc % div                        -- keep only the leftover low bits
            end
        end
    end
    return table.concat(out)
end

-- pull one quoted or bare token out of an auth-style header
local function auth_param(hdr, key)
    return hdr:match(key .. '%s*=%s*"([^"]*)"') or hdr:match(key .. '%s*=%s*([^,%s]+)')
end

-- HTTP Digest AKAv1-MD5: the RES recovered from the challenge is the password.
local function md5hex(s) return hex(ipsec.md5(s)) end
local function digest_response(user, realm, res, method, uri, nonce, nc, cnonce, qop)
    local ha1 = md5hex(user .. ":" .. realm .. ":" .. res)
    local ha2 = md5hex(method .. ":" .. uri)
    if qop then
        return md5hex(ha1 .. ":" .. nonce .. ":" .. nc .. ":" .. cnonce .. ":" .. qop .. ":" .. ha2)
    end
    return md5hex(ha1 .. ":" .. nonce .. ":" .. ha2)
end

-- The Authorization header value: AKAv1-MD5 Digest. An empty nonce/
-- response advertises IMS-AKA on the first (unprotected) REGISTER; the
-- second carries the challenge's nonce and the computed response, plus
-- qop/nc/cnonce when the P-CSCF asked for qop.
local function authz_hdr(nonce, response, qopset)
    local a = ('Digest username="%s",realm="%s",uri="sip:%s",nonce="%s",response="%s",algorithm=AKAv1-MD5')
        :format(impi, ims_realm, ims_realm, nonce or "", response or "")
    if qopset then
        a = a .. (',qop=%s,nc=%s,cnonce="%s"'):format(qopset.qop, qopset.nc, qopset.cnonce)
    end
    return a
end

-- Build the UE's IMS REGISTER toward the P-CSCF (TS 24.229 / RFC 3261):
-- the Request-URI is the home domain, Via/Contact carry the UE's own
-- (PAA) address at the SIP port, and `authz` is the AKAv1-MD5 credential.
-- Each REGISTER is a fresh non-INVITE transaction, so the branch and the
-- From tag are keyed on the CSeq; the Call-ID is stable across the pair.
local function build_register(ue_addr, cseq, authz)
    return sip.Builder()
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s-%d"):format(ue_addr, PCSCF_SIP_PORT, imsi, cseq))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s-%d"):format(impu, imsi, cseq))
        :header(sip.H_TO, ("<%s>"):format(impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(imsi, ue_addr))
        :header(sip.H_CSEQ, ("%d REGISTER"):format(cseq))
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(ue_addr, PCSCF_SIP_PORT))
        :header_u32(sip.H_EXPIRES, 600000)
        :header(sip.H_AUTHORIZATION, authz)
        :done()
end

-- Parse the 401: the AKA challenge from WWW-Authenticate. The nonce is
-- base64(RAND||AUTN); realm/qop steer the digest. No Security-Server is
-- parsed here — this datapath test authenticates at the digest layer and
-- keeps the flow plain UDP so the UDP:5060 TFT keeps matching.
local function parse_challenge(msg)
    local wa = msg:header("WWW-Authenticate")
    assert(wa ~= "", "401 without WWW-Authenticate")
    local nonce = auth_param(wa, "nonce")
    assert(nonce and nonce ~= "", "401 WWW-Authenticate without nonce")
    local blob = b64dec(nonce)
    assert(#blob >= 32, "AKA nonce shorter than RAND||AUTN")
    return {
        nonce = nonce,
        rand  = blob:sub(1, 16),
        autn  = blob:sub(17, 32),
        realm = auth_param(wa, "realm") or ims_realm,
        qop   = auth_param(wa, "qop"),
    }
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
        local ip = iface_ipv4(gtpu_ifname)
        if ip then sgw_ip, sgw_auto = ip, true end
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
        local gi = iface_index(gtpu_ifname)        -- S5/S8-U (GTP-U) side
        local ii = iface_index(inner_name)         -- access side
        local cfg = gtp.UserPlaneConfig()
        cfg.pin_dir        = ""        -- no bpffs pinning: a fresh datapath each run
        cfg.local_v4       = sgw_ip    -- outer source address for encapsulated uplink
        cfg.uplink_ifindex = gi or 0
        local made, obj = pcall(gtp.UserPlane, cfg)
        if made then
            up = obj
            if gi or ii then
                local aok, aerr = pcall(function() up:attach(gi or 0, ii or 0) end)
                line("GTP-U datapath", aok
                    and ("attached (gtpu=%s inner=%s)")
                        :format(gi and gtpu_ifname or "-", inner_name or "-")
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

    -- Steer a bearer's uplink onto the datapath as a TFT (traffic filter):
    -- inner packets matching {proto, dst addr, dst port} are encapsulated
    -- on this bearer's TEID pair (local_teid @ our side, remote_teid @ the
    -- PGW/UPF). IMS SIP signalling rides the default bearer, so the match
    -- is UDP toward the P-CSCF on the SIP port -- the UE's uplink SIP then
    -- classifies onto the default bearer's TEID, which the UPF's uplink PDR
    -- routes on to the P-CSCF. add_filter also installs the matching decap
    -- (rx) entry keyed on local_teid, so the 401/200 the P-CSCF sends back
    -- decapsulate on that same bearer and reach the UE. The encap datapath
    -- keys the TX maps on the inner *destination*, so dst_addr fills the
    -- Tunnel's ue_addr (classification-address) slot.
    local function program_filter(ebi, local_teid, remote_teid, remote_addr,
                                  proto, dst_addr, dst_port)
        if not up then return end
        if not (dst_addr and dst_addr ~= "" and remote_addr and remote_addr ~= "") then
            line("GTP-U filter", ("EBI %d not programmed (missing P-CSCF/peer address)"):format(ebi))
            return
        end
        local t = gtp.Tunnel()
        t.local_teid, t.remote_teid = local_teid, remote_teid
        t.ebi, t.ue_addr, t.remote_addr = ebi, dst_addr, remote_addr
        local f = gtp.TrafficFilter()
        f.tunnel  = t
        f.proto   = proto
        f.ue_port = dst_port           -- inner dst port; host order, loader htons
        local pok, perr = pcall(function() up:add_filter(f) end)
        line("GTP-U filter", pok
            and ("EBI %d  ul TEID %#x / dl TEID %#x @ %s  proto %d -> %s:%d")
                :format(ebi, local_teid, remote_teid, remote_addr, proto, dst_addr, dst_port)
            or ("EBI %d add_filter failed: %s"):format(ebi, why(perr)))
        if pok then
            st.peers[remote_addr] = true
            st.sig_teid = local_teid   -- default bearer carries the signalling
            st.bearers[#st.bearers + 1] =
                { ebi = ebi, teid = local_teid, port = dst_port,
                  kind = "signalling", dst = dst_addr }
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
    local sock                 -- UE SIP socket (non-local UE PAA source)
    local ue_bound = false     -- did the transparent PAA bind succeed
    local uac, uac2            -- the two RFC 3261 non-INVITE client transactions
    local ch                   -- the parsed 401 challenge
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

    -- Send a REGISTER over the UE socket (which the datapath encapsulates)
    -- and, when the datapath is up, confirm the encap ran by reading the
    -- per-TEID tx counter a moment later (locally-generated traffic egresses
    -- through TC just after sendto returns).
    local function send_register(wire, label)
        local before = (up and st.sig_teid) and up:stats(st.sig_teid) or nil
        local sok, serr = pcall(function() sock:sendto(wire, st.pcscf, PCSCF_SIP_PORT) end)
        if not sok then return fail(("REGISTER send failed: %s"):format(why(serr))) end
        line("-> REGISTER", ("%s, %d B -> P-CSCF %s:%d"):format(label, #wire, st.pcscf, PCSCF_SIP_PORT))
        if before then
            loop:after(50, function()                 -- let the TC egress program run
                local a   = up:stats(st.sig_teid)
                local dtx = a.tx_pkts - before.tx_pkts
                local dby = a.tx_bytes - before.tx_bytes
                local dng = a.err_tx_no_neigh - before.err_tx_no_neigh
                if dtx > 0 then
                    line("GTP-U encap", ("REGISTER encapsulated on TEID %#x (+%d pkt / %d B)")
                        :format(st.sig_teid, dtx, dby))
                elseif dng > 0 then
                    line("GTP-U encap", ("matched but no outer L2 (err_tx_no_neigh +%d); "
                        .. "prime the peer or set a static MAC"):format(dng))
                else
                    line("GTP-U encap", "no tx counter movement (REGISTER not steered onto the bearer?)")
                end
            end)
        end
    end

    -- Make the UE PAA locally deliverable so the decapped downlink (the
    -- P-CSCF's 401/200, whose inner dst is the PAA) reaches the UE socket.
    -- The rx decap entry hands the inner packet to the local stack, but the
    -- PAA is an address this host does not own, so without a local route the
    -- kernel would try to forward -- and drop -- it. `ip addr add <PAA>/32
    -- dev lo` puts it in the local routing table (delivered whatever
    -- interface it arrives on) without answering ARP for it on the wire.
    -- Best-effort and only meaningful with the decap datapath up, so it is
    -- attempted only then (needs CAP_NET_ADMIN); it degrades to a reported
    -- line and is removed again in teardown. The PAA is matched as a
    -- dotted-quad before it reaches the shell, so it cannot smuggle syntax.
    local function add_paa_route()
        if not (up and st.ue_addr and st.ue_addr:match("^%d+%.%d+%.%d+%.%d+$")) then return end
        local ok, out = ip_cmd(("addr add %s/32 dev lo"):format(st.ue_addr))
        if not ok and out:find("[Ee]xists") then ok = true end   -- already present
        paa_route_added = ok
        line("PAA local route", ok
            and ("%s/32 dev lo (decapsulated downlink now deliverable)"):format(st.ue_addr)
            or  ("could not add %s/32 (need CAP_NET_ADMIN?): %s"):format(st.ue_addr, out))
    end
    local function del_paa_route()
        if paa_route_added then ip_cmd(("addr del %s/32 dev lo"):format(st.ue_addr)) end
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

    -- Round 2: verify the AKA challenge, derive RES, and send the
    -- authenticated REGISTER carrying the AKAv1-MD5 digest response.
    on_401 = function(m401)
        local okc, res = pcall(parse_challenge, m401)
        if not okc then return fail("cannot parse 401 challenge: " .. why(res)) end
        ch = res
        line("RAND", hex(ch.rand)); line("AUTN", hex(ch.autn))

        local okv, keys = pcall(function() return ipsec.aka_verify(K, OPc, ch.rand, ch.autn) end)
        if not okv then return fail("AKA AUTN verification failed: " .. why(keys)) end
        line("AUTN verified", ("SQN %s, RES %s"):format(hex(keys.sqn), hex(keys.res)))

        reg_cseq = reg_cseq + 1
        local nc, cnonce = "00000001", hex(ipsec.md5(imsi .. tostring(reg_cseq)):sub(1, 8))
        local response = digest_response(impi, ch.realm, keys.res, "REGISTER",
                                         "sip:" .. ims_realm, ch.nonce, nc, cnonce, ch.qop)
        local authz = authz_hdr(ch.nonce, response,
                                ch.qop and { qop = ch.qop, nc = nc, cnonce = cnonce })

        local reg2 = build_register(st.ue_addr, reg_cseq, authz)
        uac2 = sip.Transaction(sip.NON_INVITE_CLIENT)
        send_register(reg2, "AKAv1-MD5 authenticated")
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
            return net.UdpSocket(st.ue_addr, PCSCF_SIP_PORT, false, true)
        end)
        if okb then
            sock, ue_bound = s, true
            line("UE SIP socket", ("%s:%d (UE PAA, transparent)"):format(st.ue_addr, PCSCF_SIP_PORT))
        else
            sock, ue_bound = net.UdpSocket("0.0.0.0", 0), false
            line("UE SIP socket",
                 ("SGW source (UE PAA bind refused, need CAP_NET_ADMIN: %s); "
                  .. "no reply can return"):format(why(s)))
        end
        loop:add_fd(sock:fd(), net.NET_RD, on_sip_readable)

        -- The P-CSCF is reached through the tunnel, so it should egress the
        -- interface encap is attached to; warn if the FIB would send it
        -- elsewhere (encap classifies on the inner headers, so the L2 next
        -- hop is irrelevant, but the frame must physically leave via inner).
        local dev = route_dev(st.pcscf)
        if dev and inner_name and inner_name ~= "" and dev ~= inner_name then
            line("note", ("%s routes via %s, not %s -- add a route so it reaches encap")
                :format(st.pcscf, dev, inner_name))
        end

        -- Baseline the downlink counter so report_rx can show the 401/200
        -- arriving through the decap entry.
        if up and st.sig_teid then st.rx0 = up:stats(st.sig_teid) end

        reg_cseq = reg_cseq + 1
        uac = sip.Transaction(sip.NON_INVITE_CLIENT)
        local reg1 = build_register(st.ue_addr, reg_cseq, authz_hdr("", ""))
        send_register(reg1, "unprotected")
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
            if rsp.pco and #rsp.pco > 0 then st.pcscf = pco_pcscf_v4(rsp.pco) end
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
                program_filter(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr,
                               IPPROTO_UDP, st.pcscf, PCSCF_SIP_PORT)
            else
                line("GTP-U filter",
                     ("EBI %d not programmed (no P-CSCF IPv4 in Create Session PCO)"):format(tun.ebi))
            end
        end,

        -- With the default bearer up the PGW opens a dedicated bearer with
        -- a Create Bearer Request (§7.2.3). The facade does not type it, so
        -- it lands here as raw wire; accept it and answer with a Create
        -- Bearer Response (§7.2.4). The response is addressed to the PGW's
        -- control TEID and echoes the request's sequence.
        on_message = function(mt, wire, host, port)
            if mt ~= gtp.GTP2_MT_CREATE_BEARER_REQUEST then return end
            local req = gtp.RawMessage.decode(wire)
            if not req:has(gtp.GTP2_IE_BEARER_CONTEXT) then return end

            -- The request's bearer context carries the PGW's S5/S8-U
            -- F-TEID; grab its raw bytes to echo back so the PGW can
            -- correlate the bearer.
            local bc = req:find(gtp.GTP2_IE_BEARER_CONTEXT)
            local pgw_u
            for i = 0, bc.children:size() - 1 do
                local ie = bc.children[i]
                if ie.type == gtp.GTP2_IE_FTEID then pgw_u = ie.value; break end
            end
            line("<- Create Bearer Req",
                 ("seq %d; accepting dedicated bearer"):format(req.sequence))

            -- Response bearer context: the EBI we allocate for the new
            -- bearer, an accepted cause, our S5/S8-U SGW F-TEID (instance
            -- 2) and the echoed PGW F-TEID (instance 3).
            local NEW_EBI = 6
            local rbc = gtp.Ie()
            rbc.type = gtp.GTP2_IE_BEARER_CONTEXT
            rbc:add_child(gtp.Ie(gtp.GTP2_IE_EBI, string.char(NEW_EBI)))
            rbc:add_child(gtp.Ie(gtp.GTP2_IE_CAUSE,
                                 cause_ie(gtp.GTP2_CAUSE_REQUEST_ACCEPTED)))
            rbc:add_child(gtp.Ie(gtp.GTP2_IE_FTEID,
                                 fteid_v4(gtp.GTP2_IF_S5S8U_SGW, S5_UP_TEID + 1, sgw_ip), 2))
            if pgw_u then rbc:add_child(gtp.Ie(gtp.GTP2_IE_FTEID, pgw_u, 3)) end

            local resp = gtp.RawMessage()
            resp.message_type = gtp.GTP2_MT_CREATE_BEARER_RESPONSE
            resp.teid     = st.pgw_ctrl_teid or 0    -- to the PGW's control TEID
            resp.sequence = req.sequence             -- echo the request's sequence
            resp:add_ie(gtp.Ie(gtp.GTP2_IE_CAUSE,
                               cause_ie(gtp.GTP2_CAUSE_REQUEST_ACCEPTED)))
            if req:has(gtp.GTP2_IE_PTI) then    -- echo the PTI if the request had one
                resp:add_ie(gtp.Ie(gtp.GTP2_IE_PTI, req:find(gtp.GTP2_IE_PTI).value))
            end
            resp:add_ie(rbc)

            ep:send_raw(resp:encode(), host, port)
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
    req.serving_network = plmn(mcc, mnc)
    req.uli             = uli_tai_ecgi(plmn(mcc, mnc), 0x0001, 0x0000001)

    -- PDN Address Allocation (§8.14): offer 0.0.0.0 to request a dynamic
    -- IPv4 address; the PGW returns the one it assigned in its own PAA.
    req.has_paa      = true
    req.paa.pdn_type = gtp.GTP2_PDN_IPV4
    req.paa.addr4    = "0.0.0.0"

    -- Protocol Configuration Options (§8.13): request the IMS P-CSCF IPv4
    -- address. Octet 1 flags the PPP/IP configuration protocol (0x80);
    -- one empty container follows -- P-CSCF IPv4 Address Request (0x000C)
    -- -- which the PGW echoes back carrying the address(es) it assigned.
    req.pco = string.char(0x80, math.floor(PCO_PCSCF_IPV4 / 256),
                          PCO_PCSCF_IPV4 % 256, 0x00)

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

    -- Teardown that needs no loop: drop the SIP socket and the UE-PAA local
    -- route. Runs whether the flow completed or aborted.
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
