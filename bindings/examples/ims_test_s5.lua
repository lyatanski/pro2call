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
-- With both interfaces attached the script then drives the datapath and
-- reads the per-TEID kernel counters back, confirming the encap path end
-- to end: a real SIP REGISTER sent from the UE toward the P-CSCF, whose
-- address the PGW returned in the Create Session Response PCO (TS 24.008
-- container 0x000C). IMS signalling rides the default bearer, so the
-- REGISTER is steered onto it and the UPF routes it to the P-CSCF; the
-- dedicated (media) bearer from the Create Bearer Request is accepted but
-- not probed.
--

local gtp = require("gtp")
local net = require("net")     -- event loop + UDP socket transport + DNS resolver
local sip = require("sip")     -- IMS REGISTER builder for the user-plane probe

-- ---- configuration ----------------------------------------------------

local pgw_host = os.getenv("PGW_IP")   or "smf"              -- PGW/SMF: a name (resolved below) or a literal IP
local sgw_ip   = os.getenv("SGW_IP")   or "0.0.0.0"
local apn      = os.getenv("IMS_APN")  or "ims"
local mcc      = os.getenv("IMS_MCC")  or "001"              -- serving PLMN (matches the IMSI
local mnc      = os.getenv("IMS_MNC")  or "01"               -- and the mnc01.mcc001 core realm)
local imsi     = os.getenv("IMS_IMSI") or "001010123456789"  -- TS 35.207 test IMSI

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
local T3_MS, N3  = 1000, 3     -- retransmission: 1s T3-RESPONSE, up to 3 sends

local IPPROTO_UDP   = 17       -- inner protocol used by the confirmation probe
local PCSCF_SIP_PORT = 5060    -- IMS signalling bearer TFT: SIP toward the P-CSCF

local PCO_PCSCF_IPV4 = 0x000c  -- TS 24.008 §10.5.6.3 P-CSCF IPv4 Address container

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

-- Build the UE's initial (unprotected) IMS REGISTER toward the P-CSCF
-- (TS 24.229 / RFC 3261): the Request-URI is the home domain, Via and
-- Contact carry the UE's own (PAA) address, and an empty AKAv1-MD5
-- Authorization advertises IMS-AKA so a live P-CSCF would answer 401.
-- Here it is the datapath probe payload -- a real SIP packet riding the
-- IMS signalling bearer in place of an opaque datagram.
local function build_register(ue_addr)
    return sip.Builder()
        :request(sip.REGISTER, "sip:" .. ims_realm)
        :header(sip.H_VIA,
                ("SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s"):format(ue_addr, PCSCF_SIP_PORT, imsi))
        :header_u32(sip.H_MAX_FORWARDS, 70)
        :header(sip.H_FROM, ("<%s>;tag=%s"):format(impu, imsi))
        :header(sip.H_TO, ("<%s>"):format(impu))
        :header(sip.H_CALL_ID, ("%s@%s"):format(imsi, ue_addr))
        :header(sip.H_CSEQ, "1 REGISTER")
        :header(sip.H_CONTACT, ("<sip:%s:%d>"):format(ue_addr, PCSCF_SIP_PORT))
        :header_u32(sip.H_EXPIRES, 600000)
        :header(sip.H_AUTHORIZATION,
                ('Digest username="%s",realm="%s",uri="sip:%s",nonce="",response="",algorithm=AKAv1-MD5')
                    :format(impi, ims_realm, ims_realm))
        :done()
end

-- Step the loop until the in-flight transaction resolves: a response
-- sets st.done, an N3 timeout or a rejection sets st.err. The endpoint's
-- own retransmission timer guarantees step() cannot block forever.
local function pump(loop, st)
    while not (st.done or st.err) do loop:step(-1) end
end

-- ---- GTPv2-C over S5/S8 ----------------------------------------------

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

    local st = { done = false, err = nil, ue_addr = nil, peers = {}, bearers = {} }

    -- ---- GTP-U user plane (eBPF datapath) ----
    -- Load the datapath when the kernel and privileges allow it; attach its
    -- TC programs to the S5/S8-U and access interfaces when their names are
    -- given. Everything degrades to a log line if the datapath, the caps or
    -- the interfaces are missing, so an unprivileged run still completes.
    local up
    local inner_name = os.getenv("GTPU_INNER_IFACE") or "eth0" -- access side (encap egress)
    if gtp.UserPlane.supported() then
        local gi = iface_index(gtpu_ifname)        -- S5/S8-U (GTP-U) side
        local ii = iface_index(inner_name)  -- access side
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
    -- routes on to the P-CSCF. The encap datapath keys the TX maps on the
    -- inner *destination*, so dst_addr fills the Tunnel's ue_addr (its
    -- classification-address) slot; add_filter also installs the matching
    -- decap (rx) entry keyed on local_teid.
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
            st.bearers[#st.bearers + 1] =
                { ebi = ebi, teid = local_teid, port = dst_port,
                  kind = "signalling", dst = dst_addr }
        end
    end

    -- Confirm the eBPF encap path with a real SIP REGISTER from the UE to
    -- the P-CSCF. encap classifies on the inner *destination* (gtpu_kern.c
    -- keys the TX maps on ip->daddr and, for a TFT, the dst port), so a
    -- packet to the P-CSCF on 5060 is exactly what the IMS signalling
    -- bearer's TFT tunnels towards the PGW. Counters are read per TEID:
    -- tx_pkts moving proves classify + encapsulate + redirect ran on that
    -- bearer; err_tx_no_neigh moving proves the classifier matched but the
    -- outer L2 could not be resolved (prime the peer or set a static MAC).
    -- Only the signalling (default) bearer is probed; the dedicated media
    -- bearer carries no probe traffic here.
    local function confirm_user_plane()
        if not up then return end                       -- datapath not loaded
        if not st.ue_addr then
            return line("user-plane probe", "skipped (no UE address assigned)")
        end
        if not inner_name or inner_name == "" then
            return line("user-plane probe",
                        "skipped (set GTPU_INNER_IFACE so encap is attached)")
        end
        if #st.bearers == 0 then
            return line("user-plane probe", "skipped (no bearers programmed)")
        end

        -- A probe only has to physically egress the interface encap is
        -- attached to; encap classifies on the inner headers, so the L2
        -- next hop is irrelevant. In a single-NIC setup the default route
        -- already carries this traffic out that interface, so we steer
        -- nothing -- forcing an on-link /32 route instead would make the
        -- kernel ARP the destination and drop the packet before it reaches
        -- TC egress. We only warn if it would leave elsewhere.
        local function route_dev(dst)
            local p = io.popen(("ip route get %s 2>/dev/null"):format(dst))
            if not p then return nil end
            local out = p:read("*a") or ""; p:close()
            return out:match("dev%s+(%S+)")
        end

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
        loop:step(100)                                   -- let ARP complete

        -- The confirmation packet is a real SIP REGISTER from the UE toward
        -- the P-CSCF (dst = P-CSCF), which the UPF accepts as uplink on the
        -- default (IMS signalling) bearer and routes onward. That is the
        -- only probe: the dedicated bearer is media (its own SDF), and a UE
        -- /32 downlink entry is untestable against a real UPF, so neither is
        -- fired at.
        local register = st.pcscf and build_register(st.ue_addr)

        -- The REGISTER must look like uplink traffic *from the UE*: its
        -- inner source has to be the PAA, not the SGW address (which is
        -- also the outer GTP-U source -- the two coinciding is exactly what
        -- looked wrong on the wire). The SGW does not own the PAA, so open
        -- the socket with a non-local source (the fourth UdpSocket arg ->
        -- IP_FREEBIND + IP_TRANSPARENT): the kernel then binds and *sends*
        -- from an address it does not own, without adding it, and being
        -- setsockopts it works where /proc/sys is read-only (a default
        -- Docker mount). Needs CAP_NET_ADMIN; falls back to the SGW source
        -- (which the UPF then drops as spoofed) when it is refused.
        local ue_bound, s = pcall(function()
            return net.UdpSocket(st.ue_addr, 0, false, true)  -- non-local source = UE PAA
        end)
        local sock = ue_bound and s or net.UdpSocket("0.0.0.0", 0)

        for _, b in ipairs(st.bearers) do
            if b.kind ~= "signalling" then
                line("user-plane probe",
                     ("EBI %d %s bearer programmed, not probed"):format(b.ebi, b.kind))
            elseif not register then
                line("user-plane probe",
                     ("EBI %d skipped (no P-CSCF address to REGISTER to)"):format(b.ebi))
            else
                local dst  = b.dst or st.pcscf
                local what = ("SIP REGISTER -> P-CSCF %s"):format(dst)
                line("user-plane probe", ue_bound
                    and ("inner source %s (UE)"):format(st.ue_addr)
                    or  "inner source = SGW (UE PAA bind refused; need CAP_NET_ADMIN)")

                local dev = route_dev(dst)
                if dev and dev ~= inner_name then
                    line("user-plane probe", ("note: %s routes via %s, not %s -- add a "
                         .. "route so it reaches encap"):format(dst, dev, inner_name))
                end

                local s0 = up:stats(b.teid)
                local sok, serr = pcall(function()
                    for _ = 1, 3 do sock:sendto(register, dst, b.port) end
                end)
                loop:step(50)                            -- let the TC program run
                if not sok then
                    line("user-plane probe",
                         ("EBI %d send failed: %s"):format(b.ebi, why(serr)))
                else
                    local s1  = up:stats(b.teid)
                    local dtx = s1.tx_pkts - s0.tx_pkts
                    local dby = s1.tx_bytes - s0.tx_bytes
                    local dng = s1.err_tx_no_neigh - s0.err_tx_no_neigh
                    if dtx > 0 then
                        line("user-plane probe",
                             ("EBI %d %s (TEID %#x port %d) OK -- encapsulated %d pkt / %d B")
                                 :format(b.ebi, what, b.teid, b.port, dtx, dby))
                    elseif dng > 0 then
                        line("user-plane probe",
                             ("EBI %d %s matched but no outer L2 (err_tx_no_neigh +%d); "
                              .. "prime the peer or set a static MAC"):format(b.ebi, what, dng))
                    else
                        line("user-plane probe",
                             ("EBI %d %s no counter movement -- dst %s port %d not steered "
                              .. "here (did the datagram reach encap?)"):format(b.ebi, what, dst, b.port))
                    end
                end
            end
        end
        sock:close()
    end

    ep:set_handler({
        -- The PGW answered the Create Session: read the cause, the
        -- allocated UE address (PAA) and the PGW's control TEID.
        on_create_session_response = function(sess, rsp)
            if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
                st.err = ("Create Session rejected, cause %d"):format(rsp.cause)
                return
            end
            st.pgw_ctrl_teid = sess:remote_teid()  -- to address later responses to the PGW
            if rsp.has_paa then st.ue_addr = rsp.paa.addr4 end
            if rsp.pco and #rsp.pco > 0 then st.pcscf = pco_pcscf_v4(rsp.pco) end
            line("<- Create Session Resp", ("accepted; PGW ctrl TEID %#x"):format(sess:remote_teid()))
            if st.ue_addr then line("PAA (UE address)", st.ue_addr) end
            line("P-CSCF (from PCO)", st.pcscf or "not returned")
            st.done = true
        end,

        -- One per bearer F-TEID in the accepted response: the PGW's
        -- data-plane endpoint (the default bearer over S5/S8-U). IMS SIP
        -- signalling rides the default bearer, so steer the UE's uplink SIP
        -- toward the P-CSCF onto it with a TFT; the UPF's default-bearer
        -- uplink PDR then accepts and routes it to the P-CSCF. A downlink
        -- UE /32 entry is deliberately not programmed -- its destination is
        -- the UE, which a real UPF rejects as uplink (a source-spoof drop,
        -- or a UE->UE loop back down the tunnel).
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
        end,

        on_timeout = function(sess, mt)
            st.err = ("PGW did not answer message type %d (after %d sends)")
                :format(mt, N3)
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

    pump(loop, st)

    -- The session is up. The PGW now pushes a Create Bearer Request to add
    -- the dedicated bearer (answered in on_message above). Keep stepping
    -- the loop, bounded to ~10s, so the script does not block forever if
    -- none arrives; step() cannot block past the timeout.
    if st.done then
        for _ = 1, 100 do
            if st.cbr_done then break end
            loop:step(100)
        end
        if not st.cbr_done then
            line("note", "no Create Bearer Request arrived within 10s")
        end
    end

    -- Push a synthetic UE datagram through each bearer and read counters.
    confirm_user_plane()

    return { loop = loop, ep = ep, sess = sess, st = st, up = up, ue_addr = st.ue_addr }
end

-- main
local pdn = attach_pdn_over_s5()
if pdn.st.err then
    line("result", pdn.st.err)
    os.exit(1)
end
line("result", "PDN connection established over S5/S8")
