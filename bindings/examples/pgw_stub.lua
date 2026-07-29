#!/usr/bin/env lua
--
-- pgw_stub.lua — a PGW (PDN Gateway) stub: the S5/S8 anchor a test SGW
-- attaches to. It stands in for the real PGW-C+U (open5gs smf+upf) so a
-- load test drives a datapath and a policy interface that are entirely
-- under its own control.
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so \
--     [PGW_BIND=0.0.0.0] [PGW_ADDR=<F-TEID address>] \
--     [PGW_POOL=10.45.0.0/16] [PGW_POOL_GW=<addr>] [PGW_PCSCF=<ipv4>] \
--     [GTPU_IFACE=eth0] [GTPU_INNER_IFACE=eth0] \
--     [GX_PCRF=<host>] [GX_PORT=3868] [GX_PROTO=tcp|sctp] \
--     [PGW_REALM=mnc01.mcc001.3gppnetwork.org] [PGW_VERBOSE=1] \
--     lua pgw_stub.lua
--
-- Two interfaces and a datapath, all on one net.Loop:
--
--   1. GTP-C on S5/S8 towards the test (gtp.Endpoint in its server role,
--      bound to :2123): Create Session, Modify Bearer and Delete Session
--      requests are answered, Echo Requests by the endpoint itself, and
--      a PCRF-installed rule is pushed back out as a Create Bearer
--      Request. Every PDN connection gets a UE address, a control TEID
--      and a user TEID allocated here.
--   2. Gx towards the PCRF (TS 29.212) over a TCP/SCTP stream socket
--      (net.stream_connect + the diam codec, framed by the Diameter
--      header's Message Length): the base peer protocol (CER/CEA,
--      DWR/DWA, DPR), a CCR-I per PDN connection whose CCA-I carries the
--      policy the Create Session Response is built from, a CCR-T on
--      teardown, and RAR/RAA — an installed charging rule turns into the
--      dedicated bearer. With no $GX_PCRF the interface stays down and a
--      local default policy is used, so the stub runs standalone.
--   3. GTP-U in the kernel (gtp.UserPlane, the gtp/u eBPF datapath): one
--      tunnel per bearer, installed the moment the SGW's F-TEID is known.
--      These are anchor-side tunnels (`core_side`): the G-PDUs arriving
--      here are uplink FROM the UE, so decap must not require the inner
--      destination to be the UE address, while that address still steers
--      the downlink encap.
--
-- UE addresses come from net.IpPool (task/inc/ippool.h): one bit per
-- address, O(1) allocate and release, and a released address waits for
-- the allocator to sweep the rest of the pool before it goes out again —
-- so a detaching UE's address is not handed to the next attach. A Create
-- Session Request that asks for a specific address (a non-zero PAA) gets
-- it when it is free; exhaustion is answered with cause 84, "all dynamic
-- addresses are occupied", not a silent failure.
--
-- Running it against bindings/examples/ims_test_s5.lua (the SGW side):
--   * the stub needs CAP_BPF + CAP_NET_ADMIN for the datapath, and
--     $GTPU_IFACE / $GTPU_INNER_IFACE set (single-NIC container: both
--     eth0), exactly as the test does;
--   * for uplink to leave the stub the kernel must route the pool, and
--     the far end must route the pool back to the stub — the address
--     pool is a different subnet from the real UPF's on purpose, so the
--     two can coexist on one network;
--   * pointing Gx at a freeDiameter-based PCRF (open5gs) means the PCRF
--     must know this peer: freeDiameter only talks to declared peers
--     without TLS, so either add a `ConnectPeer` for $GX_ORIGIN_HOST with
--     No_TLS, or run the stub with the identity the PCRF already knows
--     for the node it replaces.

local gtp  = require("gtp")  -- GTPv2-C server role + typed messages + eBPF GTP-U
local net  = require("net")  -- event loop, stream socket, interface helpers, IpPool
local diam = require("diam") -- Diameter codec + Gx dictionary

-- ---- configuration ----------------------------------------------------

local BIND      = os.getenv("PGW_BIND") or "0.0.0.0"
local GTPC_PORT = tonumber(os.getenv("PGW_GTPC_PORT") or "2123")
local POOL      = os.getenv("PGW_POOL") or "10.45.0.0/16"
local POOL_GW   = os.getenv("PGW_POOL_GW")             -- reserved, never handed out
local PCSCF     = os.getenv("PGW_PCSCF")               -- returned in the PCO when asked
local VERBOSE   = (os.getenv("PGW_VERBOSE") or "0") ~= "0"
local STATS_MS  = tonumber(os.getenv("PGW_STATS_MS") or "5000")

local GTPU_IFACE = os.getenv("GTPU_IFACE") or "eth0"
local INNER_IFACE = os.getenv("GTPU_INNER_IFACE") or "eth0"

-- Local default policy: what the stub grants when Gx is down, and the
-- floor the PCRF's answer overrides.
local DEF_QCI     = tonumber(os.getenv("PGW_QCI") or "5")       -- IMS signalling
local DEF_ARP     = tonumber(os.getenv("PGW_ARP") or "8")       -- priority level
local DEF_AMBR_UL = tonumber(os.getenv("PGW_AMBR_UL") or "1024") -- kbps
local DEF_AMBR_DL = tonumber(os.getenv("PGW_AMBR_DL") or "2048")

-- Diameter identities. The realm layout matches the ims stack's
-- (<node>.epc.<realm>), so the defaults line up with a core deployed
-- from the same variables.
local REALM        = os.getenv("PGW_REALM")       or "mnc01.mcc001.3gppnetwork.org"
local ORIGIN_HOST  = os.getenv("GX_ORIGIN_HOST")  or ("pgw.epc." .. REALM)
local ORIGIN_REALM = os.getenv("GX_ORIGIN_REALM") or ("epc." .. REALM)
local DEST_REALM   = os.getenv("GX_DEST_REALM")   or ORIGIN_REALM
local DEST_HOST    = os.getenv("GX_DEST_HOST")                  -- optional
local PCRF_HOST    = os.getenv("GX_PCRF")                       -- unset = Gx off
local PCRF_PORT    = tonumber(os.getenv("GX_PORT") or "3868")
local PCRF_PROTO   = (os.getenv("GX_PROTO") or "tcp"):lower()
local GX_TIMEOUT_MS  = tonumber(os.getenv("GX_TIMEOUT_MS") or "2000")
local GX_RETRY_MS    = tonumber(os.getenv("GX_RETRY_MS") or "5000")
local GX_WATCHDOG_MS = tonumber(os.getenv("GX_WATCHDOG_MS") or "30000")

-- Identifier spaces. Control and user TEIDs are ours to allocate; the
-- sequence numbers of PGW-initiated requests (Create Bearer) live in
-- their own high range so they read apart from the SGW's in a capture.
local CTRL_TEID_BASE = 0xC0000000
local USER_TEID_BASE = 0x80000000
local SEQ_BASE       = 0x800000

local V3GPP  = diam.VENDOR_3GPP
local APP_GX = diam.APP_GX
local RC_OK  = diam.RESULT_CODE_DIAMETER_SUCCESS

-- ---- little helpers ---------------------------------------------------

local function log(fmt, ...) io.write(fmt:format(...) .. "\n"); io.flush() end
local function line(k, v) log("   %-22s %s", k, v) end
local function vlog(fmt, ...) if VERBOSE then log("      " .. fmt, ...) end end
local function why(e) return (tostring(e):gsub("^.-:%s*", "")) end
local now = net.now_ms

-- Big-endian byte strings (Lua 5.1: arithmetic only, no bit operators).
local function be16(v) return string.char(math.floor(v / 256) % 256, v % 256) end

-- A dotted quad as the four raw bytes RADIUS-derived AVPs carry.
-- Framed-IP-Address is one of them: RFC 4005 §6.11.1 keeps the RADIUS
-- OctetString layout (4 bytes, no address-family prefix), so it must NOT
-- go out through put_addr4 — that writes the RFC 6733 Address encoding
-- (2-byte AddressType + 4 bytes), which a PCRF reads as a bad address.
-- Address-typed AVPs (AN-GW-Address here) do use put_addr4.
local function ipv4_bytes(dotted)
    local o = {}
    for byte in dotted:gmatch("%d+") do o[#o + 1] = string.char(tonumber(byte)) end
    return #o == 4 and table.concat(o) or nil
end

-- Read an optional AVP; m:str/:u32 raise on a missing one, so gate on has().
local function ostr(m, code, vendor)
    if m:has(code, vendor or 0) then return m:str(code, vendor or 0) end
    return nil
end
local function ou32(m, code, vendor)
    if m:has(code, vendor or 0) then return m:u32(code, vendor or 0) end
    return nil
end
local function ochild_u32(avp, code)
    if avp:has_child(code, V3GPP) then return avp:child(code, V3GPP):u32() end
    return nil
end

-- Protocol Configuration Options (TS 24.008 §10.5.6.3): the answer to a
-- UE asking for the P-CSCF address — container 0x000C carrying one IPv4
-- address. gtp.pco_pcscf_v4() is the matching decoder on the UE side.
local function pco_pcscf(addr4)
    local o = {}
    for byte in addr4:gmatch("%d+") do o[#o + 1] = string.char(tonumber(byte)) end
    if #o ~= 4 then return nil end
    return string.char(0x80) .. string.char(0x00, 0x0C, 0x04) .. table.concat(o)
end

-- Did the request's PCO ask for the P-CSCF IPv4 address (container
-- 0x000C, empty in a request)? Same walk as gtp::pco_pcscf_v4.
local function pco_wants_pcscf(pco)
    if not pco or #pco < 4 then return false end
    local i = 2                                    -- skip the flags octet
    while i + 2 <= #pco do
        local id  = pco:byte(i) * 256 + pco:byte(i + 1)
        local len = pco:byte(i + 2)
        if id == 0x000C then return true end
        i = i + 3 + len
    end
    return false
end

-- Minimal TS 24.008 §10.5.6.12 TFT for a dedicated bearer: "create new
-- TFT" with one bidirectional packet filter carrying the components the
-- Gx rule actually named (protocol, remote port, local port). Returns
-- nil when the rule named none — a filter with no component matches
-- everything, which is not a traffic flow template.
local function tft_create(precedence, proto, remote_port, local_port)
    local comps = {}
    if proto and proto > 0 then comps[#comps + 1] = string.char(0x30, proto) end
    if local_port and local_port > 0 then
        comps[#comps + 1] = string.char(0x40) .. be16(local_port)
    end
    if remote_port and remote_port > 0 then
        comps[#comps + 1] = string.char(0x50) .. be16(remote_port)
    end
    local body = table.concat(comps)
    if #body == 0 then return nil end
    return string.char(0x21)                       -- create new TFT, 1 filter
        .. string.char(0x31)                       -- bidirectional, filter id 1
        .. string.char(precedence % 256)
        .. string.char(#body) .. body
end

-- An IPFilterRule (RFC 6733 §4.3) as Gx carries it in Flow-Description:
--   "permit out 17 from any to 10.45.0.2 5060"
-- Pull out what a TFT and an eBPF filter can key on: the protocol number
-- and the destination port. Anything richer (ranges, address lists) is
-- left to a real PCEF — the caller skips the filter when this returns no
-- port.
local function flow_parse(desc)
    local dir, proto = desc:match("^%s*permit%s+(%a+)%s+(%d+)%s")
    if not proto then return nil end
    local port = desc:match("%s+to%s+%S+%s+(%d+)")
    return {
        dir   = dir,
        proto = tonumber(proto),
        port  = port and tonumber(port) or nil,
    }
end

-- ---- counters ---------------------------------------------------------

local stats = {
    created = 0, rejected = 0, deleted = 0, modified = 0,
    ded_req = 0, ded_ok = 0,
    ccr = 0, cca = 0, rar = 0, gx_timeout = 0,
    win0 = now(), win_created = 0, -- the current reporting window
}

-- ---- UE address pool and identifier allocation ------------------------

local pool_ok, pool = pcall(net.IpPool, POOL)
if not pool_ok then
    io.stderr:write(("bad PGW_POOL %q: %s\n"):format(POOL, why(pool)))
    os.exit(1)
end
if POOL_GW then
    local ok, err = pcall(function() pool:reserve(POOL_GW) end)
    if not ok then log("!! cannot reserve gateway %s: %s", POOL_GW, why(err)) end
end

local next_ctrl, next_user, next_seq, next_sid = 0, 0, 0, 0
local function alloc_ctrl_teid() next_ctrl = next_ctrl + 1; return CTRL_TEID_BASE + next_ctrl end
local function alloc_user_teid() next_user = next_user + 1; return USER_TEID_BASE + next_user end
local function alloc_seq() next_seq = (next_seq + 1) % 0x400000; return SEQ_BASE + next_seq end

-- RFC 6733 §8.8 Session-Id: <DiameterIdentity>;<high>;<low>;<optional>.
local RUN_ID = os.time()
local function alloc_session_id(imsi)
    next_sid = next_sid + 1
    return ("%s;%d;%d;%s"):format(ORIGIN_HOST, RUN_ID, next_sid, imsi or "")
end

-- ---- session table ----------------------------------------------------
--
-- A PDN connection, indexed three ways: by the control TEID we allocated
-- (how the SGW addresses every later message), by Gx Session-Id (how the
-- PCRF does), and by the request key (SGW control TEID + IMSI) so a
-- retransmitted Create Session Request is answered instead of creating a
-- second connection and leaking an address.

local by_ctrl, by_gx, by_key = {}, {}, {}
local session_count = 0

local function req_key(host, sgw_c_teid, imsi)
    return ("%s/%08x/%s"):format(host, sgw_c_teid, imsi or "")
end

local function session_drop(sess)
    if sess.dropped then return end
    sess.dropped = true
    by_ctrl[sess.pgw_c_teid] = nil
    if sess.gx_sid then by_gx[sess.gx_sid] = nil end
    by_key[sess.key] = nil
    session_count = session_count - 1
    if sess.ue_addr then
        local ok, err = pcall(function() pool:release(sess.ue_addr) end)
        if not ok then log("!! cannot release %s: %s", sess.ue_addr, why(err)) end
    end
end

-- ---- GTP-U datapath (eBPF) --------------------------------------------

local ep          -- gtp.Endpoint (the GTP-C server), set in run()
local up          -- gtp.UserPlane, nil when unavailable
local pgw_addr    -- the address our F-TEIDs advertise

local function datapath_open()
    if not gtp.UserPlane.supported() then
        line("GTP-U datapath", "unsupported (non-eBPF build or missing CAP_BPF/CAP_NET_ADMIN)")
        return
    end
    local gi  = net.if_index(GTPU_IFACE)
    local ii  = net.if_index(INNER_IFACE)
    local cfg = gtp.UserPlaneConfig()
    cfg.pin_dir        = ""          -- a fresh datapath each run
    cfg.local_v4       = pgw_addr    -- outer source of the downlink G-PDUs
    cfg.uplink_ifindex = gi
    local made, obj = pcall(gtp.UserPlane, cfg)
    if not made then
        line("GTP-U datapath", "unavailable (" .. why(obj) .. ")")
        return
    end
    up = obj
    if gi == 0 and ii == 0 then
        line("GTP-U datapath", "loaded (set GTPU_IFACE/GTPU_INNER_IFACE to attach TC)")
        return
    end
    local ok, err = pcall(function() up:attach(gi, ii) end)
    line("GTP-U datapath", ok
        and ("attached (gtpu=%s inner=%s)"):format(GTPU_IFACE, INNER_IFACE)
        or  ("attach failed: " .. why(err)))
end

-- The default bearer's tunnel. Anchor side: decap takes the uplink whose
-- inner destination is the far host (core_side), while the UE address
-- keys the downlink encap toward the SGW.
local function tunnel_of(sess)
    local t = gtp.Tunnel()
    t.local_teid  = sess.pgw_u_teid          -- uplink G-PDUs arrive on this
    t.remote_teid = sess.sgw_u_teid          -- downlink G-PDUs carry this
    t.ebi         = sess.ebi
    t.ue_addr     = sess.ue_addr
    t.remote_addr = sess.sgw_u_addr
    t.core_side   = true
    return t
end

local function program_tunnel(sess)
    if not (up and sess.sgw_u_teid and sess.sgw_u_addr) then return end
    local ok, err = pcall(function() up:add_tunnel(tunnel_of(sess)) end)
    sess.tunnelled = ok
    vlog("%s GTP-U bearer EBI %d  %#x <- %#x @ %s  UE %s  %s", sess.imsi, sess.ebi,
         sess.pgw_u_teid, sess.sgw_u_teid, sess.sgw_u_addr, sess.ue_addr,
         ok and "installed" or ("failed: " .. why(err)))
end

local function update_tunnel(sess)
    if not (up and sess.tunnelled) then return program_tunnel(sess) end
    local ok, err = pcall(function() up:update_tunnel(tunnel_of(sess)) end)
    vlog("%s GTP-U bearer EBI %d updated -> %#x @ %s %s", sess.imsi, sess.ebi,
         sess.sgw_u_teid, sess.sgw_u_addr, ok and "" or ("failed: " .. why(err)))
end

local function remove_tunnel(sess)
    if not (up and sess.tunnelled) then return end
    pcall(function() up:del_tunnel(tunnel_of(sess)) end)
    sess.tunnelled = false
    for _, d in ipairs(sess.dedicated or {}) do
        if d.filtered then pcall(function() up:del_filter(d.filter) end) end
    end
end

-- ---- Gx (Diameter) client ---------------------------------------------

local gx = {
    conn = nil, up = false, rxbuf = "", hbh = 0, e2e = os.time() % 0x10000,
    watchdog = nil, terminating = {}, -- Session-Ids awaiting their CCA-T
}
local finish_create        -- forward: the Create Session Response builder
local create_bearer        -- forward: RAR -> Create Bearer Request

local function gx_ids()
    gx.hbh = (gx.hbh + 1) % 0x7FFFFFFF
    gx.e2e = (gx.e2e + 1) % 0x7FFFFFFF
    return gx.hbh, gx.e2e
end

local function gx_send(wire, what)
    if not gx.conn then return false end
    local ok, err = pcall(function() gx.conn:send(wire, 1000) end)
    if not ok then log("!! Gx send (%s) failed: %s", what, why(err)) end
    return ok
end

-- Request preamble shared by CER/DWR/CCR: our identity, and for the
-- application requests the realm the PCRF lives in.
local function gx_request(cmd, app, routed)
    local hbh, e2e = gx_ids()
    local b = diam.Builder():request(cmd, app):ids(hbh, e2e)
    if routed then b:proxiable() end
    return b, hbh
end

local function gx_identity(b)
    return b:put_str(diam.AVP_ORIGIN_HOST, ORIGIN_HOST)
            :put_str(diam.AVP_ORIGIN_REALM, ORIGIN_REALM)
end

local function gx_cer()
    local host_ip = net.if_addr4(GTPU_IFACE)
    if host_ip == "" then host_ip = pgw_addr end
    local b = gx_request(diam.CMD_CAPABILITIES_EXCHANGE, 0, false)
    gx_identity(b)
        :put_addr4(diam.AVP_HOST_IP_ADDRESS, host_ip)
        :put_u32(diam.AVP_VENDOR_ID, V3GPP)
        :put_str(diam.AVP_PRODUCT_NAME, "pro2call-pgw-stub")
        :put_u32(diam.AVP_ORIGIN_STATE_ID, RUN_ID % 0x7FFFFFFF)
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_GX)
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, V3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_GX)
        :end_group()
        :put_u32(diam.AVP_SUPPORTED_VENDOR_ID, V3GPP)
        :put_u32(diam.AVP_FIRMWARE_REVISION, 1)
    gx_send(b:done(), "CER")
end

-- CCR-I (TS 29.212 §5.6.2): the PDN connection announced to the PCRF,
-- carrying the address just allocated (Framed-IP-Address) — the key the
-- PCRF correlates an Rx session against — plus the access, the APN and
-- the default bearer QoS the PGW is prepared to grant.
local function gx_ccr_initial(sess)
    local b = gx_request(diam.CMD_CREDIT_CONTROL, APP_GX, true)
    b:put_str(diam.AVP_SESSION_ID, sess.gx_sid)
     :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_GX)
    gx_identity(b)
     :put_str(diam.AVP_DESTINATION_REALM, DEST_REALM)
    if DEST_HOST then b:put_str(diam.AVP_DESTINATION_HOST, DEST_HOST) end
    b:put_u32(diam.AVP_CC_REQUEST_TYPE, diam.CC_REQUEST_TYPE_INITIAL_REQUEST)
     :put_u32(diam.AVP_CC_REQUEST_NUMBER, sess.gx_ccr_no)
     :put_u32(diam.AVP_ORIGIN_STATE_ID, RUN_ID % 0x7FFFFFFF)
     :begin_group(diam.AVP_SUBSCRIPTION_ID)
        :put_u32(diam.AVP_SUBSCRIPTION_ID_TYPE, diam.SUBSCRIPTION_ID_TYPE_END_USER_IMSI)
        :put_str(diam.AVP_SUBSCRIPTION_ID_DATA, sess.imsi)
     :end_group()
    if sess.msisdn and sess.msisdn ~= "" then
        b:begin_group(diam.AVP_SUBSCRIPTION_ID)
            :put_u32(diam.AVP_SUBSCRIPTION_ID_TYPE, diam.SUBSCRIPTION_ID_TYPE_END_USER_E164)
            :put_str(diam.AVP_SUBSCRIPTION_ID_DATA, sess.msisdn)
         :end_group()
    end
    b:put_str(diam.AVP_FRAMED_IP_ADDRESS, ipv4_bytes(sess.ue_addr))
     :put_str(diam.AVP_CALLED_STATION_ID, sess.apn)
     :put_u32(diam.AVP_IP_CAN_TYPE, diam.IP_CAN_TYPE_3GPP_EPS)
     :put_u32(diam.AVP_RAT_TYPE, diam.RAT_TYPE_EUTRAN)
     :put_u32(diam.AVP_NETWORK_REQUEST_SUPPORT, 1) -- we accept PCRF-initiated bearers
     :put_u32(diam.AVP_BEARER_USAGE, diam.BEARER_USAGE_GENERAL)
     :begin_group(diam.AVP_DEFAULT_EPS_BEARER_QOS)
        :put_u32(diam.AVP_QOS_CLASS_IDENTIFIER, DEF_QCI)
        :begin_group(diam.AVP_ALLOCATION_RETENTION_PRIORITY)
            :put_u32(diam.AVP_PRIORITY_LEVEL, DEF_ARP)
            :put_u32(diam.AVP_PRE_EMPTION_CAPABILITY, 1)   -- DISABLED
            :put_u32(diam.AVP_PRE_EMPTION_VULNERABILITY, 0) -- ENABLED
        :end_group()
     :end_group()
     :begin_group(diam.AVP_QOS_INFORMATION)
        :put_u32(diam.AVP_APN_AGGREGATE_MAX_BITRATE_UL, DEF_AMBR_UL * 1000)
        :put_u32(diam.AVP_APN_AGGREGATE_MAX_BITRATE_DL, DEF_AMBR_DL * 1000)
     :end_group()
    if sess.sgw_c_addr then
        b:put_addr4(diam.AVP_AN_GW_ADDRESS, sess.sgw_c_addr)
    end
    stats.ccr = stats.ccr + 1
    return gx_send(b:done(), "CCR-I")
end

local function gx_ccr_terminate(sess)
    if not (gx.up and sess.gx_sid) then return end
    sess.gx_ccr_no = sess.gx_ccr_no + 1
    local b = gx_request(diam.CMD_CREDIT_CONTROL, APP_GX, true)
    b:put_str(diam.AVP_SESSION_ID, sess.gx_sid)
     :put_u32(diam.AVP_AUTH_APPLICATION_ID, APP_GX)
    gx_identity(b)
     :put_str(diam.AVP_DESTINATION_REALM, DEST_REALM)
    if DEST_HOST then b:put_str(diam.AVP_DESTINATION_HOST, DEST_HOST) end
    b:put_u32(diam.AVP_CC_REQUEST_TYPE, diam.CC_REQUEST_TYPE_TERMINATION_REQUEST)
     :put_u32(diam.AVP_CC_REQUEST_NUMBER, sess.gx_ccr_no)
     :put_u32(diam.AVP_TERMINATION_CAUSE, diam.TERMINATION_CAUSE_DIAMETER_LOGOUT)
     :put_str(diam.AVP_FRAMED_IP_ADDRESS, ipv4_bytes(sess.ue_addr))
    stats.ccr = stats.ccr + 1
    -- The Gx session outlives the PDN connection by one round trip: keep
    -- the id so the CCA-T is recognised after the session record is gone.
    gx.terminating[sess.gx_sid] = sess.imsi
    gx_send(b:done(), "CCR-T")
end

-- The policy a Create Session Response is built from: the local default,
-- overridden by whatever the CCA-I actually carried.
local function policy_default()
    return { qci = DEF_QCI, arp = DEF_ARP,
             ambr_ul = DEF_AMBR_UL, ambr_dl = DEF_AMBR_DL,
             source = "local default", rules = {} }
end

-- Charging-Rule-Install / Charging-Rule-Definition (TS 29.212 §5.3.1):
-- each definition with its own QCI is a candidate for a dedicated
-- bearer; its Flow-Information gives the filter.
local function rules_from(m)
    local out = {}
    for i = 0, m.avps:size() - 1 do
        local a = m.avps[i]
        if a.code == diam.AVP_CHARGING_RULE_INSTALL and a.vendor_id == V3GPP then
            for j = 0, a.children:size() - 1 do
                local c = a.children[j]
                if c.code == diam.AVP_CHARGING_RULE_DEFINITION then
                    local r = { name = "?", flows = {} }
                    for k = 0, c.children:size() - 1 do
                        local d = c.children[k]
                        if d.code == diam.AVP_CHARGING_RULE_NAME then
                            r.name = d:str()
                        elseif d.code == diam.AVP_QOS_CLASS_IDENTIFIER then
                            r.qci = d:u32()
                        elseif d.code == diam.AVP_PRECEDENCE then
                            r.precedence = d:u32()
                        elseif d.code == diam.AVP_FLOW_INFORMATION then
                            if d:has_child(diam.AVP_FLOW_DESCRIPTION, V3GPP) then
                                local f = flow_parse(
                                    d:child(diam.AVP_FLOW_DESCRIPTION, V3GPP):str())
                                if f then r.flows[#r.flows + 1] = f end
                            end
                        elseif d.code == diam.AVP_MAX_REQUESTED_BANDWIDTH_UL then
                            r.mbr_ul = d:u32()
                        elseif d.code == diam.AVP_MAX_REQUESTED_BANDWIDTH_DL then
                            r.mbr_dl = d:u32()
                        end
                    end
                    out[#out + 1] = r
                elseif c.code == diam.AVP_CHARGING_RULE_BASE_NAME then
                    out[#out + 1] = { name = c:str(), predefined = true, flows = {} }
                elseif c.code == diam.AVP_CHARGING_RULE_NAME then
                    out[#out + 1] = { name = c:str(), predefined = true, flows = {} }
                end
            end
        end
    end
    return out
end

local function policy_from_cca(m)
    local p = policy_default()
    p.source = "PCRF"
    if m:has(diam.AVP_DEFAULT_EPS_BEARER_QOS, V3GPP) then
        local q = m:find(diam.AVP_DEFAULT_EPS_BEARER_QOS, V3GPP)
        p.qci = ochild_u32(q, diam.AVP_QOS_CLASS_IDENTIFIER) or p.qci
        if q:has_child(diam.AVP_ALLOCATION_RETENTION_PRIORITY, V3GPP) then
            local arp = q:child(diam.AVP_ALLOCATION_RETENTION_PRIORITY, V3GPP)
            p.arp = ochild_u32(arp, diam.AVP_PRIORITY_LEVEL) or p.arp
        end
    end
    if m:has(diam.AVP_QOS_INFORMATION, V3GPP) then
        local q = m:find(diam.AVP_QOS_INFORMATION, V3GPP)
        local ul = ochild_u32(q, diam.AVP_APN_AGGREGATE_MAX_BITRATE_UL)
        local dl = ochild_u32(q, diam.AVP_APN_AGGREGATE_MAX_BITRATE_DL)
        if ul then p.ambr_ul = math.floor(ul / 1000) end
        if dl then p.ambr_dl = math.floor(dl / 1000) end
    end
    p.bcm   = ou32(m, diam.AVP_BEARER_CONTROL_MODE, V3GPP)
    p.rules = rules_from(m)
    return p
end

-- A CCA answering one of our CCRs. Only the initial one gates a Create
-- Session Response; the termination answer is bookkeeping.
local function on_cca(m)
    stats.cca = stats.cca + 1
    local sid  = ostr(m, diam.AVP_SESSION_ID)
    local sess = sid and by_gx[sid]
    local rc   = ou32(m, diam.AVP_RESULT_CODE)
    local crt  = ou32(m, diam.AVP_CC_REQUEST_TYPE)

    if not sess then
        local imsi = sid and gx.terminating[sid]
        if imsi then
            gx.terminating[sid] = nil
            vlog("%s CCA-T result %s (Gx session closed)", imsi, tostring(rc))
        else
            vlog("CCA for an unknown session (%s), result %s", sid or "?", tostring(rc))
        end
        return
    end
    if crt == diam.CC_REQUEST_TYPE_TERMINATION_REQUEST then
        if sid then gx.terminating[sid] = nil end
        vlog("%s CCA-T result %s", sess.imsi, tostring(rc))
        return
    end
    if not sess.pending then return end            -- late answer, already replied

    if rc and rc ~= RC_OK then
        -- The PCRF refused the connection: no policy, no session.
        log("<> %s CCA-I rejected the PDN connection (Result-Code %d)", sess.imsi, rc)
        return finish_create(sess, nil, gtp.GTP2_CAUSE_REQUEST_REJECTED)
    end
    finish_create(sess, policy_from_cca(m))
end

-- RAR: the PCRF changing policy mid-session. Answer it, then act — an
-- installed rule with its own QCI becomes a dedicated bearer, a release
-- cause tears the connection down from the network side.
local function on_rar(m)
    stats.rar = stats.rar + 1
    local sid  = ostr(m, diam.AVP_SESSION_ID)
    local sess = sid and by_gx[sid]

    local b = diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
    if m.proxiable then b:proxiable() end
    b:put_str(diam.AVP_SESSION_ID, sid or "")
     :put_u32(diam.AVP_RESULT_CODE, sess and RC_OK
              or diam.RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID)
    gx_identity(b)
    if sess then b:put_u32(diam.AVP_ORIGIN_STATE_ID, RUN_ID % 0x7FFFFFFF) end
    gx_send(b:done(), "RAA")

    if not sess then
        log("<> RAR for an unknown Gx session (%s) -> UNKNOWN_SESSION_ID", sid or "?")
        return
    end
    if sess.pending then
        -- The PDN connection is not established yet (its CCA-I is still
        -- outstanding), so there is nothing to hang a bearer off.
        log("<> %s RAR before the PDN connection is up -- policy not applied",
            sess.imsi)
        return
    end
    local rules = rules_from(m)
    log("<> %s RAR: %d rule(s) installed", sess.imsi, #rules)
    for _, r in ipairs(rules) do
        vlog("%s rule %s qci=%s flows=%d", sess.imsi, r.name, tostring(r.qci), #r.flows)
        if r.qci and r.qci ~= sess.policy.qci then
            create_bearer(sess, r)
        end
    end
end

-- One complete Diameter message off the stream.
local function gx_dispatch(frame)
    local ok, m = pcall(diam.parse, frame)
    if not ok then
        log("!! Gx: unparseable %d-byte message: %s", #frame, why(m))
        return
    end
    if m.request then
        if m.cmd == diam.CMD_DEVICE_WATCHDOG then
            local b = diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
                :put_u32(diam.AVP_RESULT_CODE, RC_OK)
            gx_identity(b)
            gx_send(b:done(), "DWA")
        elseif m.cmd == diam.CMD_DISCONNECT_PEER then
            local b = diam.Builder():answer(m.cmd, m.app):ids(m.hbh, m.e2e)
                :put_u32(diam.AVP_RESULT_CODE, RC_OK)
            gx_identity(b)
            gx_send(b:done(), "DPA")
            log("<> Gx: PCRF sent DPR -- closing")
            gx.closing = true
        elseif m.cmd == diam.CMD_RE_AUTH then
            on_rar(m)
        else
            vlog("Gx: ignoring request %s (%d)", m:name(), m.cmd)
        end
        return
    end

    if m.cmd == diam.CMD_CAPABILITIES_EXCHANGE then
        local rc = ou32(m, diam.AVP_RESULT_CODE)
        gx.up = (rc == RC_OK)
        gx.peer = ostr(m, diam.AVP_ORIGIN_HOST)
        log("<> Gx: CEA from %s, Result-Code %s -> %s", gx.peer or "?",
            tostring(rc), gx.up and "up" or "down")
    elseif m.cmd == diam.CMD_CREDIT_CONTROL then
        on_cca(m)
    elseif m.cmd == diam.CMD_DEVICE_WATCHDOG then
        vlog("Gx: DWA")
    else
        vlog("Gx: ignoring answer %s (%d)", m:name(), m.cmd)
    end
end

-- The Diameter header's 24-bit Message Length frames the byte stream.
local function gx_frame()
    while #gx.rxbuf >= 20 do
        local b    = gx.rxbuf
        local mlen = b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
        if mlen < 20 then
            log("!! Gx: bad Message Length %d -- dropping the connection", mlen)
            gx.closing = true
            return
        end
        if #b < mlen then return end               -- wait for the rest
        gx.rxbuf = b:sub(mlen + 1)
        gx_dispatch(b:sub(1, mlen))
    end
end

local loop = net.Loop()
local gx_connect                                   -- forward (reconnect timer)

local function gx_close(reason)
    if gx.conn then
        pcall(function() loop:del_fd(gx.conn:fd()) end)
        pcall(function() gx.conn:close() end)
    end
    gx.conn, gx.up, gx.rxbuf, gx.closing = nil, false, "", false
    gx.terminating = {}                            -- no answer is coming now
    if gx.watchdog then loop:cancel(gx.watchdog); gx.watchdog = nil end
    log("<> Gx: %s -- retrying in %dms", reason, GX_RETRY_MS)
    loop:after(GX_RETRY_MS, function() gx_connect() end)
end

local function gx_readable()
    while true do
        local ok, d = pcall(function() return gx.conn:recv(-1) end)
        if not ok then return gx_close("recv error: " .. why(d)) end
        if d.closed then return gx_close("the PCRF closed the connection") end
        if d.timed_out then break end
        gx.rxbuf = gx.rxbuf .. d.data
    end
    gx_frame()
    if gx.closing then gx_close("peer disconnect") end
end

local function gx_tick()
    gx.watchdog = loop:after(GX_WATCHDOG_MS, function()
        if gx.up then
            local b = gx_request(diam.CMD_DEVICE_WATCHDOG, 0, false)
            gx_identity(b):put_u32(diam.AVP_ORIGIN_STATE_ID, RUN_ID % 0x7FFFFFFF)
            gx_send(b:done(), "DWR")
        end
        gx_tick()
    end)
end

-- ---- GTP-C server (S5/S8) ---------------------------------------------

-- Assemble and send the Create Session Response. cause nil = accepted;
-- policy nil on a rejection. Called either straight from the request (Gx
-- down) or from the CCA-I / the Gx deadline.
finish_create = function(sess, policy, cause)
    if not sess.pending then return end
    sess.pending = false
    if sess.gx_timer then loop:cancel(sess.gx_timer); sess.gx_timer = nil end

    if cause then
        local rsp = gtp.CreateSessionResponse()
        rsp.teid, rsp.sequence, rsp.cause = sess.sgw_c_teid, sess.seq, cause
        ep:send_create_session_response(rsp, sess.sgw_c_addr, sess.sgw_c_port)
        stats.rejected = stats.rejected + 1
        log("-> %s Create Session Response: rejected, cause %d", sess.imsi, cause)
        remove_tunnel(sess)
        session_drop(sess)
        return
    end

    sess.policy = policy or policy_default()
    local rsp = gtp.CreateSessionResponse()
    rsp.teid     = sess.sgw_c_teid                 -- the SGW's control TEID
    rsp.sequence = sess.seq
    rsp.cause    = gtp.GTP2_CAUSE_REQUEST_ACCEPTED

    -- PGW S5/S8-C F-TEID (instance 1): where the SGW addresses Modify /
    -- Delete Session from here on.
    local c = gtp.Fteid()
    c.if_type, c.teid, c.addr4 = gtp.GTP2_IF_S5S8C_PGW, sess.pgw_c_teid, pgw_addr
    rsp.has_pgw_fteid, rsp.pgw_fteid = true, c

    rsp.has_paa      = true
    rsp.paa.pdn_type = gtp.GTP2_PDN_IPV4
    rsp.paa.addr4    = sess.ue_addr

    rsp.has_ambr     = true
    rsp.ambr.ul_kbps = sess.policy.ambr_ul
    rsp.ambr.dl_kbps = sess.policy.ambr_dl
    rsp.apn_restriction = 0
    if sess.want_pcscf and PCSCF then
        local pco = pco_pcscf(PCSCF)
        if pco then rsp.pco = pco end
    end

    -- Default bearer: accepted, with the granted QoS and our S5/S8-U
    -- F-TEID at instance 2 (the PGW end of the user plane).
    local bc = gtp.BearerContext()
    bc.ebi, bc.cause = sess.ebi, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
    bc.has_qos       = true
    bc.qos.qci       = sess.policy.qci
    bc.qos.pl        = sess.policy.arp
    local u = gtp.Fteid()
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_PGW, sess.pgw_u_teid, pgw_addr
    bc:add_fteid(2, u)
    rsp:add_bearer(bc)

    sess.csresp = rsp                              -- kept for retransmissions
    ep:send_create_session_response(rsp, sess.sgw_c_addr, sess.sgw_c_port)
    stats.created     = stats.created + 1
    stats.win_created = stats.win_created + 1
    log("-> %s Create Session Response: PAA %s, EBI %d, QCI %d, AMBR %d/%d kbps (%s)%s",
        sess.imsi, sess.ue_addr, sess.ebi, sess.policy.qci,
        sess.policy.ambr_ul, sess.policy.ambr_dl, sess.policy.source,
        sess.want_pcscf and PCSCF and (", P-CSCF " .. PCSCF) or "")

    -- Rules that came with the CCA-I and need their own bearer.
    for _, r in ipairs(sess.policy.rules or {}) do
        if r.qci and r.qci ~= sess.policy.qci then create_bearer(sess, r) end
    end
end

-- The SGW's user-plane F-TEID out of a bearer context (any instance:
-- what matters is that it is the S5/S8-U side).
local function sgw_user_fteid(bc)
    for i = 0, bc.fteids:size() - 1 do
        local e = bc.fteids[i]
        if e.fteid.teid ~= 0 then return e.fteid end
    end
    return nil
end

local function on_create_session_request(req, host, port)
    local imsi = req.imsi ~= "" and req.imsi or nil
    local key  = req_key(host, req.sender_fteid.teid, imsi)

    -- A retransmission (same peer, same control TEID, same sequence):
    -- answer it again, or let the original request finish.
    local prev = by_key[key]
    if prev then
        if prev.pending then
            vlog("%s duplicate Create Session Request (seq %d) while the PCRF answers",
                 imsi or "?", req.sequence)
        elseif prev.csresp then
            prev.csresp.sequence = req.sequence
            ep:send_create_session_response(prev.csresp, host, port)
            vlog("%s duplicate Create Session Request -> resent the response",
                 imsi or "?")
        end
        return
    end

    local bc = req.bearers:size() > 0 and req.bearers[0] or nil
    local uf = bc and sgw_user_fteid(bc) or nil
    local sess = {
        imsi = imsi or "?", msisdn = req.msisdn, apn = req.apn,
        seq = req.sequence, key = key,
        sgw_c_teid = req.sender_fteid.teid,
        sgw_c_addr = host, sgw_c_port = port,
        ebi = bc and bc.ebi or 5,
        sgw_u_teid = uf and uf.teid or nil,
        sgw_u_addr = uf and (uf.addr4 ~= "" and uf.addr4 or uf.addr6) or nil,
        pgw_c_teid = alloc_ctrl_teid(), pgw_u_teid = alloc_user_teid(),
        want_pcscf = pco_wants_pcscf(req.pco),
        pending = true, gx_ccr_no = 0, dedicated = {}, ded_ebi = 5,
    }
    by_ctrl[sess.pgw_c_teid] = sess
    by_key[key]              = sess
    session_count            = session_count + 1

    log("<- %s Create Session Request: APN %q, SGW ctrl TEID %#x, EBI %d",
        sess.imsi, sess.apn, sess.sgw_c_teid, sess.ebi)

    -- Mandatory pieces of an S5/S8 attach.
    if not (imsi and bc and uf) then
        return finish_create(sess, nil, gtp.GTP2_CAUSE_MANDATORY_IE_MISSING)
    end

    -- The address: honour a specific request (a non-zero PAA) when it is
    -- free, else take the next one from the pool.
    local wanted = req.has_paa and req.paa.addr4 or nil
    if wanted and wanted ~= "" and wanted ~= "0.0.0.0" then
        local ok = pcall(function() pool:reserve(wanted) end)
        if ok then
            sess.ue_addr = wanted
            vlog("%s honoured the requested address %s", sess.imsi, wanted)
        end
    end
    if not sess.ue_addr then
        if pool:available() == 0 then
            log("!! %s pool %s is exhausted (%d in use)", sess.imsi, POOL, pool:used())
            return finish_create(sess, nil,
                                 gtp.GTP2_CAUSE_ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED)
        end
        sess.ue_addr = pool:alloc()
    end

    -- The user plane can go in now: both F-TEIDs are known.
    program_tunnel(sess)

    -- Policy: ask the PCRF, or grant the local default straight away.
    if gx.up then
        sess.gx_sid    = alloc_session_id(sess.imsi)
        by_gx[sess.gx_sid] = sess
        if gx_ccr_initial(sess) then
            sess.gx_timer = loop:after(GX_TIMEOUT_MS, function()
                sess.gx_timer = nil
                stats.gx_timeout = stats.gx_timeout + 1
                log("!! %s no CCA-I within %dms -- granting the local default policy",
                    sess.imsi, GX_TIMEOUT_MS)
                finish_create(sess, nil)
            end)
            return
        end
    end
    finish_create(sess, nil)
end

local function on_modify_bearer_request(req, host, port)
    local sess = by_ctrl[req.teid]
    if not sess then
        local rsp = gtp.ModifyBearerResponse()
        rsp.teid, rsp.sequence = 0, req.sequence
        rsp.cause = gtp.GTP2_CAUSE_CONTEXT_NOT_FOUND
        ep:send_modify_bearer_response(rsp, host, port)
        log("<- Modify Bearer for an unknown TEID %#x -> Context Not Found", req.teid)
        return
    end
    stats.modified = stats.modified + 1

    -- A relocated SGW (or the S1 leg coming up) moves the far end of the
    -- user plane; re-point the tunnel at it.
    local moved = false
    for i = 0, req.bearers:size() - 1 do
        local bc = req.bearers[i]
        if bc.ebi == sess.ebi then
            local uf = sgw_user_fteid(bc)
            if uf then
                local addr = uf.addr4 ~= "" and uf.addr4 or uf.addr6
                if uf.teid ~= sess.sgw_u_teid or addr ~= sess.sgw_u_addr then
                    sess.sgw_u_teid, sess.sgw_u_addr = uf.teid, addr
                    moved = true
                end
            end
        end
    end
    if moved then update_tunnel(sess) end

    local rsp = gtp.ModifyBearerResponse()
    rsp.teid, rsp.sequence = sess.sgw_c_teid, req.sequence
    rsp.cause      = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
    rsp.linked_ebi = sess.ebi
    rsp.has_ambr   = true
    rsp.ambr.ul_kbps, rsp.ambr.dl_kbps = sess.policy.ambr_ul, sess.policy.ambr_dl
    local bc = gtp.BearerContext()
    bc.ebi, bc.cause = sess.ebi, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
    local u = gtp.Fteid()
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_PGW, sess.pgw_u_teid, pgw_addr
    bc:add_fteid(2, u)
    rsp:add_bearer(bc)
    ep:send_modify_bearer_response(rsp, host, port)
    log("<> %s Modify Bearer: EBI %d%s", sess.imsi, sess.ebi,
        moved and (" -> SGW-U %#x @ %s"):format(sess.sgw_u_teid, sess.sgw_u_addr) or "")
end

local function on_delete_session_request(req, host, port)
    local sess = by_ctrl[req.teid]
    local rsp  = gtp.DeleteSessionResponse()
    rsp.sequence = req.sequence
    if not sess then
        rsp.teid, rsp.cause = 0, gtp.GTP2_CAUSE_CONTEXT_NOT_FOUND
        ep:send_delete_session_response(rsp, host, port)
        log("<- Delete Session for an unknown TEID %#x -> Context Not Found", req.teid)
        return
    end

    gx_ccr_terminate(sess)                         -- tell the PCRF first

    -- What the bearer actually carried, read out before the datapath
    -- entry goes away: rx is the uplink this anchor decapsulated, tx the
    -- downlink it encapsulated.
    local carried = ""
    if up and sess.tunnelled then
        local ok, st = pcall(function() return up:stats(sess.pgw_u_teid) end)
        if ok then
            carried = (", GTP-U rx %d pkt / tx %d pkt"):format(st.rx_pkts, st.tx_pkts)
        end
    end
    remove_tunnel(sess)
    local addr = sess.ue_addr
    session_drop(sess)
    stats.deleted = stats.deleted + 1

    rsp.teid, rsp.cause = sess.sgw_c_teid, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
    ep:send_delete_session_response(rsp, host, port)
    log("<> %s Delete Session: released %s (%d/%d addresses in use%s)",
        sess.imsi, addr, pool:used(), pool:size(), carried)
end

-- ---- dedicated bearer (PCRF rule -> Create Bearer Request) ------------

-- Push a rule out as a dedicated bearer. The endpoint has no client-side
-- transaction for PGW-initiated requests, so the message is encoded and
-- sent raw with a sequence from our own space; the SGW's Create Bearer
-- Response lands in on_message below.
create_bearer = function(sess, rule)
    local flow = rule.flows[1]
    sess.ded_ebi = sess.ded_ebi + 1
    local ded = {
        ebi = sess.ded_ebi, name = rule.name, rule = rule,
        pgw_u_teid = alloc_user_teid(), seq = alloc_seq(),
    }

    local bc = gtp.BearerContext()
    bc.ebi     = ded.ebi
    bc.has_qos = true
    bc.qos.qci = rule.qci
    bc.qos.pl  = sess.policy.arp
    if rule.mbr_ul then bc.qos.mbr_ul = math.floor(rule.mbr_ul / 1000) end
    if rule.mbr_dl then bc.qos.mbr_dl = math.floor(rule.mbr_dl / 1000) end
    local tft = tft_create(rule.precedence or 255,
                           flow and flow.proto or nil,
                           nil, flow and flow.port or nil)
    if tft then bc.tft = tft end
    local u = gtp.Fteid()
    u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_PGW, ded.pgw_u_teid, pgw_addr
    bc:add_fteid(1, u)                             -- S5/S8-U PGW F-TEID

    local req = gtp.CreateBearerRequest()
    req.teid, req.sequence = sess.sgw_c_teid, ded.seq
    req.linked_ebi = sess.ebi
    req.has_ambr   = true
    req.ambr.ul_kbps, req.ambr.dl_kbps = sess.policy.ambr_ul, sess.policy.ambr_dl
    req:add_bearer(bc)

    local ok, err = pcall(function()
        ep:send_raw(req:encode(), sess.sgw_c_addr, sess.sgw_c_port)
    end)
    if not ok then
        log("!! %s Create Bearer Request (rule %s) failed: %s",
            sess.imsi, rule.name, why(err))
        return
    end
    sess.dedicated[#sess.dedicated + 1] = ded
    sess.ded_by_seq = sess.ded_by_seq or {}
    sess.ded_by_seq[ded.seq] = ded
    stats.ded_req = stats.ded_req + 1
    log("-> %s Create Bearer Request: EBI %d for rule %s (QCI %s%s)",
        sess.imsi, ded.ebi, rule.name, tostring(rule.qci),
        tft and ", TFT" or ", no TFT")
end

-- The accepted dedicated bearer's own datapath entry: a traffic filter
-- steering the flow's downlink onto its TEID pair. Only installed when
-- the rule named a protocol and a UE-side port — a wildcard filter would
-- swallow the default bearer's traffic instead of just the media.
local function program_dedicated(sess, ded)
    if not (up and ded.sgw_u_teid) then return end
    local flow = ded.rule.flows[1]
    if not (flow and flow.proto and flow.port) then
        vlog("%s EBI %d: no port-specific filter in rule %s -- default bearer keeps the flow",
             sess.imsi, ded.ebi, ded.name)
        return
    end
    local t = gtp.Tunnel()
    t.local_teid, t.remote_teid = ded.pgw_u_teid, ded.sgw_u_teid
    t.ebi, t.ue_addr, t.remote_addr = ded.ebi, sess.ue_addr, ded.sgw_u_addr
    t.core_side = true
    local f = gtp.TrafficFilter()
    f.tunnel, f.proto, f.ue_port = t, flow.proto, flow.port
    local ok, err = pcall(function() up:add_filter(f) end)
    ded.filter, ded.filtered = f, ok
    vlog("%s EBI %d GTP-U filter proto %d port %d -> %#x/%#x %s", sess.imsi,
         ded.ebi, flow.proto, flow.port, ded.pgw_u_teid, ded.sgw_u_teid,
         ok and "installed" or ("failed: " .. why(err)))
end

-- Anything the endpoint has no typed callback for: the Create Bearer
-- Response to a request we sent raw (it matches no client transaction).
local function on_message(mt, wire, host, port)
    if mt ~= gtp.GTP2_MT_CREATE_BEARER_RESPONSE then
        vlog("ignoring message type %d from %s:%d", mt, host, port)
        return
    end
    local ok, rsp = pcall(gtp.CreateBearerResponse.decode, wire)
    if not ok then
        log("!! unparseable Create Bearer Response from %s: %s", host, why(rsp))
        return
    end
    -- Correlate by the header TEID (our control TEID) and the sequence.
    local sess = by_ctrl[rsp.teid]
    local ded  = sess and sess.ded_by_seq and sess.ded_by_seq[rsp.sequence]
    if not (sess and ded) then
        vlog("Create Bearer Response for an unknown bearer (TEID %#x, seq %d)",
             rsp.teid, rsp.sequence)
        return
    end
    if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
        log("<- %s Create Bearer Response: EBI %d rejected, cause %d",
            sess.imsi, ded.ebi, rsp.cause)
        return
    end
    for i = 0, rsp.bearers:size() - 1 do
        local bc = rsp.bearers[i]
        for j = 0, bc.fteids:size() - 1 do
            local e = bc.fteids[j]
            if e.fteid.if_type == gtp.GTP2_IF_S5S8U_SGW then
                ded.sgw_u_teid = e.fteid.teid
                ded.sgw_u_addr = e.fteid.addr4 ~= "" and e.fteid.addr4
                                 or e.fteid.addr6
            end
        end
    end
    stats.ded_ok = stats.ded_ok + 1
    log("<- %s Create Bearer Response: EBI %d accepted (SGW-U %#x @ %s)",
        sess.imsi, ded.ebi, ded.sgw_u_teid or 0, ded.sgw_u_addr or "?")
    program_dedicated(sess, ded)
end

-- ---- periodic throughput line -----------------------------------------

local function tick()
    local t    = now()
    local win  = (t - stats.win0) / 1000
    local rate = win > 0 and (stats.win_created / win) or 0
    log("== %d session(s) active | %d created (%.0f/s last %.0fs), %d modified,"
        .. " %d deleted, %d rejected | pool %d/%d | %d dedicated bearer(s)"
        .. " | Gx %s (CCR %d, CCA %d, RAR %d%s)",
        session_count, stats.created, rate, win, stats.modified, stats.deleted,
        stats.rejected, pool:used(), pool:size(), stats.ded_ok,
        gx.up and "up" or "down", stats.ccr, stats.cca, stats.rar,
        stats.gx_timeout > 0 and (", %d timeouts"):format(stats.gx_timeout) or "")
    stats.win0, stats.win_created = t, 0
    loop:after(STATS_MS, tick)
end

-- ---- run --------------------------------------------------------------

gx_connect = function()
    if not PCRF_HOST then return end
    local proto = PCRF_PROTO == "sctp" and net.PROTO_SCTP or net.PROTO_TCP
    local ok, c = pcall(net.stream_connect, PCRF_HOST, PCRF_PORT, proto, 3000)
    if not ok then
        log("<> Gx: cannot reach the PCRF at %s:%d/%s (%s) -- retrying in %dms",
            PCRF_HOST, PCRF_PORT, PCRF_PROTO, why(c), GX_RETRY_MS)
        loop:after(GX_RETRY_MS, function() gx_connect() end)
        return
    end
    gx.conn, gx.rxbuf = c, ""
    loop:add_fd(c:fd(), net.NET_RD, function() gx_readable() end)
    log("<> Gx: connected to %s:%d/%s -- sending CER", PCRF_HOST, PCRF_PORT, PCRF_PROTO)
    gx_cer()
    gx_tick()
end

local function run()
    -- The address our F-TEIDs advertise has to be a real one; derive it
    -- from the GTP-U interface when the bind address is the any-address.
    pgw_addr = os.getenv("PGW_ADDR") or ""
    if pgw_addr == "" then
        pgw_addr = (BIND ~= "0.0.0.0" and BIND ~= "" and BIND) or net.if_addr4(GTPU_IFACE)
    end
    if pgw_addr == "" then
        io.stderr:write(("cannot determine the PGW F-TEID address: set PGW_ADDR " ..
                         "or GTPU_IFACE (tried %q)\n"):format(GTPU_IFACE))
        os.exit(1)
    end

    local ok, endpoint = pcall(gtp.Endpoint, loop, BIND, GTPC_PORT)
    if not ok then
        io.stderr:write(("cannot bind GTP-C on %s:%d: %s\n")
            :format(BIND, GTPC_PORT, why(endpoint)))
        os.exit(1)
    end
    ep = endpoint
    ep:set_recovery(1)
    -- GTP-C output rides the loop (the endpoint's default): answering a wide
    -- attach burst queues the responses and the loop pushes them out in
    -- batched sendmmsg() calls, so no session waits in the kernel while the
    -- next request is being decoded. ep:tx_sent()/tx_calls() report the ratio.
    ep:set_handler({
        on_create_session_request = on_create_session_request,
        on_modify_bearer_request  = on_modify_bearer_request,
        on_delete_session_request = on_delete_session_request,
        on_message                = on_message,
        on_echo_request = function(host, port, recovery)
            vlog("Echo Request from %s:%d (recovery %d)", host, port, recovery)
        end,
    })

    log("== PGW stub ready")
    line("GTP-C (S5/S8)", ("%s:%d"):format(ep:local_host(), ep:local_port()))
    line("F-TEID address", pgw_addr)
    line("UE address pool", ("%s (%d addresses%s)"):format(POOL, pool:size(),
        POOL_GW and (", gateway " .. POOL_GW .. " reserved") or ""))
    line("P-CSCF (PCO)", PCSCF or "not configured")
    line("default policy", ("QCI %d, ARP %d, AMBR %d/%d kbps")
        :format(DEF_QCI, DEF_ARP, DEF_AMBR_UL, DEF_AMBR_DL))
    datapath_open()
    if PCRF_HOST then
        line("Gx (PCRF)", ("%s:%d/%s as %s"):format(PCRF_HOST, PCRF_PORT,
            PCRF_PROTO, ORIGIN_HOST))
        line("Gx realms", ("origin %s -> destination %s"):format(ORIGIN_REALM, DEST_REALM))
        gx_connect()
    else
        line("Gx (PCRF)", "disabled (set GX_PCRF to enable) -- local policy only")
    end

    loop:after(STATS_MS, tick)
    local rok, rerr = pcall(function() loop:run() end)
    if not rok then
        io.stderr:write("loop error: " .. why(rerr) .. "\n")
        return 1
    end
    return 0
end

os.exit(run())
