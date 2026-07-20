#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] lua ims_test_s5.lua
--
-- PGW_IP may be a host name (resolved through the system resolver) or a
-- literal IP address; it defaults to "smf".
--
-- GTP-U user plane: when the eBPF datapath is available (CAP_BPF +
-- CAP_NET_ADMIN, eBPF build) the script programs each bearer's forwarding
-- entry into it. Set $GTPU_IFACE (the S5/S8-U interface facing the PGW)
-- and $GTPU_INNER_IFACE (the access side) to also attach the TC programs;
-- without them the datapath loads and the tunnels are installed in its
-- map, but no interface is hooked. Without the datapath the tunnels are
-- only reported.
--

local gtp = require("gtp")
local net = require("net")     -- event loop + UDP socket transport

-- ---- configuration ----------------------------------------------------

local pgw_host = os.getenv("PGW_IP")   or "smf"              -- PGW/SMF: a name (resolved below) or a literal IP
local sgw_ip   = os.getenv("SGW_IP")   or "0.0.0.0"
local apn      = os.getenv("IMS_APN")  or "ims"
local mcc      = os.getenv("IMS_MCC")  or "001"              -- serving PLMN (matches the IMSI
local mnc      = os.getenv("IMS_MNC")  or "01"               -- and the mnc01.mcc001 core realm)
local imsi     = os.getenv("IMS_IMSI") or "001010123456789"  -- TS 35.207 test IMSI

local S5_UP_TEID = 0x200       -- our (SGW) S5/S8-U downlink tunnel endpoint id
local T3_MS, N3  = 1000, 3     -- retransmission: 1s T3-RESPONSE, up to 3 sends

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

-- Resolve a host name to an IPv4 literal. A dotted-quad is returned
-- unchanged; otherwise we shell out to the system resolver (the net
-- binding exposes none) and take the first A record — `getent` covers
-- glibc / musl-utils, busybox `nslookup` covers Alpine. The name is
-- validated first so it cannot smuggle shell syntax into the command.
local function resolve(name)
    if name:match("^%d+%.%d+%.%d+%.%d+$") then return name end
    assert(name:match("^[%w%.%-]+$"), "invalid PGW host name: " .. name)

    local function run(cmd)
        local p = io.popen(cmd .. " 2>/dev/null"); if not p then return "" end
        local out = p:read("*a") or ""; p:close(); return out
    end

    -- getent prints only answer lines ("<ip>  STREAM <name>").
    local ip = run("getent ahostsv4 " .. name):match("(%d+%.%d+%.%d+%.%d+)")
    -- nslookup precedes the answer with the server's own address; the
    -- answer section starts at "Name:", so scan only from there.
    if not ip then
        local tail = run("nslookup " .. name):match("Name:.*")
        if tail then ip = tail:match("(%d+%.%d+%.%d+%.%d+)") end
    end
    assert(ip, "cannot resolve PGW host name: " .. name)
    return ip
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

-- Inverse of fteid_v4: pull the 32-bit TEID and the IPv4 address out of an
-- F-TEID IE value, used to learn a peer's data-plane endpoint from a raw
-- message. Returns teid, addr; addr is nil when the V4 flag is clear.
local function fteid_v4_decode(v)
    if #v < 5 then return nil end
    local teid = ((v:byte(2) * 256 + v:byte(3)) * 256 + v:byte(4)) * 256 + v:byte(5)
    local addr
    if math.floor(v:byte(1) / 0x80) % 2 == 1 and #v >= 9 then   -- V4 flag set
        addr = ("%d.%d.%d.%d"):format(v:byte(6), v:byte(7), v:byte(8), v:byte(9))
    end
    return teid, addr
end

-- A GTPv2-C Cause IE value (§8.4): the cause octet plus a spare/flags
-- octet (CS/BCE/PCE bits, all zero here).
local function cause_ie(cause) return string.char(cause, 0) end

-- Step the loop until the in-flight transaction resolves: a response
-- sets st.done, an N3 timeout or a rejection sets st.err. The endpoint's
-- own retransmission timer guarantees step() cannot block forever.
local function pump(loop, st)
    while not (st.done or st.err) do loop:step(-1) end
end

-- ---- GTPv2-C over S5/S8 ----------------------------------------------

local function attach_pdn_over_s5()
    local pgw_ip = resolve(pgw_host)
    banner(("GTPv2-C — PDN connection over S5/S8: SGW %s -> PGW %s")
        :format(sgw_ip, pgw_ip))
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

    local st = { done = false, err = nil, ue_addr = nil }

    -- ---- GTP-U user plane (eBPF datapath) ----
    -- Load the datapath when the kernel and privileges allow it; attach its
    -- TC programs to the S5/S8-U and access interfaces when their names are
    -- given. Everything degrades to a log line if the datapath, the caps or
    -- the interfaces are missing, so an unprivileged run still completes.
    local up
    if gtp.UserPlane.supported() then
        local gi = iface_index(os.getenv("GTPU_IFACE"))        -- S5/S8-U (GTP-U) side
        local ii = iface_index(os.getenv("GTPU_INNER_IFACE"))  -- access side
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
                        :format(os.getenv("GTPU_IFACE") or "-", os.getenv("GTPU_INNER_IFACE") or "-")
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

    -- Program one bearer's forwarding entry into the datapath (a no-op when
    -- it is not loaded). Downlink packets to the UE address are encapsulated
    -- to remote_teid @ remote_addr; uplink from local_teid is decapsulated.
    local function program_tunnel(ebi, local_teid, remote_teid, remote_addr)
        if not up then return end
        if not (st.ue_addr and remote_addr and remote_addr ~= "") then
            line("GTP-U tunnel", ("EBI %d not programmed (missing UE/peer address)"):format(ebi))
            return
        end
        local t = gtp.Tunnel()
        t.local_teid, t.remote_teid = local_teid, remote_teid
        t.ebi, t.ue_addr, t.remote_addr = ebi, st.ue_addr, remote_addr
        local pok, perr = pcall(function() up:add_tunnel(t) end)
        line("GTP-U tunnel", pok
            and ("EBI %d  ul TEID %#x / dl TEID %#x @ %s programmed")
                :format(ebi, local_teid, remote_teid, remote_addr)
            or ("EBI %d add_tunnel failed: %s"):format(ebi, why(perr)))
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
            line("<- Create Session Resp", ("accepted; PGW ctrl TEID %#x"):format(sess:remote_teid()))
            if st.ue_addr then line("PAA (UE address)", st.ue_addr) end
            st.done = true
        end,

        -- One per bearer F-TEID in the accepted response: the PGW's
        -- data-plane endpoint. Report it, then program the default bearer's
        -- tunnel into the GTP-U datapath (a no-op if it is not loaded).
        on_user_plane = function(sess, tun)
            line("user plane (S5/S8-U)",
                 ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                     :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
            program_tunnel(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr)
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

            -- Program the dedicated bearer's tunnel too: our uplink TEID is
            -- the one we just handed the PGW; its downlink endpoint is the
            -- PGW F-TEID carried in the request.
            if pgw_u then
                local rteid, raddr = fteid_v4_decode(pgw_u)
                if rteid then program_tunnel(NEW_EBI, S5_UP_TEID + 1, rteid, raddr) end
            end
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

    return { loop = loop, ep = ep, sess = sess, st = st, up = up, ue_addr = st.ue_addr }
end

-- main
local pdn = attach_pdn_over_s5()
if pdn.st.err then
    line("result", pdn.st.err)
    os.exit(1)
end
line("result", "PDN connection established over S5/S8")
