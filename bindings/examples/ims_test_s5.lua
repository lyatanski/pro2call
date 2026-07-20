#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PGW_IP=smf] lua ims_test_s5.lua
--
-- PGW_IP may be a host name (resolved through the system resolver) or a
-- literal IP address; it defaults to "smf".
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
        io.stderr:write(("cannot bind GTP-C on %s:2123: %s\n")
            :format(sgw_ip, tostring(ep):gsub("^.-:%s*", "")))
        os.exit(1)
    end
    ep:set_t3_ms(T3_MS)
    ep:set_n3(N3)

    local st = { done = false, err = nil, ue_addr = nil }

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
        -- data-plane endpoint. A real SGW would program its GTP-U
        -- datapath (gtp.UserPlane) here; we just report it.
        on_user_plane = function(sess, tun)
            line("user plane (S5/S8-U)",
                 ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                     :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
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

    return { loop = loop, ep = ep, sess = sess, st = st, ue_addr = st.ue_addr }
end

-- main
local pdn = attach_pdn_over_s5()
if pdn.st.err then
    line("result", pdn.st.err)
    os.exit(1)
end
line("result", "PDN connection established over S5/S8")
