#!/usr/bin/env lua
-- Attach one UE: send a Create Session toward an SGW/PGW, install the
-- GTP-U tunnel when the response arrives, hold the session briefly, then
-- detach cleanly. This is the MME/S11 shape of the workflow; change the
-- F-TEID interface types for other reference points.
--
-- The user-plane installation runs only when the eBPF datapath is
-- available (CAP_BPF + CAP_NET_ADMIN); without it the tunnel parameters
-- are just printed. In a real node the detach is driven by node
-- shutdown; here a timer stands in so the example runs to completion.
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so lua session_setup.lua \
--       LOCAL_IP PEER_IP [APN] [IMSI]

local gtp = require("gtp")
local net = require("net")   -- event loop the endpoint runs on

local ENB_UP_TEID = 0x100   -- our (downlink) tunnel endpoint id
local HOLD_MS     = 5000    -- keep the session up this long, then detach

local local_ip = arg[1]
local peer_ip  = arg[2]
if not (local_ip and peer_ip) then
    io.stderr:write("usage: session_setup.lua LOCAL_IP PEER_IP [APN] [IMSI]\n")
    os.exit(1)
end
local apn  = arg[3] or "internet"
local imsi = arg[4] or "001010123456789"

local function build_request()
    local req = gtp.CreateSessionRequest()
    req.imsi = imsi
    req.apn = apn
    req.rat_type = gtp.GTP2_RAT_EUTRAN
    req.pdn_type = gtp.GTP2_PDN_IPV4
    -- sender F-TEID (control plane) is filled in by create_session()

    local bearer = gtp.BearerContext()
    bearer.ebi = 5
    bearer.has_qos = true
    bearer.qos.qci = 9
    local up = gtp.Fteid()
    up.if_type = gtp.GTP2_IF_S1U_ENODEB
    up.teid = ENB_UP_TEID
    up.addr4 = local_ip
    bearer:add_fteid(0, up)
    req:add_bearer(bearer)
    return req
end

local loop = net.Loop()
local ep   = gtp.Endpoint(loop, local_ip)      -- binds GTP-C port 2123

local userplane
if gtp.UserPlane.supported() then
    local cfg = gtp.UserPlaneConfig()
    cfg.local_v4 = local_ip
    userplane = gtp.UserPlane(cfg)
    -- userplane:attach(gtpu_ifindex, inner_ifindex) as fits the host
end

local ue_addr = "0.0.0.0"   -- learned from the response's PAA

ep:set_handler({
    on_create_session_response = function(sess, rsp)
        if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
            print(("rejected, cause %d"):format(rsp.cause))
            loop:stop()
            return
        end
        if rsp.has_paa then
            ue_addr = rsp.paa.addr4
            print(("session up, UE address %s"):format(ue_addr))
        end
        -- Hold the session, then detach (a node would do this on shutdown).
        loop:after(HOLD_MS, function() sess:delete_session() end)
    end,

    on_user_plane = function(sess, tun)
        -- The peer told us its data-plane endpoint: create the tunnel.
        print(("user plane: EBI %d local TEID %#x -> remote TEID %#x @ %s")
            :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
        if userplane then
            local t = gtp.Tunnel()
            t.local_teid  = tun.local_teid
            t.remote_teid = tun.remote_teid
            t.remote_addr = tun.remote_addr
            t.ebi         = tun.ebi
            t.ue_addr     = ue_addr
            userplane:add_tunnel(t)
        end
    end,

    on_delete_session_response = function(sess, rsp)
        print("session deleted")
        loop:stop()
    end,

    on_timeout = function(sess, message_type)
        print(("peer did not answer message type %d"):format(message_type))
        loop:stop()
    end,
})

local sess = ep:create_session(build_request(), peer_ip)
print(("creating session, local control TEID %#x"):format(sess:local_teid()))

loop:run()
