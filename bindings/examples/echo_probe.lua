#!/usr/bin/env lua
-- Probe a GTP-C peer with an Echo Request and print its restart counter.
-- The endpoint answers Echo Requests itself and matches the response for
-- us; all this has to do is send one and wait, with a self-imposed
-- deadline since Echo is fire-and-forget (no retransmission).
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua echo_probe.lua PEER [PORT]

local gtp = require("gtp")
local net = require("net")   -- event loop the endpoint runs on

local peer = arg[1] or "127.0.0.1"
local port = tonumber(arg[2]) or gtp.GTPC_PORT

local loop = net.Loop()
local ep   = gtp.Endpoint(loop, "0.0.0.0", 0)   -- ephemeral local port

ep:set_handler({
    on_echo_response = function(host, sport, recovery)
        print(("%s:%d is alive, restart counter %d"):format(host, sport, recovery))
        loop:stop()
    end,
})
ep:send_echo(peer, port)

loop:after(3000, function()
    print(("%s:%d: no answer"):format(peer, port))
    loop:stop()
end)

loop:run()
