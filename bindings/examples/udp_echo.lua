#!/usr/bin/env lua
-- UDP send and receive driven by the net event loop.
--
-- Two UDP sockets over loopback, both registered with one net.Loop: the
-- server echoes back every datagram it receives; the client fires a
-- batch of messages and prints each echo as it arrives. Nothing blocks —
-- the loop dispatches each socket's fd when it turns readable, a timer
-- bounds the run, and loop:stop() ends it once the last echo is in.
--
-- This is the canonical event-loop shape: bind a net.UdpSocket, hand its
-- fd() to loop:add_fd() with a receive callback, and send from anywhere.
-- For a plain synchronous exchange, skip the loop and call sock:recv(ms)
-- directly (it emulates blocking up to the timeout).
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua udp_echo.lua

-- package.cpath = 'out/bindings/lua/?.so;' .. package.cpath
local net = require("net")

local HOST     = "127.0.0.1"
local MESSAGES = { "ping 1", "ping 2", "ping 3" }

local loop = net.Loop()

-- server: echo whatever arrives straight back to its sender ------------
local server = net.UdpSocket(HOST, 0) -- ephemeral port
loop:add_fd(server:fd(), net.NET_RD, function()
    while true do                     -- drain everything the loop signalled
        local dg = server:recv(-1)    -- non-blocking: poll once
        if dg.timed_out then break end
        server:sendto(dg.data, dg.host, dg.port)
    end
end)

-- client: send the batch, print each echo, stop when the last is back --
local client = net.UdpSocket(HOST, 0)
local seen   = 0
loop:add_fd(client:fd(), net.NET_RD, function()
    while true do
        local dg = client:recv(-1)
        if dg.timed_out then break end
        seen = seen + 1
        print(("echo %d/%d from %s:%d  %q")
            :format(seen, #MESSAGES, dg.host, dg.port, dg.data))
        if seen == #MESSAGES then loop:stop() end
    end
end)

local server_port = server:local_port()
print(("client :%d  ->  server :%d"):format(client:local_port(), server_port))
for _, m in ipairs(MESSAGES) do
    client:sendto(m, HOST, server_port)
end

-- safety net: never run forever if a datagram goes missing ------------
loop:after(2000, function()
    if seen < #MESSAGES then
        print(("timeout: only %d/%d echoes received"):format(seen, #MESSAGES))
    end
    loop:stop()
end)

loop:run()

os.exit(seen == #MESSAGES and 0 or 1)
