#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [TX_MODE=loop|sync] [TX_N=200000] \
--     [TX_SIZE=300] [TX_BURST=1000] lua udp_tx_bench.lua
--
-- What one net.Loop can put on the wire, with and without the loop-driven
-- send path — the send side of the load generators in this directory
-- (ims_test_s5.lua, pgw_stub.lua), isolated from any core.
--
-- TX_N datagrams of TX_SIZE bytes go from one UDP socket to a sink socket on
-- loopback, produced TX_BURST at a time from a loop iteration (a stand-in for
-- the burst a handler emits: N subscribers answered, N sessions opened). The
-- sink drains on the same loop, so nothing is measuring an artificially empty
-- socket buffer.
--
--   TX_MODE=loop  (default) sock:tx_loop(loop): a sendto() copies the datagram
--                 into the socket's queue and returns; the loop pushes the
--                 queue out at the top of the next iteration with sendmmsg(),
--                 up to net.NET_TXQ_BATCH datagrams per syscall. A full send
--                 buffer suspends the queue (NET_WR) instead of failing.
--   TX_MODE=sync  the direct path: one sendto(2) per datagram, on the caller's
--                 stack, and a full send buffer raises — which the producer
--                 here has to catch and retry, as a caller must.
--
-- Reported: datagrams/s offered by the producer, how much of that wall time was
-- spent inside the send calls themselves (the cost the caller pays before it
-- can do anything else — the thing queueing removes), the send syscalls it took
-- (sendmmsg batches vs one sendto each), and how much the kernel pushed back.
-- Datagrams lost inside loopback (a full sink) are counted, not hidden: this
-- measures the send path, and a receiver that cannot keep up is a property of
-- the sink, not of the sender.

local net = require("net")

local MODE  = os.getenv("TX_MODE") or "loop"
local QUEUE = MODE ~= "sync"
local N     = tonumber(os.getenv("TX_N")     or "200000")
local SIZE  = tonumber(os.getenv("TX_SIZE")  or "300")
local BURST = tonumber(os.getenv("TX_BURST") or "1000")

local payload = string.rep("x", SIZE)

local function line(k, v) print(("   %-26s %s"):format(k, v)) end

local loop = net.Loop()
local sink = net.UdpSocket("127.0.0.1", 0)
local tx   = net.UdpSocket("127.0.0.1", 0)
tx:connect("127.0.0.1", sink:local_port())          -- fixed peer: no per-send address
if QUEUE then tx:tx_loop(loop) end

-- Drain the sink on the loop so the producer is not measured against a socket
-- buffer nobody empties.
local rx = 0
loop:add_fd(sink:fd(), net.NET_RD, function()
    while true do
        local dg = sink:recv(-1)
        if dg.timed_out then return end
        rx = rx + 1
    end
end)

-- The producer: BURST datagrams per loop iteration until N are offered. In
-- queued mode every send is a memcpy into the queue; in sync mode every send
-- is a syscall that can fail on a full buffer, so it is retried next round.
local offered, sync_calls, sync_blocked, pending = 0, 0, 0, nil
local send_ms = 0            -- wall time spent inside the send calls
local t0, t_done
local function produce()
    local n = 0
    local s0 = net.now_ms()
    while offered < N and n < BURST do
        if QUEUE then
            tx:send(payload)
        else
            sync_calls = sync_calls + 1
            if not pcall(function() tx:send(payload) end) then
                sync_blocked = sync_blocked + 1
                break                     -- buffer full: come back next round
            end
        end
        offered = offered + 1
        n = n + 1
    end
    send_ms = send_ms + (net.now_ms() - s0)
    if offered >= N then
        t_done = net.now_ms()
        -- let the sink catch up, then stop
        loop:after(300, function() loop:stop() end)
        return
    end
    pending = loop:after(0, produce)
end

print(("\n== UDP TX bench: %d datagram(s) x %dB, %d per loop iteration, TX_MODE=%s")
    :format(N, SIZE, BURST, MODE))
t0 = net.now_ms()
produce()
loop:run()

local secs = math.max((t_done or net.now_ms()) - t0, 1) / 1000
local calls, blocked, dropped
if QUEUE then
    tx:tx_flush()
    calls, blocked, dropped = tx:tx_calls(), tx:tx_blocked(), tx:tx_dropped()
else
    calls, blocked, dropped = sync_calls, sync_blocked, 0
end

line("offered",      ("%d datagram(s) in %.3fs  ->  %.0f/s"):format(offered, secs, offered / secs))
line("in the send calls", ("%dms of %dms (%.0f%% of the caller's time)")
    :format(send_ms, secs * 1000, 100 * send_ms / (secs * 1000)))
line("send syscalls", ("%d  ->  %.1f datagram(s) per call"):format(calls, offered / math.max(calls, 1)))
line("kernel push-back", tostring(blocked))
line("dropped by the queue", tostring(dropped))
line("received by the sink", ("%d (%.1f%% — loopback sink capacity)")
    :format(rx, 100 * rx / math.max(offered, 1)))
