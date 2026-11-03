-- ims/sipio.lua — a UE's SIP socket: what leaves it, and what arrives. UDP,
-- plus a TCP listener on the same port for what the P-CSCF sends over TCP.
--
-- One place for the three things every phase does with the wire — pick the
-- P-CSCF port the message belongs to, send it and count it, drain the socket
-- and parse what came in — so that the packet counters, the trace and the
-- IMS_DUMP transcript describe every phase the same way. Which is the point:
-- a run whose SMS phase counts its datagrams differently from its call phase
-- cannot be read as one measurement.
--
-- new() takes the run's counter table and updates {tx, rx, pkt_last} on it.

local net = require("net")
local sip = require("sip")
local cfg = require("ims.cfg")
local log = require("ims.log")
local wire = require("ims.wire")

local M = {}

function M.new(stats)
    local O = {}
    local now = net.now_ms

    -- The MO always talks from its protected client port to the P-CSCF's
    -- protected SERVER port (the pair the outbound ESP policy covers, and the
    -- one usrloc has for the contact). The MT answers from that same port to
    -- the P-CSCF's protected CLIENT port — the reverse tunnel the P-CSCF's
    -- ipsec_forward() delivers terminating requests through. Before the SAs are
    -- up, and against a core with ipsec off, both are the unprotected port.
    function O.pcscf_port(sub, role)
        local ch = sub.ch
        if not (ch and ch.ss_raw) then return cfg.pcscf_port end
        if role == "mt" then return ch.p_port_c or cfg.pcscf_port end
        return ch.p_port_s or cfg.pcscf_port
    end

    -- The preloaded Route of an ORIGINATING request (TS 24.229 §5.1.2A.1): the
    -- P-CSCF's own URI — at its protected server port, since IPsec is in use —
    -- followed by the Service-Route values the 200 OK returned, in order.
    --
    -- The `orig` user on that first entry is what makes the P-CSCF take its
    -- originating path, and it is easy to get wrong: loose_route() strips the
    -- topmost Route when it names the P-CSCF itself, and the classification
    -- (proxy.cfg:101) then reads the URI that was *stripped* — not the one left
    -- behind. So the marking has to be on the P-CSCF's own entry: a request
    -- carrying the Service-Route alone, or a bare <sip:pcscf:port;lr>, leaves
    -- nothing to match and takes the *terminating* path, which fails looking
    -- exactly like a routing bug in the core. Normally the P-CSCF supplies this
    -- entry itself by prepending its own Service-Route value
    -- (pcscf_force_service_routes, commented out in this stack), so the UE
    -- synthesises it from the P-CSCF address it was given.
    function O.preload_route(b, sub)
        b:header(sip.H_ROUTE, ("<sip:orig@%s;lr>")
            :format(wire.hostport(sub.pcscf, O.pcscf_port(sub, "mo"))))
        for _, r in ipairs(sub.svc_route or {}) do b:header(sip.H_ROUTE, r) end
        return b
    end

    -- The connection a response goes back on: the one its request came in
    -- over, found by the top Via's branch (RFC 3261 §18.2.2 — a response to a
    -- request received over a stream goes over that same connection). nil for
    -- a request, and for a response to a request that came over UDP.
    local function tcp_conn_for(sub, wire)
        local t = sub.tcp
        if not (t and next(t.by_branch)) or wire:sub(1, 8) ~= "SIP/2.0 " then return nil end
        local br = wire:match("\r\n[Vv][Ii][Aa]%s*:[^\r\n]-;%s*branch=([^;,%s]+)")
            or wire:match("\r\n[Vv]%s*:[^\r\n]-;%s*branch=([^;,%s]+)")
        return br and t.by_branch[br]
    end

    -- Send to this subscriber's P-CSCF, in the given role. `what` names the
    -- message in the trace; `note` is the detail that belongs to it ("over
    -- ESP", "direct") and is printed ahead of the size.
    local function tx(sub, host, port, wire, what, note)
        log.dump(("[%d] -> %s"):format(sub.i, what), wire)
        local c = tcp_conn_for(sub, wire)
        if c then
            local ok, err = pcall(function() c.conn:send(wire, 1000) end)
            if ok then
                stats.tx = stats.tx + 1
                stats.pkt_last = now()
                if cfg.verbose then
                    log.slog(sub, "-> " .. what, ("%sover TCP, %dB -> %s:%d")
                        :format(note and (note .. ", ") or "", #wire, c.host, c.port))
                end
                return true
            end
            -- The connection is gone. RFC 3261 §18.2.2 would open a new one to
            -- the Via's sent-by; the P-CSCF matches a response by branch, not
            -- by transport, so the protected UDP port gets it there just as well.
            log.slog(sub, "-> " .. what, "TCP send failed (" .. log.why(err) .. "), over UDP")
        end
        local ok, err = pcall(function() sub.sock:sendto(wire, host, port) end)
        if ok then
            stats.tx = stats.tx + 1
            stats.pkt_last = now()
            if cfg.verbose then
                log.slog(sub, "-> " .. what, ("%s%dB -> %s:%d")
                    :format(note and (note .. ", ") or "", #wire, host, port))
            end
        else
            log.slog(sub, "-> " .. what, "send failed: " .. log.why(err))
            return false, log.why(err)
        end
        return true
    end

    function O.send(sub, role, wire, what, note)
        return tx(sub, sub.pcscf, O.pcscf_port(sub, role), wire, what, note)
    end

    -- Straight to a named host, for the one case that bypasses the core: an
    -- SMS submitted directly to the IP-SM-GW (SMS_DIRECT=1).
    function O.send_to(sub, host, port, wire, what, note)
        return tx(sub, host, port, wire, what, note)
    end

    -- Drain everything readable, parse it, and hand each message to `on_msg`.
    -- Draining to empty rather than reading one datagram per readiness event is
    -- what keeps a burst of N subscribers' responses from taking N loop
    -- iterations each.
    function O.drain(sub, sock, on_msg)
        while true do
            local dg = sock:recv(-1)
            if dg.timed_out then return end
            stats.rx = stats.rx + 1
            stats.pkt_last = now()
            local ok, m = pcall(sip.parse, dg.data)
            if not ok then
                log.slog(sub, "SIP", "ignoring unparseable datagram")
            else
                log.dump(("[%d] <- %s"):format(sub.i, m.request and "request" or "response"), dg.data)
                on_msg(sub, m, dg)
            end
        end
    end

    -- ---- SIP over TCP (RFC 3261 §18) ----
    --
    -- A request over 1300 bytes leaves the P-CSCF over TCP (RFC 3261 §18.1.1,
    -- TS 24.229 §4.2A) — a reg-event NOTIFY, an MT INVITE with a full SDP. It
    -- connects from its protected client port to the UE's protected port, the
    -- same pair as the UDP it would otherwise have used, so the listener sits on
    -- the UDP socket's address and port and the ESP policies (any protocol)
    -- cover both. The UE never dials out: its own requests are small and go
    -- over UDP. Everything that arrives on a connection is handed to on_msg
    -- exactly as a datagram is, with dg.conn set.

    -- One message off the front of a stream buffer: the header block up to the
    -- blank line, then Content-Length bytes of body (RFC 3261 §18.3 makes the
    -- header mandatory on a stream; a missing one reads as no body). Leading
    -- CRLFs are keep-alives (RFC 5626 §3.5.1) and are dropped. Returns the
    -- message and the rest, or nil and the buffer while the message is short.
    local function frame(buf)
        buf = buf:sub(buf:match("^[\r\n]*()"))
        local he = buf:find("\r\n\r\n", 1, true)
        if not he then return nil, buf end
        local head = buf:sub(1, he + 1)
        local cl = head:match("\r\n[Cc][Oo][Nn][Tt][Ee][Nn][Tt]%-[Ll][Ee][Nn][Gg][Tt][Hh]%s*:%s*(%d+)")
            or head:match("\r\n[Ll]%s*:%s*(%d+)")
        local total = he + 3 + (tonumber(cl) or 0)
        if #buf < total then return nil, buf end
        return buf:sub(1, total), buf:sub(total + 1)
    end

    local function drop_conn(sub, loop, c, why)
        local t = sub.tcp
        if not (t and t.conns[c.fd]) then return end
        t.conns[c.fd] = nil
        for br, cc in pairs(t.by_branch) do
            if cc == c then t.by_branch[br] = nil end
        end
        pcall(function() loop:del_fd(c.fd) end)
        pcall(function() c.conn:close() end)
        log.slog(sub, "SIP over TCP", ("%s:%d closed (%s)"):format(c.host, c.port, why))
    end

    local function read_conn(sub, loop, c, on_msg)
        local eof
        while true do
            local ok, sd = pcall(function() return c.conn:recv(-1) end)
            if not ok then eof = log.why(sd) break end
            if sd.closed then eof = "by the peer" break end
            if sd.timed_out then break end
            c.buf = c.buf .. sd.data
        end
        while true do
            local msg
            msg, c.buf = frame(c.buf)
            if not msg then break end
            stats.rx = stats.rx + 1
            stats.pkt_last = now()
            local ok, m = pcall(sip.parse, msg)
            if not ok then
                log.slog(sub, "SIP", "ignoring unparseable message over TCP")
            else
                log.dump(("[%d] <- %s (TCP)"):format(sub.i, m.request and "request" or "response"), msg)
                if m.request then
                    local br = m:header("Via"):match(";%s*branch=([^;,%s]+)")
                    if br then sub.tcp.by_branch[br] = c end
                end
                on_msg(sub, m, { data = msg, host = c.host, port = c.port, conn = c.conn })
            end
        end
        if eof then drop_conn(sub, loop, c, eof) end
    end

    -- Listen on the UE's protected port. Best-effort, like the transparent UDP
    -- bind: an address this host cannot bind (no datapath to put the PAA on lo)
    -- leaves the UE UDP-only, and says so.
    function O.listen(sub, loop, on_msg)
        O.close_stream(sub, loop)
        local ok, lst = pcall(function() return net.StreamListener(sub.ue_addr, sub.port_uc) end)
        if not ok then
            log.slog(sub, "UE SIP over TCP", ("no listener on %s (%s): UDP only")
                :format(wire.hostport(sub.ue_addr, sub.port_uc), log.why(lst)))
            return false
        end
        local t = { lst = lst, conns = {}, by_branch = {} }
        sub.tcp = t
        loop:add_fd(lst:fd(), net.NET_RD, function()
            while true do
                local aok, conn = pcall(function() return lst:accept(-1) end)
                if not (aok and conn) then return end
                local c = { conn = conn, fd = conn:fd(), buf = "",
                            host = conn:peer_host(), port = conn:peer_port() }
                t.conns[c.fd] = c
                log.slog(sub, "SIP over TCP", ("accepted %s"):format(wire.hostport(c.host, c.port)))
                loop:add_fd(c.fd, net.NET_RD, function() read_conn(sub, loop, c, on_msg) end)
            end
        end)
        log.slog(sub, "UE SIP over TCP", ("listening on %s"):format(wire.hostport(sub.ue_addr, sub.port_uc)))
        return true
    end

    function O.close_stream(sub, loop)
        local t = sub.tcp
        if not t then return end
        for _, c in pairs(t.conns) do drop_conn(sub, loop, c, "teardown") end
        pcall(function() loop:del_fd(t.lst:fd()) end)
        pcall(function() t.lst:close() end)
        sub.tcp = nil
    end

    return O
end

return M
