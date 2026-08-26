-- ims/sipio.lua — a UE's SIP socket: what leaves it, and what arrives.
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
        b:header(sip.H_ROUTE, ("<sip:orig@%s:%d;lr>")
            :format(sub.pcscf, O.pcscf_port(sub, "mo")))
        for _, r in ipairs(sub.svc_route or {}) do b:header(sip.H_ROUTE, r) end
        return b
    end

    -- Send to this subscriber's P-CSCF, in the given role. `what` names the
    -- message in the trace; `note` is the detail that belongs to it ("over
    -- ESP", "direct") and is printed ahead of the size.
    local function tx(sub, host, port, wire, what, note)
        log.dump(("[%d] -> %s"):format(sub.i, what), wire)
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

    return O
end

return M
