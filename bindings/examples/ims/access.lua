-- ims/access.lua — the S5/S8 access: a GTPv2-C Create Session per subscriber,
-- the eBPF GTP-U datapath, and the bearer steering that puts a UE's SIP and
-- RTP on it.
--
-- Acting as the SGW it sends a GTPv2-C Create Session per subscriber
-- (gtp.Endpoint), whose response carries the UE's address in the PAA and the
-- P-CSCF's in the PCO (TS 24.008 container 0x000C), and whose bearers are
-- steered by the eBPF GTP-U datapath. With CAP_BPF + CAP_NET_ADMIN and an eBPF
-- build the datapath is loaded once and shared; set $GTPU_IFACE (the S5/S8-U
-- interface) and $GTPU_INNER_IFACE (the access side) to attach the TC programs.
--
-- Each subscriber's SIP rides its default bearer, steered by two TFTs (UDP:5060
-- for the plain REGISTER, ESP for the protected one). Both filters carry the
-- UE's own PAA as the inner-source match, so several subscribers registering to
-- the ONE P-CSCF stay on their own bearers — without the source key their ESP
-- filters (proto 50, no ports, same P-CSCF dst) would collide. The 401/200
-- return down the same bearer's decap entry and the kernel decrypts the
-- protected ones. Media gets two more TFTs per UE (RTP and RTCP toward
-- rtpengine), programmed per call at answer time (see M.media below) and homed
-- on the dedicated bearer the Create Bearer Request brings, falling back to the
-- default bearer and re-homing if the bearer arrives later.
--
-- Two more pieces of plumbing belong here and to nothing else: the UE's PAA is
-- added to `lo` so the decapped downlink reaches the transparent UE socket
-- (see attach), and a /32 route toward the P-CSCF carries the MTU that GTP-U
-- actually leaves available (see set_pcscf_mtu) — the two halves of the size
-- budget a tunnel imposes, each documented where it is installed.
--
-- Installing the datapath, the transparent UE socket, the PAA route and the
-- media filters all need CAP_NET_ADMIN; each kernel op degrades to a reported
-- line when refused.
--
-- new(o) takes
--   o.loop, o.io, o.stats, o.subs  -- the run's shared loop, sipio, counters
--                                     (stats.sess/sess_last) and subscriber list
--                                     (empty; attach_burst() fills it)
--   o.flow          the regflow instance: arm()/disarm() are reused for the
--                   settle delay below, so a subscriber has exactly one
--                   outstanding timer whoever owns it at the moment
--   o.dispatch      the SIP message handler, wired onto every UE socket
--   o.on_ready      a fresh subscriber is attached and ready for its first
--                   REGISTER — normally flow.first_register
--   o.on_fail       Create Session was rejected, timed out, or answered with
--                   no P-CSCF/UE address — normally flow.fail
--   o.media_bearer  "auto" (the dedicated bearer once one exists) or "default"
--                   — ims/call_phase.lua's MEDIA_BEARER, read by the caller so
--                   this module does not have to know that module exists
--   o.rtcp_bearer   "media" or "default" — ims/call_phase.lua's
--                   MEDIA_RTCP_BEARER, for the same reason
--
-- returns A with
--   A.subs                the subscriber list (== o.subs, filled by attach_burst)
--   A.media.program(sub, addr, port)  the media-TFT hook ims/call_phase.lua calls
--   A.report_rx(sub, what) a downlink reply came back down this bearer's decap
--                          entry — regflow's on_response hook
--   A.attach_burst()      fire every subscriber's Create Session Request
--   A.teardown()           Delete Session every established PDN connection
--   A.collect_dp()          read the datapath counters (before anything is torn
--                            down) and A.dp_report() print what they said
--   A.tx_stats()            the endpoint's own send-side counters
--   A.cleanup()              release everything this module installed in the
--                            kernel: media filters, the PAA route, the P-CSCF
--                            MTU route (flow.release_sas/close_sockets are the
--                            caller's own, separate cleanup)

local net = require("net")
local gtp = require("gtp")
local cfg = require("ims.cfg")
local log = require("ims.log")
local ue    = require("ims.ue")

local M = {}

-- GTP-C retransmission (TS 29.274 §7.6): 1s T3-RESPONSE, up to 3 sends. The 1s
-- default is more aggressive than the spec's 3s, which shows at scale — a
-- 1000-wide Create Session burst queues behind a single-threaded PGW/SMF, so a
-- request can still be in progress when T3 fires and the retransmission reaches
-- a transaction the PGW considers open (open5gs logs
-- `ogs_gtp_xact_update_rx() failed`). Raise GTP_T3_MS to give the PGW the full
-- T3-RESPONSE window.
M.t3_ms = cfg.num("GTP_T3_MS", 1000)
M.n3    = cfg.num("GTP_N3", 3)

M.pgw_host     = cfg.str("PGW_IP", "smf")          -- a name or a literal IP
M.sgw_ip       = cfg.str("SGW_IP", "0.0.0.0")       -- auto-derived from GTPU_IFACE when unset
M.apn          = cfg.str("IMS_APN", "ims")
M.gtpu_ifname  = cfg.str("GTPU_IFACE", "eth0")       -- the S5/S8-U interface
M.inner_ifname = cfg.str("GTPU_INNER_IFACE", "eth0") -- the access side
-- The MTU put on the route toward the P-CSCF: 1500 less the 36 bytes of GTP-U
-- the datapath adds. See set_pcscf_mtu; 0 leaves routing untouched.
M.inner_mtu    = cfg.num("GTPU_INNER_MTU", 1464)

-- Per-subscriber S5/S8-U TEIDs (default + dedicated), spaced by index like the
-- protected ports and SPIs in ims/cfg.lua. The stride is 0x10, so a second and
-- third dedicated bearer stay inside this subscriber's range.
local S5_UP_TEID_BASE = 0x200
-- The EBI we assign the dedicated (media) bearer when the network asks for one,
-- and quote back when it asks us to delete it.
local DED_EBI = 6

-- Resolve a host name to an IPv4 literal via the net module's own resolver (a
-- dotted quad passes through unchanged). No external tools.
local function resolve(name)
    local ok, res = pcall(function() return net.Resolver():resolve4(name) end)
    assert(ok, ("cannot resolve PGW host name %q: %s"):format(name, log.why(res)))
    return res
end

-- ---- the uplink size budget: the route MTU toward the P-CSCF ----
--
-- The other half of the sum the downlink size budget in ims/call_phase.lua
-- describes, seen from this end. A UE's signalling rides transport-mode ESP
-- to the P-CSCF and the datapath then adds 36 bytes of GTP-U at TC egress —
-- where nothing can fragment, because a TC program cannot split a packet. So
-- a datagram that fits the 1500-byte link before encapsulation and not after
-- is dropped there, and the only trace of it is one number in this run's own
-- summary ("datapath drops ... no neighbour 2").
--
-- It lands on exactly one message: the 200 OK answering an MT INVITE, which
-- carries the SDP answer plus the dialog's whole route set — 5 Record-Route
-- and 6 Via, since a call between two subscribers of one core crosses
-- P-CSCF -> S-CSCF -> I-CSCF -> S-CSCF -> P-CSCF — so ~1470 bytes of SIP,
-- 1513 with UDP and the ESP overhead, 1549 encapsulated. The MO gets its 180
-- and then nothing, and the call is reported as failed after ringing with the
-- answer never on the wire.
--
-- The fix is to make the kernel fragment *before* the hook: the route to the
-- P-CSCF carries the MTU that is actually available, so the ESP datagram
-- leaves as two G-PDUs that both fit and the P-CSCF reassembles them. Only
-- that route is touched — the interface MTU has to stay 1500, since the
-- encapsulated packets themselves go out at up to that size.
--
-- One /32 per P-CSCF, installed once and removed at teardown (the less
-- specific route it shadows is left in place). The dev is $GTPU_INNER_IFACE,
-- not $GTPU_IFACE: encap attaches to the *inner* interface's TC egress
-- (gtpu_ebpf_attach), so that is the path a UE packet has to take to be
-- encapsulated at all, and the only one whose MTU decides whether it
-- survives. The two are the same interface on a single-NIC deployment. Only
-- with the datapath up: without GTP-U there is no encapsulation to make room
-- for and the interface MTU is already the truth.

-- The nexthop for that /32. A route with no gateway is an *on-link* route: it
-- tells the kernel to resolve the destination itself, with ARP, on that link.
-- True on a shared L2 -- a docker bridge, where every container in the compose
-- network answers for its own address -- and false under a CNI that gives each
-- pod a point-to-point veth. KinD's kindnet uses the `ptp` plugin, which
-- deletes the connected route for the pod subnet and leaves the pod holding
-- nothing but
--
--     10.244.0.1 dev eth0 scope link
--     default via 10.244.0.1 dev eth0
--
-- so a /32 `dev eth0` toward the P-CSCF has the kernel ARP for an address that
-- lives in another netns behind the node. Nothing answers -- the node does not
-- proxy-ARP -- the neighbour stays INCOMPLETE and the datagram is dropped in
-- neigh_resolve_output, which is *before* dev_queue_xmit and so before TC
-- egress: gtpu_encap never runs on it. The run then reports "rx 0 pkt, tx 0
-- pkt" with every datapath error counter at zero and every REGISTER timed
-- out, which reads as a dead datapath and is a dead route.
--
-- So keep the nexthop the kernel would have picked itself: a longest-prefix
-- match over the device's routes, which is on-link (nil) on a bridge and the
-- default gateway under ptp. Host routes are skipped -- a /32 is never
-- evidence of a link, and one of them is this route as an earlier run of this
-- function left it.
local function nexthop_toward(dst, dev)
    local f = io.open("/proc/net/route")
    if not f then return nil end
    -- The address fields are little-endian hex, so 10.244.0.1 reads
    -- "0100F40A". Everything below stays in that byte order.
    local function le(s)
        local b = {}
        for i = 1, 4 do b[i] = tonumber(s:sub(i * 2 - 1, i * 2), 16) end
        return b
    end
    local a, b, c, e = dst:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then f:close() return nil end
    local d = { tonumber(e), tonumber(c), tonumber(b), tonumber(a) }
    -- Lua 5.1 has no bitwise operators, so the mask is applied and its width
    -- counted a byte at a time -- all a prefix match needs.
    local function band(x, y)
        local r, bit = 0, 1
        for _ = 1, 8 do
            if x % 2 == 1 and y % 2 == 1 then r = r + bit end
            x, y, bit = math.floor(x / 2), math.floor(y / 2), bit * 2
        end
        return r
    end
    local function bits(x)
        local n = 0
        while x > 0 do n, x = n + x % 2, math.floor(x / 2) end
        return n
    end
    -- Longest prefix wins; on a tie the first line does, and the kernel lists
    -- the main table by prefix then metric, so that is the cheapest.
    local best, best_len = nil, -1
    local hex8 = "(%x%x%x%x%x%x%x%x)"
    for l in f:lines() do
        local iface, rdst, rgw, rmask = l:match("^(%S+)%s+" .. hex8 ..
            "%s+" .. hex8 .. "%s+%x+%s+%S+%s+%S+%s+%S+%s+" .. hex8)
        if iface == dev then
            local m, rd, g = le(rmask), le(rdst), le(rgw)
            local len, covers = 0, true
            for j = 1, 4 do
                len = len + bits(m[j])
                if band(d[j], m[j]) ~= band(rd[j], m[j]) then covers = false end
            end
            if covers and len < 32 and len > best_len then
                best_len = len
                best     = g[1] + g[2] + g[3] + g[4] > 0
                    and ("%d.%d.%d.%d"):format(g[4], g[3], g[2], g[1]) or nil
            end
        end
    end
    f:close()
    return best
end

function M.new(o)
    local loop, io_, stats, subs = o.loop, o.io, o.stats, o.subs
    local flow = o.flow
    local dispatch, on_ready, on_fail = o.dispatch, o.on_ready, o.on_fail
    local now = net.now_ms
    local T3_MS, N3 = M.t3_ms, M.n3

    -- Fill the SGW address from the GTP-U interface when left at any-address;
    -- 0.0.0.0 gives an invalid outer source and F-TEID address.
    local sgw_ip, sgw_auto = M.sgw_ip, false
    if sgw_ip == "0.0.0.0" then
        local ip = net.if_addr4(M.gtpu_ifname)
        if ip ~= "" then sgw_ip, sgw_auto = ip, true end
    end
    local pgw_ip = resolve(M.pgw_host)

    log.banner(("GTPv2-C — %d subscriber(s) over S5/S8: SGW %s -> PGW %s")
        :format(cfg.nsubs, sgw_ip, pgw_ip))
    if sgw_auto then log.line("SGW address", ("%s (auto from %s)"):format(sgw_ip, M.gtpu_ifname)) end
    if pgw_ip ~= M.pgw_host then log.line("PGW address", ("%s -> %s"):format(M.pgw_host, pgw_ip)) end

    local ok, ep = pcall(gtp.Endpoint, loop, sgw_ip)     -- binds sgw_ip:2123 (GTP-C)
    if not ok then
        io.stderr:write(("cannot bind GTP-C on %s:2123: %s\n"):format(sgw_ip, log.why(ep)))
        os.exit(1)
    end
    ep:set_t3_ms(T3_MS)
    ep:set_n3(N3)
    ep:set_tx_loop(true)

    -- ---- shared GTP-U datapath (loaded once) ----
    local up
    if gtp.UserPlane.supported() then
        local gi = net.if_index(M.gtpu_ifname)
        local ii = net.if_index(M.inner_ifname)
        local dcfg = gtp.UserPlaneConfig()
        dcfg.pin_dir        = ""        -- a fresh datapath each run
        dcfg.local_v4       = sgw_ip    -- outer source for encapsulated uplink
        dcfg.uplink_ifindex = gi
        local made, obj = pcall(gtp.UserPlane, dcfg)
        if made then
            up = obj
            if gi ~= 0 or ii ~= 0 then
                local aok, aerr = pcall(function() up:attach(gi, ii) end)
                log.line("GTP-U datapath", aok
                    and ("attached (gtpu=%s inner=%s)"):format(gi ~= 0 and M.gtpu_ifname or "-", M.inner_ifname)
                    or  ("attach failed: " .. log.why(aerr)))
            else
                log.line("GTP-U datapath", "loaded (set GTPU_IFACE/GTPU_INNER_IFACE to attach TC)")
            end
        else
            log.line("GTP-U datapath", "unavailable (" .. log.why(obj) .. ")")
        end
    else
        log.line("GTP-U datapath", "unsupported (non-eBPF build or missing CAP_BPF/CAP_NET_ADMIN)")
    end

    local by_imsi, by_teid = {}, {}
    local mtu_routes, mtu_tried = {}, {}
    local dpending, tguard = 0, nil     -- outstanding Delete Session txns (teardown)
    local dp = nil                      -- datapath counters, cached by collect_dp()

    -- ---- steering the access ----

    -- Steer a subscriber's SIP onto its default bearer with two TFTs (UDP for
    -- the plain REGISTER, ESP for the protected one). ue_saddr = the UE's PAA is
    -- the inner-source match that keeps concurrent subscribers registering to
    -- the one P-CSCF on their own bearers; add_filter also installs the shared
    -- decap entry so the 401/200 return down this bearer.
    local function program_filter(sub, tun)
        sub.sig_teid    = tun.local_teid
        sub.remote_addr = tun.remote_addr
        -- Kept whole, not just the TEID: media filters need the same bearer
        -- fields, and this is the fallback when no dedicated bearer shows up.
        sub.def_bearer  = { ebi = tun.ebi, local_teid = tun.local_teid,
                            remote_teid = tun.remote_teid,
                            remote_addr = tun.remote_addr }
        if not up then return end
        if not (sub.pcscf and tun.remote_addr and tun.remote_addr ~= "") then
            log.slog(sub, "GTP-U filter", "not programmed (missing P-CSCF/peer address)")
            return
        end
        local function add_tft(proto, ue_port, label)
            local t = gtp.Tunnel()
            t.local_teid, t.remote_teid = tun.local_teid, tun.remote_teid
            t.ebi, t.ue_addr, t.remote_addr = tun.ebi, sub.pcscf, tun.remote_addr
            local f = gtp.TrafficFilter()
            f.tunnel, f.proto, f.ue_port = t, proto, ue_port
            f.ue_saddr = sub.ue_addr                 -- inner source = this UE (concurrency key)
            local pok, perr = pcall(function() up:add_filter(f) end)
            log.slog(sub, "GTP-U filter", pok
                and ("EBI %d %s  TEID %#x/%#x @ %s  proto %d src %s -> %s%s")
                    :format(tun.ebi, label, tun.local_teid, tun.remote_teid, tun.remote_addr,
                            proto, sub.ue_addr, sub.pcscf, ue_port > 0 and (":" .. ue_port) or "")
                or  ("EBI %d %s add_filter failed: %s"):format(tun.ebi, label, log.why(perr)))
        end
        add_tft(cfg.IPPROTO_UDP, cfg.pcscf_port, "SIP")  -- unprotected REGISTER
        add_tft(cfg.IPPROTO_ESP, 0,              "ESP")  -- protected traffic
    end

    -- Make the UE PAA locally deliverable (net.addr_add adds <PAA>/32 to lo,
    -- RTNETLINK) so the decapped downlink whose inner dst is the PAA reaches the
    -- transparent UE socket. Best-effort, only with the datapath up.
    local function add_paa_route(sub)
        if not (up and sub.ue_addr and sub.ue_addr:match("^%d+%.%d+%.%d+%.%d+$")) then return end
        local ok2, err = pcall(function() net.addr_add("lo", sub.ue_addr, 32) end)
        sub.paa_added = ok2
        log.slog(sub, "PAA local route", ok2
            and ("%s/32 dev lo"):format(sub.ue_addr)
            or  ("could not add %s/32 (need CAP_NET_ADMIN?): %s"):format(sub.ue_addr, log.why(err)))
    end

    -- The nexthop and the route itself: see the big comment block above this
    -- function's helper (nexthop_toward). Attempted (so a refusal is reported
    -- once, not once per subscriber) and installed (what cleanup() removes) are
    -- separate: 400 subscribers share one P-CSCF and one route.
    local function set_pcscf_mtu(sub)
        if not (up and M.inner_mtu > 0 and sub.pcscf) then return end
        if mtu_tried[sub.pcscf] then return end
        mtu_tried[sub.pcscf] = true
        local r = net.Route()
        r.dst, r.prefixlen, r.dev, r.mtu = sub.pcscf, 32, M.inner_ifname, M.inner_mtu
        local gw = nexthop_toward(sub.pcscf, M.inner_ifname)
        if gw then r.gateway = gw end
        local ok2, err = pcall(function() net.route_add(r) end)
        if ok2 then mtu_routes[sub.pcscf] = r end
        log.line("P-CSCF route MTU", ok2
            and ("%s/32 %sdev %s mtu %d (GTP-U leaves 1500-36)")
                :format(sub.pcscf, gw and ("via %s "):format(gw) or "", M.inner_ifname, M.inner_mtu)
            or  ("could not set %d toward %s (need CAP_NET_ADMIN?): %s — an answered call's 200 OK will not fit")
                :format(M.inner_mtu, sub.pcscf, log.why(err)))
    end

    -- Confirm a downlink reply arrived through the decap entry.
    local function report_rx(sub, what)
        if not (up and sub.sig_teid and sub.rx0) then return end
        local drx = up:stats(sub.sig_teid).rx_pkts - sub.rx0.rx_pkts
        if drx > 0 then
            log.slog(sub, "GTP-U decap", ("%s via downlink (rx +%d on TEID %#x)")
                :format(what, drx, sub.sig_teid))
        end
    end

    -- ---- media steering: TFTs learnt from the SDP, per call ----
    --
    -- Two per UE (RTP, and RTCP on the next port), each carrying the UE's own PAA
    -- as the inner-source match: that is what keeps many UEs talking to the ONE
    -- rtpengine on their own bearers, exactly as it does for the one P-CSCF.
    local function apply_media_tfts(sub, op, only)
        if not (up and sub.media_tft) then return end
        for _, t in ipairs(sub.media_tft.tuples) do
            local bearer = t.bearer
            if bearer and (only == nil or only == t.follows_media) then
                local tun = gtp.Tunnel()
                tun.local_teid, tun.remote_teid = bearer.local_teid, bearer.remote_teid
                tun.ebi, tun.ue_addr, tun.remote_addr = bearer.ebi, t.addr, bearer.remote_addr
                local f = gtp.TrafficFilter()
                f.tunnel, f.proto, f.ue_port = tun, t.proto, t.port
                f.ue_saddr = sub.ue_addr
                local pok, perr = pcall(function()
                    if op == "del" then up:del_filter(f) else up:add_filter(f) end
                end)
                -- A failed delete is expected and harmless: several filters share
                -- one bearer's decap entry, and removing the first takes that
                -- entry with it, so the rest have nothing left to unhook.
                if not pok and op ~= "del" and cfg.verbose then
                    log.slog(sub, "media filter", ("%s %s %s:%d failed: %s")
                        :format(op, t.label, t.addr, t.port, log.why(perr)))
                end
            end
        end
    end

    -- Which bearer media rides. "auto" (o.media_bearer) prefers the dedicated
    -- bearer the Create Bearer Request brought, since that is what the
    -- Rx->Gx->Create Bearer chain exists for; "default" forces the default
    -- bearer, which is worth having because a UPF whose dedicated-bearer uplink
    -- PDR carries an SDF filter that does not match our negotiated 5-tuple
    -- drops the uplink.
    local function media_bearer(sub)
        if o.media_bearer ~= "default" and sub.ded_bearer and not sub.ded_released then
            return sub.ded_bearer, "dedicated"
        end
        return sub.def_bearer, "default"
    end

    local function program_media_tfts(sub, addr, port)
        if not (up and addr and port and port > 0) then return end
        local bearer, kind = media_bearer(sub)
        if not bearer then return end
        local rtcp_on_media = o.rtcp_bearer == "media"
        local rtcp_bearer   = rtcp_on_media and bearer or sub.def_bearer
        sub.media_tft = { kind = kind, tuples = {
            { proto = cfg.IPPROTO_UDP, addr = addr, port = port, label = "RTP",
              bearer = bearer, follows_media = true },
            { proto = cfg.IPPROTO_UDP, addr = addr, port = port + 1, label = "RTCP",
              bearer = rtcp_bearer, follows_media = rtcp_on_media },
        } }
        apply_media_tfts(sub, "add")
        log.slog(sub, "media on bearer", ("%s (EBI %d, TEID %#x) -> %s:%d, RTCP on the %s bearer")
            :format(kind, bearer.ebi or 0, bearer.local_teid or 0, addr, port,
                    rtcp_on_media and kind or "default"))
    end

    -- The Create Bearer Request and the SDP answer race. If the bearer is known
    -- when the media 5-tuple is learnt, the filters go straight onto it;
    -- otherwise they went onto the default bearer and are re-homed here. Which
    -- bearer each call's media actually landed on is reported either way —
    -- "media on the default bearer" is a legitimate finding, not something to
    -- hide.
    local function rehome_media(sub)
        if not (up and sub.media_tft and sub.ded_bearer) then return end
        if o.media_bearer == "default" or sub.ded_released then return end
        local cur
        for _, t in ipairs(sub.media_tft.tuples) do
            if t.follows_media then cur = t.bearer break end
        end
        if not cur or cur.local_teid == sub.ded_bearer.local_teid then return end
        apply_media_tfts(sub, "del", true)
        for _, t in ipairs(sub.media_tft.tuples) do
            if t.follows_media then t.bearer = sub.ded_bearer end
        end
        sub.media_tft.kind = "dedicated (re-homed)"
        apply_media_tfts(sub, "add", true)
        log.slog(sub, "media re-homed", ("onto the dedicated bearer (EBI %d, TEID %#x)")
            :format(sub.ded_bearer.ebi or 0, sub.ded_bearer.local_teid or 0))
    end

    -- ---- registration: the access plumbing, then the exchange ----

    -- Make the PAA deliverable, give the route its tunnel MTU, prime the
    -- neighbour table and bind the transparent UE socket: everything a UE needs
    -- before its first REGISTER.
    local function attach(sub)
        add_paa_route(sub)
        set_pcscf_mtu(sub)

        -- encap resolves the outer L2 with bpf_fib_lookup (reads the neighbour
        -- table, never ARPs); a throwaway datagram warms the peer's entry.
        if sub.remote_addr then
            local prime = net.UdpSocket("0.0.0.0", 0)
            pcall(function() prime:sendto("x", sub.remote_addr, 2152) end)
            prime:close()
        end

        -- The REGISTER's inner source must be the PAA (not the SGW/outer source),
        -- so bind a non-local transparent socket (IP_FREEBIND + IP_TRANSPARENT)
        -- that also receives the 401/200 returned to the PAA. Needs
        -- CAP_NET_ADMIN; falls back to the SGW source (which the UPF drops as
        -- spoofed) when refused.
        local okb, s = pcall(function()
            return net.UdpSocket(sub.ue_addr, sub.port_uc, false, true)
        end)
        if okb then
            sub.sock = s
            log.slog(sub, "UE SIP socket", ("%s:%d (UE PAA, transparent)")
                :format(sub.ue_addr, sub.port_uc))
        else
            sub.sock = net.UdpSocket("0.0.0.0", 0)
            log.slog(sub, "UE SIP socket", ("SGW source (UE PAA bind refused: %s); no reply can return")
                :format(log.why(s)))
        end
        loop:add_fd(sub.sock:fd(), net.NET_RD, function()
            io_.drain(sub, sub.sock, dispatch)
        end)
        -- Put this UE's output on the loop (queue now, batched sendmmsg from the
        -- loop). NET_RD is the fd's steady-state interest above, which the queue
        -- restores after adding NET_WR to ride out a full send buffer.
        sub.sock:tx_loop(loop, net.NET_RD)

        -- No second socket: with one protected port in both roles (see
        -- ims/register.lua's security_client) the P-CSCF delivers terminating
        -- requests to this same port, so the MT INVITE, a NOTIFY and any BYE from
        -- the far end arrive here and the caller's dispatcher sorts them out.

        if up and sub.sig_teid then sub.rx0 = up:stats(sub.sig_teid) end
    end

    -- A fresh PDN connection: attach, then hand off to the exchange.
    local function begin_registration(sub)
        if not (sub.pcscf and sub.ue_addr) then
            return on_fail(sub, "no P-CSCF/UE address from Create Session")
        end
        attach(sub)
        on_ready(sub)
    end

    -- ---- teardown ----

    -- One Delete Session transaction resolved (response, timeout or send
    -- failure); when the last one settles, stop the loop.
    local function del_done(sub, ok2, note)
        if sub.deleted then return end
        sub.deleted, sub.del_ok = true, ok2 and true or false
        if note then log.slog(sub, "Delete Session", note) end
        dpending = dpending - 1
        if dpending <= 0 then
            if tguard then loop:cancel(tguard); tguard = nil end
            loop:stop()
        end
    end

    -- ---- GTP-C ----

    ep:set_handler({
        -- The PGW answered a Create Session: read the PAA and P-CSCF; kick off
        -- registration after on_user_plane has programmed the filters (it runs
        -- right after this handler), giving the primed neighbour time to resolve.
        on_create_session_response = function(sess, rsp)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            if rsp.cause ~= gtp.GTP2_CAUSE_REQUEST_ACCEPTED then
                return on_fail(sub, ("Create Session rejected, cause %d"):format(rsp.cause))
            end
            stats.sess = stats.sess + 1; stats.sess_last = now()
            sub.pgw_ctrl_teid = sess:remote_teid()
            if rsp.has_paa then sub.ue_addr = rsp.paa.addr4 end
            if rsp.pco and #rsp.pco > 0 then
                local p = gtp.pco_pcscf_v4(rsp.pco)
                sub.pcscf = p ~= "" and p or nil
            end
            if cfg.verbose then
                log.slog(sub, "<- Create Session Resp", ("PAA %s, P-CSCF %s")
                    :format(sub.ue_addr or "?", sub.pcscf or "none"))
            end
            flow.arm(sub, 200, function() begin_registration(sub) end)
        end,

        -- One per bearer F-TEID in the accepted response (the default bearer):
        -- steer the subscriber's uplink SIP onto it.
        on_user_plane = function(sess, tun)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            log.slog(sub, "user plane (S5/S8-U)", ("EBI %d  SGW TEID %#x -> PGW TEID %#x @ %s")
                :format(tun.ebi, tun.local_teid, tun.remote_teid, tun.remote_addr))
            program_filter(sub, tun)
        end,

        -- Network-initiated dedicated bearer (§7.2.3): accept it with a typed
        -- Create Bearer Response addressed to the subscriber's PGW control TEID
        -- (correlated by the request's header TEID = our control TEID). This is
        -- the media bearer the Rx->Gx->Create Bearer chain exists to build, so it
        -- is recorded and media is homed (or re-homed) onto it.
        on_create_bearer_request = function(req, host, port)
            local sub = by_teid[req.teid]
            local pgw_u
            if req.bearers:size() > 0 then
                local fts = req.bearers[0].fteids
                if fts:size() > 0 then pgw_u = fts[0].fteid end
            end
            -- A subscriber gets MORE than one of these: the PCRF installs a rule
            -- at registration and another for the call's actual media, so a second
            -- request arrives with its own PGW TEID and its own SDF. Each
            -- therefore needs its OWN EBI and UE-side TEID — answering both with
            -- EBI 6 and one TEID leaves us steering media onto the first bearer
            -- while the network runs the media rule on the second, which the UPF
            -- then rejects uplink ("Off-filter G-PDU") and delivers downlink on a
            -- TEID we have no decap entry for. The per-subscriber TEID stride is
            -- 0x10, so +n stays inside it.
            local n    = (sub and (sub.ded_n or 0) + 1) or 1
            local ebi  = DED_EBI + n - 1
            local teid = (sub and sub.ded_teid + n - 1) or (S5_UP_TEID_BASE - 1)
            local rbc = gtp.BearerContext()
            rbc.ebi, rbc.cause = ebi, gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            local u = gtp.Fteid()
            u.if_type, u.teid, u.addr4 = gtp.GTP2_IF_S5S8U_SGW, teid, sgw_ip
            rbc:add_fteid(2, u)
            if pgw_u then rbc:add_fteid(3, pgw_u) end

            local resp = gtp.CreateBearerResponse()
            resp.teid     = (sub and sub.pgw_ctrl_teid) or 0
            resp.sequence = req.sequence
            resp.cause    = gtp.GTP2_CAUSE_REQUEST_ACCEPTED
            resp.pti      = req.pti
            resp:add_bearer(rbc)
            ep:send_create_bearer_response(resp, host, port)
            if sub then
                sub.ded_n = n
                log.slog(sub, "<> Create Bearer", ("seq %d, EBI %d accepted (media #%d, TEID %#x)")
                    :format(req.sequence, ebi, n, teid))
                -- The newest dedicated bearer is the one the call's media rule
                -- lives on, so it becomes the media home; re-home anything already
                -- programmed elsewhere. The Create Bearer Request and the SDP
                -- answer race, and both orders have to work.
                sub.ded_bearer = {
                    ebi = ebi, local_teid = teid,
                    remote_teid = pgw_u and pgw_u.teid or 0,
                    remote_addr = (pgw_u and pgw_u.addr4 ~= "" and pgw_u.addr4)
                                  or sub.remote_addr,
                }
                rehome_media(sub)
            end
        end,

        -- A Delete Session Request was answered: this PDN connection is torn down.
        on_delete_session_response = function(sess, rsp)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            log.slog(sub, "<- Delete Session Resp", ("cause %d"):format(rsp.cause))
            del_done(sub, true)
        end,

        -- The other half of the dedicated bearer's life. When a call clears, the
        -- P-CSCF tears its Rx session down, the PCRF removes the PCC rule over Gx
        -- and the SMF sends us a Delete Bearer Request — which the endpoint has no
        -- typed message for, so it arrives here as raw bytes.
        --
        -- Answering it matters beyond tidiness: ignore it and the SMF retries,
        -- keeps the bearer half-removed and leaves the session in a state where
        -- the NEXT run's Create Session comes back with PDRs the UPF then rejects
        -- ("Send Error Indication"), so that run gets no downlink at all and every
        -- registration times out for no visible reason. One response per request
        -- costs nothing and keeps the stack clean between runs. Hand-encoded
        -- because a GTPv2 response with a Cause and a linked EBI is 20 bytes and
        -- the alternative is a typed message pair in the gtp facade for this one
        -- path.
        on_message = function(mt, wire_bytes, host, port)
            if #wire_bytes < 12 then return end
            local function be(s, i, n)      -- big-endian read, Lua 5.1 safe
                local v = 0
                for k = i, i + n - 1 do v = v * 256 + s:byte(k) end
                return v
            end
            if mt ~= gtp.GTP2_MT_DELETE_BEARER_REQUEST then return end
            local function u16(v) return string.char(math.floor(v / 256) % 256, v % 256) end
            local function u24(v)
                return string.char(math.floor(v / 65536) % 256,
                                   math.floor(v / 256) % 256, v % 256)
            end
            local function u32(v)
                return string.char(math.floor(v / 16777216) % 256,
                                   math.floor(v / 65536) % 256,
                                   math.floor(v / 256) % 256, v % 256)
            end
            -- The request's header TEID is our control TEID, exactly as the Create
            -- Bearer Request's is, so the same index correlates it.
            local sub = by_teid[be(wire_bytes, 5, 4)]
            local seq = be(wire_bytes, 9, 3)

            -- Walk the request's IEs: type(1) length(2) spare/instance(1) value.
            local function ies_of(body, from)
                local out, i = {}, from
                while i + 3 <= #body do
                    local len = be(body, i + 1, 2)
                    out[#out + 1] = { t = body:byte(i), inst = body:byte(i + 3) % 16,
                                      v = body:sub(i + 4, i + 3 + len) }
                    i = i + 4 + len
                end
                return out
            end
            -- Which bearers. TS 29.274 §7.2.9.2 has two top-level EBIs (73), told
            -- apart by instance. Instance 0 is the Linked EBI: the whole PDN
            -- connection goes away. Instance 1 is EPS Bearer IDs: only the
            -- bearers named go, and it is how open5gs removes a dedicated bearer
            -- when a call or a registration's Rx session ends. A Bearer Context
            -- (93) carrying an EBI names one bearer as well. The two need
            -- different answers. Quoting a linked EBI back when only one bearer
            -- was asked about tells the SMF the PDN connection is gone. The SMF
            -- rejects that response ("No Bearer", "No EPS Bearer ID"), and this
            -- run then skips its own Delete Session, leaking the session.
            local ebis, whole_pdn = {}, false
            for _, ie in ipairs(ies_of(wire_bytes, 13)) do
                if ie.t == 93 then
                    for _, inner in ipairs(ies_of(ie.v, 1)) do
                        if inner.t == 73 and #inner.v >= 1 then
                            ebis[#ebis + 1] = inner.v:byte(1) % 16
                        end
                    end
                elseif ie.t == 73 and ie.inst == 1 then
                    for k = 1, #ie.v do ebis[#ebis + 1] = ie.v:byte(k) % 16 end
                elseif ie.t == 73 then
                    whole_pdn = true
                end
            end

            local ies = string.char(2) .. u16(2) .. string.char(0) ..     -- Cause
                        string.char(gtp.GTP2_CAUSE_REQUEST_ACCEPTED, 0)
            for _, ebi in ipairs(ebis) do
                local inner = string.char(73) .. u16(1) .. string.char(0) ..
                              string.char(ebi) ..
                              string.char(2) .. u16(2) .. string.char(0) ..
                              string.char(gtp.GTP2_CAUSE_REQUEST_ACCEPTED, 0)
                ies = ies .. string.char(93) .. u16(#inner) .. string.char(0) .. inner
            end
            local rsp = string.char(0x48, gtp.GTP2_MT_DELETE_BEARER_RESPONSE) ..
                        u16(8 + #ies) .. u32((sub and sub.pgw_ctrl_teid) or 0) ..
                        u24(seq) .. string.char(0) .. ies
            local ok2, err = pcall(function() ep:send_raw(rsp, host, port) end)
            if sub then
                -- The bearer is gone, so media must not stay steered onto it; the
                -- default bearer is always there to fall back to.
                if sub.ded_bearer then
                    for _, e in ipairs(ebis) do
                        if e == sub.ded_bearer.ebi then sub.ded_released = true end
                    end
                end
                if whole_pdn then sub.pdn_gone = true end
                log.slog(sub, "<> Delete Bearer", ok2
                    and ("seq %d, %s released"):format(seq, whole_pdn and "PDN connection"
                         or ("EBI " .. table.concat(ebis, ",")))
                    or  ("seq %d, response failed: %s"):format(seq, log.why(err)))
            end
        end,

        on_timeout = function(sess, mt)
            local sub = by_imsi[sess:imsi()]
            if not sub then return end
            if mt == gtp.GTP2_MT_DELETE_SESSION_REQUEST then
                del_done(sub, false, ("no Delete Session response (%d sends)"):format(N3))
            else
                on_fail(sub, ("PGW did not answer message type %d (after %d sends)")
                    :format(mt, N3))
            end
        end,
    })

    local A = {}
    A.subs = subs
    A.media = { program = program_media_tfts }
    A.report_rx = report_rx

    -- ---- the attach burst ----
    --
    -- Fire off every subscriber's Create Session Request up front; the endpoint
    -- multiplexes the transactions and the callbacks drive each to registration
    -- on the one loop.
    function A.attach_burst()
        log.banner("Create Session Requests")

        -- One request, re-filled per subscriber. Everything here is identical
        -- for every UE — the PLMN, ULI and PCO encodings especially, which are
        -- three helper calls returning fresh byte strings — so building a whole
        -- message object per subscriber re-did all of it N times.
        -- create_session() copies the request into the Session it returns, so
        -- re-using this one is safe: nothing downstream keeps a reference to it.
        local CSR = gtp.CreateSessionRequest()
        CSR.apn      = M.apn
        CSR.rat_type = gtp.GTP2_RAT_EUTRAN
        CSR.pdn_type = gtp.GTP2_PDN_IPV4
        CSR.serving_network = gtp.plmn_encode(cfg.mcc, cfg.mnc)
        CSR.uli             = gtp.uli_tai_ecgi(cfg.mcc, cfg.mnc, 0x0001, 0x0000001)
        CSR.has_paa      = true
        CSR.paa.pdn_type = gtp.GTP2_PDN_IPV4
        CSR.paa.addr4    = "0.0.0.0"                     -- request a dynamic IPv4
        CSR.pco = gtp.pco_request_pcscf()                -- ask for the P-CSCF IPv4

        local CSR_C = gtp.Fteid()
        CSR_C.if_type = gtp.GTP2_IF_S5S8C_SGW            -- sender F-TEID: SGW S5/S8-C
        CSR.sender_fteid = CSR_C

        -- The bearer's F-TEID is the one per-subscriber field, so the single
        -- bearer context is rebuilt each time (clear_bearers + add_bearer); the
        -- QoS and EBI on it are constant.
        local CSR_BC = gtp.BearerContext()
        CSR_BC.ebi, CSR_BC.has_qos, CSR_BC.qos.qci = 5, true, 9
        local CSR_U = gtp.Fteid()                        -- bearer F-TEID: SGW S5/S8-U
        CSR_U.if_type, CSR_U.addr4 = gtp.GTP2_IF_S5S8U_SGW, sgw_ip

        -- Point the shared template at one subscriber. Called from inside the
        -- loop, not ahead of it: filling early would let the next subscriber's
        -- values overwrite the template before this one's request left.
        local function fill_csr(sub)
            CSR.imsi   = sub.imsi
            CSR_C.teid = sub.ctrl_teid
            CSR.sender_fteid = CSR_C
            CSR_U.teid = sub.up_teid
            CSR_BC:clear_fteids(); CSR_BC:add_fteid(2, CSR_U)
            CSR:clear_bearers(); CSR:add_bearer(CSR_BC)
            return CSR
        end

        local burst_t0 = now()
        for i = 1, cfg.nsubs do
            -- The identity and its protected ports/SPIs come from ims/ue.lua;
            -- the S5/S8-U TEIDs are this module's own resource, spaced by the
            -- same index. So is the control TEID: the value the endpoint's own
            -- allocator would give the i-th request, pinned so a Create Bearer
            -- Request's header TEID always correlates back to it.
            local sub = ue.new(i, "session")
            sub.up_teid   = S5_UP_TEID_BASE + sub.idx * 0x10       -- default bearer
            sub.ded_teid  = S5_UP_TEID_BASE + sub.idx * 0x10 + 1   -- dedicated (media)
            sub.ctrl_teid = i
            subs[i] = sub
            by_imsi[sub.imsi] = sub

            local sess = ep:create_session(fill_csr(sub), pgw_ip)
            sub.sess = sess
            by_teid[sess:local_teid()] = sub
            if cfg.verbose then
                log.slog(sub, "-> Create Session Req", ("SGW ctrl TEID %#x, IMSI %s")
                    :format(sess:local_teid(), sub.imsi))
            end
        end

        -- How long the attach burst took to leave the client, split into the
        -- part on the caller's path (build + hand off every request) and the
        -- part in the kernel (the endpoint's queue drained with batched
        -- sendmmsg — what the loop would do at the top of its next iteration
        -- anyway). With the direct path the two are the same thing: one sendto
        -- per request, inline.
        local offer = now() - burst_t0
        ep:tx_flush()
        return { n = cfg.nsubs, offer = offer, total = now() - burst_t0 }
    end

    -- Send a Delete Session Request for every established PDN connection and wait
    -- for the responses (T3/N3 retransmission), so the PGW/SMF frees each
    -- session-pool entry instead of leaking it until timeout.
    function A.teardown()
        local del = {}
        for _, s in ipairs(subs) do
            -- Skip a PDN connection the network already told us it released (a
            -- Delete Bearer with a linked EBI): asking again only earns a
            -- "context not found" and muddies the teardown tally.
            if s.sess and s.pgw_ctrl_teid and not s.pdn_gone then
                del[#del + 1] = s
            end
        end
        if #del == 0 then return loop:stop() end
        log.banner(("Delete Session Requests — tearing down %d PDN connection(s)"):format(#del))
        dpending = #del
        -- overall deadline so a lost response cannot hang teardown forever
        tguard = loop:after(#del + T3_MS * N3 + 2000,
                            function() tguard = nil; loop:stop() end)
        for _, s in ipairs(del) do
            local dok, derr = pcall(function() return s.sess:delete_session() end)
            if dok then
                log.slog(s, "-> Delete Session Req", ("linked EBI -> PGW ctrl TEID %#x")
                    :format(s.pgw_ctrl_teid))
            else
                del_done(s, false, "send failed: " .. log.why(derr))
            end
        end
    end

    -- Loop-driven TX accounting for the endpoint: sent/calls is the batching
    -- ratio (datagrams per sendmmsg() syscall), blocked counts the times the
    -- kernel pushed back and the queue rode it out instead of failing a send.
    function A.tx_stats()
        return { sent = ep:tx_sent(), calls = ep:tx_calls(),
                 blocked = ep:tx_blocked(), dropped = ep:tx_dropped() }
    end

    -- Datapath counters, read while the datapath is still loaded and before
    -- cleanup() removes any of the filters they are keyed on. Aggregated over
    -- every bearer the run programmed, because the error tallies are the
    -- point: a downlink the network sent on a TEID we never programmed a decap
    -- entry for is counted as err_unknown_teid here and is invisible
    -- everywhere else — the tool would otherwise report it as "the network
    -- never answered". dp_report() prints what was collected here, later,
    -- after the run's other summary lines.
    function A.collect_dp()
        if not up then return end
        local d = { rx = 0, tx = 0, unknown = 0, malformed = 0, no_neigh = 0, teids = 0 }
        for _, sub in ipairs(subs) do
            for _, b in ipairs({ sub.def_bearer, sub.ded_bearer }) do
                if b and b.local_teid then
                    local oks, s = pcall(function() return up:stats(b.local_teid) end)
                    if oks then
                        d.teids     = d.teids + 1
                        d.rx        = d.rx + s.rx_pkts
                        d.tx        = d.tx + s.tx_pkts
                        d.unknown   = d.unknown + s.err_unknown_teid
                        d.malformed = d.malformed + s.err_malformed
                        d.no_neigh  = d.no_neigh + s.err_tx_no_neigh
                    end
                end
            end
        end
        dp = d
    end

    function A.dp_report()
        if not dp then return end
        log.banner(("GTP-U datapath (aggregate over %d programmed bearer(s))"):format(dp.teids))
        log.line("decap / encap", ("rx %d pkt, tx %d pkt"):format(dp.rx, dp.tx))
        if dp.unknown + dp.malformed + dp.no_neigh > 0 then
            log.line("datapath drops", ("unknown TEID %d, malformed %d, no neighbour %d")
                :format(dp.unknown, dp.malformed, dp.no_neigh))
            if dp.unknown > 0 then
                log.line("", "a G-PDU arrived on a TEID with no decap entry -- most likely a")
                log.line("", "bearer we accepted in signalling but never steered.")
            end
        elseif dp.tx == 0 and dp.teids > 0 then
            -- Nothing encapsulated and nothing dropped at the hook either: the
            -- packets never got as far as gtpu_encap. TC egress runs inside
            -- dev_queue_xmit, so anything the kernel drops earlier -- an unresolved
            -- neighbour above all -- is invisible to every counter above and looks
            -- exactly like a datapath that does not work.
            log.line("datapath idle", "no UE packet reached TC egress")
            log.line("", "nothing was encapsulated and nothing was dropped at the hook, so")
            log.line("", "the kernel never handed these packets to the device: check")
            log.line("", "`ip neigh` for the inner destination and whether its route is")
            log.line("", "on-link toward a peer that is not actually on that link.")
        end
    end

    -- Release everything this module put in the kernel: the media filters
    -- (harmless to fail — see apply_media_tfts), the PAA route on `lo`, and
    -- the P-CSCF MTU route (removing it uncovers the less-specific route it
    -- shadowed). flow.release_sas() and flow.close_sockets() are the caller's
    -- own, separate half of teardown.
    function A.cleanup()
        for _, sub in ipairs(subs) do
            if sub.media_tft then pcall(function() apply_media_tfts(sub, "del") end) end
        end
        for _, sub in ipairs(subs) do
            if sub.paa_added then pcall(function() net.addr_del("lo", sub.ue_addr, 32) end) end
        end
        for _, r in pairs(mtu_routes) do pcall(function() net.route_del(r) end) end
    end

    return A
end

return M
