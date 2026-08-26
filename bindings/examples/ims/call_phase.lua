-- ims/call_phase.lua — calls between pairs of subscribers, with real RTP on a
-- sampled subset, as a phase with its own report.
--
-- Pairs are structural: 1<->2, 3<->4, ... where the odd index originates (MO)
-- and the even one terminates (MT). Both ends of a pair live in this process on
-- the same net.Loop and the same monotonic clock, which is what makes the
-- setup-time decomposition possible with no clock synchronisation at all: t2-t0
-- is a true one-way core latency, not half a round trip. Per leg the flow is
--
--   MO --INVITE (Route: orig, SDP offer)--> P-CSCF -> S-CSCF -> ... -> MT
--   MT --180 Ringing--> ... --> MO,  then after CALL_ANSWER_MS a 200 OK with
--   the answer SDP; MO ACKs, media runs for CALL_HOLD_MS, MO sends BYE.
--
-- The callee is dialled by NUMBER: the Request-URI and To of that INVITE are the
-- tel URI of its MSISDN (CALL_URI=tel, the default) — what a handset does, and
-- one more link of the chain under test rather than assumed, because the number
-- only routes if the HSS returned it as a public identity of the callee's
-- subscription, so the terminating side has to resolve MSISDN -> IMPU ->
-- registered contact. The numbers are derived from the IMSI (see ims/cfg.lua)
-- and bindings/examples/cx_hss.lua derives the same ones; CALL_URI=sip dials the
-- registered sip IMPU instead, which is what to fall back to against an HSS that
-- has no MSISDNs for the range.
--
-- The dialog layer is the sip module's own: a sip.Dialog (RFC 3261 §12) per call
-- with sip.Transaction(INVITE_CLIENT) on the MO side and INVITE_SERVER on the MT
-- side, fed the traffic and read back for state — the same discipline the
-- registration code uses.
--
-- The bodies are the sdp module's: sdp.offer builds the audio offer and the
-- answer, sdp.parse reads the rewritten one back. Two rules it applies so this
-- file does not have to — a media-level c= overrides the session-level one
-- (RFC 8866 §5.7, and rtpengine emits both), and m= port 0 is a rejected stream
-- (RFC 3264 §6) rather than a silent zero port — are exactly the two that
-- otherwise send media to the wrong host and look like a network fault.
--
-- Media is relayed by the IMS (the S-CSCF drives rtpengine on the INVITE and on
-- the reply carrying SDP), so each UE's RTP peer is rtpengine, learnt from the
-- rewritten SDP. Two measurements come out of the phase:
--
--   * call setup time, decomposed per segment (post-dial delay, session setup,
--     each transit direction separately, media cut-through, release) reported as
--     p50/p95/p99/max rather than means, since the mean hides the knee;
--   * call quality per direction — loss/jitter from our own receive stats, the
--     peer's view of our uplink from RTCP report blocks, RTT from their
--     lsr/dlsr, and a G.107 MOS *estimate* computed from those packet statistics
--     (no audio is decoded, so it is not PESQ/POLQA).

local net   = require("net")
local sip   = require("sip")
local rtp   = require("rtp")     -- RTP/RTCP media session on the same net.Loop
local sdp   = require("sdp")     -- SDP codec: the audio offer and the answer's media
local cfg   = require("ims.cfg")
local log   = require("ims.log")
local wire  = require("ims.wire")
local stats_ = require("ims.stats")

local M = {}

-- ---- the knobs --------------------------------------------------------
--
-- Two axes that must not be conflated: how many calls are placed (the signalling
-- load) and how many of them carry RTP (the media load). Per call the datapath
-- sees 4 streams x 50 pps = 200 packets/s, and this tool does the sends and
-- receives for all of them on one single-threaded Lua loop, crossing SWIG per
-- packet — so full-rate media on every call saturates the *tool* first, and a
-- saturated tool inflates its own setup-time marks while still printing
-- plausible numbers. Hence: many calls with CALL_MEDIA=0 to measure setup time
-- under load, a few calls with media to measure quality, or media on a sampled
-- subset to measure quality while load is applied.
M.on    = cfg.flag("IMS_CALL", true)          -- run the phase at all
M.pairs = cfg.num("CALL_PAIRS")               -- nil = every eligible pair
-- Offered call arrival rate: the independent variable of the experiment — a knee
-- cannot be found without being able to set the offered rate. It is NOT a remedy
-- for failures; 0 (the default) is a single burst, consistent with the
-- deliberately unramped registration side.
M.cps       = cfg.num("CALL_CPS", 0)
M.answer_ms = cfg.num("CALL_ANSWER_MS", 200)   -- MT ring hold
M.hold_ms   = cfg.num("CALL_HOLD_MS", 2000)    -- talk time
M.t_ms      = cfg.num("CALL_T_MS", 10000)      -- per-step deadline
-- How many calls carry RTP. A small sample by default; -1 = all of them.
M.media     = cfg.num("CALL_MEDIA", 1)
-- Which bearer carries media: "auto" uses the dedicated bearer once the Create
-- Bearer Request brings one (re-homing if it arrives after the answer),
-- "default" keeps media on the default bearer — worth having, because a UPF
-- whose dedicated-bearer uplink PDR carries an SDF filter that does not match
-- our negotiated 5-tuple drops the uplink outright.
M.bearer    = cfg.str("MEDIA_BEARER", "auto")

local MEDIA = {
    pt       = cfg.num("MEDIA_PT", 0),          -- 0 = G.711 PCMU
    rate     = cfg.num("MEDIA_RATE", 8000),     -- codec clock
    ptime_ms = cfg.num("MEDIA_PTIME_MS", 20),   -- packetisation
    -- RFC 3550 §6.2 wants a minimum RTCP interval of 5 s; 1 s here is a
    -- deliberate lab choice, because a 2 s call at 5 s would produce no usable
    -- report series at all. Do not "fix" this to the spec value without also
    -- lengthening the calls.
    rtcp_ms  = cfg.num("RTCP_MS", 1000),
    -- Which bearer carries RTCP. The dedicated bearer's PCC rule on this stack
    -- describes only the RTP 5-tuple, so RTCP on it is dropped by the UPF as an
    -- "Off-filter G-PDU" — and RTCP is where the peer's view of OUR uplink comes
    -- from (loss, jitter) plus the round trip, so losing it costs a whole
    -- measurement axis. The default bearer's uplink PDR is catch-all, so RTCP
    -- rides it by default; the reports still describe the RTP path, only the RTT
    -- reflects the bearer the reports themselves travelled. Set
    -- MEDIA_RTCP_BEARER=media to keep both on one bearer, as a UE would.
    rtcp_bearer = cfg.str("MEDIA_RTCP_BEARER", "default"),
    -- Each subscriber's RTP port plus its RTCP port (RFC 3550 §11 wants
    -- port + 1), so the stride is 4: room to spare, clear of the SIP ports.
    port_base = 40000,
}
M.MEDIA = MEDIA

-- The encoding name a=rtpmap carries. A static payload type names itself
-- (RFC 3551 §6), so the default needs no knob; a dynamic one (96..127) has no
-- assignment to borrow and must be named, because offering it as PCMU negotiates
-- cleanly and then plays noise. Caught here, at load, rather than as an
-- exception from the first INVITE.
MEDIA.codec = cfg.str("MEDIA_CODEC", sdp.pt_encoding(MEDIA.pt))
if MEDIA.codec == "" then
    io.stderr:write(("MEDIA_PT=%d is a dynamic payload type; set MEDIA_CODEC " ..
                     "(and MEDIA_RATE) to the encoding it stands for\n"):format(MEDIA.pt))
    os.exit(2)
end

-- One packetisation interval of payload. G.711 is one byte per sample, so at
-- 8 kHz / 20 ms this is the canonical 160-byte packet; for another codec the size
-- is only nominal (nothing decodes it) while the timestamp step stays right,
-- which is what the receiver's jitter estimate is computed from.
MEDIA.samples = math.max(1, math.floor(MEDIA.rate * MEDIA.ptime_ms / 1000))
MEDIA.payload = ("\170"):rep(MEDIA.samples)

-- ---- feeding the sip module's machines --------------------------------
--
-- A machine in its terminal state is not something to hide: fsm_act()
-- (task/src/fsm.c) warns "fsm: already in the terminal state" and the facade
-- turns the FSM_E_FINAL into an exception, so a bare pcall around the feed
-- swallows the error and leaves one unexplained WARN line per call on stderr.
-- Every event that reaches a terminal machine here is one it is CORRECT to drop,
-- so the guard belongs at the feed, not around it:
--
--   * the ACK for a 2xx is its OWN transaction (RFC 3261 §17.2.1) — sending the
--     200 OK ended the INVITE server transaction and handed retransmission to
--     the TU, so the ACK that follows has no transaction left to move. This is
--     the one that fires on every answered call;
--   * a retransmitted 200 OK, or a BYE that crosses our own, arrives at a dialog
--     or client transaction we have already torn down.
--
-- The method is taken as a value rather than wrapped in a closure: these run once
-- per message, and pcall(m.recv, m, msg) allocates nothing.
local function feed_ev(m, ev)
    if m and not m:terminated() then pcall(m.event, m, ev) end
end
local function feed_msg(m, msg)
    if m and not m:terminated() then pcall(m.recv, m, msg) end
end

-- ---- the phase --------------------------------------------------------

function M.new(ctx)
    local loop, io_, subs = ctx.loop, ctx.io, ctx.subs
    local media_hook = ctx.media or {}
    local now = net.now_ms
    local P = {}

    local calls, by_callid = {}, {}
    local pending, guard, finished = 0, nil, nil
    local st = {
        pairs_total = 0, eligible = 0, attempted = 0, answered = 0, released = 0,
        media_calls = 0, first_invite = nil, last_answer = nil,
        by_status = {},                       -- final-response counts, non-2xx
        stage = {},                           -- where a failed call died
        kpi = { pdd = {}, sst = {}, sst_net = {}, mo_transit = {}, mt_transit = {},
                answer = {}, cut = {}, release = {} },
        media = { streams = 0, calls = 0, zero = 0, early = 0, late = 0, no_reports = 0,
                  unconnected = 0,   -- streams opened for a call that never answered
                  tx = 0, rx = 0, tx_err = 0, tx_why = nil,
                  dl_loss = {}, dl_jitter = {}, ul_loss = {}, ul_jitter = {},
                  exp_loss = {}, rtt = {}, mos = {} },
    }
    P.stats = st

    local function media_port(sub) return MEDIA.port_base + sub.idx * 4 end

    -- ---- the downlink size budget ------------------------------------------
    --
    -- Everything the network sends to a UE over S5/S8 crosses GTP-U, which adds
    -- 36 bytes (outer IPv4 + UDP + GTP header). On a 1500-byte path that leaves
    -- 1464 bytes for the packet the P-CSCF emits — and a G-PDU that would exceed
    -- the MTU does not arrive: the outer packet is fragmented and the decap
    -- cannot classify a fragment that carries no GTP header, so both halves are
    -- lost. Measured on this stack, downlink packets of 1452 bytes arrive and
    -- 1480 do not.
    --
    -- The tool only controls one term of that sum — the size of the requests it
    -- sends, since the proxies then add ~500 bytes of Record-Route, P-Charging-*,
    -- P-Asserted-Identity and Via to whatever it emitted. So the call messages
    -- are deliberately lean: short tags/branches/Call-ID, no Contact where it is
    -- optional, no Security-Verify outside the REGISTER that RFC 3329 §2.2 asks
    -- for it in. Without that, an 882-byte ACK came back as a 1480-byte downlink
    -- and vanished, which looks exactly like the far end ignoring the request.
    --
    -- The uplink half of the same sum is not about message size at all — it is a
    -- route MTU, so the kernel fragments before the datapath's TC hook rather
    -- than losing the packet at it. See set_pcscf_mtu in ims_test_s5.lua.

    -- The MO's INVITE, from its protected client port. No Require/Supported: with
    -- both ends ours, advertising 100rel would oblige PRACK handling and session
    -- timers a refresh cycle, and neither buys a measurement.
    local function build_invite(c)
        local mo = c.mo
        -- The dialled address (cfg.dial_uri): by default the callee's tel URI, so
        -- the Request-URI carries a number and the core has to resolve it through
        -- the HSS profile to the callee's registered contact.
        local b = io_.preload_route(wire.builder:request(sip.INVITE, c.callee), mo)
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s")
                            :format(mo.ue_addr, mo.port_uc, c.branch))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, c.from_hdr)
            :header(sip.H_TO, c.to_hdr)
            :header(sip.H_CALL_ID, c.call_id)
            :header(sip.H_CSEQ, ("%d INVITE"):format(c.cseq))
            -- The INVITE must come from the registered contact: the P-CSCF
            -- matches usrloc on aor/received_port (pcscf_is_registered), so this
            -- is the same address:port the protected REGISTER left from, over the
            -- same SA.
            :header(sip.H_CONTACT, wire.contact(mo))
            -- The P-CSCF checks this against the registration and re-asserts it
            -- as P-Asserted-Identity (proxy.cfg route[MORIG]) — so it stays the
            -- sip IMPU this UE registered even when it dials a number: the
            -- caller's own tel URI is an alias of the same subscription, and
            -- asserting an alias is only accepted if the P-CSCF learnt it from
            -- P-Associated-URI, which turns a working call into a 403 on some
            -- stacks for nothing.
            :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(mo.impu))
            :header(sip.H_ALLOW, "INVITE, ACK, CANCEL, BYE")
        -- No Security-Verify: RFC 3329 §2.2 wants it on the request that follows
        -- the Security-Server offer — the authenticated REGISTER, which does
        -- carry it — and the ~110 bytes it costs here come back amplified in the
        -- terminating INVITE the callee has to receive.
        b:header(sip.H_CONTENT_TYPE, "application/sdp")
        return b:done(c.offer)
    end

    -- An ACK or a BYE from the MO goes to the dialog's remote target through its
    -- route set, with the local/remote URI+tag pair as the 200 OK settled it. The
    -- ACK for a 2xx is its own transaction, hence its own branch; the ACK for a
    -- non-2xx belongs to the INVITE transaction and reuses the INVITE's branch
    -- (and needs no route set — it goes where the INVITE went).
    local function build_in_dialog(c, method, mname, cseq, branch, route)
        local mo = c.mo
        local b  = wire.builder:request(method, c.target or c.callee)
        for _, r in ipairs(route or {}) do b:header(sip.H_ROUTE, r) end
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s")
                            :format(mo.ue_addr, mo.port_uc, branch))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, c.from_hdr)
            :header(sip.H_TO, c.to_hdr)
            :header(sip.H_CALL_ID, c.call_id)
            :header(sip.H_CSEQ, ("%d %s"):format(cseq, mname))
            -- Contact is optional in ACK and BYE, but this P-CSCF's originating
            -- path needs it: without it pcscf_is_registered() does not find the
            -- registration and answers the BYE with "403 Forbidden - You must
            -- register first with a S-CSCF", even though the INVITE that opened
            -- the dialog from the same port passed the same check.
            :header(sip.H_CONTACT, wire.contact(mo))
        return b:done()
    end

    -- Answer with a payload type the offer actually listed (RFC 3264 §6): keep
    -- ours when it is on offer, else take the offer's first. Returns the type
    -- plus the codec name and clock to echo back — for a dynamic type there is no
    -- static name to fall back on, so the answer takes them from the offer's own
    -- a=rtpmap rather than claiming PCMU and playing noise.
    local function answer_pt(stream)
        local pt = MEDIA.pt
        if stream and not stream:has_pt(pt) and stream:pt_count() > 0 then
            local first = stream:pt_at(0)
            if first >= 0 then pt = first end
        end
        if pt == MEDIA.pt then return pt, MEDIA.codec, MEDIA.rate end
        if stream:has_rtpmap(pt) then
            local r = stream:rtpmap(pt)
            return pt, r.enc, r.clock
        end
        local enc, clock = sdp.pt_encoding(pt), sdp.pt_clock(pt)
        if enc ~= "" then return pt, enc, clock end
        return MEDIA.pt, MEDIA.codec, MEDIA.rate  -- nothing nameable; keep ours
    end

    -- ---- media: one rtp.Stream per leg, on the shared loop ----
    --
    -- Sourced from the UE's own address with a non-local bind (IP_FREEBIND +
    -- IP_TRANSPARENT), like the SIP socket: the RTP that leaves must carry the
    -- address the SDP advertises, or the UPF drops it as spoofed.
    local function open_media(c, sub, role)
        local port = media_port(sub)
        local ok, s = pcall(rtp.Stream, loop, sub.ue_addr, port, true)
        if not ok then
            log.slog(sub, "media session", ("cannot bind %s:%d: %s")
                :format(sub.ue_addr, port, log.why(s)))
            return nil, nil
        end
        local stm = { role = role, rx = 0, tx = 0, tx_err = 0, first = nil, last = nil,
                      early = 0, late = 0, reports = 0, ul_lost = nil, ul_jitter = {} }
        pcall(function()
            s:set_payload_type(MEDIA.pt)
            s:set_clock_rate(MEDIA.rate)
            s:set_rtcp_interval(MEDIA.rtcp_ms)
            s:set_cname(sub.impu)
        end)
        -- Report blocks the peer wrote about US are the only measurement of our
        -- uplink there is; they arrive on either an SR (rtpengine sends media, so
        -- it sends SRs) or an RR, so both paths feed the same collector.
        local function note(reports)
            stm.reports = stm.reports + 1
            for _, r in ipairs(reports) do
                if r.ssrc == s:ssrc() then
                    stm.ul_lost = r.packets_lost
                    stm.ul_frac = r.fraction_lost
                    stm.ul_jitter[#stm.ul_jitter + 1] = r.jitter / (MEDIA.rate / 1000)
                end
            end
        end
        s:set_handler({
            on_rtp = function()
                local t = now()
                stm.rx = stm.rx + 1
                stm.first = stm.first or t
                stm.last  = t
                -- Media cut-through is measured at the originating side: the
                -- first packet the caller actually hears (t8 - t6).
                if role == "mo" and not c.t.t8 then c.t.t8 = t end
                -- Media before the answer is early/leaked media; media after our
                -- BYE is rtpengine teardown lag. Both are counted rather than
                -- folded into the loss figures.
                if not c.answered_at then stm.early = stm.early + 1 end
                if c.released_at then stm.late = stm.late + 1 end
            end,
            on_sender_report   = function(_, _, reports) note(reports) end,
            on_receiver_report = function(_, reports) note(reports) end,
        })
        return s, stm
    end

    -- A send that fails is recorded, not swallowed: "no RTP arrived" and "the
    -- kernel refused every send" look identical in the receive statistics, and
    -- only one of them is a network problem.
    local function media_send(s, stm)
        if not (s and stm) then return end
        local ok, err = pcall(function() s:send(MEDIA.payload, MEDIA.samples) end)
        if ok then stm.tx = (stm.tx or 0) + 1 else
            stm.tx_err = (stm.tx_err or 0) + 1
            stm.tx_why = stm.tx_why or log.why(err)
        end
    end

    local function media_tick(c)
        c.media_timer = nil
        if c.media_stop then return end
        if c.mo_ready then media_send(c.sess_mo, c.mstat_mo) end
        if c.mt_ready then media_send(c.sess_mt, c.mstat_mt) end
        c.media_timer = loop:after(MEDIA.ptime_ms, function() media_tick(c) end)
    end

    -- One timer per call, not per stream: it feeds both directions, which halves
    -- the timer churn on the loop that also has to measure itself.
    local function start_media(c)
        if c.media_timer or c.media_stop then return end
        if not (c.sess_mo or c.sess_mt) then return end
        media_tick(c)
    end

    -- Stop sending and tell the peer (RTCP BYE, so rtpengine releases its ports
    -- rather than holding them for its 60 s timeout). The sessions stay open:
    -- packets still arriving are the late-media count.
    local function stop_media(c)
        c.media_stop = true
        if c.media_timer then loop:cancel(c.media_timer); c.media_timer = nil end
        if c.sess_mo then pcall(function() c.sess_mo:bye("call cleared") end) end
        if c.sess_mt then pcall(function() c.sess_mt:bye("call cleared") end) end
    end

    -- The audio stream a body offers or answers, or nil with the reason said out
    -- loud. s.addr is the resolved one: rtpengine emits a session-level c= AND a
    -- media-level c=, and the media one is the relay (RFC 8866 §5.7). The sdp
    -- module applies that rule, so this reads one field; s:rejected() is the
    -- port-0 case (RFC 3264 §6).
    local function audio_of(body, sub, what)
        local okp, doc = pcall(sdp.parse, body)
        local s = okp and doc:has_audio() and doc:audio() or nil
        if not (s and not s:rejected() and s.addr ~= "") then
            log.slog(sub, "media", okp and ("%s carries no usable audio stream"):format(what)
                                       or ("cannot parse the %s SDP: %s"):format(what, log.why(doc)))
            return nil
        end
        return s
    end

    -- Point a leg's media at what the SDP named, and steer the datapath at it —
    -- rtpengine's address and port are only known once the SDP has been
    -- rewritten and come back, so the media filters are late-bound per call and
    -- cannot be pre-programmed at attach the way the signalling ones are.
    local function point_media(sub, sess, s, what)
        if media_hook.program then media_hook.program(sub, s.addr, s.port) end
        local sok = pcall(function() sess:set_peer(s.addr, s.port) end)
        if not sok then
            log.slog(sub, "media", ("cannot point the session at the %s"):format(what))
        end
        return sok
    end

    -- ---- call lifecycle ----

    -- Identifiers are kept SHORT on purpose, and it is not cosmetic: see the note
    -- on the downlink size budget above. Uniqueness is still guaranteed — the
    -- call index is unique within the run and the UE address within the pool, and
    -- every message of the call carries both.
    local function make_call(n, mo, mt, with_media)
        local c = {
            n = n, mo = mo, mt = mt, media = with_media, cseq = 1,
            call_id  = ("c%d@%s"):format(n, mo.ue_addr),
            from_tag = ("o%d"):format(n),
            to_tag   = ("t%d"):format(n),
            branch   = ("z9hG4bK%d"):format(n),
            -- The dialog and transaction machines the sip module already carries:
            -- fed the traffic and read back for state, so the call phase has no
            -- hand-rolled state variable either.
            dlg_mo = sip.Dialog(), dlg_mt = sip.Dialog(),
            txn_mo = sip.Transaction(sip.INVITE_CLIENT),
            txn_mt = sip.Transaction(sip.INVITE_SERVER),
            route_mo = {}, route_mt = {},
            t = {}, stage = "invite",
        }
        -- From identifies the caller (its registered IMPU); To is the address
        -- dialled, which by default is the callee's number and not an identity
        -- this process ever registered. The far end matches the call on the
        -- Call-ID, so it does not have to recognise the form.
        c.callee   = mt.dial
        c.from_hdr = ("<%s>;tag=%s"):format(mo.impu, c.from_tag)
        c.to_hdr   = ("<%s>"):format(c.callee)
        return c
    end

    local function carm(c, ms, fn)
        if c.timer then loop:cancel(c.timer) end
        c.timer = loop:after(ms, function() c.timer = nil; fn() end)
    end

    -- Setup-time KPIs from the marks. Every figure is a difference of two
    -- readings of ONE monotonic clock taken in this process, so the one-way
    -- transit figures carry no clock skew — that is the whole point of putting
    -- both UEs in one process, and nothing else in the setup can measure them.
    local function record_kpis(c)
        local t, k = c.t, st.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.pdd,        "t0", "t4")   -- post-dial delay: what a user hears as ringing
        push(k.sst,        "t0", "t6")   -- session setup time: the headline number
        push(k.mo_transit, "t0", "t2")   -- MO -> MT through the core, one way
        push(k.mt_transit, "t3", "t4")   -- the return path, independently
        push(k.answer,     "t5", "t6")   -- the 200 OK path, independently
        push(k.cut,        "t6", "t8")   -- media cut-through: answer to audio
        push(k.release,    "t9", "t10")  -- BYE round trip
        -- SST with our own deliberate ring hold removed, so M.answer_ms does not
        -- sit inside the headline figure.
        if t.t0 and t.t6 and t.t3 and t.t5 then
            k.sst_net[#k.sst_net + 1] = (t.t6 - t.t0) - (t.t5 - t.t3)
        end
    end

    local function call_finish(c)
        if c.done then return end
        c.done = true
        if c.timer then loop:cancel(c.timer); c.timer = nil end
        stop_media(c)
        record_kpis(c)
        pending = pending - 1
        if pending <= 0 then
            if guard then loop:cancel(guard); guard = nil end
            finished()
        end
    end

    -- A failed call is attributed to the stage it died at — invite, ringing,
    -- answered, media or release — exactly as a failed registration is.
    local function call_fail(c, msg, status)
        if c.done then return end
        -- Name the cause when the stack's protected-port sharing explains it (see
        -- begin), instead of filing another "no ringing".
        if c.port_clash and c.stage == "invite" then
            msg = msg .. " (P-CSCF protected port shared with the caller)"
        end
        c.err, c.fail_stage = msg, c.stage
        if status then stats_.bump(st.by_status, status) end
        stats_.fail(st.stage, c.stage, msg)
        log.slog(c.mo, "call", ("%d FAILED at %s: %s"):format(c.n, c.stage, msg))
        call_finish(c)
    end

    -- MO: the far end answered. Learn the dialog's remote target, route set and
    -- To (with the tag the answer settled), point our media at whatever the
    -- rewritten SDP says, ACK, and hold the call up for M.hold_ms.
    local function on_answered(c, m)
        c.t.t6 = now()
        c.answered_at = c.t.t6
        c.stage = "answered"
        st.answered = st.answered + 1
        st.last_answer = c.t.t6
        c.to_hdr   = m:header("To")
        c.target   = wire.contact_uri(m) or c.callee
        c.route_mo = wire.route_set(m, true)

        if c.media and c.sess_mo then
            local s = audio_of(m.body, c.mo, "answer")
            if s then
                c.mo_ready = point_media(c.mo, c.sess_mo, s, "answer")
                if cfg.verbose then
                    log.slog(c.mo, "media peer", ("%s:%d (pt %s)"):format(s.addr, s.port,
                        s:pt_count() > 0 and tostring(s:pt_at(0)) or "-"))
                end
            end
        end

        local w = build_in_dialog(c, sip.ACK, "ACK", c.cseq, c.branch .. "-ack", c.route_mo)
        c.t.t7 = now()
        io_.send(c.mo, "mo", w, "ACK")
        start_media(c)

        c.stage = "media"
        carm(c, M.hold_ms, function()
            -- Always BYE: rtpengine holds a port pair per call for its 60 s
            -- timeout, so a run that walks away from calls exhausts its
            -- 30000-40000 range instead of failing anything visibly.
            c.stage = "release"
            c.t.t9  = now()
            c.released_at = c.t.t9
            stop_media(c)
            local bye = build_in_dialog(c, sip.BYE, "BYE", c.cseq + 1,
                                        c.branch .. "-bye", c.route_mo)
            feed_ev(c.dlg_mo, sip.DE_TERMINATE)
            io_.send(c.mo, "mo", bye, "BYE")
            carm(c, M.t_ms, function()
                -- No 200 to our BYE: released as far as we are concerned, but
                -- recorded as such rather than as an answered-and-released call.
                log.slog(c.mo, "call", ("%d no 200 to the BYE"):format(c.n))
                call_finish(c)
            end)
        end)
    end

    -- MT: answer the INVITE we are holding, with the SDP answer.
    local function send_answer(c)
        if c.done or not c.mt_req then return end
        local mt = c.mt
        local body = sdp.offer{ addr = mt.ue_addr, port = media_port(mt),
                                pt = c.mt_pt or MEDIA.pt,
                                codec = c.mt_codec or MEDIA.codec,
                                rate = c.mt_rate or MEDIA.rate,
                                ptime = MEDIA.ptime_ms }
        local w = wire.response(mt, c.mt_req, { status = 200, reason = "OK",
                                                to_tag = c.to_tag, body = body })
        -- The 2xx ends the INVITE server transaction (§17.2.1); the ACK that
        -- follows is a transaction of its own, which is why P.request feeds it
        -- through feed_msg rather than into this machine.
        feed_ev(c.txn_mt, sip.TE_SEND_2XX)
        feed_ev(c.dlg_mt, sip.DE_CONFIRM)
        c.t.t5 = now()
        io_.send(mt, "mt", w, "200 OK (answer)")
        -- A UE starts sending as it answers; the MO starts at its ACK, so t8 - t6
        -- measures answer-to-audio across the relay, not our own delay.
        c.mt_ready = c.sess_mt ~= nil
        start_media(c)
    end

    -- MT: an INVITE arrived on the protected port.
    local function on_invite(sub, c, m)
        c.t.t2 = now()
        c.stage = "ringing"
        feed_msg(c.txn_mt, m)
        feed_msg(c.dlg_mt, m)
        c.mt_req   = m                    -- what the responses must echo back
        c.route_mt = wire.route_set(m, false)

        if c.media and c.sess_mt then
            local s = audio_of(m.body, sub, "offer")
            if s then
                c.mt_pt, c.mt_codec, c.mt_rate = answer_pt(s)
                point_media(sub, c.sess_mt, s, "offer")
                c.mt_ready = false        -- armed at the answer
                if cfg.verbose then
                    log.slog(sub, "media peer", ("%s:%d (pt %d %s/%d)")
                        :format(s.addr, s.port, c.mt_pt, c.mt_codec, c.mt_rate))
                end
            end
        end

        -- 180 now (that is what the MO's post-dial delay measures), 200 OK after
        -- the deliberate ring hold.
        local ring = wire.response(sub, m, { status = 180, reason = "Ringing",
                                             to_tag = c.to_tag })
        feed_ev(c.txn_mt, sip.TE_SEND_1XX)
        feed_ev(c.dlg_mt, sip.DE_EARLY)
        c.t.t3 = now()
        io_.send(sub, "mt", ring, "180 Ringing")
        loop:after(M.answer_ms, function() send_answer(c) end)
    end

    -- Incoming requests: the MT INVITE and its ACK, plus a BYE from whichever end
    -- releases first. Both arrive on the protected port.
    function P.request(sub, m)
        local c = by_callid[m:call_id()]
        if m.method == sip.INVITE then
            if not c then
                return log.slog(sub, "call", "INVITE for an unknown Call-ID; ignored")
            end
            if c.t.t2 then return end            -- retransmission; already ringing
            return on_invite(sub, c, m)
        elseif m.method == sip.ACK then
            -- Absorbed by the transaction only when a non-2xx final left one
            -- alive (Completed -ACK-> Confirmed). After a 2xx there is nothing to
            -- absorb it — see feed_msg.
            if c then feed_msg(c.txn_mt, m) end
            return
        elseif m.method == sip.BYE then
            -- Answer it whoever we are; then this call is over for us. A BYE we
            -- receive is terminating for us, so it came from the P-CSCF's
            -- protected client port and the answer goes back to it ("mt").
            io_.send(sub, "mt", wire.response(sub, m, {
                status = 200, reason = "OK", to_tag = (c and c.to_tag) or "x",
            }), "200 OK (BYE)")
            if c and not c.done then
                feed_msg(sub == c.mt and c.dlg_mt or c.dlg_mo, m)
                if not c.released_at then c.released_at = now() end
                st.released = st.released + 1
                stop_media(c)
                call_finish(c)
            end
            return
        elseif m.method == sip.CANCEL then
            if c then call_fail(c, "cancelled by the network", nil) end
            return
        end
        if cfg.verbose then
            log.slog(sub, "call", ("ignoring in-dialog %s"):format(m.method_name))
        end
    end

    -- Responses to what the MO sent: the INVITE's provisionals and final, and the
    -- 200 to our BYE.
    function P.response(sub, m)
        local c = by_callid[m:call_id()]
        if not c then
            -- Never drop SIP silently: a response for a Call-ID we do not know is
            -- either a stray retransmission or a real bug, and telling the two
            -- apart from the outside is impossible without saying so.
            if cfg.verbose then
                log.slog(sub, "call", ("%d %s for an unknown Call-ID"):format(m.status, m.reason))
            end
            return
        end
        local okc, cs = pcall(function() return m:cseq() end)
        local meth = okc and cs.method or sip.M_UNKNOWN

        if meth == sip.BYE then
            if m.status >= 200 and not c.done then
                c.t.t10 = now()
                st.released = st.released + 1
                call_finish(c)
            end
            return
        end
        if meth ~= sip.INVITE or c.done then return end

        feed_msg(c.txn_mo, m)
        feed_msg(c.dlg_mo, m)

        if m.status == 100 then
            c.t.t1 = c.t.t1 or now()
            return
        elseif m.status > 100 and m.status < 200 then
            if not c.t.t4 then
                c.t.t4 = now()
                if cfg.verbose then
                    log.slog(sub, "<- " .. tostring(m.status), ("%s (dialog %s)")
                        :format(m.reason, c.dlg_mo:state_name()))
                end
            end
            carm(c, M.t_ms, function() call_fail(c, "no final response after ringing") end)
            return
        elseif m.status >= 200 and m.status < 300 then
            if c.t.t6 then return end            -- 200 retransmission
            return on_answered(c, m)
        end

        -- Any other final: ACK it (the ACK for a non-2xx belongs to the INVITE
        -- transaction, so it reuses its branch and needs no route set) and record
        -- where the network said no.
        c.to_hdr = m:header("To")
        local ack = build_in_dialog(c, sip.ACK, "ACK", c.cseq, c.branch, nil)
        io_.send(c.mo, "mo", ack, "ACK (non-2xx)")
        call_fail(c, ("%d %s"):format(m.status, m.reason), m.status)
    end

    function P.begin(done)
        finished = done
        -- Structural pairs: 1<->2, 3<->4, ... A pair is eligible only when BOTH
        -- ends registered, and the denominator stays the structural count —
        -- silently shrinking it would turn a registration failure into a perfect
        -- call-success rate.
        st.pairs_total = math.floor(#subs / 2)
        local list = {}
        for p = 1, st.pairs_total do
            local mo, mt = subs[2 * p - 1], subs[2 * p]
            local ready = mo.registered and mt.registered
                and mo.sock and mt.sock and #(mo.svc_route or {}) > 0
            if ready then
                st.eligible = st.eligible + 1
                if not M.pairs or #list < M.pairs then
                    list[#list + 1] = { mo = mo, mt = mt }
                end
            end
        end
        if #list == 0 then
            log.banner(("Calls — none placed (%d/%d pair(s) eligible; a call needs BOTH ends registered with a Service-Route)")
                :format(st.eligible, st.pairs_total))
            return done()
        end

        local nmedia = M.media < 0 and #list or math.min(M.media, #list)
        st.media_calls = nmedia
        log.banner(("Calls — %d of %d eligible pair(s) (%d structural), %d carrying RTP%s")
            :format(#list, st.eligible, st.pairs_total, nmedia,
                    M.cps > 0 and (" at %.1f call/s"):format(M.cps) or " in one burst"))
        -- What is actually dialled, spelled out: a run that fails because the HSS
        -- profile carries no such identity is otherwise indistinguishable from a
        -- routing fault, and this is the line that tells them apart.
        log.line("dialled address", ("%s   (CALL_URI=%s%s)"):format(
            list[1].mt.dial, cfg.dial_uri,
            cfg.dial_uri == "sip" and "" or ", needs the number in the HSS profile"))

        pending = #list
        local spacing = M.cps > 0 and math.floor(1000 / M.cps) or 0
        -- Overall deadline so a lost 200 OK cannot hang the run.
        guard = loop:after(spacing * #list + M.t_ms + M.hold_ms + 5000, function()
            guard = nil
            for _, c in ipairs(calls) do
                if not c.done then call_fail(c, "call phase deadline", nil) end
            end
            if pending > 0 then pending = 0; done() end
        end)

        for i, p in ipairs(list) do
            local c = make_call(i, p.mo, p.mt, i <= nmedia)
            calls[i] = c
            by_callid[c.call_id] = c
            p.mo.call, p.mt.call = c, c
            -- The P-CSCF hands out protected port pairs from a pool sized by
            -- ims_ipsec_pcscf's ipsec_max_connections (default 2), and shares them
            -- between UEs once it runs out — the pairs even overlap ((5062,5063)
            -- then (5063,5064)). When the MO's protected SERVER port is also the
            -- MT's protected CLIENT port, this P-CSCF sends the terminating INVITE
            -- from the wrong pair: it matches no ESP policy for the callee, so it
            -- leaves unprotected (or not at all) and the callee never rings. Flag
            -- it up front, so the failure is attributed to a stack that is
            -- under-provisioned for concurrent UEs rather than looking like a core
            -- routing bug.
            if p.mo.ch and p.mt.ch and p.mo.ch.p_port_s
               and p.mo.ch.p_port_s == p.mt.ch.p_port_c then
                c.port_clash = true
                st.port_clash = (st.port_clash or 0) + 1
                log.slog(p.mo, "protected ports",
                    ("call %d shares P-CSCF port %d (MO server = MT client); raise ipsec_max_connections")
                    :format(i, p.mo.ch.p_port_s))
            end
            local function fire()
                if c.media then
                    c.sess_mo, c.mstat_mo = open_media(c, p.mo, "mo")
                    c.sess_mt, c.mstat_mt = open_media(c, p.mt, "mt")
                    c.media = (c.sess_mo ~= nil) and (c.sess_mt ~= nil)
                end
                c.offer = sdp.offer{ addr = p.mo.ue_addr, port = media_port(p.mo),
                                     pt = MEDIA.pt, codec = MEDIA.codec,
                                     rate = MEDIA.rate, ptime = MEDIA.ptime_ms }
                local w = build_invite(c)
                feed_ev(c.txn_mo, sip.TE_SEND_REQUEST)
                c.t.t0 = now()
                st.first_invite = st.first_invite or c.t.t0
                st.attempted = st.attempted + 1
                if io_.send(p.mo, "mo", w, ("INVITE (call %d -> %s)"):format(i, c.callee)) then
                    -- The message names what did arrive, so "the core never
                    -- answered" and "the core answered but the callee never rang"
                    -- are not reported as the same failure.
                    carm(c, M.t_ms, function()
                        call_fail(c, c.t.t1 and "no ringing after 100 Trying"
                                            or  "no response to the INVITE")
                    end)
                else
                    call_fail(c, "INVITE send failed", nil)
                end
            end
            if spacing > 0 then loop:after((i - 1) * spacing, fire) else fire() end
        end
    end

    -- ---- media quality, read once the loop has stopped ----
    --
    -- Read here rather than at BYE so late media (rtpengine teardown lag) is
    -- included in the counts. Four independent views per stream, because any one
    -- of them can be the thing that is broken:
    --   1. our own receive stats  — the downlink, as we saw it;
    --   2. the peer's report block — the only measurement of our uplink;
    --   3. RTT from that block's lsr/dlsr;
    --   4. expected-vs-received at a fixed ptime — computed without RTCP at all,
    --      which is what catches "no reports ever arrived" (the shape the
    --      rtpengine routing bug takes) instead of reporting it as no data.
    function P.collect()
        local mm = st.media
        for _, c in ipairs(calls) do
            -- A call that never reached its 200 OK still opened both sockets at
            -- INVITE time, and they carried nothing because nothing was ever
            -- negotiated. Those streams are counted APART from the media figures:
            -- folded in, they report a signalling failure as one-way audio, and
            -- when the only call carrying RTP is the one that failed they leave
            -- every quality row reading "no samples" with nothing to say why.
            local connected, counted = c.answered_at ~= nil, 0
            for _, side in ipairs({ { c.sess_mo, c.mstat_mo }, { c.sess_mt, c.mstat_mt } }) do
                local s, stm = side[1], side[2]
                if s and stm and not connected then
                    mm.unconnected = mm.unconnected + 1
                elseif s and stm then
                    mm.streams = mm.streams + 1
                    counted = counted + 1
                    local ok, sm = pcall(function() return s:stats() end)
                    if ok then
                        mm.early = mm.early + stm.early
                        mm.late  = mm.late + stm.late
                        mm.tx    = mm.tx + sm.tx_packets
                        mm.rx    = mm.rx + sm.rx_packets
                        mm.tx_err = mm.tx_err + (stm.tx_err or 0)
                        mm.tx_why = mm.tx_why or stm.tx_why
                        if sm.rx_packets == 0 then
                            -- One-way audio: the case loss percentages alone
                            -- report as "no data" rather than as broken.
                            mm.zero = mm.zero + 1
                        else
                            local recvd = sm.rx_packets
                            local lost  = math.max(0, sm.rx_lost)
                            mm.dl_loss[#mm.dl_loss + 1] = lost / (recvd + lost) * 100
                            mm.dl_jitter[#mm.dl_jitter + 1] = sm.rx_jitter / (MEDIA.rate / 1000)
                            -- 4: expected from the elapsed span at a fixed ptime.
                            if stm.first and stm.last and stm.last > stm.first then
                                local expect = (stm.last - stm.first) / MEDIA.ptime_ms + 1
                                mm.exp_loss[#mm.exp_loss + 1] =
                                    math.max(0, (expect - recvd) / expect * 100)
                            end
                        end
                        if sm.rtt_ms >= 0 then mm.rtt[#mm.rtt + 1] = sm.rtt_ms end
                        if stm.reports == 0 then mm.no_reports = mm.no_reports + 1 end
                        if stm.ul_frac then
                            mm.ul_loss[#mm.ul_loss + 1] = stm.ul_frac / 256 * 100
                        end
                        for _, j in ipairs(stm.ul_jitter) do
                            mm.ul_jitter[#mm.ul_jitter + 1] = j
                        end
                        -- MOS from this stream's own numbers: one-way delay taken
                        -- as RTT/2 plus a jitter-buffer allowance of
                        -- 2*jitter + ptime.
                        if sm.rx_packets > 0 then
                            local jit   = sm.rx_jitter / (MEDIA.rate / 1000)
                            local delay = (sm.rtt_ms >= 0 and sm.rtt_ms / 2 or 0)
                                          + 2 * jit + MEDIA.ptime_ms
                            local lost  = math.max(0, sm.rx_lost)
                            mm.mos[#mm.mos + 1] =
                                stats_.mos_estimate(delay, lost / (sm.rx_packets + lost) * 100)
                        end
                    end
                end
            end
            if counted > 0 then mm.calls = mm.calls + 1 end
        end
    end

    -- ---- the report ----

    local STAGES = {
        { key = "invite",   label = "INVITE / no response" },
        { key = "ringing",  label = "ringing / no answer" },
        { key = "answered", label = "answered / ACK" },
        { key = "media",    label = "media / talk time" },
        { key = "release",  label = "release (BYE)" },
    }
    local KPIS = {
        { k = "pdd",        label = "post-dial delay  t4-t0" },
        { k = "sst",        label = "session setup    t6-t0" },
        { k = "sst_net",    label = "  ... less our ring hold" },
        { k = "mo_transit", label = "MO->MT transit   t2-t0" },
        { k = "mt_transit", label = "MT->MO return    t4-t3" },
        { k = "answer",     label = "answer transit   t6-t5" },
        { k = "cut",        label = "media cut-through t8-t6" },
        { k = "release",    label = "release delay    t10-t9" },
    }

    function P.report()
        if st.pairs_total == 0 then return end
        log.banner(("Call setup — %d answered / %d attempted (%d of %d structural pair(s) eligible)")
            :format(st.answered, st.attempted, st.eligible, st.pairs_total))
        if st.attempted > 0 then
            log.line("ASR (answer/seizure)", ("%.1f%%"):format(st.answered / st.attempted * 100))
        end
        log.line("calls released (BYE)", tostring(st.released))
        if st.port_clash and st.port_clash > 0 then
            log.line("SHARED P-CSCF PORTS", ("%d call(s): the MO's protected server port is also the")
                :format(st.port_clash))
            log.line("", "MT's protected client port, so the P-CSCF sends the terminating")
            log.line("", "INVITE from the wrong pair. Raise ims_ipsec_pcscf's")
            log.line("", "ipsec_max_connections to the concurrent UE count and restart it.")
        end

        -- Failure attribution: where a call died, the same way a registration's
        -- stage is reported.
        stats_.stages(STAGES, st.stage, 28)

        for _, e in ipairs(KPIS) do
            local s = stats_.summarize(st.kpi[e.k])
            if s then log.line(e.label, stats_.dist(s, "ms")) end
        end
        if stats_.summarize(st.kpi.mo_transit) then
            log.line("", "(transit figures are true one-way latencies: both UEs share this")
            log.line("", " process's monotonic clock, so there is no skew to correct for)")
        end

        -- Failure counts by SIP status, most frequent first.
        for _, e in ipairs(stats_.ranked(st.by_status)) do
            log.line(("failed %d %s"):format(e.k, sip.status_phrase(e.k)), tostring(e.n))
        end

        -- A number the HSS profile does not carry is its own failure, and an easy
        -- one to misread: the I-CSCF answers 404 (no such public identity) or the
        -- S-CSCF 480 (the identity exists but nothing is registered against it)
        -- while registration, IPsec and the datapath all look healthy. Name it,
        -- with both fixes, whenever a number was dialled and those came back.
        if cfg.dial_uri ~= "sip"
           and (st.by_status[404] or st.by_status[604] or st.by_status[480]) then
            log.line("DIALLED NUMBER UNRESOLVED", ("the callee was addressed as %s")
                :format(subs[2] and subs[2].dial or ("a " .. cfg.dial_uri .. " URI")))
            log.line("", "the HSS must return that number as a public identity of the")
            log.line("", "callee's subscription: cx_hss.lua does (HSS_MSISDN, and the")
            log.line("", "same IMS_MSISDN_CC / IMS_MSISDN_DIGITS as here), a real HSS")
            log.line("", "needs the MSISDN provisioned for the IMSI range. CALL_URI=phone")
            log.line("", "dials the sip;user=phone form instead if the core will not route")
            log.line("", "a tel: Request-URI, CALL_URI=sip dials the sip IMPU and needs no")
            log.line("", "number at all.")
        end

        -- ---- media quality ----
        local mm = st.media
        if mm.streams > 0 then
            log.banner(("Media quality — %d stream(s) over %d of %d call(s) carrying RTP  [%s, %d ms, RTCP %d ms]")
                :format(mm.streams, mm.calls, st.media_calls,
                        MEDIA.pt == 0 and "G.711 PCMU" or ("payload type " .. MEDIA.pt),
                        MEDIA.ptime_ms, MEDIA.rtcp_ms))
            log.line("packets sent / received", ("%d / %d"):format(mm.tx, mm.rx))
            if mm.tx_err > 0 then
                log.line("SEND FAILURES", ("%d packet(s) never left the socket: %s")
                    :format(mm.tx_err, tostring(mm.tx_why)))
            end
            log.line("downlink loss (ours)",  stats_.dist(stats_.summarize(mm.dl_loss), "%", "%.2f"))
            log.line("downlink jitter",       stats_.dist(stats_.summarize(mm.dl_jitter), "ms", "%.2f"))
            log.line("uplink loss (peer RR)", stats_.dist(stats_.summarize(mm.ul_loss), "%", "%.2f"))
            log.line("uplink jitter (RR)",    stats_.dist(stats_.summarize(mm.ul_jitter), "ms", "%.2f"))
            log.line("round trip (lsr/dlsr)", stats_.dist(stats_.summarize(mm.rtt), "ms", "%.2f"))
            log.line("expected-vs-received",  stats_.dist(stats_.summarize(mm.exp_loss), "%", "%.2f"))
            -- Labelled at the point of printing, so the number cannot be re-read
            -- later as a decoded-audio score.
            log.line("MOS (G.107 estimate)",  stats_.dist(stats_.summarize(mm.mos), "", "%.2f"))
            log.line("", "MOS is estimated from packet statistics only -- no audio is")
            log.line("", "decoded, so it is not PESQ/POLQA.")
            if mm.zero > 0 then
                log.line("ONE-WAY AUDIO", ("%d of %d stream(s) received nothing at all")
                    :format(mm.zero, mm.streams))
            end
            if mm.unconnected > 0 then
                log.line("streams not counted", ("%d belonged to call(s) that never answered")
                    :format(mm.unconnected))
            end
            if mm.no_reports > 0 then
                log.line("no RTCP received", ("%d stream(s) -- uplink figures come from fewer streams")
                    :format(mm.no_reports))
            end
            if mm.early > 0 then
                log.line("early media", ("%d packet(s) before the 200 OK"):format(mm.early))
            end
            if mm.late > 0 then
                log.line("late media", ("%d packet(s) after the BYE (relay teardown lag)"):format(mm.late))
            end
        elseif mm.unconnected > 0 then
            -- The distinction that matters: nothing was measured because no call
            -- carrying RTP ever connected. Said plainly here, because the
            -- alternative — a page of "no samples" — reads as a media fault.
            log.banner(("Media quality — nothing to measure: every RTP call failed before the answer (%d stream(s))")
                :format(mm.unconnected))
            log.line("", "the sockets opened at INVITE time and no SDP was ever negotiated,")
            log.line("", "so no RTP was expected. The cause is in the call-failure")
            log.line("", "attribution above, not in the media path.")
        elseif st.media_calls > 0 then
            log.banner("Media quality — no stream opened (media sockets need CAP_NET_ADMIN for the UE source)")
        end
    end

    -- Rated over their own window (first INVITE to last answer) so the
    -- registration phase that precedes them does not dilute the figure.
    function P.throughput()
        if st.attempted == 0 then return end
        local w = ((st.last_answer or st.first_invite) - st.first_invite) / 1000
        log.line("calls attempted", ("%d  (%d answered, %d released)")
            :format(st.attempted, st.answered, st.released))
        log.line("calls answered", w > 0
            and ("%d in %.2fs  ->  %.1f/s"):format(st.answered, w, st.answered / w)
            or  ("%d (single burst, under one clock tick)"):format(st.answered))
    end

    -- A phase passes when every call it actually placed was answered.
    function P.ok() return st.attempted == 0 or st.answered == st.attempted end

    return P
end

return M
