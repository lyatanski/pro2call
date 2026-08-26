-- ims/sms_phase.lua — SMS over IMS (TS 24.341), as a phase with its own report.
--
-- The UE puts an RPDU (TS 24.011) carrying a TPDU (TS 23.040) in the body of a
-- SIP MESSAGE with Content-Type application/vnd.3gpp.sms. The path is
-- UE -> P-CSCF -> S-CSCF -> (iFC) IP-SM-GW -> ... -> IP-SM-GW -> S-CSCF ->
-- P-CSCF -> UE, so a delivered message exercises the same terminating routing an
-- MT INVITE does — plus the ISC leg and, in SGd mode, a Diameter round trip to
-- the SC.
--
-- The gateway is bindings/examples/ipsmgw.lua and the service centre
-- bindings/examples/smsc_stub.lua. Nothing here assumes either: with SMS_DIRECT=1
-- the UE addresses the gateway itself, which proves the codec and the emulator
-- without needing the S-CSCF's iFC to fire (the right first step when MT never
-- arrives).
--
-- One message is a chain of hops, and each is timed:
--
--   t0  submit        MESSAGE(RP-DATA / SMS-SUBMIT) to the SC address
--   t1  202 Accepted  the IP-SM-GW took responsibility (TS 24.341 §5.3.2.4)
--   t2  MT MESSAGE    the recipient receives RP-DATA / SMS-DELIVER
--   t3  200 OK        the recipient's SIP hop for that delivery
--   t4  RP-ACK out    the recipient's relay-layer acknowledgement
--   t5  RP-ACK in     the gateway's report back to the sender
--   t6  report        the SMS-STATUS-REPORT, when TP-SRR was set
--
-- t0 and t2 are readings of ONE monotonic clock in THIS process, so t2-t0 is a
-- true one-way core latency carrying no clock skew — the same property the call
-- phase's mo_transit has, and the reason both ends of every pair live in one
-- process.
--
-- Nothing new is needed on the datapath: SMS is signalling and rides the ESP TFT
-- the protected REGISTER already installed. That is asserted rather than assumed
-- — the phase counts its own datagrams through the same sipio the registration
-- does, so a message that never left shows up as a send failure and not as a
-- silent timeout.

local net   = require("net")
local sip   = require("sip")
local sms   = require("sms")     -- SMS codec: the TPDU and RP layers in a MESSAGE body
local cfg   = require("ims.cfg")
local log   = require("ims.log")
local wire  = require("ims.wire")
local stats_ = require("ims.stats")

local M = {}

-- The phase is orthogonal to the call phase: IMS_CALL=0 IMS_SMS=1 measures SMS
-- alone, both together measures them in sequence.
M.on = cfg.flag("IMS_SMS", false)
-- Messages per submitting subscriber. The default walks the whole content
-- matrix once, which is the interesting run; a number larger than the matrix
-- repeats it.
M.per_sub = cfg.num("SMS_PER_SUB")
M.pairs   = cfg.num("SMS_PAIRS")     -- nil = every eligible pair
-- Offered submit rate, like CALL_CPS: 0 is a single burst, consistent with the
-- deliberately unramped registration side.
M.mps  = cfg.num("SMS_MPS", 0)
M.t_ms = cfg.num("SMS_T_MS", 20000)  -- per-message deadline
-- Ask for a status report. It costs an extra MT MESSAGE per message and only the
-- SC can produce one, so it is off unless asked for.
M.srr  = cfg.flag("SMS_SRR", false)
-- Where a submit is addressed. The service centre PSI by default, which is what
-- a UE does; SMS_DIRECT=1 sends to SMS_GW_HOST:SMS_GW_PORT and skips the core.
M.sc_uri  = cfg.str("SMS_SC_URI", "sip:smsc@" .. cfg.realm)
M.sc_addr = cfg.str("SMS_SC_ADDR", "+123456789")
M.direct  = cfg.flag("SMS_DIRECT", false)
M.gw_host = cfg.str("SMS_GW_HOST", "")
M.gw_port = cfg.num("SMS_GW_PORT", 5065)

-- The content matrix. Each entry is submitted and the received text is compared
-- byte for byte with what was sent, which is the assertion that finds the UDH
-- fill-bit and TP-UDL-units bugs and the one thing a hand-typed alphabet table
-- cannot fake. `alpha` nil means let the codec choose (GSM 7-bit when it fits,
-- UCS2 otherwise), as a handset does.
--
-- SMS_MATRIX=gsm7,ucs2 restricts it by name; SMS_MATRIX=off sends the first
-- entry only, for a pure-throughput run where the payload is noise. The
-- non-ASCII text is written as literal UTF-8 bytes, NOT as \u{...}: Lua 5.1 has
-- no \u escape and silently drops the backslash, so "5\u{20AC}" would become the
-- eight ASCII characters "5u{20AC}". The round-trip assertion would still pass —
-- both ends mangle it the same way — while never exercising the extension table
-- or a surrogate pair, which is precisely the coverage this matrix exists for.
local MATRIX = {
    { name = "gsm7",   text = "IMS SMS test 1234567890" },
    { name = "ext",    text = "cost 5€: {a|b} ~ [x] \\y" },
    { name = "accent", text = "èéùìòÇØÅßÉ¤¡§¿ÄÖÑÜàäöñü" },
    { name = "ucs2",   text = "Привет, мир — SMS over IMS" },
    { name = "emoji",  text = "delivered 🙂👍 ok" },
    { name = "binary", text = "\0\1\2\3\127\255\0\254", alpha = "8bit" },
    { name = "full",   text = string.rep("A", 160) },       -- exactly 160 septets
    { name = "concat", text = string.rep("concatenated 1234567890 ", 18) },
}

local ALPHA = { gsm7 = sms.ALPHA_GSM7, ucs2 = sms.ALPHA_UCS2,
                ["8bit"] = sms.ALPHA_8BIT }

-- The matrix, filtered by SMS_MATRIX and repeated to per_sub length.
local function plan_of()
    local want = os.getenv("SMS_MATRIX")
    local base = {}
    if want == "off" then
        base[1] = MATRIX[1]
    elseif want and want ~= "" then
        local keep = {}
        for n in want:gmatch("[^,]+") do keep[n:gsub("%s", "")] = true end
        for _, it in ipairs(MATRIX) do
            if keep[it.name] then base[#base + 1] = it end
        end
        if #base == 0 then base[1] = MATRIX[1] end
    else
        for _, it in ipairs(MATRIX) do base[#base + 1] = it end
    end
    local n = M.per_sub or #base
    local out = {}
    for i = 1, n do out[i] = base[(i - 1) % #base + 1] end
    return out
end

function M.new(ctx)
    local loop, io_, subs = ctx.loop, ctx.io, ctx.subs
    local now = net.now_ms
    local P = {}

    -- Messages in flight, keyed both ways: by the Call-ID of the MESSAGE we sent
    -- (to match its 202/4xx) and by RP-MR (to match the RP-ACK, which comes back
    -- in a NEW out-of-dialog MESSAGE, TS 24.341 §5.3.2.4 — so there is no dialog
    -- to match it against).
    local msgs, by_callid, by_mr = {}, {}, {}
    -- A status report arrives AFTER its message has settled — that is the point
    -- of TP-SRR: the SC reports once the recipient actually has the message,
    -- which is later than the RP-ACK that closed the submit. So the correlation
    -- for it has to outlive by_mr, which finish() clears.
    local rep_by_mr = {}
    local pending, guard, finished = 0, nil, nil
    local st = {
        pairs_total = 0, eligible = 0,
        attempted = 0, accepted = 0, acked = 0, delivered = 0, verified = 0,
        orphans = 0,                          -- deliveries matching no submit
        first_submit = nil, last_delivery = nil,
        reports = 0,                          -- status reports received
        by_cause = {},                        -- RP-ERROR cause -> count
        by_status = {},                       -- non-2xx SIP finals
        stage = {},                           -- where a failed message died
        mismatch = {},                        -- matrix name -> count
        by_matrix = {},                       -- matrix name -> { sent, ok }
        kpi = { accept = {}, ack = {}, transit = {}, deliver_ok = {},
                report = {}, total = {} },
    }
    P.stats = st

    -- Where a submit goes, and from which port. Direct mode skips the core
    -- entirely (proving the codec and the gateway without the S-CSCF's iFC);
    -- otherwise it is an originating request exactly like the INVITE.
    local function build_message(sub, ruri, body, cseq, br)
        local b = wire.builder:request(sip.MESSAGE, ruri)
        if not M.direct then io_.preload_route(b, sub) end
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s")
                            :format(sub.ue_addr, sub.port_uc, br))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, ("<%s>;tag=%s-m%d"):format(sub.impu, sub.imsi, cseq))
            :header(sip.H_TO, ("<%s>"):format(ruri))
            :header(sip.H_CALL_ID, ("sms-%s-%d@%s"):format(sub.imsi, cseq, sub.ue_addr))
            :header(sip.H_CSEQ, ("%d MESSAGE"):format(cseq))
            :header(sip.H_CONTACT, ("<sip:%s:%d>;%s")
                                   :format(sub.ue_addr, sub.port_uc, sms.FEATURE_TAG))
            :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(sub.impu))
            :header(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)
        return b:done(body)
    end

    local function send(sub, wire_bytes, what)
        if M.direct then
            return io_.send_to(sub, M.gw_host, M.gw_port, wire_bytes, what, "direct")
        end
        return io_.send(sub, "mo", wire_bytes, what)
    end

    -- Out-of-dialog answer to a MESSAGE we received. A MESSAGE creates no dialog
    -- (RFC 3428 §4), so there is no route set to echo and no to-tag to remember
    -- — just the RFC 3261 §8.2.6 fields, from this UE's protected port back to
    -- the P-CSCF's protected client port.
    local function respond(sub, req, status, reason)
        local w = wire.response(sub, req, { status = status, reason = reason,
                                            to_tag = sub.imsi .. "-r",
                                            record_route = false })
        local what = ("%d %s (MESSAGE)"):format(status, reason)
        if M.direct then return io_.send_to(sub, M.gw_host, M.gw_port, w, what, "direct") end
        return io_.send(sub, "mt", w, what)
    end

    -- One counter for "work still outstanding", decremented by a finished
    -- message AND by the scheduler releasing its own sentinel. Without the
    -- sentinel a spaced run (SMS_MPS>0) would end the phase the moment its FIRST
    -- message settled, because the rest had not been issued yet and the count
    -- was legitimately zero.
    local function dec()
        pending = pending - 1
        if pending > 0 then return end
        if guard then loop:cancel(guard); guard = nil end
        finished()
    end

    local function finish(msg, ok, stage, detail)
        if msg.done then return end
        msg.done = true
        if msg.timer then loop:cancel(msg.timer); msg.timer = nil end
        by_callid[msg.call_id] = nil
        by_mr[msg.mr_key] = nil
        if not ok then
            stats_.bump(st.stage, stage or "unknown")
            log.slog(msg.mo, "sms", ("message %d (%s) FAILED at %s: %s")
                :format(msg.i, msg.item.name, stage or "?", detail or "?"))
        end
        dec()
    end

    local function arm(msg)
        if msg.timer then loop:cancel(msg.timer) end
        msg.timer = loop:after(M.t_ms, function()
            msg.timer = nil
            -- Name the furthest hop that DID happen, so "the gateway never
            -- answered" and "the gateway answered but the recipient never got
            -- it" are not reported as the same failure.
            local stage, detail
            if not msg.t.t1 then stage, detail = "accept", "no 202 for the submit"
            elseif not msg.t.t2 then stage, detail = "transit", "accepted, but never delivered"
            elseif not msg.t.t4 then stage, detail = "mt_ack", "delivered, but the recipient never acknowledged"
            elseif not msg.t.t5 then stage, detail = "mo_ack", "delivered, but no RP-ACK came back to the sender"
            else stage, detail = "unknown", "every hop completed but the message never settled" end
            finish(msg, false, stage, detail)
        end)
    end

    -- Record a message as fully accounted for: the recipient has it and the
    -- sender has been told. A status report, when asked for, is a separate
    -- (later) event and does not hold the message open.
    local function settle(msg)
        local t, k = msg.t, st.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.accept,     "t0", "t1")
        push(k.transit,    "t0", "t2")   -- MO submit -> MT deliver, one clock
        push(k.deliver_ok, "t2", "t3")
        push(k.total,      "t0", "t4")
        push(k.ack,        "t0", "t5")
        -- No status-report figure here: it arrives after the message has
        -- settled, so the report branch records it directly (see rep_by_mr).
        if t.t2 then st.last_delivery = t.t2 end
        finish(msg, true)
    end

    -- Everything a delivered message has to satisfy before it counts. The text
    -- comparison is the point of the whole phase: a byte difference here is a
    -- codec bug (the septet alignment, the length units, an alphabet mapping)
    -- that no amount of successful signalling reveals.
    local function verify(msg, got)
        local m = st.by_matrix[msg.item.name]
        if not m then m = { sent = 0, ok = 0 }; st.by_matrix[msg.item.name] = m end
        if got == msg.text then
            m.ok = m.ok + 1
            st.verified = st.verified + 1
            return true
        end
        stats_.bump(st.mismatch, msg.item.name)
        log.slog(msg.mt, "sms", ("content MISMATCH (%s): sent %d bytes, received %d")
            :format(msg.item.name, #msg.text, #got))
        return false
    end

    -- A DELIVER arrived at `sub`. Returns the message record this delivery
    -- belongs to, plus — once every part of a concatenated message is in — the
    -- reassembled text and the list of records to verify against it.
    --
    -- A concatenated message is N SIP MESSAGEs, each with its own 202 and its own
    -- RP-ACK, so N records are outstanding and all N have to settle. Only the
    -- last part can be verified, because only then is there a whole text to
    -- compare — so the verification is applied to every member at that point.
    -- Counting the group as one message instead would make `submitted` and
    -- `delivered` disagree by the part count.
    local function match_delivery(sub, tpdu, text)
        local wait = sub.sms_wait
        if not wait or #wait == 0 then return nil, nil, nil end

        if tpdu:has_concat() then
            local c     = tpdu:concat()
            local group = sub.sms_groups[c.ref]
            if not group then return nil, nil, nil end
            local member = group.members[c.seq]
            if not group.parts[c.seq] then
                group.parts[c.seq] = text
                group.got = group.got + 1
            end
            if group.got < group.total then return member, nil, nil end
            sub.sms_groups[c.ref] = nil
            for _, m in ipairs(group.members) do
                for i, w in ipairs(wait) do
                    if w == m then table.remove(wait, i); break end
                end
            end
            return member, table.concat(group.parts, "", 1, group.total), group.members
        end

        -- Single part: match on the content, so a corrupted body becomes a
        -- mismatch rather than a misattributed success.
        for i, m in ipairs(wait) do
            if not m.group and m.text == text then
                table.remove(wait, i)
                return m, text, { m }
            end
        end
        -- Nothing matched: attribute it to the oldest outstanding single-part
        -- message so the difference is counted rather than lost.
        for i, m in ipairs(wait) do
            if not m.group then
                table.remove(wait, i)
                return m, text, { m }
            end
        end
        return nil, nil, nil
    end

    -- A MESSAGE request arrived on a UE's socket. It is either a delivery to
    -- this UE, a relay-layer report about something this UE sent, or a status
    -- report; the RPDU says which, and the direction is SC -> MS in all three
    -- cases because everything reaching a UE comes from the network side.
    function P.request(sub, req)
        local ct = req:header("Content-Type"):lower()
        if not ct:find("vnd.3gpp.sms", 1, true) then
            log.slog(sub, "sms", ("MESSAGE with Content-Type %q -- 415"):format(ct))
            return respond(sub, req, 415, "Unsupported Media Type")
        end

        local okp, rp = pcall(sms.parse_rpdu, req.body, sms.DIR_SC_TO_MS)
        if not okp then
            log.slog(sub, "sms", "unparseable RPDU: " .. log.why(rp))
            return respond(sub, req, 400, "Bad Request")
        end

        -- The gateway's report about a message THIS UE submitted.
        if rp.type == sms.RP_T_ACK or rp.type == sms.RP_T_ERROR then
            respond(sub, req, 200, "OK")
            local msg = by_mr[("%d:%d"):format(sub.i, rp.mr)]
            if not msg then
                return log.slog(sub, "sms", ("%s RP-MR %d matches no submit")
                    :format(rp:type_name(), rp.mr))
            end
            if rp.type == sms.RP_T_ERROR then
                stats_.bump(st.by_cause, rp.cause)
                return finish(msg, false, "rp_error",
                              ("RP-ERROR %d (%s)"):format(rp.cause, rp:cause_name()))
            end
            st.acked = st.acked + 1
            msg.t.t5 = now()
            log.slog(sub, "sms", ("RP-ACK for message %d (%s) after %d ms")
                :format(msg.i, msg.item.name, msg.t.t5 - msg.t.t0))
            -- The sender is satisfied. The recipient may already have
            -- acknowledged (the gateway is a store-and-forward hop, so the order
            -- is not fixed); settle once both are in.
            if msg.t.t4 then settle(msg) end
            return
        end

        if rp.type ~= sms.RP_T_DATA or not rp:has_tpdu() then
            return respond(sub, req, 400, "Bad Request")
        end

        local okt, tpdu = pcall(function() return rp:tpdu() end)
        if not okt then
            log.slog(sub, "sms", "unparseable TPDU: " .. log.why(tpdu))
            return respond(sub, req, 400, "Bad Request")
        end

        -- A status report: the SC saying what became of a submitted message.
        if tpdu.type == sms.T_STATUS_REPORT then
            respond(sub, req, 200, "OK")
            local ack = sms.ack(sms.DIR_MS_TO_SC, rp.mr)
            sub.sms_cseq = (sub.sms_cseq or 0) + 1
            send(sub, build_message(sub, M.sc_uri, ack, sub.sms_cseq,
                     ("z9hG4bK-smsr-%s-%d"):format(sub.imsi, sub.sms_cseq)),
                 "MESSAGE (RP-ACK for a status report)")
            st.reports = st.reports + 1
            local msg = rep_by_mr[("%d:%d"):format(sub.i, tpdu.mr)]
            if msg then
                -- Recorded straight into the distribution: the message has
                -- already settled, so settle() will not run again.
                local k = st.kpi.report
                k[#k + 1] = now() - msg.t.t0
                if not tpdu:delivered() then
                    stats_.bump(st.stage, "report_failed")
                    log.slog(sub, "sms", ("status report for message %d says %s")
                        :format(msg.i, tpdu:status_name()))
                else
                    log.slog(sub, "sms", ("status report for message %d: %s")
                        :format(msg.i, tpdu:status_name()))
                end
            else
                log.slog(sub, "sms", ("status report TP-MR %d: %s")
                    :format(tpdu.mr, tpdu:status_name()))
            end
            return
        end

        if tpdu.type ~= sms.T_DELIVER then
            log.slog(sub, "sms", ("ignoring a delivered %s"):format(tpdu:type_name()))
            return respond(sub, req, 200, "OK")
        end

        -- A delivery. Answer the SIP hop first, then the relay layer.
        local t2 = now()
        respond(sub, req, 200, "OK")
        local t3 = now()
        st.delivered = st.delivered + 1

        local okx, text = pcall(function() return tpdu:text() end)
        if not okx then
            log.slog(sub, "sms", "undecodable user data: " .. log.why(text))
            text = ""
        end

        -- RP-ACK back towards the SC: a NEW out-of-dialog MESSAGE from this UE
        -- (TS 24.341 §5.3.2.6), not a body on the 200 OK.
        local ack = sms.ack(sms.DIR_MS_TO_SC, rp.mr)
        sub.sms_cseq = (sub.sms_cseq or 0) + 1
        local br = ("z9hG4bK-smsa-%s-%d"):format(sub.imsi, sub.sms_cseq)
        local sent = send(sub, build_message(sub, M.sc_uri, ack, sub.sms_cseq, br),
                          ("MESSAGE (RP-ACK, RP-MR %d)"):format(rp.mr))
        local t4 = sent and now() or nil

        local msg, whole, members = match_delivery(sub, tpdu, text)
        if not msg then
            st.orphans = st.orphans + 1
            return log.slog(sub, "sms", ("delivery from %s matches no submit (%d bytes)")
                :format(tpdu.addr:display(), #text))
        end

        -- Timestamp the part that actually arrived, whichever it is.
        msg.t.t2, msg.t.t3, msg.t.t4 = msg.t.t2 or t2, t3, t4
        if not whole then
            if cfg.verbose then
                local c = tpdu:concat()
                log.slog(sub, "sms", ("part %d/%d of reference %d in")
                    :format(c.seq, c.total, c.ref))
            end
            return
        end

        log.slog(sub, "sms", ("delivered message %d (%s) from %s in %d ms")
            :format(msg.i, msg.item.name, tpdu.addr:display(), t2 - msg.t.t0))
        -- The whole text exists now, so every record in the group is verified
        -- against it and settles as soon as its own RP-ACK is in.
        for _, m in ipairs(members) do
            verify(m, whole)
            if m.t.t5 then settle(m) end
        end
    end

    -- Responses to a MESSAGE we sent: the 202 for a submit, or the 200 for an
    -- RP-ACK we relayed (which needs no bookkeeping).
    function P.response(sub, m)
        local msg = by_callid[m:call_id()]
        if not msg then
            if m.status >= 300 then
                stats_.bump(st.by_status, m.status)
                log.slog(sub, "sms", ("%d %s for a MESSAGE we no longer track")
                    :format(m.status, m.reason))
            end
            return
        end
        if m.status < 200 then return end          -- a provisional, if any
        if m.status >= 300 then
            stats_.bump(st.by_status, m.status)
            return finish(msg, false, "accept", ("%d %s"):format(m.status, m.reason))
        end
        if msg.t.t1 then return end                -- retransmitted 202
        msg.t.t1 = now()
        st.accepted = st.accepted + 1
        log.slog(sub, "sms", ("%d %s for message %d (%s) after %d ms")
            :format(m.status, m.reason, msg.i, msg.item.name, msg.t.t1 - msg.t.t0))
    end

    function P.begin(done)
        finished = done
        -- Structural pairs, as in the call phase: 1<->2, 3<->4, ... The odd index
        -- submits, the even index receives. The denominator stays the structural
        -- count, so a registration failure cannot turn into a perfect SMS
        -- success rate.
        st.pairs_total = math.floor(#subs / 2)
        local list = {}
        for p = 1, st.pairs_total do
            local mo, mt = subs[2 * p - 1], subs[2 * p]
            local ready = mo.registered and mt.registered and mo.sock and mt.sock
                and (M.direct or #(mo.svc_route or {}) > 0)
            if ready then
                st.eligible = st.eligible + 1
                if not M.pairs or #list < M.pairs then
                    list[#list + 1] = { mo = mo, mt = mt }
                end
            end
        end

        local plan = plan_of()
        if #list == 0 then
            log.banner(("SMS — none sent (%d/%d pair(s) eligible; a message needs BOTH ends registered%s)")
                :format(st.eligible, st.pairs_total, M.direct and "" or " with a Service-Route"))
            return done()
        end

        local names = {}
        for _, it in ipairs(plan) do names[#names + 1] = it.name end
        log.banner(("SMS — %d of %d eligible pair(s) (%d structural), %d message(s) each%s")
            :format(#list, st.eligible, st.pairs_total, #plan,
                    M.mps > 0 and (" at %.1f msg/s"):format(M.mps) or " in one burst"))
        log.line("destination", M.direct
            and ("%s:%d (direct, bypassing the core)"):format(M.gw_host, M.gw_port)
            or M.sc_uri)
        log.line("content", table.concat(names, " "))
        if M.srr then log.line("status reports", "requested (TP-SRR)") end

        -- Build the work list first, so the deadline can be sized from it.
        local work = {}
        for _, p in ipairs(list) do
            p.mt.sms_wait   = p.mt.sms_wait or {}
            p.mt.sms_groups = p.mt.sms_groups or {}
            for _, item in ipairs(plan) do
                work[#work + 1] = { mo = p.mo, mt = p.mt, item = item }
            end
        end

        if M.direct and M.gw_host == "" then
            log.banner("SMS — SMS_DIRECT=1 needs SMS_GW_HOST; skipping the phase")
            return done()
        end

        local spacing = M.mps > 0 and math.floor(1000 / M.mps) or 0
        pending = 0
        local mr_seq = 0

        -- One submit, possibly split into several messages.
        local function submit(w, idx)
            local mo, mt, item = w.mo, w.mt, w.item
            local alpha = item.alpha and ALPHA[item.alpha] or sms.ALPHA_AUTO

            -- The recipient's number in TP-DA. Deliberately the IMSI digits and
            -- NOT mt.msisdn: an SMS is resolved by the IP-SM-GW, not by the HSS
            -- profile, and ipsmgw.lua's default rule turns the digits it is given
            -- straight back into sip:<digits>@<realm> — which is the IMPU this
            -- run registered, so nothing has to be provisioned or configured. The
            -- MSISDN form works too, but only once the gateway is told to produce
            -- the matching identity: run it with IPSMGW_TEL=1
            -- (sip:+<digits>@<realm>;user=phone, the alias cx_hss.lua puts in the
            -- profile) and set `to` to mt.msisdn.
            local to = mt.imsi

            local okp, parts = pcall(function()
                mr_seq = mr_seq + 1
                local args = { to = to, text = item.text, sc = M.sc_addr,
                               alphabet = alpha, srr = M.srr, mr = mr_seq % 256 }
                return sms.parts(sms.submit_parts(args, mr_seq % 65536, false))
            end)
            if not okp then
                log.banner(("SMS — cannot build %q: %s"):format(item.name, log.why(parts)))
                return
            end

            -- A multi-part message needs a record the recipient can find by
            -- concatenation reference, holding every part's message record so all
            -- of them settle when the last part arrives.
            local group = nil
            if #parts > 1 then
                group = { ref = mr_seq % 65536, total = #parts, got = 0,
                          parts = {}, members = {} }
                mt.sms_groups[group.ref] = group
            end
            for pi, rpdu in ipairs(parts) do
                mo.sms_cseq = (mo.sms_cseq or 0) + 1
                local mr = (mr_seq + pi - 1) % 256
                local br = ("z9hG4bK-sms-%s-%d"):format(mo.imsi, mo.sms_cseq)
                local w2 = build_message(mo, M.sc_uri, rpdu, mo.sms_cseq, br)
                local msg = {
                    i = idx, mo = mo, mt = mt, item = item,
                    text = item.text, group = group,
                    mr = mr, mr_key = ("%d:%d"):format(mo.i, mr),
                    call_id = ("sms-%s-%d@%s"):format(mo.imsi, mo.sms_cseq, mo.ue_addr),
                    t = {}, done = false,
                }
                msgs[#msgs + 1] = msg
                by_callid[msg.call_id] = msg
                by_mr[msg.mr_key] = msg
                rep_by_mr[msg.mr_key] = msg
                mt.sms_wait[#mt.sms_wait + 1] = msg
                if group then group.members[pi] = msg end
                pending = pending + 1
                st.attempted = st.attempted + 1
                local mm = st.by_matrix[item.name]
                if not mm then mm = { sent = 0, ok = 0 }; st.by_matrix[item.name] = mm end
                mm.sent = mm.sent + 1

                msg.t.t0 = now()
                st.first_submit = st.first_submit or msg.t.t0
                if send(mo, w2, ("MESSAGE submit %d/%d (%s -> %s)")
                                :format(pi, #parts, item.name, to)) then
                    arm(msg)
                else
                    finish(msg, false, "send", "MESSAGE send failed")
                end
            end
        end

        -- Overall deadline so a lost report cannot hang the run.
        guard = loop:after(spacing * #work + M.t_ms + 5000, function()
            guard = nil
            for _, msg in ipairs(msgs) do
                if not msg.done then finish(msg, false, "guard", "SMS phase deadline") end
            end
            if pending > 0 then pending = 0; done() end
        end)

        -- The sentinel: one unit of outstanding work standing for "not every
        -- submit has been issued yet". Released after the last one, so a message
        -- that settles before its successors are even scheduled cannot end the
        -- phase early.
        pending = 1
        if spacing > 0 then
            for i, w in ipairs(work) do
                loop:after((i - 1) * spacing, function() submit(w, i) end)
            end
            loop:after((#work - 1) * spacing + 1, dec)
        else
            for i, w in ipairs(work) do submit(w, i) end
            dec()
        end
    end

    -- ---- the report ----
    --
    -- Validity first (did the content survive), then the per-hop latencies. The
    -- percentiles are reported rather than means for the same reason the call
    -- phase reports them: a mean hides the knee, and the knee is the finding.
    local STAGES = {
        { key = "send",     label = "MESSAGE send failed" },
        { key = "accept",   label = "no 202 for the submit" },
        { key = "rp_error", label = "refused (RP-ERROR)" },
        { key = "transit",  label = "accepted, never delivered" },
        { key = "mt_ack",   label = "delivered, recipient never acknowledged" },
        { key = "mo_ack",   label = "delivered, no RP-ACK to the sender" },
        { key = "report_failed", label = "status report says not delivered" },
        { key = "guard",    label = "SMS phase deadline" },
        { key = "unknown",  label = "other" },
    }

    function P.report()
        if st.pairs_total == 0 then return end
        log.banner(("SMS — %d delivered / %d submitted (%d of %d structural pair(s) eligible)")
            :format(st.delivered, st.attempted, st.eligible, st.pairs_total))
        if st.attempted > 0 then
            log.line("delivery rate", ("%.1f%%"):format(st.delivered / st.attempted * 100))
            log.line("accepted (202)", ("%d  (%.1f%%)")
                :format(st.accepted, st.accepted / st.attempted * 100))
            log.line("acknowledged (RP-ACK)", ("%d  (%.1f%%)")
                :format(st.acked, st.acked / st.attempted * 100))
        end
        if st.reports > 0 then log.line("status reports", tostring(st.reports)) end
        if st.orphans > 0 then
            log.line("UNMATCHED deliveries", ("%d — arrived but match no submit"):format(st.orphans))
        end

        -- Content integrity: the assertion the whole phase exists for. A byte
        -- difference is a codec bug — the UDH septet alignment, the TP-UDL units,
        -- an alphabet mapping — and no amount of successful signalling reveals it.
        local nmis = stats_.total(st.mismatch)
        if next(st.by_matrix) then
            local names = {}
            for n in pairs(st.by_matrix) do names[#names + 1] = n end
            table.sort(names)
            local parts = {}
            for _, n in ipairs(names) do
                local m = st.by_matrix[n]
                parts[#parts + 1] = ("%s %d/%d"):format(n, m.ok, m.sent)
            end
            log.line("content verified", table.concat(parts, "  "))
        end
        if nmis > 0 then
            log.line("CONTENT MISMATCHES", ("%d — the received text differs from what was sent")
                :format(nmis))
            for n, c in pairs(st.mismatch) do print(("     %-28s %d"):format(n, c)) end
        end

        -- Failure attribution: the furthest hop each failed message reached.
        local nfail = stats_.total(st.stage)
        if nfail > 0 then
            log.line("failed", tostring(nfail))
            stats_.stage_counts(STAGES, st.stage)
        end
        for _, e in ipairs(stats_.ranked(st.by_cause)) do
            print(("     RP-ERROR %-36s %d"):format(sms.rp_cause_name(e.k), e.n))
        end
        for _, e in ipairs(stats_.ranked(st.by_status)) do
            print(("     SIP %-40s %d"):format(("%d %s"):format(
                e.k, sip.status_phrase(e.k)), e.n))
        end

        local k = st.kpi
        log.banner("SMS latency (percentiles, not means — a mean hides the knee)")
        log.line("submit -> 202 Accepted", stats_.dist(stats_.summarize(k.accept), "ms"))
        log.line("submit -> MT delivery",  stats_.dist(stats_.summarize(k.transit), "ms"))
        log.line("delivery -> 200 OK",     stats_.dist(stats_.summarize(k.deliver_ok), "ms"))
        log.line("submit -> recipient ACK", stats_.dist(stats_.summarize(k.total), "ms"))
        log.line("submit -> sender RP-ACK", stats_.dist(stats_.summarize(k.ack), "ms"))
        if #k.report > 0 then
            log.line("submit -> status report", stats_.dist(stats_.summarize(k.report), "ms"))
        end
        print("   submit -> MT delivery is a true one-way core latency: both marks are")
        print("   readings of ONE monotonic clock in this process, so no skew is in it.")
    end

    function P.throughput()
        if st.attempted == 0 or not st.first_submit then return end
        local w = ((st.last_delivery or st.first_submit) - st.first_submit) / 1000
        log.line("messages submitted", ("%d  (%d delivered, %d verified)")
            :format(st.attempted, st.delivered, st.verified))
        log.line("messages delivered", w > 0
            and ("%d in %.2fs  ->  %.1f/s"):format(st.delivered, w, st.delivered / w)
            or  ("%d (single burst, under one clock tick)"):format(st.delivered))
    end

    -- A phase passes when every message it sent arrived with its content intact.
    function P.ok()
        return st.attempted == 0
            or (st.delivered == st.attempted and st.verified == st.attempted)
    end

    return P
end

return M
