-- ims/rereg_phase.lua — registering again from a new address, as a phase with
-- its own report.
--
-- A subscriber that is registered raises a SECOND PDN connection, is given a
-- different IP address with it, and registers again from there. It does not
-- de-register first, and nothing the first registration holds is released: that
-- is the whole point. It is what a handset does when it loses coverage and
-- comes back on a different PDN, when a PGW re-anchors it, or simply when it is
-- switched off and on again long before its contact expires — and it is the one
-- moment where the core has to notice that the binding it holds for the old
-- address is dead.
--
-- Whether it does is not something the new registration succeeding says
-- anything about. A registrar adds a binding per contact URI and removes one
-- only at Expires: 0 or at expiry (RFC 3261 §10.3), so keeping BOTH is the
-- letter of the rule and a perfectly ordinary thing to do — and a core that
-- keeps both will fork every terminating request to an address nothing answers
-- on, for as long as the registration lasts (IMS_EXPIRES defaults to a week).
--
-- There is a third answer, and it is the one a well-behaved registrar gives:
-- the 200 OK lists the old contact with an expiry of a second or two. That is a
-- registrar that DID notice, cutting the binding short instead of dropping it
-- outright, so its subscribers get the de-registration NOTIFY the event package
-- exists for. It is only half an answer, though — the binding is scheduled to
-- go, not gone — so the probes below are held back until the expiry the
-- registrar itself named has passed, and they then ask whether anything still
-- holds it. The state is read from the two nodes that hold it, from both
-- directions:
--
--   the registrar (S-CSCF)  the Contact set in the REGISTER 200 OK, and then a
--                           reg-event PROBE — a short-lived SUBSCRIBE — sent
--                           from the NEW contact. Its reg-info body lists every
--                           binding the registrar holds for the identity, which
--                           is what turns this from an inference into a
--                           reading; and the NOTIFY carrying it is at the same
--                           time proof that terminating requests reach the new
--                           contact at all.
--
--   the proxy (P-CSCF)      the same probe sent from the STALE contact, over
--                           the SAs the old registration raised. A P-CSCF that
--                           has dropped that binding answers 403 — its
--                           pcscf_is_registered() check, which route[MORIG]
--                           puts every originating request through, whatever
--                           its method; one that still holds it forwards the
--                           request into the core like any other. Plus anything
--                           the core sends the stale contact unbidden, which is
--                           the same finding observed rather than probed for.
--
-- The two can disagree, and which of them leaked is the difference between a
-- stale row in a database and terminating requests actually being sent to an
-- address that is gone. Both are reported; either one is a leak.
--
-- The stale contact's probe subscribes from the same contact the reg-event
-- phase subscribed from, and a registrar keys a reg subscription on (watcher
-- contact, presentity) — so the two may be folded into one, and the
-- de-registration NOTIFY at teardown then arrives on this phase's dialog rather
-- than on that phase's. It is one reason this phase runs last: by then the
-- reg-event phase has made its measurement, and everything after is this one's.
--
-- Everything the old incarnation holds stays up for exactly this reason — its
-- socket on the loop, its ESP SAs in the kernel, its PAA on `lo`, its bearers
-- in the datapath — so a NOTIFY the core sends to the old contact is received
-- and answered rather than lost, and "the core still routes there" is an
-- observation instead of a guess.
--
-- The access half — the Create Session that earns the new address, its bearers
-- and TFTs, the new transparent socket — belongs to the script that owns the
-- access and arrives here as ctx.access.relocate. Over Gm there is no second
-- address to move to, which is why this phase exists only in the S5/S8 test.

local net    = require("net")
local sip    = require("sip")
local cfg    = require("ims.cfg")
local log    = require("ims.log")
local ue     = require("ims.ue")
local wire   = require("ims.wire")
local stats_ = require("ims.stats")
-- The reg-info reader and the SUBSCRIBE builder, shared with the phase that
-- opens real subscriptions: one document format read one way, whoever asked.
local reg_event = require("ims.reg_event")

local M = {}

-- Off by default. It is the one phase that deliberately leaves the core holding
-- state a run did not ask for — a second registration per subscriber, and
-- possibly a stale binding after it — so a run opts into it.
M.on     = cfg.flag("IMS_REREG", false)
M.cycles = math.max(1, math.floor(cfg.num("REREG_CYCLES", 1)))
M.nsubs  = cfg.num("REREG_SUBS")            -- nil = every eligible subscriber
-- Offered relocation rate, like CALL_CPS: the independent variable, not a
-- remedy for failures. 0 (the default) is a single burst.
M.rps    = cfg.num("REREG_RPS", 0)
M.t_ms   = cfg.num("REREG_T_MS", 20000)     -- Create Session + re-REGISTER
M.probe_t_ms = cfg.num("REREG_PROBE_T_MS", 5000)

-- An expiry this short on the contact left behind is a registrar timing the
-- binding out, not keeping it: nothing asked for it (the REGISTER asked for
-- IMS_EXPIRES, a week by default) and no refresh will renew it, because the UE
-- that would have refreshed it is registered somewhere else now.
M.expiring_s = cfg.num("REREG_EXPIRING_S", 60)
-- The cap on how long the probes wait for that expiry to pass. A registrar is
-- free to name any expiry it likes; this phase is not free to hold a run open
-- for it, so past the cap the probes go out anyway and report what they find.
M.settle_ms  = cfg.num("REREG_SETTLE_MS", 8000)

-- Expires on the two probes, and the reason it is not 0.
--
-- Expires: 0 is what this wants in principle: RFC 6665 §4.4.3 makes it a FETCH
-- — one NOTIFY carrying the current document, no subscription left behind, so
-- the probe reads the state without becoming part of it. kamailio's
-- ims_registrar_scscf does not implement it. subscribe_to_reg() maps a
-- non-positive Expires straight to UNSUBSCRIBE (registrar_notify.c), looks the
-- watcher contact up in usrloc, and when it finds no subscription to remove it
-- logs "could not get subscriber" and exits the route WITHOUT REPLYING — the
-- probe times out and reports "unreachable" for a contact the proxy forwarded
-- perfectly well. When it does find one, it removes it, which on the stale
-- contact is the reg-event phase's own subscription.
--
-- So the default is a short-lived subscription: answered in milliseconds,
-- NOTIFYed with the document, and reaped by the de-REGISTER at teardown well
-- before it expires. Set REREG_PROBE_EXPIRES=0 against a notifier that does
-- implement the fetch.
M.probe_expires = cfg.num("REREG_PROBE_EXPIRES", 60)

-- Which Call-ID the new REGISTER carries. "same" carries the initial
-- registration's over to the new address (TS 24.229 §5.1.1.4), which is the
-- interesting case: it is the only thing that lets a registrar recognise the
-- two registrations as one UE rather than two, so a core that does not clean up
-- under it will not clean up under anything. "new" derives a fresh one from the
-- new address, modelling a handset that was switched off and on again — the
-- case where the core has nothing but the identity to correlate on.
M.call_id = (cfg.str("REREG_CALLID", "same")):lower()

-- REREG_STRICT=0 measures without judging: the report is identical, only the
-- run's exit status stops depending on what the core did with the old contact.
M.strict = cfg.flag("REREG_STRICT", true)

function M.new(ctx)
    local loop, io_, subs = ctx.loop, ctx.io, ctx.subs
    local access = ctx.access
    local now = net.now_ms
    local P = {}

    -- The two probes of each relocation, keyed by the Call-ID of the SUBSCRIBE
    -- that carries them, so they are answered here and not by the reg-event
    -- phase — whose own subscriptions these are not, and whose report they
    -- would otherwise turn up in as orphans.
    local by_callid = {}
    local records = {}
    local pending, guard, finished = 0, nil, nil

    local st = {
        eligible = 0, attempted = 0, relocated = 0, registered = 0,
        probes = 0, notified = 0,
        waited = 0,          -- relocations that had an expiry to wait out
        binding = {},        -- what the registrar said about the old contact
        proxy   = {},        -- what the P-CSCF did with it
        verdict = {},        -- the two together
        stale_rx = {},       -- unsolicited traffic to a contact that was left
        stage = {},          -- where a relocation died, and why
        by_status = {},      -- non-2xx finals for a probe
        first = nil, last = nil,
        kpi = { pdn = {}, rereg = {}, probe = {}, total = {} },
    }
    P.stats = st

    -- ---- reading the registrar's document ----

    -- What a reg-info document (RFC 3680 §5.1) says about the two contacts this
    -- relocation is about. Every <registration> element is scanned rather than
    -- only the one naming an identity of this UE: a contact bound to ANY
    -- identity of the implicit registration set is a contact the core will route
    -- to, and it is the contact, not the identity, that is under test here.
    local function read_doc(r, m)
        -- Nothing to look for until the relocation has both addresses: a
        -- document that arrives while the new PDN connection is still being
        -- raised describes a state this relocation has not reached.
        if not (r.old_at and r.new_at) then return nil end
        if not m.body or m.body == "" then return nil end
        local ct = m:header("Content-Type"):lower()
        if not ct:find("reginfo+xml", 1, true) then return nil end
        local regs = reg_event.parse(m.body)
        if #regs == 0 then return nil end
        -- Matched on address:port rather than on the whole URI, exactly as the
        -- reg-event phase matches its own binding: the registrar is free to
        -- hand a contact back with parameters of its own (received, expires,
        -- the +g.3gpp.smsip feature tag) and none of them change which socket
        -- the binding points at.
        local function look(want)
            local seen, active, event = false, false, ""
            for _, rg in ipairs(regs) do
                for _, c in ipairs(rg.contacts) do
                    if c.uri:find(want, 1, true) then
                        seen = true
                        if c.state == "active" then active = true end
                        if c.event ~= "" then event = c.event end
                    end
                end
            end
            return { seen = seen, active = active, event = event }
        end
        local n = 0
        for _, rg in ipairs(regs) do n = n + #rg.contacts end
        return { at = now(), identities = #regs, contacts = n,
                 old = look(r.old_at), new = look(r.new_at) }
    end

    -- ---- the verdict ----

    -- The binding the 200 OK listed for the contact left behind, if it listed
    -- one. Matched on address:port rather than on the whole URI, for the reason
    -- read_doc matches that way.
    local function listed_old(r)
        for _, c in ipairs(r.contacts or {}) do
            if c.uri:find(r.old_at, 1, true) then return c end
        end
        return nil
    end

    -- The registrar's word on the contact that was left behind, taken from the
    -- strongest source that answered.
    --
    -- A document beats the 200 OK's Contact set, and not only because it is
    -- newer: the set is not conclusive in one direction. A registrar is free to
    -- echo only the binding it has just written, so a set the old contact is
    -- missing from says nothing — unless the set names more than one binding,
    -- which makes it an enumeration and the absence an answer. Hence
    -- "unlisted", for the case where the 200 OK did not mention it and there
    -- was nothing else to ask.
    --
    -- Finding it there IS conclusive, and the expiry is what it says: the one
    -- the UE asked for means the registrar is holding the binding, a second or
    -- two means it noticed and is timing it out, and zero means it has already
    -- removed it.
    local function binding_of(r)
        local q = r.probe.new
        local d = (q and q.doc) or r.doc
        if d then
            if not d.old.seen then return "gone" end
            return d.old.active and "active" or "terminated"
        end
        if not (r.contacts and #r.contacts > 0) then return "unknown" end
        local c = r.listed
        if not c then return #r.contacts > 1 and "gone" or "unlisted" end
        if c.expires == 0 then return "gone" end
        if c.expires and c.expires <= M.expiring_s then return "expiring" end
        return "active"
    end

    -- What the P-CSCF did with the contact that was left behind. Anything it
    -- sent there unbidden settles it before any probe does — that is the
    -- forwarding itself, not a question about it. Otherwise the probe from the
    -- stale contact answers: 403 is its registration check refusing an
    -- originating request from a binding it no longer has, and any other final
    -- means the request was forwarded into the core like any other. No answer
    -- at all is neither: the binding may be gone, and so may the SAs the
    -- request rode, and from here those look the same.
    local function proxy_of(r)
        if next(r.stale_rx) then return "forwarding" end
        local q = r.probe.old
        if not (q and q.result) then return "unknown" end
        if q.status == 403 then return "rejected" end
        if q.status then return "forwarding" end
        return "unreachable"
    end

    local function verdict_of(r)
        local leak  = (r.binding == "active") or (r.proxy == "forwarding")
        local clean = (r.binding == "gone" or r.binding == "terminated"
                       or r.binding == "expiring")
                      or (r.proxy == "rejected")
        if leak and clean then return "split" end
        if leak  then return "retained" end
        if clean then return "cleaned" end
        return "unknown"
    end

    -- ---- one relocation ----

    local finish, settle_probe, send_probe

    -- One unit of outstanding work per subscriber, plus the scheduler's own
    -- sentinel — a spaced run would otherwise end the phase the moment its
    -- FIRST subscriber settled, because the rest had not started yet.
    local function dec()
        pending = pending - 1
        if pending > 0 then return end
        if guard then loop:cancel(guard); guard = nil end
        finished()
    end

    finish = function(r, stage, detail)
        if r.done then return end
        r.done = true
        if r.timer then loop:cancel(r.timer); r.timer = nil end
        for _, k in ipairs({ "new", "old" }) do
            local q = r.probe[k]
            if q and q.timer then loop:cancel(q.timer); q.timer = nil end
        end
        st.last = now()
        if stage then
            stats_.fail(st.stage, stage, detail or "unknown")
            log.slog(r.sub, "re-registration", ("FAILED at %s: %s")
                :format(stage, detail or "?"))
        else
            r.binding = binding_of(r)
            r.proxy   = proxy_of(r)
            r.verdict = verdict_of(r)
            stats_.bump(st.binding, r.binding)
            stats_.bump(st.proxy,   r.proxy)
            stats_.bump(st.verdict, r.verdict)
            st.kpi.total[#st.kpi.total + 1] = st.last - r.t0
            log.slog(r.sub, "old contact", ("%s -> %s: registrar %s, P-CSCF %s (%s)")
                :format(r.old_at, r.new_at or "?", r.binding, r.proxy, r.verdict))
        end
        r.after(stage == nil)
    end

    -- A probe settled: by its document, by a final that is an answer in itself,
    -- or by its own deadline. The relocation is judged when both have.
    settle_probe = function(q, result)
        if q.result then return end
        q.result = result
        if q.timer then loop:cancel(q.timer); q.timer = nil end
        -- Where the answer came back matters as much as what it said: a reply
        -- that reaches an address other than the one that asked is the core
        -- routing by contact rather than by Via, and the whole question here is
        -- which contact it believes in.
        local back = q.at or q.reply_at
        log.slog(q.from, ("probe from the %s contact"):format(q.which),
            ("%s:%d -> %s%s"):format(q.from.ue_addr, q.from.port_uc, result,
                (back and back ~= q.from)
                    and (" (answered to %s:%d)"):format(back.ue_addr, back.port_uc) or ""))
        local r = q.r
        r.waiting = r.waiting - 1
        if r.waiting <= 0 then finish(r) end
    end

    -- Both probes, sent together — after the wait, when the registrar named an
    -- expiry to wait out.
    local function send_probes(r)
        if r.done then return end
        r.waiting = 1                     -- a sentinel of the same kind as dec()'s:
        send_probe(r, r.sub, "new")            -- a first probe that fails to send must
        if r.old then send_probe(r, r.old, "old") end   -- not judge the relocation
        r.waiting = r.waiting - 1                  -- before the second is even sent
        if r.waiting <= 0 then finish(r) end
    end

    send_probe = function(r, from, which)
        local q = {
            r = r, which = which, from = from, t0 = now(),
            -- The presentity is the identity the network associated with the
            -- registration, for the same reason the reg-event phase's is: the
            -- temporary IMPU is barred, and a barred identity is not one the
            -- P-CSCF will assert or the S-CSCF authorise.
            impu     = from.default_impu or from.impu,
            call_id  = ("x%d-%d%s@%s"):format(from.i, r.gen, which, from.ue_addr),
            from_tag = ("x%d%d%s"):format(from.i, r.gen, which),
            branch   = ("z9hG4bKx%d-%d%s"):format(from.i, r.gen, which),
            cseq     = 1, expires = M.probe_expires,
        }
        r.probe[which] = q
        by_callid[q.call_id] = q
        r.waiting = r.waiting + 1
        st.probes = st.probes + 1
        if not io_.send(from, "mo", reg_event.subscribe(io_, from, q),
                        ("SUBSCRIBE (reg probe, %s contact)"):format(which)) then
            return settle_probe(q, "send failed")
        end
        q.timer = loop:after(M.probe_t_ms, function()
            q.timer = nil
            settle_probe(q, q.status and ("%d, then no document"):format(q.status)
                            or "no answer")
        end)
    end

    -- Move one subscriber onto a new PDN connection and judge what the core
    -- does with the contact it leaves. `after(ok)` chains the next cycle.
    local function relocate(sub, gen, after)
        local r = {
            sub = sub, gen = gen, t0 = now(), waiting = 0, after = after,
            old_at = ("%s:%d"):format(sub.ue_addr, sub.port_uc),
            probe = {}, stale_rx = {}, done = false,
        }
        records[#records + 1] = r
        sub.rereg = r
        st.attempted = st.attempted + 1
        st.first = st.first or r.t0

        -- Pinned before the REGISTER that uses it, and only once: every later
        -- cycle keeps the Call-ID this one fixed, which is what "the same
        -- registration" means over a run that relocates a subscriber twice.
        if M.call_id == "same" then
            sub.reg_call_id = sub.reg_call_id
                or ("%s@%s"):format(sub.imsi, sub.ue_addr)
        end

        -- The access is given the whole of it; this deadline covers both halves
        -- so neither a PGW that never answers nor a core that never completes
        -- the registration can leave the phase waiting on its guard.
        r.timer = loop:after(M.t_ms, function()
            r.timer = nil
            finish(r, r.t_pdn and "register" or "session", "relocation deadline")
        end)

        access.relocate(sub,
            -- The new PDN connection is up: `old` is the incarnation left
            -- behind, still on the loop with its own socket, SAs and bearers.
            function(old, err)
                if r.done then return end
                if not old then
                    return finish(r, "session", err or "no new PDN connection")
                end
                r.old, r.t_pdn = old, now()
                old.rereg = r                  -- what arrives there is this relocation's
                r.new_at  = ("%s:%d"):format(sub.ue_addr, sub.port_uc)
                st.relocated = st.relocated + 1
                st.kpi.pdn[#st.kpi.pdn + 1] = r.t_pdn - r.t0
                log.slog(sub, "relocated", ("%s -> %s (PDN connection %d, %d ms)")
                    :format(r.old_at, r.new_at, gen, r.t_pdn - r.t0))
            end,
            -- The registration from the new address is terminal.
            function(ok, err)
                if r.done then return end
                if not ok then
                    return finish(r, "register", err or "the re-registration failed")
                end
                r.t_reg    = now()
                r.contacts = sub.reg_contacts
                r.listed   = listed_old(r)
                st.registered = st.registered + 1
                if sub.reg_ms then st.kpi.rereg[#st.kpi.rereg + 1] = sub.reg_ms end
                -- The registration is in, so the deadline that covered it has
                -- nothing left to guard; what follows is bounded by the wait
                -- below, the probes' own deadlines and the phase guard.
                if r.timer then loop:cancel(r.timer); r.timer = nil end

                -- Now ask both nodes what they are holding. The new contact's
                -- probe is the registrar's own statement; the stale contact's is
                -- the P-CSCF's, and it can only be sent while that incarnation
                -- is still up — which it is, because nothing released it.
                --
                -- Held back when the registrar answered by SHORTENING the old
                -- binding instead of dropping it: asking before the expiry it
                -- named has passed would report a binding that is on its way out
                -- as one that is being kept, which is the opposite finding.
                local c = r.listed
                local wait = 0
                if c and c.expires and c.expires > 0 and c.expires <= M.expiring_s then
                    wait = math.min(c.expires * 1000 + 500, M.settle_ms)
                    log.slog(sub, "old contact", ("registrar cut it to %ds; probing in %dms")
                        :format(c.expires, wait))
                end
                r.wait = wait
                if wait > 0 then
                    st.waited = st.waited + 1
                    loop:after(wait, function() send_probes(r) end)
                else
                    send_probes(r)
                end
            end)
    end

    -- ---- what arrives ----

    -- Every message, before any phase acts on it. Two things matter here.
    --
    -- A REQUEST the core sends to an incarnation a relocation left behind is the
    -- core using a contact it was told to replace, so it is counted against that
    -- relocation. Requests only: a response is the answer to something that
    -- incarnation sent — its own probe, or the de-REGISTER teardown sends through
    -- it — and says nothing about who the core would route to. Nor does the
    -- answer to a probe of ours, which is judged as a probe.
    --
    -- And any reg-info document at all, whoever it was addressed to: when the
    -- reg-event phase is running its live subscription produces one for free
    -- after every registration change, and it is the registrar's own statement
    -- exactly as a probe's is.
    function P.observe(sub, m)
        local r = sub.rereg
        if not r then return end
        local ours = by_callid[m:call_id()]
        if m.request and sub.owner and r.t_reg and not ours then
            stats_.bump(r.stale_rx, m.method_name)
            stats_.bump(st.stale_rx, m.method_name)
        end
        if m.request and m.method == sip.NOTIFY and not ours then
            local d = read_doc(r, m)
            if d then r.doc, r.doc_at = d, sub end
        end
    end

    -- A NOTIFY. True when it answers one of this phase's probes, which is what
    -- keeps it out of the reg-event phase's books.
    function P.request(sub, m)
        local q = by_callid[m:call_id()]
        if not q then return false end
        -- Answered first, whatever the body turns out to be: a notifier that
        -- gets no 200 OK terminates the subscription and retransmits, and a
        -- probe that is judged on a document it then damaged is not a
        -- measurement (RFC 6665 §4.4.1).
        io_.send(sub, "mt", wire.response(sub, m, {
            status = 200, reason = "OK", to_tag = q.from_tag,
        }), "200 OK (NOTIFY)")
        if q.doc then return true end        -- a retransmission; measured once
        q.doc = read_doc(q.r, m)
        q.at  = sub                          -- which contact it was delivered to
        if not q.doc then
            return settle_probe(q, "NOTIFY carried no reg-info document")
        end
        st.notified = st.notified + 1
        st.kpi.probe[#st.kpi.probe + 1] = q.doc.at - q.t0
        settle_probe(q, "notified")
        return true
    end

    -- The reply to a probe's SUBSCRIBE. The document, not this, is the answer —
    -- except when there will be no document, which a non-2xx final says, and
    -- 403 from the P-CSCF is the very thing the stale contact's probe asks.
    function P.response(sub, m)
        local q = by_callid[m:call_id()]
        if not q then return false end
        if m.status < 200 then return true end
        if not q.status then q.status, q.t1, q.reply_at = m.status, now(), sub end
        if m.status >= 300 then
            stats_.bump(st.by_status, m.status)
            settle_probe(q, ("%d %s"):format(m.status, m.reason))
        end
        return true
    end

    -- ---- the phase ----

    function P.begin(done)
        finished = done
        -- A relocation needs a registered UE with a Service-Route (both probes
        -- are originating requests) and an access that can raise a second PDN
        -- connection for it. The denominator stays every subscriber, so a
        -- registration failure cannot turn into a perfect relocation rate.
        local list = {}
        for _, s in ipairs(subs) do
            if s.registered and s.sock and #(s.svc_route or {}) > 0 then
                st.eligible = st.eligible + 1
                if not M.nsubs or #list < M.nsubs then list[#list + 1] = s end
            end
        end
        if not (access and access.relocate) then
            log.banner("Re-registration — none run (this access cannot raise a second PDN connection)")
            return done()
        end
        if #list == 0 then
            log.banner(("Re-registration — none run (%d/%d subscriber(s) eligible; " ..
                        "a relocation needs a registered UE with a Service-Route)")
                :format(st.eligible, #subs))
            return done()
        end

        -- Each incarnation binds its own protected ports, and a port is 16 bits:
        -- a wide run has room for fewer of them. Clamped rather than refused —
        -- one relocation still answers the question, and the line says why the
        -- rest were dropped.
        local cycles = math.max(1, math.min(M.cycles, ue.gens() - 1))

        log.banner(("Re-registration — %d of %d eligible subscriber(s) moving to a new " ..
                    "PDN connection %d time(s)%s")
            :format(#list, st.eligible, cycles,
                    M.rps > 0 and (" at %.1f/s"):format(M.rps) or " in one burst"))
        log.line("without", "a de-REGISTER, and without releasing anything the old one holds")
        log.line("Call-ID", M.call_id == "same"
            and "carried over from the initial registration (TS 24.229 §5.1.1.4)"
            or  "derived afresh from the new address (a handset that just attached)")
        log.line("probes", ("reg-event SUBSCRIBE, Expires: %d, from the new contact and " ..
                            "from the stale one"):format(M.probe_expires))
        if cycles < M.cycles then
            log.line("", ("REREG_CYCLES=%d asked for more incarnations than the protected-port " ..
                          "layout holds for %d subscriber(s)"):format(M.cycles, cfg.nsubs))
        end

        -- Cycles are sequential per subscriber: the next relocation starts from
        -- the address the last one ended on, and stops the moment one fails —
        -- a subscriber that is no longer registered has nothing to relocate.
        local function cycle(sub, n)
            relocate(sub, n, function(ok)
                if ok and n < cycles then return cycle(sub, n + 1) end
                dec()
            end)
        end

        local spacing = M.rps > 0 and math.floor(1000 / M.rps) or 0
        -- Overall deadline so a lost answer cannot hang the run.
        guard = loop:after(
            spacing * #list + cycles * (M.t_ms + M.settle_ms + M.probe_t_ms) + 2000,
            function()
                guard = nil
                for _, r in ipairs(records) do
                    if not r.done then finish(r, "guard", "re-registration phase deadline") end
                end
                if pending > 0 then pending = 0; done() end
            end)

        pending = 1                       -- the scheduler's sentinel; see dec()
        for i, s in ipairs(list) do
            pending = pending + 1
            if spacing > 0 then
                loop:after((i - 1) * spacing, function() cycle(s, 1) end)
            else
                cycle(s, 1)
            end
        end
        dec()
    end

    -- ---- the report ----

    local STAGES = {
        { key = "session",  label = "no second PDN connection (GTP-C)" },
        { key = "register", label = "new address, but the re-REGISTER failed" },
        { key = "guard",    label = "re-registration phase deadline" },
        { key = "unknown",  label = "other" },
    }

    -- A tally printed in a fixed order with the rest appended, so a value the
    -- core produced that this phase has no name for is still shown.
    local function counts(t, order)
        local out, seen = {}, {}
        for _, k in ipairs(order) do
            if t[k] then out[#out + 1] = ("%s %d"):format(k, t[k]); seen[k] = true end
        end
        for _, e in ipairs(stats_.ranked(t)) do
            if not seen[e.k] then out[#out + 1] = ("%s %d"):format(e.k, e.n) end
        end
        return #out > 0 and table.concat(out, "   ") or "nothing said"
    end

    function P.report()
        if st.attempted == 0 then return end
        local kept = (st.verdict.retained or 0) + (st.verdict.split or 0)
        log.banner(("Re-registration — %d relocated / %d attempted (%d of %d subscriber(s) eligible)")
            :format(st.relocated, st.attempted, st.eligible, #subs))
        log.line("re-registered", ("%d  (%.1f%%)")
            :format(st.registered, st.registered / st.attempted * 100))
        log.line("registrar (S-CSCF)", counts(st.binding,
            { "active", "expiring", "terminated", "gone", "unlisted", "unknown" }))
        log.line("proxy (P-CSCF)", counts(st.proxy,
            { "forwarding", "rejected", "unreachable", "unknown" }))
        log.line("VERDICT", counts(st.verdict, { "retained", "split", "cleaned", "unknown" }))
        if (st.verdict.split or 0) > 0 then
            log.line("", "split: the two nodes disagree about the same contact. Which of them")
            log.line("", "leaked decides what it costs -- a registrar holding it forks requests")
            log.line("", "to a dead address, a proxy holding it keeps admitting traffic FROM one")
            log.line("", "and keeps the SAs behind it alive.")
        end

        -- What each of those words means, said once and only when it happened.
        if (st.binding.active or 0) > 0 then
            log.line("", "active: the registrar still lists the contact of an address this UE")
            log.line("", "no longer has. Every terminating request for it is forked there too,")
            log.line("", "for the whole of IMS_EXPIRES -- nothing expires a binding early.")
        end
        if (st.binding.expiring or 0) > 0 then
            log.line("", "expiring: the registrar kept the old contact but cut its expiry to")
            log.line("", "seconds -- it DID notice, and is timing the binding out rather than")
            log.line("", "dropping it, so its subscribers still get the de-registration NOTIFY.")
            log.line("", "The probes were held back past that expiry, so what they found is")
            log.line("", "what was left once it had passed.")
        end
        if (st.binding.terminated or 0) + (st.binding.gone or 0) > 0 then
            log.line("", "terminated / gone: the registrar's own document no longer offers the")
            log.line("", "old contact as a binding, so nothing it routes will be forked there.")
            log.line("", "That is the registrar half of the cleanup, done.")
        end
        if (st.proxy.forwarding or 0) > 0 then
            log.line("", "forwarding: the P-CSCF still holds the stale contact in usrloc -- it")
            log.line("", "either sent it a request of its own accord or let an originating one")
            log.line("", "from it through pcscf_is_registered(). That is the half that puts")
            log.line("", "packets on the wire toward an address that is gone.")
        end
        if (st.binding.unlisted or 0) > 0 then
            log.line("", "unlisted: the REGISTER 200 OK did not name the old contact and no")
            log.line("", "document was obtained to confirm it. A registrar may echo only the")
            log.line("", "binding it just wrote, so that is not the same as it being gone --")
            log.line("", "the probe is what settles it (see the failures below).")
        end
        if next(st.stale_rx) then
            local parts = {}
            for _, e in ipairs(stats_.ranked(st.stale_rx)) do
                parts[#parts + 1] = ("%s %d"):format(e.k, e.n)
            end
            log.line("sent to a stale contact", table.concat(parts, "  "))
            log.line("", "unsolicited, after the subscriber had registered from its new address.")
        end
        if st.probes > 0 then
            log.line("probes answered", ("%d of %d carried a reg-info document")
                :format(st.notified, st.probes))
        end
        -- Read after the loop, so the teardown's own answers are in. A PGW that
        -- anchors one PDN connection per IMSI+APN releases the first the moment
        -- the second is created (open5gs does), and the reader has to know that
        -- before reading the P-CSCF line: the core was never told, so its
        -- bindings are unaffected, but the bearer under the stale contact was
        -- gone from the moment the subscriber moved.
        local dropped = 0
        for _, r in ipairs(records) do
            if r.old and r.old.pdn_missing then dropped = dropped + 1 end
        end
        if dropped > 0 then
            log.line("PDN connection dropped", ("%d of %d by the PGW itself")
                :format(dropped, st.relocated))
            log.line("", "the Delete Session for the connection left behind came back \"context")
            log.line("", "not found\": this PGW anchors one PDN connection per IMSI and APN, so")
            log.line("", "the relocation replaced it rather than adding to it. The IMS was not")
            log.line("", "told, so what the CSCFs hold is unaffected -- but the bearer under the")
            log.line("", "stale contact stopped existing when the subscriber moved.")
        end

        local nfail = stats_.total(st.stage)
        if nfail > 0 then
            log.line("failed", tostring(nfail))
            stats_.stages(STAGES, st.stage, 40)
        end
        for _, e in ipairs(stats_.ranked(st.by_status)) do
            print(("     SIP %-40s %d"):format(("%d %s"):format(
                e.k, sip.status_phrase(e.k)), e.n))
        end
        if st.by_status[500] then
            log.line("", "500 to a probe is the same P-CSCF fault the reg-event phase reports:")
            log.line("", "it asserted an empty P-Asserted-Identity, so the S-CSCF would not")
            log.line("", "authorise the subscription. No document comes back, and the registrar")
            log.line("", "line above then rests on the REGISTER 200 OK's Contact set alone.")
        end
        if st.stage.register then
            log.line("", "a re-REGISTER that times out where the first one worked is the")
            log.line("", "P-CSCF's SA table, not the core: it keys an SA by destination and SPI")
            log.line("", "and does not reliably delete the old one, so a reused SPI matches a")
            log.line("", "state whose replay window has passed sequence 1 (see ims/ue.lua).")
        end

        log.banner("Re-registration latency (percentiles, not means — a mean hides the knee)")
        log.line("Create Session -> new IP", stats_.dist(stats_.summarize(st.kpi.pdn), "ms"))
        log.line("", "carries the fixed 200 ms this script waits between the Create Session")
        log.line("", "Response and the first REGISTER, exactly as the attach does.")
        log.line("REGISTER -> 200 OK", stats_.dist(stats_.summarize(st.kpi.rereg), "ms"))
        log.line("probe -> reg-info", stats_.dist(stats_.summarize(st.kpi.probe), "ms"))
        log.line("whole relocation", stats_.dist(stats_.summarize(st.kpi.total), "ms"))
        if st.waited > 0 then
            log.line("", ("and %d of them carry the expiry the registrar named on the old")
                :format(st.waited))
            log.line("", "binding, which the probes wait out before they ask.")
        end
        if kept > 0 then
            print("   The old contact outliving the address it names is what this phase is for.")
            print("   REREG_STRICT=0 keeps the measurement and drops it from the exit status.")
        end
    end

    -- Rate over the phase's own window, so the attach burst before it does not
    -- dilute the figure.
    function P.throughput()
        if st.attempted == 0 or not st.first then return end
        local w = ((st.last or st.first) - st.first) / 1000
        log.line("relocations", w > 0
            and ("%d re-registered in %.2fs  ->  %.1f/s"):format(st.registered, w, st.registered / w)
            or  ("%d re-registered (single burst, under one clock tick)"):format(st.registered))
    end

    -- The phase passes when every relocation completed and no node was left
    -- holding the contact the subscriber moved off. "unknown" does not fail it:
    -- nothing was established either way, and a run that fails on silence
    -- teaches the reader to ignore it.
    function P.ok()
        if st.attempted == 0 then return true end
        if stats_.total(st.stage) > 0 then return false end
        if not M.strict then return true end
        return (st.verdict.retained or 0) + (st.verdict.split or 0) == 0
    end

    return P
end

return M
