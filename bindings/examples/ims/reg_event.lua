-- ims/reg_event.lua — the registration-state subscription (RFC 3680,
-- TS 24.229 §5.1.1.3), as a phase with its own report.
--
-- After the 200 OK the UE SUBSCRIBEs to the registration state of its own
-- public identity and the S-CSCF NOTIFYs it with a reginfo document.
--
-- This is the half of TS 24.229 §5.1.1.3 no REGISTER exchange covers: the
-- subscription is what carries de-registration and network-initiated
-- re-authentication back to the handset, so a core that registers UEs and never
-- notifies them looks perfectly healthy right up to the day it has something to
-- tell them. It earns its place twice over. The NOTIFY is the first
-- *terminating* request a UE receives, so the P-CSCF's inbound SA is exercised
-- before any call depends on it; and the reginfo body lists the implicit
-- registration set, which says whether the number a call phase is about to dial
-- is an identity of the callee at all.
--
-- One subscription per registered UE, with every hop timed:
--
--   t0  SUBSCRIBE   to its own IMPU, through the Service-Route
--   t1  200 OK      the S-CSCF accepted the subscription
--   t2  NOTIFY      the reg-info document: the state the network holds
--   t3  200 OK      our answer to it (RFC 6665 §4.4.1 — a notifier that gets
--                   none tears the subscription down again)
--
-- t0 and t2 are readings of ONE monotonic clock in this process, so t2-t0 is a
-- true one-way figure, exactly as the call and SMS phases' transit figures are.
--
-- The 200 OK and the NOTIFY race, and both orders happen: kamailio's
-- ims_registrar_scscf sends the first NOTIFY from inside subscribe_to_reg(), so
-- it can overtake the reply it was triggered by. Neither is treated as the
-- other's precondition — the record settles when both are in, and the deadline
-- names whichever is missing.

local net   = require("net")
local sip   = require("sip")
local cfg   = require("ims.cfg")
local log   = require("ims.log")
local wire  = require("ims.wire")
local stats_ = require("ims.stats")

local M = {}

-- The knobs are named REG_EVENT_*, not SUBS_*: IMS_SUBS is the subscriber
-- COUNT, and two knobs a letter apart meaning "how many UEs" and "the reg
-- event" would be read as each other sooner or later.
M.on = cfg.flag("IMS_REG_EVENT", true)
-- RFC 3680 §5 leaves the default to the notifier; one hour is what a UE asks
-- for and is long enough that nothing expires inside a run. The S-CSCF may
-- grant less (its own subscription_max_expires), which is reported rather than
-- argued with.
M.expires = cfg.num("REG_EVENT_EXPIRES", 3600)
M.t_ms    = cfg.num("REG_EVENT_T_MS", 10000)   -- per-subscription deadline
-- Offered subscribe rate, like CALL_CPS: the independent variable of an
-- experiment, NOT a remedy for failures. 0 (the default) is a single burst,
-- consistent with the deliberately unramped registration side.
M.rps     = cfg.num("REG_EVENT_RPS", 0)
-- REG_EVENT_EXCLUSIVE=1 makes the document answer one more question: is this
-- UE's contact the ONLY one the registrar still offers? Off by default, because
-- several bindings per identity are legitimate (RFC 3261 §10.3) and the
-- ordinary run asserts only that its own binding is among them. On, any other
-- contact still `active` fails the subscription — which is what a UE that came
-- back on a new address without de-registering (the chart's rereg test runs
-- this script back to back with IMS_DEREG=0) should never leave behind: the
-- old contact names an address the UE no longer has, and every terminating
-- request for it is forked there too until IMS_EXPIRES runs out.
M.exclusive = cfg.flag("REG_EVENT_EXCLUSIVE", false)

-- ---- the reginfo document ---------------------------------------------

-- One attribute out of an XML start tag. The leading %s is not decoration:
-- without it "state" would also match the tail of any attribute name ending in
-- it, and a pattern that quietly reads the wrong attribute is worse than one
-- that reads none.
local function xattr(s, k) return s:match('%s' .. k .. '%s*=%s*"([^"]*)"') end

-- The socket a contact URI names — host:port, without the scheme, the user
-- part or any parameter — which is all that decides where a request forked to
-- it goes. XML-escaped in the document, so the `&lt;` a registrar may leave
-- around it is stripped along with the rest.
local function hostport(uri)
    local s = uri:gsub("^&lt;", ""):gsub("^<", "")
    s = s:gsub("^sips?:", "")
    s = s:gsub("^[^@;>&]*@", "")
    return s:match("^([^;>&]+)") or s
end

-- The reg event's body (RFC 3680 §5.1, application/reginfo+xml): one
-- <registration> per public identity of the implicit registration set, each
-- listing the contacts bound to it. Read with patterns rather than an XML
-- parser, and deliberately so — the document is machine-generated, flat and
-- attribute-only, and the two things asserted from it (is this identity active,
-- is our own contact among its bindings) are two attributes and one element. A
-- parser would be a dependency for no more information.
--
-- Chunked at each opening tag rather than matched as
-- <registration>...</registration>, so an identity carrying no contacts — which
-- a notifier is free to write self-closed — is still counted rather than
-- silently skipped, and a missing identity is exactly the finding this phase
-- exists to make.
function M.parse(body)
    local out, pos = {}, 1
    while true do
        local s = body:find("<registration", pos, true)
        if not s then break end
        local e = body:find("<registration", s + 13, true) or (#body + 1)
        local chunk = body:sub(s, e - 1)
        local head  = chunk:match("^<registration([^>]*)") or ""
        local r = { aor = xattr(head, "aor") or "", state = xattr(head, "state") or "",
                    contacts = {} }
        for c in chunk:gmatch("<contact(.-)</contact>") do
            r.contacts[#r.contacts + 1] = {
                state = xattr(c, "state") or "", event = xattr(c, "event") or "",
                expires = tonumber(xattr(c, "expires") or ""),
                uri   = c:match("<uri>%s*(.-)%s*</uri>") or "",
            }
        end
        out[#out + 1] = r
        pos = e
    end
    return out
end

-- ---- the phase --------------------------------------------------------

function M.new(ctx)
    local loop, io_, subs = ctx.loop, ctx.io, ctx.subs
    local now = net.now_ms
    local P = {}

    -- Subscriptions are keyed by the Call-ID of the SUBSCRIBE that opened them,
    -- which is what both the 200 OK and every NOTIFY of that dialog carry. The
    -- index is NOT cleared when the phase ends: the S-CSCF sends one more NOTIFY
    -- when the registration goes away, and matching it is how the run can say
    -- the UE was told about its own de-registration.
    local by_callid = {}
    local pending, guard, finished = 0, nil, nil
    local st = {
        eligible = 0, attempted = 0, accepted = 0, notified = 0, verified = 0,
        terminated = 0,          -- NOTIFYs saying the registration is gone
        orphans = 0,             -- NOTIFYs matching no subscription of ours
        first = nil, last = nil,
        by_status = {},          -- non-2xx finals for the SUBSCRIBE
        stage = {},              -- where a subscription died, and why
        states = {},             -- Subscription-State token -> count
        identities = {},         -- identities per reg-info document
        dialable = 0,            -- documents listing the address the call phase dials
        kpi = { accept = {}, notify = {}, ack = {} },
    }
    P.stats = st

    -- The UE's SUBSCRIBE to the registration state of its own public identity:
    -- Request-URI, To and From are all its IMPU, and the Event/Accept pair is
    -- what makes it a reg subscription rather than any other package —
    -- kamailio's can_subscribe_to_reg() reads the Event header and answers
    -- anything else with 489 Bad Event.
    --
    -- It is an out-of-dialog ORIGINATING request, so it carries what an INVITE
    -- carries: the preloaded Route (see sipio.preload_route) and the Contact
    -- this UE registered — the P-CSCF matches usrloc on it in
    -- pcscf_is_registered() before it lets an originating request through at all.
    local function build_subscribe(sub, u)
        local b = io_.preload_route(wire.builder:request(sip.SUBSCRIBE, sub.impu), sub)
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s:%d;branch=%s")
                            :format(sub.ue_addr, sub.port_uc, u.branch))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, ("<%s>;tag=%s"):format(sub.impu, u.from_tag))
            :header(sip.H_TO, ("<%s>"):format(sub.impu))
            :header(sip.H_CALL_ID, u.call_id)
            :header(sip.H_CSEQ, ("%d SUBSCRIBE"):format(u.cseq))
            :header(sip.H_CONTACT, wire.contact(sub))
            :header(sip.H_P_PREFERRED_IDENTITY, ("<%s>"):format(sub.impu))
            :header(sip.H_EVENT, "reg")
            :header(sip.H_ACCEPT, "application/reginfo+xml")
            :header_u32(sip.H_EXPIRES, M.expires)
        return b:done()
    end

    -- One unit of outstanding work per subscription, plus the scheduler's own
    -- sentinel — a spaced run would otherwise end the phase the moment its
    -- FIRST subscription settled, because the rest had not been issued yet.
    local function dec()
        pending = pending - 1
        if pending > 0 then return end
        if guard then loop:cancel(guard); guard = nil end
        finished()
    end

    -- A failed subscription is attributed to the hop it died at and to the
    -- reason within it, the way a failed call and a failed registration are —
    -- "no NOTIFY" and "a NOTIFY describing somebody else's registration" are
    -- both `reginfo` stage failures and nothing like the same fault.
    local function settle_fail(u, stage, detail)
        if u.done then return end
        u.done = true
        if u.timer then loop:cancel(u.timer); u.timer = nil end
        -- by_callid keeps its entry on purpose: the subscription lives on past
        -- the phase and its last NOTIFY arrives at de-registration.
        stats_.fail(st.stage, stage or "unknown", detail or "unknown")
        log.slog(u.sub, "reg-event", ("subscription FAILED at %s: %s")
            :format(stage or "?", detail or "?"))
        dec()
    end

    local function arm(u)
        if u.timer then loop:cancel(u.timer) end
        u.timer = loop:after(M.t_ms, function()
            u.timer = nil
            -- Name the furthest hop that DID happen: "the S-CSCF never took the
            -- subscription" and "it took it and never notified" are different
            -- faults with different fixes.
            if not u.t.t1 then
                settle_fail(u, "accept", "no 200 OK for the SUBSCRIBE")
            elseif not u.t.t2 then
                settle_fail(u, "notify", "subscribed, but no NOTIFY ever came")
            else
                settle_fail(u, "unknown", "both hops completed but the subscription never settled")
            end
        end)
    end

    local function settle(u)
        if u.done or not (u.t.t1 and u.t.t2) then return end
        local t, k = u.t, st.kpi
        local function push(list, a, b)
            if t[a] and t[b] then list[#list + 1] = t[b] - t[a] end
        end
        push(k.accept, "t0", "t1")   -- SUBSCRIBE -> 200 OK
        push(k.notify, "t0", "t2")   -- SUBSCRIBE -> the state, one clock
        push(k.ack,    "t2", "t3")   -- our own turnaround on the NOTIFY
        st.last = t.t2
        u.done = true
        if u.timer then loop:cancel(u.timer); u.timer = nil end
        dec()
    end

    -- Everything a reg-info document has to say before the subscription counts:
    -- one of this UE's own identities is registered, and one of the contacts
    -- bound to it is the contact this UE registered. Anything less means the
    -- core is telling the UE a registration state that is not the one it is in
    -- — which is the whole reason to ask.
    --
    -- The dialled address is checked at the same time but never failed on: it is
    -- the call phase's precondition, not this one's, and reporting it here is
    -- what turns a later "404 for the number" from a mystery into a provisioning
    -- line that was visible before the first INVITE.
    local function check_reginfo(u, m)
        local sub = u.sub
        local ct  = m:header("Content-Type"):lower()
        if not ct:find("reginfo+xml", 1, true) then
            return false, ("NOTIFY body is %s, not application/reginfo+xml")
                :format(ct ~= "" and ct or "typeless")
        end
        local regs = M.parse(m.body)
        if #regs == 0 then
            return false, ("reg-info carries no <registration> element (%d bytes)")
                :format(#m.body)
        end
        u.identities = #regs
        -- "This UE's own identity" is a SET, not the one URI it registered: the
        -- registered IMPU first, then everything the 200 OK associated with it.
        -- Without an ISIM the registered IMPU is the temporary, barred one and
        -- the network deliberately never names it in a reg-info document, so
        -- matching on it alone fails a core for being correct — which is the
        -- opposite of what this phase is for.
        --
        -- Only the matching moves. The SUBSCRIBE still goes to sub.impu and
        -- still asserts sub.impu, because that pairing is the one the S-CSCF can
        -- authorise: can_subscribe_to_reg() accepts the asserted identity either
        -- as the presentity's own AOR or as an *unbarred* entry in its service
        -- profile, and the temporary IMPU is neither of those for an associated
        -- presentity. Subscribing to the associated identity while asserting the
        -- registered one is a 403.
        local own = { sub.impu }
        for _, a in ipairs(sub.assoc or {}) do own[#own + 1] = a end
        local mine
        for _, id in ipairs(own) do
            for _, r in ipairs(regs) do
                if wire.same_id(r.aor, id) then mine = r; break end
            end
            if mine then break end
        end
        for _, r in ipairs(regs) do
            if wire.same_id(r.aor, sub.dial) and r.state == "active" then u.dialable = true end
        end
        if not mine then
            local names = {}
            for _, r in ipairs(regs) do names[#names + 1] = r.aor end
            return false, ("reg-info names %s, none of this UE's own identities (%s)")
                :format(#names > 0 and table.concat(names, ",") or "nothing",
                        table.concat(own, ","))
        end
        u.aor   = mine.aor
        u.state = mine.state
        if mine.state ~= "active" then
            return false, ("reg-info says this identity is %q, not active"):format(mine.state)
        end
        -- The binding, matched on address:port rather than on the whole URI: the
        -- S-CSCF may hand back the contact with parameters of its own (received,
        -- expires, the +g.3gpp.smsip feature tag) and none of them change which
        -- socket the binding points at.
        local want = ("%s:%d"):format(sub.ue_addr, sub.port_uc)
        local found = false
        for _, c in ipairs(mine.contacts) do
            if c.uri:find(want, 1, true) then u.event = c.event; found = true; break end
        end
        if not found then
            return false, ("this identity is registered, but to %d other contact(s), not %s")
                :format(#mine.contacts, want)
        end
        if not M.exclusive then return true end
        -- Every <registration>, not only `mine`: a contact bound to ANY identity
        -- of the implicit set is one the S-CSCF will fork a terminating request
        -- to, and it is the contact that is stale, not the identity. Compared on
        -- the exact host:port — a substring match would let 10.10.0.2:5060 hide
        -- inside 10.10.0.12:5060 — and each counted once, since the same binding
        -- is listed under every identity it serves.
        local stale, seen = {}, {}
        for _, r in ipairs(regs) do
            for _, c in ipairs(r.contacts) do
                local at = hostport(c.uri)
                if c.state == "active" and at ~= want and not seen[at] then
                    seen[at] = true
                    stale[#stale + 1] = c.expires
                        and ("%s (expires in %ds)"):format(at, c.expires) or at
                end
            end
        end
        u.stale = #stale
        if #stale > 0 then
            return false, ("%d other contact(s) still active beside %s: %s")
                :format(#stale, want, table.concat(stale, ", ")), "stale"
        end
        return true
    end

    -- A NOTIFY arrived on a UE's socket: the network's view of that UE's own
    -- registration. Answer the SIP hop first, then read the body — a notifier
    -- that gets no 200 OK terminates the subscription, and a run that fails the
    -- body check would then also have broken the thing it was measuring.
    function P.request(sub, m)
        local u  = by_callid[m:call_id()]
        local t2 = now()
        -- Answered even when it matches nothing we track: 481 would tell the
        -- S-CSCF to drop a subscription that is most likely ours (a NOTIFY that
        -- overtook its own 200 OK), and an unmatched one is counted below rather
        -- than turned into a teardown.
        io_.send(sub, "mt", wire.response(sub, m, {
            status = 200, reason = "OK",
            to_tag = (u and u.from_tag) or ("r%d"):format(sub.i),
        }), "200 OK (NOTIFY)")
        local t3 = now()

        local ss    = m:header("Subscription-State"):lower()
        local state = ss:match("^%s*([%w%-]+)") or "?"
        if not u then
            st.orphans = st.orphans + 1
            return log.slog(sub, "reg-event",
                ("NOTIFY (%s) for a subscription this run does not track"):format(state))
        end
        stats_.bump(st.states, state)

        -- A later state change on a subscription that has already been measured.
        -- At teardown this is the S-CSCF telling the UE its registration is gone
        -- — the half of the reg event that only a de-REGISTER exercises, and the
        -- one a UE actually needs.
        if u.done then
            if state == "terminated" then
                st.terminated = st.terminated + 1
                log.slog(sub, "reg-event", ("NOTIFY: subscription terminated (%s)")
                    :format(sip.auth_param(ss, "reason") ~= "" and sip.auth_param(ss, "reason")
                            or "no reason given"))
            else
                log.slog(sub, "reg-event", ("NOTIFY: %s (state change after the phase)"):format(state))
            end
            return
        end

        -- A NOTIFY we have already read: answered above (the notifier is
        -- retransmitting because it wants one), counted once. The S-CSCF may also
        -- send a legitimate second document before the phase settles — the first
        -- one is the measurement, so this is the same decision.
        if u.t.t2 then return end
        u.t.t2, u.t.t3 = t2, t3
        st.notified = st.notified + 1
        local okb, detail, stage = check_reginfo(u, m)
        if not okb then return settle_fail(u, stage or "reginfo", detail) end
        st.verified = st.verified + 1
        st.identities[#st.identities + 1] = u.identities
        if u.dialable then st.dialable = st.dialable + 1 end
        if cfg.verbose then
            log.slog(sub, "reg-event", ("%s as %s, %d identity(ies), contact %s after %d ms")
                :format(u.state, u.aor ~= "" and u.aor or "?", u.identities,
                        u.event ~= "" and u.event or "bound", t2 - u.t.t0))
        end
        settle(u)
    end

    -- The reply to the SUBSCRIBE. 200 and 202 both create the subscription
    -- (RFC 6665 §4.1.2.1); anything else means there is none.
    function P.response(sub, m)
        local u = by_callid[m:call_id()]
        if not u then
            if m.status >= 300 then
                stats_.bump(st.by_status, m.status)
                log.slog(sub, "reg-event", ("%d %s for a subscription we no longer track")
                    :format(m.status, m.reason))
            end
            return
        end
        if m.status < 200 then return end
        if m.status >= 300 then
            stats_.bump(st.by_status, m.status)
            return settle_fail(u, "accept", ("%d %s"):format(m.status, m.reason))
        end
        if u.t.t1 then return end                     -- retransmitted final
        u.t.t1 = now()
        st.accepted = st.accepted + 1
        -- What the notifier granted, which may be less than we asked for.
        u.granted = tonumber(m:header("Expires"))
        if cfg.verbose then
            log.slog(sub, "reg-event", ("%d %s after %d ms (expires %s)")
                :format(m.status, m.reason, u.t.t1 - u.t.t0,
                        u.granted and tostring(u.granted) or "unstated"))
        end
        settle(u)
    end

    function P.begin(done)
        finished = done
        -- A SUBSCRIBE is an originating request, so it needs exactly what an
        -- INVITE needs: a live registration and the Service-Route to send it
        -- through. The denominator stays every subscriber, so a registration
        -- failure cannot turn into a perfect subscription rate.
        local list = {}
        for _, s in ipairs(subs) do
            if s.registered and s.sock and #(s.svc_route or {}) > 0 then
                st.eligible = st.eligible + 1
                list[#list + 1] = s
            end
        end
        if #list == 0 then
            log.banner(("Reg-event — none sent (%d/%d subscriber(s) eligible; a SUBSCRIBE needs a registered UE with a Service-Route)")
                :format(st.eligible, #subs))
            return done()
        end
        log.banner(("Reg-event — %d of %d subscriber(s) subscribing to their own registration state%s")
            :format(#list, #subs,
                    M.rps > 0 and (" at %.1f sub/s"):format(M.rps) or " in one burst"))
        log.line("event package", ("reg (RFC 3680), Expires: %d, Accept: application/reginfo+xml")
            :format(M.expires))
        if M.exclusive then
            log.line("exclusive", "any other active contact in the document fails the subscription")
        end

        local spacing = M.rps > 0 and math.floor(1000 / M.rps) or 0
        local function subscribe(sub)
            sub.regev_cseq = (sub.regev_cseq or 0) + 1
            -- Short identifiers for the same reason the call phase uses them
            -- (see ims/call_phase.lua's downlink size budget): the reg-info
            -- NOTIFY is the largest thing the network sends a UE outside a call,
            -- and every byte of the dialog id comes back inside it.
            local u = {
                sub = sub, cseq = sub.regev_cseq,
                call_id  = ("r%d@%s"):format(sub.i, sub.ue_addr),
                from_tag = ("r%d"):format(sub.i),
                branch   = ("z9hG4bKr%d-%d"):format(sub.i, sub.regev_cseq),
                identities = 0, dialable = false, state = "", event = "",
                aor = "",   -- which of the UE's identities the document named
                t = {}, done = false,
            }
            sub.regev = u
            by_callid[u.call_id] = u
            pending = pending + 1
            st.attempted = st.attempted + 1
            u.t.t0 = now()
            st.first = st.first or u.t.t0
            if io_.send(sub, "mo", build_subscribe(sub, u),
                        ("SUBSCRIBE (reg, %s)"):format(sub.impu)) then
                arm(u)
            else
                settle_fail(u, "send", "SUBSCRIBE send failed")
            end
        end

        -- Overall deadline so a lost NOTIFY cannot hang the run.
        guard = loop:after(spacing * #list + M.t_ms + 2000, function()
            guard = nil
            for _, u in pairs(by_callid) do
                if not u.done then settle_fail(u, "guard", "reg-event phase deadline") end
            end
            if pending > 0 then pending = 0; done() end
        end)

        pending = 1                       -- the scheduler's sentinel; see dec()
        if spacing > 0 then
            for i, s in ipairs(list) do loop:after((i - 1) * spacing, function() subscribe(s) end) end
            loop:after((#list - 1) * spacing + 1, dec)
        else
            for _, s in ipairs(list) do subscribe(s) end
            dec()
        end
    end

    -- ---- the report ----
    --
    -- Validity first: a subscription that was accepted and notified but whose
    -- document describes some other registration state is a failure, and a
    -- louder one than a subscription that was refused outright.
    local STAGES = {
        { key = "send",    label = "SUBSCRIBE send failed" },
        { key = "accept",  label = "no 200 OK for the SUBSCRIBE" },
        { key = "notify",  label = "subscribed, never notified" },
        { key = "reginfo", label = "notified, but the state was not this UE's" },
        { key = "stale",   label = "notified, but an older contact is still bound" },
        { key = "guard",   label = "reg-event phase deadline" },
        { key = "unknown", label = "other" },
    }

    function P.report()
        if st.attempted == 0 then return end
        log.banner(("Reg-event — %d confirmed / %d subscribed (%d of %d subscriber(s) eligible)")
            :format(st.verified, st.attempted, st.eligible, #subs))
        log.line("accepted (200 OK)", ("%d  (%.1f%%)")
            :format(st.accepted, st.accepted / st.attempted * 100))
        log.line("notified (reg-info)", ("%d  (%.1f%%)")
            :format(st.notified, st.notified / st.attempted * 100))
        -- The implicit registration set as the network sees it. This is the line
        -- that says, before any INVITE, whether the callee's number is an
        -- identity of the callee's subscription at all.
        local ids = stats_.summarize(st.identities)
        if ids then log.line("identities per UE", stats_.dist(ids, "", "%.0f")) end
        if st.verified > 0 and cfg.dial_uri ~= "sip" then
            log.line("dialled form present", ("%d / %d reg-info document(s) list it")
                :format(st.dialable, st.verified))
            if st.dialable < st.verified then
                log.line("", "the address the call phase dials is not among the identities the")
                log.line("", "HSS returned for these subscribers, so a call to it will come back")
                log.line("", "404/604 from the I-CSCF or 480 from the S-CSCF -- the same cause the")
                log.line("", "call phase reports as DIALLED NUMBER UNRESOLVED, with the two fixes.")
            end
        end
        if st.terminated > 0 then
            log.line("de-registration told", ("%d UE(s) were NOTIFYed that their registration ended")
                :format(st.terminated))
        end
        if st.orphans > 0 then
            log.line("UNMATCHED NOTIFYs", ("%d — arrived for no subscription of ours"):format(st.orphans))
        end
        if next(st.states) then
            local ss = {}
            for s, n in pairs(st.states) do ss[#ss + 1] = ("%s %d"):format(s, n) end
            table.sort(ss)
            log.line("subscription states", table.concat(ss, "  "))
        end

        local nfail = stats_.total(st.stage)
        if nfail > 0 then
            log.line("failed", tostring(nfail))
            stats_.stages(STAGES, st.stage)
        end
        if next(st.by_status) then
            for _, e in ipairs(stats_.ranked(st.by_status)) do
                print(("     SIP %-40s %d"):format(("%d %s"):format(
                    e.k, sip.status_phrase(e.k)), e.n))
            end
            if st.by_status[489] then
                log.line("", "489 Bad Event: the S-CSCF does not serve the reg package here.")
                log.line("", "kamailio needs ims_registrar_scscf and a route[SUBSCRIBE] that")
                log.line("", "calls can_subscribe_to_reg()/subscribe_to_reg(\"location\").")
            end
        end
        -- Accepted but never notified has one cause that is invisible from here
        -- and worth naming, because it is a property of the path rather than of
        -- the core: the reg-info document is the largest thing the network sends
        -- a UE outside a call, and a downlink that does not fit the tunnel is
        -- lost whole (see the downlink size budget in ims/call_phase.lua).
        if st.stage.stale then
            log.line("", "stale: the registrar still offers a contact this UE registered from")
            log.line("", "an address it has since left, without de-registering. Nothing in the")
            log.line("", "REGISTER asked for that binding to go, so only the core can notice")
            log.line("", "it is dead -- and until it does, every terminating request for this")
            log.line("", "identity is forked to it too (REG_EVENT_EXCLUSIVE=1 is what asked).")
        end
        if st.stage.notify then
            log.line("", "a subscription accepted and never notified may be a NOTIFY that did")
            log.line("", "not fit: with 36 bytes of GTP-U on a 1500-byte path the reg-info")
            log.line("", "document plus its headers is the first downlink big enough to be")
            log.line("", "fragmented, and a fragment carries no GTP header to classify.")
        end

        log.banner("Reg-event latency (percentiles, not means — a mean hides the knee)")
        log.line("SUBSCRIBE -> 200 OK", stats_.dist(stats_.summarize(st.kpi.accept), "ms"))
        log.line("SUBSCRIBE -> NOTIFY", stats_.dist(stats_.summarize(st.kpi.notify), "ms"))
        log.line("NOTIFY -> our 200 OK", stats_.dist(stats_.summarize(st.kpi.ack), "ms"))
        if stats_.summarize(st.kpi.notify) then
            print("   SUBSCRIBE -> NOTIFY is a true one-way figure: both marks are readings")
            print("   of ONE monotonic clock in this process, so no skew is in it.")
        end
    end

    -- Rate over the phase's own window (first SUBSCRIBE to last NOTIFY), so the
    -- registration burst before it does not dilute the figure.
    function P.throughput()
        if st.attempted == 0 or not st.first then return end
        local w = ((st.last or st.first) - st.first) / 1000
        log.line("subscriptions", w > 0
            and ("%d confirmed in %.2fs  ->  %.1f/s"):format(st.verified, w, st.verified / w)
            or  ("%d confirmed (single burst, under one clock tick)"):format(st.verified))
    end

    -- A phase passes when every subscription it opened was confirmed by a
    -- document describing that subscriber's own registration state.
    function P.ok() return st.attempted == 0 or st.verified == st.attempted end

    return P
end

return M
