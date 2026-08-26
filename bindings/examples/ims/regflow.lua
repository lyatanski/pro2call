-- ims/regflow.lua — the registration exchange (RFC 3261 §10, TS 24.229 §5.1,
-- TS 33.203 §6.1/§6.3), driven over one UE socket on one net.Loop.
--
--   1. REGISTER (unprotected) with an empty AKAv1-MD5 Authorization that
--      advertises IMS-AKA, and a Security-Client offer carrying the UE's two
--      inbound SPIs, its protected ports and the ESP algorithms.
--   2. 401 with the AKA challenge (nonce = base64(RAND||AUTN)) and the
--      P-CSCF's Security-Server (its SPIs and protected ports).
--   3. Verify AUTN against the USIM secret, derive RES/CK/IK, and hand IK with
--      the negotiated ports and SPIs to an ipsec.Esp, which installs the four
--      transport-mode ESP SAs and the policies that steer traffic onto them.
--   4. REGISTER (protected, ESP) from the UE's protected client port to the
--      P-CSCF's protected server port, carrying the AKAv1-MD5 digest computed
--      from RES and a Security-Verify; then 200 OK.
--   5. deregister() releases the binding with an Expires:0 REGISTER over the
--      same SA. That is what makes the P-CSCF destroy its half of the IPsec
--      state — contact expiry does not reap it, and a stack left holding SAs
--      from earlier runs registers fewer UEs on each one.
--
-- What is NOT here is where the UE's address came from and what happens after
-- the 200 OK: over Gm the address is one this host owns and the run ends,
-- over S5/S8 it is a PAA from a Create Session and four more phases follow.
-- Those are the caller's, and they are the whole difference between
-- bindings/examples/ims_test_gm.lua and bindings/examples/ims_test_s5.lua.
--
-- new(o) takes
--   o.loop           the shared net.Loop
--   o.io             an ims.sipio instance (same stats table as below)
--   o.stats          run counters: regs, reg_last, latency, protected, sa_fail
--   o.subs           the subscriber list (read at deregister/teardown time)
--   o.on_terminal    a subscriber reached a terminal state — the caller's own
--                    accounting for "one fewer outstanding"
--   o.on_registered  optional, at the 200 OK, after svc_route/assoc are in
--   o.on_response    optional, for every response, after the machines have
--                    seen it (the S5/S8 script reads its datapath counters
--                    here, to say the reply came back down the bearer)

local net   = require("net")
local sip   = require("sip")
local ipsec = require("ipsec")
local cfg   = require("ims.cfg")
local log   = require("ims.log")
local wire  = require("ims.wire")
local register = require("ims.register")

local M = {}

function M.new(o)
    local loop, io_, stats = o.loop, o.io, o.stats
    local now = net.now_ms
    local F = { xfrm = nil }        -- opened on the first 401 that offers SAs

    -- ---- per-subscriber deadline over the shared loop ----
    function F.disarm(sub)
        if sub.timer then loop:cancel(sub.timer); sub.timer = nil end
    end
    function F.arm(sub, ms, fn)
        F.disarm(sub)
        sub.timer = loop:after(ms, function() sub.timer = nil; fn() end)
    end

    -- ---- terminal states ----

    function F.fail(sub, msg)
        sub.err = msg
        sub.fail_stage = sub.stage       -- snapshot the stage reached at give-up
        log.slog(sub, "result", "FAILED: " .. msg)
        o.on_terminal(sub)
    end
    local fail = F.fail

    local function succeed(sub, m)
        sub.registered = true
        sub.stage = "done"
        sub.reg_ms = now() - sub.t0
        stats.regs = stats.regs + 1
        stats.reg_last = now()
        stats.latency[#stats.latency + 1] = sub.reg_ms
        if sub.protected then stats.protected = stats.protected + 1 end
        -- Captured here, at the one message that carries them: the phases that
        -- follow cannot originate a request without the Service-Route, and
        -- nothing else ever says which identities this registration owns. No
        -- fallback is invented when either is absent — a guessed Route would
        -- fail as "mis-routed by the core" and hide the real cause.
        sub.svc_route = wire.service_route(m)
        sub.assoc     = wire.associated_uris(m)
        if o.on_registered then o.on_registered(sub, m) end
        log.slog(sub, "result", ("registered in %dms (%s)")
            :format(sub.reg_ms, sub.protected and "over ESP" or "unprotected"))
        o.on_terminal(sub)
    end

    -- ---- the three machines, in lock-step with the wire ----

    -- Advance a subscriber's machines for a REGISTER we are sending.
    --
    -- The events are injected directly rather than derived from the message.
    -- `sub.reg:send(sip.parse(wire))` reads better, but it re-parses the wire we
    -- just built — a full parse, a string copy per header, and a deep copy
    -- across the binding — purely so the codec can tell us which transition we
    -- are making. We already know: the script decided it. So this mirrors
    -- sip::Registration::send()'s own mapping for an outbound REGISTER, keyed on
    -- the same registration state. `dereg` picks DEREGISTER over REFRESH for the
    -- Expires:0 teardown REGISTER.
    local REG_SEND_EV = {
        [sip.RS_IDLE]       = sip.RE_SEND,   -- first REGISTER
        [sip.RS_CHALLENGED] = sip.RE_AUTH,   -- the authenticated retry
    }
    local function feed_sent(sub, dereg)
        local ev = REG_SEND_EV[sub.reg:state()]
        if not ev and sub.reg:registered() then
            ev = dereg and sip.RE_DEREGISTER or sip.RE_REFRESH
        end
        -- Anything else (a REGISTER already in flight) is a retransmission and
        -- moves no machine — exactly what Registration::send() does with it.
        if ev then pcall(function() sub.reg:event(ev) end) end
        pcall(function() sub.auth:event(sip.AE_SEND) end)
        -- Each REGISTER is its own transaction (§17.1.2): re-arm, then send.
        pcall(function() sub.txn:restart():event(sip.TE_SEND_REQUEST) end)
    end

    -- Send a REGISTER, feed the machines, and arm the step deadline. The port
    -- is the P-CSCF's protected server port once the SAs are up and its
    -- unprotected one before that — which is exactly sipio's "mo" role.
    local function send(sub, wire_bytes, label)
        feed_sent(sub, false)
        local ok, err = io_.send(sub, "mo", wire_bytes, "REGISTER", label)
        if not ok then return fail(sub, "REGISTER send: " .. tostring(err)) end
        F.arm(sub, cfg.sip_t_ms, function()
            fail(sub, "timed out awaiting a SIP response")
        end)
    end

    -- ---- round 2: the challenge ----
    --
    -- Verify the AKA challenge, derive RES/CK/IK, raise the ESP SAs and send
    -- the protected REGISTER (the kernel ESP-wraps it, so it egresses as IP
    -- proto 50) with a Security-Verify echoing the offer we accepted.
    local function on_401(sub, m401)
        sub.stage = "auth"           -- challenged; now authenticating toward 200 OK
        local okc, ch = pcall(register.parse_challenge, m401)
        if not okc then return fail(sub, "cannot parse 401 challenge: " .. log.why(ch)) end
        sub.ch = ch
        if cfg.verbose then
            log.slog(sub, "<- 401", ("IMS-AKA challenge (RAND %s)"):format(cfg.hex(ch.rand)))
        end

        local okv, keys = pcall(register.verify_aka, ch)
        if not okv then return fail(sub, "AKA AUTN verification failed: " .. log.why(keys)) end
        if cfg.verbose then
            log.slog(sub, "AUTN verified", ("SQN %s, RES %s")
                :format(cfg.hex(keys.sqn), cfg.hex(keys.res)))
        end

        sub.cseq = sub.cseq + 1
        sub.authz = register.digest(sub, ch, keys)   -- kept for the Expires:0 de-REGISTER

        if not register.offers_ipsec(ch) then
            if cfg.require_ipsec then
                return fail(sub, "401 carried no Security-Server (IMS_IPSEC=0 to allow " ..
                                 "an unprotected authenticated REGISTER)")
            end
            log.slog(sub, "Security-Server", "absent -- unprotected authenticated REGISTER")
            return send(sub, register.build(sub, sub.authz), "AKAv1-MD5 (digest only)")
        end

        if not F.xfrm then
            local okx, x = pcall(function() return ipsec.Xfrm() end)
            if not okx then return fail(sub, "cannot open NETLINK_XFRM: " .. log.why(x)) end
            F.xfrm = x
        end
        log.slog(sub, "P-CSCF ports", ("client %s / server %d, SPIs %#x/%#x")
            :format(ch.p_port_c or 0, ch.p_port_s, ch.p_spi_c or 0, ch.p_spi_s))

        -- The bundle the two Security- headers settled on, handed to the ipsec
        -- module: our own protected ports and inbound SPIs, the P-CSCF's from
        -- the 401, and IK as the integrity key (the offer negotiated ealg=null,
        -- so the cipher stays cipher_null and CK goes unused).
        --
        -- port_us is port_uc — the UE advertises ONE protected port in both
        -- roles (see ims/register.lua's security_client, which has the whole
        -- reason). The facade installs TS 33.203 §6.3's four SAs from these
        -- fields either way, so the pairing choice stays here, beside the
        -- offer that made it, rather than baked into the kernel plumbing:
        -- SA1/SA3 carry the REGISTER exchange with the P-CSCF's protected
        -- server port, SA2/SA4 the terminating requests with its client port.
        --
        -- A second 401 (a stale nonce, up to cfg.auth_cap) re-negotiates, and
        -- the UE's own SPIs do not change: the previous bundle goes out first,
        -- or the kernel refuses every SA that names one of them as already
        -- installed and the whole retry is reported as refused operations.
        if sub.esp then sub.esp:release(F.xfrm) end
        local e = ipsec.Esp()
        e.ue,      e.pcscf  = sub.ue_addr, sub.pcscf
        e.port_uc, e.port_us = sub.port_uc, sub.port_uc
        e.spi_uc,  e.spi_us  = sub.spi_uc, sub.spi_us
        e.port_pc, e.port_ps = ch.p_port_c or 0, ch.p_port_s
        e.spi_pc,  e.spi_ps  = ch.p_spi_c or 0, ch.p_spi_s
        e.auth_key = keys.ik
        sub.esp = e             -- what teardown releases (F.release_sas)
        -- hex() of a 16-byte key: build it only if it will be printed.
        if cfg.verbose then
            log.slog(sub, "ESP keys", ("enc=%s auth(IK)=%s")
                :format(e.enc_key == "" and "null" or cfg.hex(e.enc_key),
                        cfg.hex(keys.ik)))
        end

        -- A half-offered Security-Server (a port or an SPI missing) raises
        -- here, before any netlink traffic, and is a negotiation failure —
        -- distinct from the kernel refusing operations it did understand.
        local oke, bad = pcall(function() return e:establish(F.xfrm) end)
        if not oke then return fail(sub, "cannot raise the ESP SAs: " .. log.why(bad)) end
        if bad > 0 then
            -- Without the SAs the "protected" REGISTER leaves in the clear and
            -- the P-CSCF discards it; say so once, here, rather than let it
            -- surface as an unexplained timeout per subscriber.
            for i = 0, e:error_count() - 1 do log.slog(sub, "IPsec", e:error_at(i)) end
            stats.sa_fail = stats.sa_fail + 1
            return fail(sub, ("%d of 8 IPsec operations refused (CAP_NET_ADMIN?)"):format(bad))
        end
        log.slog(sub, "IPsec", ("%d SAs + %d policies, UE %s:%d <-> %s:%d/%d")
            :format(e:sa_count(), e:policy_count(), sub.ue_addr, sub.port_uc,
                    sub.pcscf, ch.p_port_s, ch.p_port_c or 0))
        sub.protected = true
        send(sub, register.build(sub, sub.authz, "Security-Verify", ch.ss_raw),
             "AKAv1-MD5 over ESP")
    end

    -- ---- round 1 ----

    -- The caller has the socket bound and on the loop; this is the REGISTER.
    function F.first_register(sub)
        sub.cseq  = sub.cseq + 1
        sub.stage = "register"       -- driving the initial REGISTER / 401 exchange
        sub.t0    = now()
        send(sub, register.build(sub, register.advertise(sub),
                                 "Security-Client", register.security_client(sub)),
             "unprotected")
    end

    -- ---- a response arrived ----

    -- Feed the machines and dispatch on what the registration machine makes of
    -- it: a 401 to answer, a 2xx that registered us, or a final that did not.
    function F.handle(sub, m)
        if sub.done then return end   -- ignore late replies once terminal
        F.disarm(sub)
        pcall(function() sub.txn:recv(m) end)
        pcall(function() sub.auth:recv(m) end)
        local ok = pcall(function() sub.reg:recv(m) end)  -- classifies 401 / 2xx / fail
        if not ok then
            log.slog(sub, "SIP", ("ignoring %s in state %s")
                :format(tostring(m.status), sub.reg:state_name()))
            return
        end
        if o.on_response then o.on_response(sub, m) end
        if sub.reg:state() == sip.RS_CHALLENGED then
            sub.attempts = sub.attempts + 1
            if sub.attempts > cfg.auth_cap then
                pcall(function() sub.auth:event(sip.AE_GIVE_UP) end)
                return fail(sub, "authentication failed (repeated 401)")
            end
            on_401(sub, m)
        elseif sub.reg:registered() then
            succeed(sub, m)
        elseif sub.reg:failed() then
            fail(sub, ("registration rejected: %d %s"):format(m.status, m.reason))
        end
    end

    -- ---- releasing the bindings ----

    -- One protected REGISTER with Expires:0 over the established SA, carrying
    -- the same Authorization as the successful one (the S-CSCF de-registers an
    -- already-registered IMPU with Expires:0 without a fresh challenge). Its
    -- explicit contact-removal path is what reaps the P-CSCF's SAs; contact
    -- expiry is not. Fire-and-forget — the caller gives them a moment to
    -- egress and be processed. Returns how many went out.
    function F.deregister()
        local dr = {}
        for _, s in ipairs(o.subs) do
            if s.registered and s.sock and s.ch and s.authz then dr[#dr + 1] = s end
        end
        if #dr == 0 then return 0 end
        log.banner(("De-REGISTER — releasing %d registration(s) so the P-CSCF reaps their IPsec SAs")
            :format(#dr))
        for _, s in ipairs(dr) do
            s.cseq = s.cseq + 1
            -- The Security-Verify goes only on a REGISTER that actually rides
            -- an SA; the header name is passed unconditionally because build()
            -- keys on the value.
            local sec_hdr = s.protected and s.ch.ss_raw or nil
            feed_sent(s, true)   -- REGISTERED -> DEREGISTERING
            io_.send(s, "mo", register.build(s, s.authz, "Security-Verify", sec_hdr, 0),
                     "de-REGISTER", "Expires:0")
        end
        return #dr
    end

    -- ---- teardown ----

    -- Our own kernel state first (while the addresses are still meaningful),
    -- then the sockets.
    function F.release_sas()
        if not F.xfrm then return end
        for _, s in ipairs(o.subs) do
            if s.esp then s.esp:release(F.xfrm) end
        end
    end

    function F.close_sockets()
        for _, s in ipairs(o.subs) do
            if s.sock then
                pcall(function() loop:del_fd(s.sock:fd()) end)
                s.sock:close()
            end
        end
    end

    return F
end

return M
