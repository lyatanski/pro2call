-- ims/ue.lua — one subscriber.
--
-- The identity a UE registers with, the resources it holds while it does, and
-- the sip module's own machines that drive the exchange. Everything here is
-- derived from the subscriber's index, so a run of N subscribers needs nothing
-- provisioned but the IMSI range and the one key set (see ims/cfg.lua).
--
-- A script adds its own fields to what new() returns — S5/S8 TEIDs, a GTP-C
-- session, a call, a subscription — and they are documented where they are
-- used. What is here is what the registration itself needs.

local sip = require("sip")
local cfg = require("ims.cfg")

local M = {}

-- IMSI i = base + (i-1) (< 2^53, so exact as a double), 15 digits.
function M.imsi(i)
    return ("%015.0f"):format(tonumber(cfg.base_imsi) + (i - 1))
end

-- `stage` is where a subscriber that fails before anything happens is
-- attributed: the Gm test starts at its first REGISTER, the S5/S8 one at the
-- Create Session that has to precede it.
function M.new(i, stage)
    local idx    = i - 1
    local imsi   = M.imsi(i)
    local impu   = ("sip:%s@%s"):format(imsi, cfg.realm)
    local msisdn = cfg.msisdn_of(imsi)
    local tel    = ("tel:+%s"):format(msisdn)
    local phone  = ("sip:+%s@%s;user=phone"):format(msisdn, cfg.realm)
    return {
        i = i, idx = idx,
        imsi = imsi,
        impu = impu,
        impi = ("%s@%s"):format(imsi, cfg.realm),
        msisdn = msisdn,
        -- How others address this subscriber (cfg.dial_uri). A separate field
        -- from impu on purpose — the UE keeps identifying *itself* by the IMPU
        -- it registered (From, P-Preferred-Identity, the RTCP CNAME), which is
        -- the identity the P-CSCF matches its registration on, while the
        -- number is only ever a destination.
        dial = (cfg.dial_uri == "sip") and impu
               or (cfg.dial_uri == "phone") and phone
               or tel,

        -- The protected ports and the two inbound ESP SPIs, spaced by the
        -- index so concurrent subscribers sharing one UE address never
        -- collide. The UE advertises ONE protected port in both roles (see
        -- ims/register.lua's security_client), so port_us is reserved and
        -- never bound — it stays in the layout to keep the stride unchanged.
        port_uc = cfg.port_uc_base + idx * 4,
        port_us = cfg.port_us_base + idx * 4,
        spi_uc  = cfg.spi_base + idx * 2,
        spi_us  = cfg.spi_base + idx * 2 + 1,

        -- The registration dialog as the sip module models it: a
        -- sip.Registration (RFC 3261 §10 / TS 24.229 §5.1) composed with a
        -- sip.AuthChallenge (§22 digest), fed the traffic and read back for
        -- state — so there is no hand-rolled phase variable anywhere. One
        -- transaction machine, re-armed with restart() for each REGISTER (each
        -- is its own transaction, §17.1.2) rather than a fresh machine — and
        -- so a fresh allocation — per request.
        reg  = sip.Registration(),
        auth = sip.AuthChallenge(),
        txn  = sip.Transaction(sip.NON_INVITE_CLIENT),
        cseq = 0, attempts = 0,

        ue_addr = nil,     -- the address the UE registers from
        pcscf   = nil,     -- the P-CSCF it registers with
        sock    = nil, timer = nil,
        ch      = nil,     -- the 401's challenge and Security-Server
        authz   = nil,     -- the Authorization that earned the 200 OK
        -- The ipsec.Esp raised at the 401 (ims/regflow.lua): it remembers the
        -- SAs and policies the kernel accepted, and releasing it at teardown
        -- deletes exactly those and nothing else.
        esp     = nil,
        protected = false,     -- did the REGISTER actually ride ESP
        registered = false, done = false, err = nil,
        stage = stage or "register", fail_stage = nil,
        t0 = nil, reg_ms = nil,

        -- The Service-Route from the REGISTER 200 OK, mirrored into every
        -- originating request the UE makes afterwards — without it the P-CSCF
        -- classifies the request as terminating and mis-routes it.
        svc_route = nil,
        -- The non-barred identities the 200 OK associated with this
        -- registration, in the order the network listed them. `impu` above is
        -- what the UE registered; this is what the network calls it
        -- afterwards, and the two differ whenever the registered IMPU is the
        -- barred temporary one.
        assoc = nil,
    }
end

return M
