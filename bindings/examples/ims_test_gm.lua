#!/usr/bin/env lua
--
-- Usage:
--   LUA_CPATH=<build>/bindings/lua/?.so [PCSCF_IP=pcscf] [IMS_SUBS=N] lua ims_test_gm.lua
--
-- IMS registration over Gm with IMS-AKA and IPsec, and nothing else: N
-- subscribers (IMS_SUBS, default 1) register with the P-CSCF concurrently on one
-- net.Loop, straight over the access network — no GTP tunnel under them, no
-- calls, no SMS, no reg-event subscription.
--
-- bindings/examples/ims_test_s5.lua is this same registration carried over an
-- S5/S8 PDN connection, plus every phase that follows it. Keeping the Gm leg on
-- its own is what makes it the first probe to run against a stack: when it
-- fails, the fault is in the IMS (P-CSCF / I-CSCF / S-CSCF / HSS) or in the USIM
-- keys, because there is no PGW, no eBPF datapath and no bearer in the path to
-- be the other explanation — and ims_test_s5.lua's registration failures can
-- only be read as core faults once this one passes.
--
-- The two scripts run the same registration because they run the SAME CODE: the
-- exchange itself (REGISTER -> 401 -> ESP SAs -> protected REGISTER -> 200 OK,
-- and the Expires:0 release), the identities, the message building and the
-- statistics live in the ims/ modules beside this file — ims/regflow.lua above
-- all, whose header walks the flow step by step. What is left here is what is
-- particular to Gm:
--
--   * the P-CSCF is named (PCSCF_IP), not learnt from a Create Session PCO;
--   * the UE's source address is a real address of THIS host (IMS_UE_IP, by
--     default the first IPv4 address of IMS_UE_IFACE), because over Gm the
--     P-CSCF replies to the address it received the REGISTER from, so that
--     address has to be routable back here. Subscribers share it and are
--     separated by port and SPI, so one container address carries all of them;
--   * nothing follows the 200 OK: the registrations are released and the run
--     ends, which is why this file is a few hundred lines and the S5/S8 one is
--     not.
--
-- Installing ESP SAs needs CAP_NET_ADMIN. Each kernel op degrades to a reported
-- line when refused, and since an unprotected "protected" REGISTER is dropped by
-- the P-CSCF the summary names the missing capability rather than reporting a
-- plain registration failure.
--
-- One stack-side failure mode is worth naming here, because from the UE side it
-- is indistinguishable from a dead core: a P-CSCF that hands out an SPI it has
-- used before WITHOUT having deleted the old SA (kamailio's ims_ipsec_pcscf logs
-- `clean_sa(): Error sending delete SAs command via netlink socket` when its
-- delete path fails) is left holding a state — the kernel keys one by
-- destination and SPI, so the old one answers for the new offer — whose replay
-- window has already advanced. Our fresh SA starts at sequence 1, so its kernel
-- discards the protected REGISTER as a replay, silently, before kamailio ever
-- sees it. The signature is exact: the ESP packet is on the wire, nothing comes
-- back, OUR xfrm counters are all zero, and the P-CSCF's own
-- XfrmInStateSeqError climbs — `docker exec <pcscf> grep -v " 0$"
-- /proc/net/xfrm_stat`. Restarting the P-CSCF clears it; there is nothing the UE
-- side can do about it, which is why the summary points at it rather than
-- pretending otherwise.

-- The modules this shares with ims_test_s5.lua live in ims/ beside this file.
-- Make them requirable however the script was invoked (the C modules keep
-- coming from LUA_CPATH).
package.path = ((arg and arg[0] or ""):match("^(.*)[/\\]") or ".") .. "/?.lua;" .. package.path

local net = require("net")            -- event loop + UDP socket + DNS + interface helpers

local cfg     = require("ims.cfg")    -- the environment: realm, IMSI range, keys, timers
local log     = require("ims.log")    -- banners, the aligned summary lines, the trace
local stats_  = require("ims.stats")  -- distributions, stage tallies, xfrm counters
local ue      = require("ims.ue")     -- one subscriber: identity, ports, SPIs, FSMs
local sipio   = require("ims.sipio")  -- the UE socket: send, drain, count
local regflow = require("ims.regflow")-- the REGISTER exchange itself

-- ---- configuration ----------------------------------------------------
--
-- Everything shared with the S5/S8 test — IMS_MCC / IMS_MNC / IMS_REALM,
-- IMS_IMSI, IMS_SUBS, IMS_K / IMS_OPC, IMS_EXPIRES, IMS_DEREG, IMS_IPSEC,
-- SIP_T_MS, IMS_VERBOSE — is read by ims/cfg.lua and documented there. What
-- follows is Gm's own.

local pcscf_host = os.getenv("PCSCF_IP") or "pcscf"   -- a name or a literal IP

-- The UE's own address: a real address of this host, since the P-CSCF answers
-- whatever it received the REGISTER from. IMS_UE_IP overrides it (an address
-- this host does not own is bound with IP_FREEBIND + IP_TRANSPARENT, which then
-- needs the reply routed back here by something else).
local ue_iface = os.getenv("IMS_UE_IFACE") or "eth0"
local ue_addr  = os.getenv("IMS_UE_IP")
if not ue_addr or ue_addr == "" then ue_addr = net.if_addr4(ue_iface) end
if not ue_addr or ue_addr == "" then
    io.stderr:write(("no IPv4 address on %q: set IMS_UE_IP or IMS_UE_IFACE\n"):format(ue_iface))
    os.exit(2)
end

-- ---- the run ----------------------------------------------------------

local function run()
    local loop = net.Loop()
    local now  = net.now_ms

    -- Resolve the P-CSCF once, with the net module's own resolver (a dotted
    -- quad passes through unchanged) — no external tools.
    local pcscf
    do
        local ok, res = pcall(function() return net.Resolver():resolve4(pcscf_host) end)
        if not ok then
            io.stderr:write(("cannot resolve P-CSCF %q: %s\n"):format(pcscf_host, log.why(res)))
            os.exit(2)
        end
        pcscf = res
    end

    local subs = {}
    for i = 1, cfg.nsubs do
        local sub = ue.new(i)
        sub.ue_addr, sub.pcscf = ue_addr, pcscf
        subs[i] = sub
    end

    local stats = { tx = 0, rx = 0, regs = 0, protected = 0, sa_fail = 0,
                    start = now(), pkt_last = nil, reg_last = nil, latency = {} }
    local io_  = sipio.new(stats)
    local pending = cfg.nsubs
    local flow                                  -- declared first: finish() uses it

    log.banner(("Gm registration — %d subscriber(s) to P-CSCF %s:%d (%s)")
        :format(cfg.nsubs, pcscf, cfg.pcscf_port, pcscf_host))
    log.line("UE address", ("%s (ports %d..%d)")
        :format(ue_addr, cfg.port_uc_base, cfg.port_uc_base + (cfg.nsubs - 1) * 4))
    log.line("home domain", cfg.realm)
    log.line("IMSI range", cfg.nsubs > 1
        and ("%s .. %s"):format(subs[1].imsi, subs[cfg.nsubs].imsi)
        or  subs[1].imsi)

    -- A subscriber reached a terminal state; when the last one does, release
    -- the registrations (so the P-CSCF reaps their ESP SAs) and stop the loop.
    local function finish(sub)
        if sub.done then return end
        sub.done = true
        flow.disarm(sub)
        pending = pending - 1
        if pending > 0 then return end
        if cfg.dereg and flow.deregister() > 0 then
            -- Fire-and-forget: a moment for them to egress and be processed.
            loop:after(1000, function() loop:stop() end)
        else
            loop:stop()
        end
    end

    flow = regflow.new{ loop = loop, io = io_, stats = stats, subs = subs,
                        on_terminal = finish }

    -- Nothing here subscribes or calls, so no terminating request is expected;
    -- one that arrives anyway is reported, not answered.
    local function on_msg(sub, m, dg)
        if m.request then
            return log.slog(sub, "<- request", ("ignoring %s from %s:%d")
                :format(m.method_name, dg.host, dg.port))
        end
        flow.handle(sub, m)
    end

    -- Bind the UE socket and send the unprotected REGISTER. The UE's address is
    -- normally one this host owns, so a plain bind is enough. IMS_UE_IP may name
    -- one it does not (a simulated PDN address), and that needs IP_FREEBIND +
    -- IP_TRANSPARENT — and CAP_NET_ADMIN.
    local function begin_registration(sub)
        local okb, s = pcall(function() return net.UdpSocket(ue_addr, sub.port_uc) end)
        if not okb then
            local okt, t = pcall(function()
                return net.UdpSocket(ue_addr, sub.port_uc, false, true)
            end)
            if not okt then
                return flow.fail(sub, ("cannot bind %s:%d: %s")
                    :format(ue_addr, sub.port_uc, log.why(s)))
            end
            s = t
            log.slog(sub, "UE SIP socket", ("%s:%d (non-local source, transparent)")
                :format(ue_addr, sub.port_uc))
        else
            log.slog(sub, "UE SIP socket", ("%s:%d"):format(ue_addr, sub.port_uc))
        end
        sub.sock = s
        loop:add_fd(sub.sock:fd(), net.NET_RD, function()
            io_.drain(sub, sub.sock, on_msg)
        end)
        -- Put this UE's output on the loop (queue now, batched sendmmsg from the
        -- loop). NET_RD is the fd's steady-state interest, which the queue
        -- restores after adding NET_WR to ride out a full send buffer.
        sub.sock:tx_loop(loop, net.NET_RD)
        flow.first_register(sub)
    end

    log.banner("REGISTER — IMS-AKA challenge, ESP SAs, protected REGISTER")
    -- A single burst, deliberately: the offered load is the independent variable
    -- of the experiment, and spacing the REGISTERs would hide the very knee a
    -- registration test is run to find.
    for _, sub in ipairs(subs) do begin_registration(sub) end

    local rok, rerr = pcall(function() loop:run() end)

    flow.release_sas()
    flow.close_sockets()
    if not rok then io.stderr:write("loop error: " .. log.why(rerr) .. "\n") end
    return subs, stats
end

-- main
local t0 = net.now_ms()
local subs, stats = run()
local elapsed = (net.now_ms() - t0) / 1000

-- Tally registrations and, for the rest, the stage each subscriber reached when
-- it gave up: the initial REGISTER / 401 challenge, or authentication (AKA
-- verify + ESP SAs + the protected REGISTER / 200 OK).
local STAGES = {
    { key = "register", label = "REGISTER / 401 challenge" },
    { key = "auth",     label = "authentication / 200 OK" },
    { key = "other",    label = "other / incomplete" },
}
local ok, tally, esp_silent = 0, {}, 0
for _, sub in ipairs(subs) do
    if sub.registered then
        ok = ok + 1
    else
        -- A protected REGISTER that got no answer at all: either the P-CSCF
        -- never replied, or one of the two kernels dropped an ESP packet. Ours
        -- reports itself (the xfrm banner below); the P-CSCF's does not, so the
        -- hint has to say where to look. See the header on a reused SPI whose
        -- stale SA rejects our sequence 1 as a replay.
        if sub.protected and (sub.err or ""):find("timed out", 1, true) then
            esp_silent = esp_silent + 1
        end
        stats_.fail(tally, sub.fail_stage or "other", sub.err or "unknown")
    end
end

log.banner(("Summary: %d / %d subscriber(s) registered over Gm in %.2fs"):format(ok, #subs, elapsed))
if ok > 0 then
    log.line("IPsec", ("%d of %d registration(s) rode ESP"):format(stats.protected, ok))
end
if stats.sa_fail > 0 then
    log.line("", "the kernel refused SA/policy installs -- run with CAP_NET_ADMIN")
end
if ok < #subs then
    log.line("failed", tostring(#subs - ok))
    stats_.stages(STAGES, tally, 28)
end
if esp_silent > 0 then
    log.line("silent over ESP", ("%d protected REGISTER(s) got no reply at all"):format(esp_silent))
    log.line("", "with our own xfrm counters clean below, the drop is on the P-CSCF:")
    log.line("", 'docker exec <pcscf> grep -v " 0$" /proc/net/xfrm_stat -- a climbing')
    log.line("", "XfrmInStateSeqError is a stale SA on a reused SPI (see the header).")
end

stats_.xfrm_report()

log.banner("Timing (first REGISTER of a subscriber to its 200 OK)")
local d = stats_.summarize(stats.latency)
log.line("registration latency", d
    and ("p50 %dms  p95 %dms  max %dms  (min %dms, n=%d)"):format(d.p50, d.p95, d.max, d.min, d.n)
    or  "no samples")
-- Rate over the burst itself (first REGISTER to last 200 OK), so the
-- de-REGISTER and teardown do not dilute it.
if stats.regs > 0 and stats.reg_last then
    local r, w = stats_.per_s(stats.regs, stats.reg_last, stats.start)
    log.line("registrations", w > 0
        and ("%d in %.2fs  ->  %.1f/s"):format(stats.regs, w, r)
        or  ("%d (single burst, under one clock tick)"):format(stats.regs))
end
log.line("SIP packets", ("%d sent, %d received"):format(stats.tx, stats.rx))

os.exit(ok == #subs and 0 or 1)
