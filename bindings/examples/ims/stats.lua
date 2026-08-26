-- ims/stats.lua — counting, and reporting what was counted.
--
-- Distributions rather than means, failures attributed to the stage they died
-- at, and the kernel's own drop counters. All of it shared, because a figure
-- that means one thing in the Gm test and another in the S5/S8 one is worse
-- than no figure.

local log = require("ims.log")

local M = {}

-- ---- keyed tallies ----------------------------------------------------

-- Bump a count in a keyed tally (a failure stage, a SIP status, an RP cause).
function M.bump(t, k) t[k] = (t[k] or 0) + 1 end

-- Add one failure to a stage tally, keeping the distinct reasons within the
-- stage: "no ringing" and "478 Unresolvable destination" are both `invite`
-- failures and nothing like the same fault.
function M.fail(t, stage, reason)
    local e = t[stage]
    if not e then e = { n = 0, reasons = {} }; t[stage] = e end
    e.n = e.n + 1
    M.bump(e.reasons, reason or "unknown")
    return e
end

-- A keyed tally as a list, most frequent first — the order every failure
-- listing prints in.
function M.ranked(t)
    local out = {}
    for k, n in pairs(t) do out[#out + 1] = { k = k, n = n } end
    table.sort(out, function(a, b) return a.n > b.n end)
    return out
end

-- Print a stage tally in a fixed order, each stage followed by its distinct
-- reasons. `stages` is a list of {key=, label=} so the reader sees the hops in
-- the order a subscriber walks them, and a stage with no failures prints
-- nothing at all.
function M.stages(stages, t, width)
    width = width or 45
    local fmt = ("     %%-%ds %%d"):format(width)
    for _, s in ipairs(stages) do
        local e = t[s.key]
        if e then
            print(fmt:format(s.label, e.n))
            for _, r in ipairs(M.ranked(e.reasons)) do
                print(("        %-45s %d"):format(r.k, r.n))
            end
        end
    end
end

-- The same in the shape a phase that keeps counts without reasons uses.
function M.stage_counts(stages, t)
    for _, s in ipairs(stages) do
        local n = t[s.key]
        if n then print(("     %-45s %d"):format(s.label, n)) end
    end
end

function M.total(t)
    local n = 0
    for _, e in pairs(t) do n = n + (type(e) == "table" and e.n or e) end
    return n
end

-- ---- distributions ----------------------------------------------------

-- Report distributions, not means: the mean hides the knee, which is the whole
-- reason for measuring latency against offered load.
function M.summarize(t)
    local n = #t
    if n == 0 then return nil end
    local s = {}
    for i = 1, n do s[i] = t[i] end
    table.sort(s)
    local sum = 0
    for i = 1, n do sum = sum + s[i] end
    local function q(p) return s[math.max(1, math.min(n, math.ceil(p * n)))] end
    return { n = n, min = s[1], p50 = q(0.50), p95 = q(0.95), p99 = q(0.99),
             max = s[n], mean = sum / n }
end

-- Every distribution prints the same way, and always with its n: a percentile
-- over three samples is not a percentile, and the reader has to be able to see
-- that.
function M.dist(s, unit, fmt)
    if not s then return "no samples" end
    fmt = fmt or "%.0f"
    return (("p50 " .. fmt .. "  p95 " .. fmt .. "  p99 " .. fmt .. "  max " .. fmt .. " %s  (n=%d)")
        :format(s.p50, s.p95, s.p99, s.max, unit, s.n))
end

-- A rate over the window it actually happened in: from `start` to the last
-- event of its kind, so a grace period or a teardown cannot dilute the burst
-- that was measured. Returns the rate and the window (0/0 when nothing
-- happened at all).
function M.per_s(n, last, start)
    if n == 0 or not last then return 0, 0 end
    local w = (last - start) / 1000
    if w <= 0 then return 0, 0 end
    return n / w, w
end

-- A listening-quality ESTIMATE from packet statistics alone — an ITU-T G.107
-- (E-model) simplification. No audio is decoded, so this is NOT PESQ/POLQA:
-- it is the right tool for "did quality degrade as load rose" and the wrong
-- one for a verdict on a codec. Printed labelled as an estimate for that
-- reason.
function M.mos_estimate(delay_ms, loss_pct)
    local d  = math.max(0, delay_ms or 0)
    local Id = 0.024 * d                               -- delay impairment
    if d > 177.3 then Id = Id + 0.11 * (d - 177.3) end  -- interactivity knee
    local p  = math.max(0, loss_pct or 0) / 100
    local Ie = 30 * math.log(1 + 15 * p)   -- G.711 + packet-loss concealment
    local R  = 93.2 - Id - Ie
    if R <= 0 then return 1.0 end
    if R >= 100 then return 4.5 end
    local mos = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
    return math.max(1.0, math.min(4.5, mos))
end

-- ---- the kernel's own drop counters -----------------------------------

-- Everything protected rides transport-mode ESP, and a packet the kernel
-- refuses — no matching SA, a selector that misses the inbound policy — is
-- dropped in complete silence: the tool sees exactly what it sees when the
-- network never sent anything at all. These counters tell the two apart, so
-- they are worth the four lines. Only non-zero rows are reported.
function M.xfrm_errors()
    local f = io.open("/proc/net/xfrm_stat")
    if not f then return nil end
    local out = {}
    for l in f:lines() do
        local k, v = l:match("^(%S+)%s+(%d+)")
        if k and tonumber(v) > 0 then out[#out + 1] = ("%s=%d"):format(k, tonumber(v)) end
    end
    f:close()
    return out
end

function M.xfrm_report()
    local xe = M.xfrm_errors()
    if not (xe and #xe > 0) then return end
    log.banner("Kernel ESP drops (non-zero /proc/net/xfrm_stat counters)")
    log.line("xfrm", table.concat(xe, "  "))
    log.line("", "a packet counted here was refused by our own kernel, not lost")
    log.line("", "in the network -- check the SA/policy selectors for that port.")
end

return M
