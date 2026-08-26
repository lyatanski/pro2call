-- ims/log.lua — the running commentary.
--
-- Every line these tests print about themselves while they run: the phase
-- banners, the aligned key/value lines the summaries are built from, and the
-- per-subscriber trace. Kept in one place because the trace has a cost — see
-- cfg.verbose — and a rule about when to write is only worth anything if
-- there is one gate to apply it at.

local cfg = require("ims.cfg")

local M = {}

-- Batch the writes: banner() flushes, so a crash loses at most the current
-- phase, and nothing else pays for an unbuffered stdout per line.
io.stdout:setvbuf("full", 65536)

function M.banner(t) print(("\n== %s"):format(t)); io.stdout:flush() end
function M.line(k, v) print(("   %-24s %s"):format(k, v)) end

-- The message out of an error value, without the "file:line:" the Lua runtime
-- prefixes to it: these are reported to a reader, not to a debugger.
function M.why(e) return (tostring(e):gsub("^.-:%s*", "")) end

-- Prefix a log line with the subscriber index when running more than one.
-- Silent unless verbose: the per-subscriber trace is the first thing to go at
-- scale. Call sites whose arguments are themselves expensive to build (hex(),
-- string.format over several fields) test cfg.verbose themselves, since Lua
-- evaluates them before this function is entered.
function M.slog(sub, k, v)
    if not cfg.verbose then return end
    M.line(cfg.nsubs > 1 and ("[%d] %s"):format(sub.i, k) or k, v)
end

-- A whole message as text (IMS_DUMP=1), for the questions a summary line
-- cannot answer: route set ordering, tags, which Record-Route came back.
function M.dump(what, wire)
    if not cfg.dump then return end
    print(("\n--- %s (%d bytes)"):format(what, #wire))
    io.write((wire:gsub("\r\n", "\n")))
    io.stdout:flush()
end

return M
