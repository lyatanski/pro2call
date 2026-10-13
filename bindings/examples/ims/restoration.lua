-- ims/restoration.lua — reading a 504 that asks the UE to register again
-- (S-CSCF restoration, TS 24.229 §4.14.3 and §5.1.2A.1.6).
--
-- When the S-CSCF holding a user restarts or fails, the user's registration
-- state is gone with it, and an originating request is the first the network
-- hears of the UE since. Terminating requests can be re-aimed at a surviving
-- S-CSCF without the UE's help; an originating one cannot, because it follows
-- the Route the UE holds. So the network answers it with a 504 (Server
-- Time-out) that carries an instruction — the 3GPP IM CN subsystem XML body
-- (§7.6) with
--
--   <ims-3gpp version="1"><alternative-service>
--     <type>restoration</type><reason>...</reason>
--     <action>initial-registration</action>
--   </alternative-service></ims-3gpp>
--
-- — and the UE performs an initial registration (§5.1.1.2). The S-CSCF sends it
-- when it cannot get the user's profile back from the HSS (§5.4.3.2 I-III,
-- route[RESTORE_BY_REGISTRATION] in the local stack's serving.cfg); the P-CSCF
-- when it cannot reach the S-CSCF at all (§5.2.6.3.2A); an entry IBCF when it
-- cannot forward (§5.10.3.5).
--
-- A 504 is acted on only when it passes all three of §5.1.2A.1.6's tests, and
-- none of them is decoration:
--
--   1. its P-Asserted-Identity is a URI the UE was handed at registration — in
--      the Service-Route (the S-CSCF asserts its own) or the Path (the P-CSCF
--      asserts its own). That is what makes the instruction the UE's own
--      network's: a 504 from anywhere past the S-CSCF — a far-end proxy that
--      timed out — carries no such identity, and a UE that re-registered on
--      every one would tear down its registration whenever a callee's network
--      was slow;
--   2. its Content-Type is application/3gpp-ims+xml, whatever the
--      Content-Disposition says;
--   3. the body's <alternative-service> has <type>restoration</type> and
--      <action>initial-registration</action>.
--
-- Only REGISTER is out of scope: §5.1.2A covers every method except it, and a
-- REGISTER that fails is the registration procedure's own business.
--
-- Pure reading: no state, no sockets. Acting on the verdict is
-- ims/regflow.lua's restore().

local wire = require("ims.wire")

local M = {}

M.CONTENT_TYPE = "application/3gpp-ims+xml"

-- Every element `name` in `xml`, its text with surrounding whitespace trimmed.
-- The schema (§7.6, table 7.6.1) declares no target namespace, so the element
-- names appear unprefixed; and <type> may legitimately occur twice in one
-- <alternative-service> (table 7.6.3's rule 2: restoration is the first child
-- or the third or later), so every occurrence is returned, not the first.
local function texts(xml, name)
    local out = {}
    for v in xml:gmatch("<" .. name .. "[^>]*>(.-)</" .. name .. ">") do
        out[#out + 1] = v:match("^%s*(.-)%s*$")
    end
    return out
end

local function has(list, want)
    for _, v in ipairs(list) do if v == want then return true end end
    return false
end

-- The URIs the UE holds for this registration that the network may assert in
-- a restoration 504: the Service-Route and the Path from the REGISTER 200 OK.
local function asserted_by_own_network(sub, m)
    local pai = wire.uris(m, "P-Asserted-Identity", true)
    if #pai == 0 then return false, "no P-Asserted-Identity" end
    for _, list in ipairs({ sub.svc_route or {}, sub.path or {} }) do
        for _, own in ipairs(list) do
            for _, a in ipairs(pai) do
                if wire.same_id(a, own) then return true end
            end
        end
    end
    return false, ("P-Asserted-Identity %s is not in the Service-Route or Path")
        :format(pai[1])
end

-- Does this response ask the UE to perform S-CSCF restoration?
--
-- Returns true and the body's <reason> text when it does; false and why not
-- when it does not, so a 504 that was not acted on can be reported as such
-- rather than vanish.
function M.check(sub, m)
    if m.status ~= 504 then return false, "not a 504" end
    local ok, why = asserted_by_own_network(sub, m)
    if not ok then return false, why end
    local ct = (m:header("Content-Type"):lower():match("^%s*([^;%s]+)")) or ""
    if ct ~= M.CONTENT_TYPE then
        return false, ("Content-Type %q"):format(ct ~= "" and ct or "none")
    end
    local body = m.body or ""
    -- "with the <ims-3gpp> element, including a version attribute"
    local root = body:match("<ims%-3gpp([^>]*)>")
    if not (root and root:find("version%s*=")) then
        return false, "no <ims-3gpp version=...> element"
    end
    local alt = body:match("<alternative%-service[^>]*>(.-)</alternative%-service>")
    if not alt then return false, "no <alternative-service>" end
    if not has(texts(alt, "type"), "restoration") then
        return false, "<alternative-service> type is not restoration"
    end
    if not has(texts(alt, "action"), "initial-registration") then
        return false, "<alternative-service> action is not initial-registration"
    end
    return true, texts(alt, "reason")[1] or ""
end

return M
