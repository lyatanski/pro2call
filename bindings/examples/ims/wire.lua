-- ims/wire.lua — writing SIP, and reading the headers the sip module leaves as
-- text.
--
-- One Builder for the whole run and the handful of header readers that more
-- than one phase needs. The route set, the remote target and the Service-Route
-- are all name-addr lists, so they are all the same read; keeping that read in
-- one place is why a folded header (several hops in one comma-separated value)
-- works everywhere rather than in whichever caller remembered it.

local sip = require("sip")

local M = {}

-- One Builder for the whole run: request()/response() re-init the write
-- buffer, so successive messages cannot bleed into each other and no message
-- pays for the buffer it is written into. Safe because these scripts are
-- single-threaded and never have two messages half-built at once.
M.builder = sip.Builder()

-- A UE's contact: the address and protected port it registered, which is also
-- the socket every phase sends from and every terminating request arrives at.
function M.contact(sub) return ("<sip:%s:%d>"):format(sub.ue_addr, sub.port_uc) end

-- A response from `sub` to `req`. Via order matters and Record-Route must be
-- echoed in the order received — that is how the far end learns its route set
-- for the ACK and the BYE. The To tag is added only when the request has none
-- (a mid-dialog request already carries it).
--
-- record_route=false is for a request that opened no dialog (a MESSAGE, RFC
-- 3428 §4): there is no route set to echo, and echoing one invents a dialog
-- neither end has.
function M.response(sub, req, o)
    local b    = M.builder:response(o.status, o.reason)
    local vias = req:header_values("Via")
    for i = 0, vias:size() - 1 do b:header(sip.H_VIA, vias[i]) end
    if o.record_route ~= false then
        local rrs = req:header_values("Record-Route")
        for i = 0, rrs:size() - 1 do b:header(sip.H_RECORD_ROUTE, rrs[i]) end
    end
    local to = req:header("To")
    if not to:find(";tag=", 1, true) then to = to .. ";tag=" .. o.to_tag end
    b:header(sip.H_FROM, req:header("From"))
        :header(sip.H_TO, to)
        :header(sip.H_CALL_ID, req:header("Call-ID"))
        :header(sip.H_CSEQ, req:header("CSeq"))
        :header(sip.H_CONTACT, M.contact(sub))
    if o.body then b:header(sip.H_CONTENT_TYPE, o.content_type or "application/sdp") end
    return b:done(o.body or "")
end

-- Every <...> of a header, in the order it appeared, across however many
-- header instances carry it. Record-Route and Service-Route values are always
-- name-addr, so pulling the angle-bracketed URIs out in order copes with both
-- one header per hop and several hops folded into one comma-separated value,
-- without a splitter that has to know a comma inside <> is not a separator.
-- `bare` strips the brackets, for values that are compared as identities
-- rather than sent on as routes.
function M.uris(m, name, bare)
    local out  = {}
    local vals = m:header_values(name)
    local pat  = bare and "<([^>]*)>" or "<[^>]*>"
    for i = 0, vals:size() - 1 do
        for uri in vals[i]:gmatch(pat) do out[#out + 1] = uri end
    end
    return out
end

-- The dialog's route set is the Record-Route list: in the order it appeared
-- for the side that received the request (the MT), reversed for the side that
-- received the response (the MO) — RFC 3261 §12.1.
function M.route_set(m, reverse)
    local out = M.uris(m, "Record-Route")
    if reverse then
        for i = 1, math.floor(#out / 2) do
            out[i], out[#out - i + 1] = out[#out - i + 1], out[i]
        end
    end
    return out
end

-- The dialog's remote target: the far end's Contact URI.
function M.contact_uri(m)
    local c = m:header("Contact")
    if c == "" then return nil end
    return c:match("<([^>]*)>") or c:match("^%s*([^;%s]+)")
end

-- The Service-Route the S-CSCF returned in the REGISTER 200 OK. Mirroring it
-- into an originating request's Route is NOT optional: both CSCFs pick the
-- originating path on the Route URI ("sip:orig@..." / "sip:mo@..."), so a
-- request without it is classified as *terminating* and fails in a way that
-- looks like a routing bug in the core (proxy.cfg / serving.cfg request_route).
function M.service_route(m) return M.uris(m, "Service-Route") end

-- The identities the REGISTER 200 OK associated with this registration
-- (TS 24.229 §5.1.1.1A), bare — no angle brackets, so they compare as
-- identities rather than as routes.
--
-- This matters because these UEs have no ISIM. A UE registers with a TEMPORARY
-- public user identity derived from the IMSI (TS 23.003 §13.4B), and that one
-- is provisioned BARRED: good for the REGISTER and for nothing else. The
-- identities the network will actually talk about are the non-barred ones it
-- returns here — with open5gs's HSS, sip:<msisdn>@<realm> and tel:<msisdn>
-- (hss_cx_download_user_data). Both CSCF sides filter on that flag: kamailio
-- builds this header from the unbarred identities (build_p_associated_uri) and
-- builds a reg-info document from the same set, so a UE that only ever knows
-- its own IMPU cannot recognise its own registration state.
function M.associated_uris(m) return M.uris(m, "P-Associated-URI", true) end

-- Two URIs naming the same identity: compared case-insensitively and without
-- their parameters, so the tel URI a run dials and the one the HSS provisioned
-- are the same identity even when one carries a phone-context (RFC 3966 §3)
-- and the other does not.
local function norm(u)
    local s = (u or ""):lower()
    s = s:gsub("%s+", "")
    s = s:gsub("[;>].*$", "")
    s = s:gsub("^<", "")
    return s
end
function M.same_id(a, b) return norm(a) == norm(b) end

return M
