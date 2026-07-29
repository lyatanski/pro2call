-- sdp_min.lua — the minimum SDP (RFC 4566) an IMS UE needs to place a
-- call: build the audio offer it sends in an INVITE, and read back the
-- answer's media address and port so RTP has somewhere to go.
--
-- Deliberately minimal, and deliberately NOT named `sdp`: the project
-- carries a full typed SDP API in sdp/inc/sdp.h with no implementation
-- behind it yet, and that module will own `require("sdp")` when it lands
-- (ims_call_load_test_plan.md, phase 6). Until then this covers the one
-- offer/answer shape the load test controls end to end, and nothing more:
-- one audio stream, RTP/AVP, a single payload type.
--
--   local sdp = require("sdp_min")
--
--   local offer = sdp.offer{ addr = ue_paa, port = 40000 }
--   -- ... INVITE with `offer` as the body, 200 OK comes back ...
--   local a = sdp.parse(rsp.body)
--   if a.audio and not a.audio.rejected then
--       rtp_session:set_peer(a.audio.addr, a.audio.port)
--   end
--
-- Parsing is liberal (bare LF accepted, unknown lines and attributes
-- ignored, trailing whitespace trimmed) and generation is strict (CRLF,
-- RFC 4566 line order) — the usual split, since the answer comes from
-- whatever the network runs (here rtpengine, which rewrites both SDPs)
-- while the offer is ours.

local M = {}

local CRLF = "\r\n"

-- ---- offer -------------------------------------------------------------

-- o= needs a session id that is unique per session from this originator
-- (RFC 4566 §5.2 suggests an NTP-style timestamp). Seeded from the wall
-- clock so two runs of the tool never collide, then incremented; callers
-- that need a fixed value (tests) pass `id`.
local next_id = os.time()

-- Build an audio offer. Only `addr` (the address RTP should be sent TO,
-- i.e. our own media address — the UE's PDN address) and `port` are
-- required; everything else defaults to G.711 mu-law telephony, the
-- payload the RTP facade also defaults to.
--
--   addr, port          where we receive RTP (c= and m=)
--   pt                  payload type (default 0, PCMU)
--   codec, rate         a=rtpmap encoding name / clock rate
--   ptime               a=ptime, milliseconds per packet (default 20)
--   dir                 sendrecv | sendonly | recvonly | inactive
--   id, version, user, name   o= / s= overrides
function M.offer(opts)
    opts = opts or {}
    local addr = opts.addr
    local port = tonumber(opts.port)
    assert(type(addr) == "string" and addr ~= "",
           "sdp.offer: addr (our own media address) is required")
    assert(port and port >= 0 and port <= 65535 and port % 1 == 0,
           "sdp.offer: port must be an integer in 0..65535")

    local pt    = tonumber(opts.pt) or 0
    local codec = opts.codec or "PCMU"
    local rate  = tonumber(opts.rate) or 8000
    local ptime = tonumber(opts.ptime) or 20
    local dir   = opts.dir or "sendrecv"

    local id = opts.id
    if not id then
        next_id = next_id + 1
        id = next_id
    end

    -- IPv4 only: the PDN type the tool requests is IPv4, so addrtype is
    -- always IP4 (an IPv6 UE would need IP6 here and in c=).
    local lines = {
        "v=0",
        ("o=%s %s %s IN IP4 %s"):format(opts.user or "-", tostring(id),
                                        tostring(opts.version or 1), addr),
        ("s=%s"):format(opts.name or "-"),
        ("c=IN IP4 %s"):format(addr),
        "t=0 0",
        ("m=audio %d RTP/AVP %d"):format(port, pt),
        ("a=rtpmap:%d %s/%d"):format(pt, codec, rate),
        ("a=ptime:%d"):format(ptime),
        ("a=%s"):format(dir),
    }
    return table.concat(lines, CRLF) .. CRLF
end

-- ---- answer ------------------------------------------------------------

-- c=<nettype> <addrtype> <connection-address>; the address may carry a
-- TTL and/or a multicast count ("224.2.1.1/127/3"), neither of which a
-- UE call uses — keep only the address itself.
local function parse_conn(value)
    local addr = value:match("^%s*IN%s+IP[46]%s+([^%s/]+)")
    return addr
end

-- m=<media> <port>[/<count>] <proto> <fmt> ...
local function parse_media(value)
    local mtype, port, proto, fmts =
        value:match("^%s*(%S+)%s+(%d+)/?%d*%s+(%S+)%s*(.*)$")
    if not mtype then return nil end
    local m = {
        type  = mtype,
        port  = tonumber(port),
        proto = proto,
        pts   = {},
        rtpmap = {},
        fmtp   = {},
    }
    -- A zero port means the stream was rejected (RFC 3264 §6): the answer
    -- parsed fine, there is just no media to send.
    m.rejected = m.port == 0
    for f in fmts:gmatch("%S+") do
        local n = tonumber(f)
        m.pts[#m.pts + 1] = n or f
    end
    return m
end

-- a=rtpmap:<pt> <encoding name>/<clock rate>[/<encoding parameters>]
local function parse_rtpmap(value)
    local pt, name, rate, params =
        value:match("^(%d+)%s+([^/%s]+)/(%d+)/?(%S*)")
    if not pt then return nil end
    return tonumber(pt), {
        codec  = name,
        rate   = tonumber(rate),
        params = params ~= "" and params or nil,
    }
end

local DIRS = { sendrecv = true, sendonly = true, recvonly = true, inactive = true }

-- Parse an SDP body. Returns a table:
--
--   origin   { user, id, version, addr }   from o=
--   addr     session-level c= address (may be nil)
--   media    array of streams, in offer order
--   audio    the first audio stream, or nil
--
-- Each stream carries type/port/proto/pts plus rejected (port 0), its
-- resolved `addr` (media-level c= if present, else the session-level
-- one), rtpmap[pt] = {codec, rate, params}, fmtp[pt], ptime and dir.
-- Raises on input that is not SDP at all (no v= line); anything it does
-- not recognise is skipped, so a richer answer than we offered parses.
function M.parse(body)
    assert(type(body) == "string", "sdp.parse: body must be a string")

    local out = { media = {} }
    local cur                    -- the stream attributes currently belong to
    local sess_dir               -- session-level direction, inherited by streams

    for line in body:gmatch("[^\r\n]+") do
        local kind, value = line:match("^(%a)=(.*)$")
        if kind then
            value = value:gsub("%s+$", "")
            if kind == "v" then
                out.version = value
            elseif kind == "o" then
                local user, id, ver, addr =
                    value:match("^(%S+)%s+(%S+)%s+(%S+)%s+IN%s+IP[46]%s+(%S+)")
                if user then
                    out.origin = { user = user, id = id, version = ver, addr = addr }
                end
            elseif kind == "s" then
                out.name = value
            elseif kind == "c" then
                local addr = parse_conn(value)
                -- Before the first m= this is the session default; after
                -- it, it overrides that stream's address (RFC 4566 §5.7).
                if cur then cur.addr = addr else out.addr = addr end
            elseif kind == "m" then
                cur = parse_media(value)
                if cur then
                    out.media[#out.media + 1] = cur
                    if not out[cur.type] then out[cur.type] = cur end
                end
            elseif kind == "a" then
                local name, av = value:match("^([^:]+):?(.*)$")
                if name == "rtpmap" then
                    local pt, rm = parse_rtpmap(av)
                    if pt and cur then cur.rtpmap[pt] = rm end
                elseif name == "fmtp" then
                    local pt, params = av:match("^(%d+)%s+(.*)$")
                    if pt and cur then cur.fmtp[tonumber(pt)] = params end
                elseif name == "ptime" then
                    local ms = tonumber(av)
                    if ms then
                        if cur then cur.ptime = ms else out.ptime = ms end
                    end
                elseif DIRS[name] then
                    if cur then cur.dir = name else sess_dir = name end
                end
            end
        end
    end

    assert(out.version, "not SDP: no v= line")

    -- Fill each stream's inherited defaults once, so callers read one
    -- place instead of re-implementing the session/media fallback.
    for _, m in ipairs(out.media) do
        m.addr  = m.addr  or out.addr
        m.ptime = m.ptime or out.ptime
        m.dir   = m.dir   or sess_dir or "sendrecv"
    end
    return out
end

return M
