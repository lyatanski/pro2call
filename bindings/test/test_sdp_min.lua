#!/usr/bin/env lua
-- Tests for the minimal SDP helper (bindings/examples/sdp_min.lua).
--
-- Pure Lua, unprivileged and offline: no bindings module is loaded, so
-- this needs only LUA_PATH pointing at the examples directory. Covered:
--   - the generated offer is well-formed RFC 4566 and round-trips
--     through the parser;
--   - liberal parsing: bare LF, unknown lines, unknown attributes,
--     trailing whitespace;
--   - session vs media level c= (media wins) and inherited ptime/dir;
--   - several m= sections: attributes attach to the preceding stream;
--   - a zero m= port is reported as a rejected stream, not an error;
--   - rtpmap with encoding parameters, and fmtp;
--   - an rtpengine-shaped answer yields the media address and port;
--   - input that is not SDP raises.
--
-- Run: LUA_PATH=<src>/bindings/examples/?.lua lua test_sdp_min.lua

local sdp = require("sdp_min")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- offer ---------------------------------------------------------------
local offer = sdp.offer{ addr = "10.45.0.2", port = 40000, id = 42 }
check(offer:sub(1, 5) == "v=0\r\n", "offer starts with v=0 and CRLF")
check(offer:sub(-2) == "\r\n", "offer ends with CRLF")
check(not offer:find("[^\r]\n"), "offer uses CRLF only (no bare LF)")
check(offer:find("o=- 42 1 IN IP4 10.45.0.2", 1, true), "o= carries the id and address")
check(offer:find("c=IN IP4 10.45.0.2", 1, true), "session c= is our address")
check(offer:find("m=audio 40000 RTP/AVP 0", 1, true), "m= audio, PCMU")
check(offer:find("a=rtpmap:0 PCMU/8000", 1, true), "default codec is PCMU/8000")
check(offer:find("a=ptime:20", 1, true), "default ptime is 20ms")
check(offer:find("a=sendrecv", 1, true), "default direction is sendrecv")

-- RFC 4566 requires v= o= s= before c=, t= before the first m=
local vpos = offer:find("v=", 1, true)
local opos = offer:find("o=", 1, true)
local spos = offer:find("s=", 1, true)
local cpos = offer:find("c=", 1, true)
local tpos = offer:find("t=", 1, true)
local mpos = offer:find("m=", 1, true)
check(vpos < opos and opos < spos and spos < cpos and cpos < tpos and tpos < mpos,
      "offer line order is v o s c t m")

-- the id increments when not supplied, so two offers never collide
local a1 = sdp.parse(sdp.offer{ addr = "10.45.0.2", port = 1000 })
local a2 = sdp.parse(sdp.offer{ addr = "10.45.0.2", port = 1000 })
check(a1.origin.id ~= a2.origin.id, "o= session id differs between offers")

-- overrides
local dyn = sdp.offer{ addr = "10.45.0.9", port = 41000, pt = 96,
                       codec = "AMR", rate = 8000, ptime = 40, dir = "sendonly",
                       user = "ue", name = "call", version = 7, id = 1 }
check(dyn:find("o=ue 1 7 IN IP4 10.45.0.9", 1, true), "o= honours user/id/version")
check(dyn:find("s=call", 1, true), "s= honours name")
check(dyn:find("m=audio 41000 RTP/AVP 96", 1, true), "m= honours port and pt")
check(dyn:find("a=rtpmap:96 AMR/8000", 1, true), "rtpmap honours codec")
check(dyn:find("a=ptime:40", 1, true) and dyn:find("a=sendonly", 1, true),
      "ptime and direction honoured")

-- offer -> parse round-trip
local r = sdp.parse(offer)
check(r.version == "0", "parsed version")
check(r.addr == "10.45.0.2", "parsed session address")
check(r.origin.user == "-" and r.origin.id == "42", "parsed origin")
check(r.name == "-", "parsed session name")
check(#r.media == 1, "one media stream")
check(r.audio ~= nil, "audio shortcut set")
check(r.audio.type == "audio" and r.audio.port == 40000, "audio type and port")
check(r.audio.proto == "RTP/AVP", "audio proto")
check(r.audio.rejected == false, "non-zero port is not rejected")
check(#r.audio.pts == 1 and r.audio.pts[1] == 0, "payload type list")
check(r.audio.addr == "10.45.0.2", "audio inherits the session address")
check(r.audio.ptime == 20, "audio ptime")
check(r.audio.dir == "sendrecv", "audio direction")
check(r.audio.rtpmap[0].codec == "PCMU" and r.audio.rtpmap[0].rate == 8000,
      "audio rtpmap")

-- offer arguments are validated
check(not pcall(sdp.offer, { port = 1000 }), "offer without addr raises")
check(not pcall(sdp.offer, { addr = "10.0.0.1" }), "offer without port raises")
check(not pcall(sdp.offer, { addr = "10.0.0.1", port = 70000 }), "port out of range raises")
check(not pcall(sdp.offer, { addr = "10.0.0.1", port = "x" }), "non-numeric port raises")

-- liberal parsing -----------------------------------------------------
-- bare LF, an unknown line type, an unknown attribute, trailing spaces
local loose = table.concat({
    "v=0",
    "o=- 1 1 IN IP4 192.168.1.1",
    "s=-",
    "c=IN IP4 192.168.1.1   ",
    "t=0 0",
    "z=3730928400 -1h",                 -- unknown to us; must be skipped
    "m=audio 5004 RTP/AVP 8 0",
    "a=rtpmap:8 PCMA/8000",
    "a=unknown-attribute:whatever",     -- must be skipped
    "a=ptime:30",
}, "\n") .. "\n"
local l = sdp.parse(loose)
check(l.addr == "192.168.1.1", "bare LF parses; trailing space trimmed")
check(l.audio.port == 5004, "LF-separated m= parses")
check(#l.audio.pts == 2 and l.audio.pts[1] == 8 and l.audio.pts[2] == 0,
      "multiple payload types, in order")
check(l.audio.rtpmap[8].codec == "PCMA", "rtpmap for the first pt")
check(l.audio.ptime == 30, "media ptime")

-- media-level c= overrides the session level; rtpmap parameters; fmtp
local override = table.concat({
    "v=0",
    "o=- 1 1 IN IP4 10.0.0.1",
    "s=-",
    "c=IN IP4 10.0.0.1",
    "a=inactive",                        -- session-level direction
    "t=0 0",
    "m=audio 6000 RTP/AVP 111",
    "c=IN IP4 172.16.0.5",               -- this stream lives elsewhere
    "a=rtpmap:111 opus/48000/2",
    "a=fmtp:111 useinbandfec=1",
}, "\r\n") .. "\r\n"
local o = sdp.parse(override)
check(o.addr == "10.0.0.1", "session address still recorded")
check(o.audio.addr == "172.16.0.5", "media-level c= overrides the session one")
check(o.audio.rtpmap[111].codec == "opus", "rtpmap encoding name")
check(o.audio.rtpmap[111].rate == 48000, "rtpmap clock rate")
check(o.audio.rtpmap[111].params == "2", "rtpmap encoding parameters")
check(o.audio.fmtp[111] == "useinbandfec=1", "fmtp captured")
check(o.audio.dir == "inactive", "session-level direction inherited")

-- several streams: each attribute belongs to the m= above it
local multi = table.concat({
    "v=0",
    "o=- 1 1 IN IP4 10.0.0.1",
    "s=-",
    "c=IN IP4 10.0.0.1",
    "t=0 0",
    "m=audio 7000 RTP/AVP 0",
    "a=rtpmap:0 PCMU/8000",
    "a=ptime:20",
    "a=sendrecv",
    "m=video 0 RTP/AVP 99",              -- rejected by the answerer
    "a=rtpmap:99 H264/90000",
    "a=inactive",
}, "\r\n") .. "\r\n"
local mm = sdp.parse(multi)
check(#mm.media == 2, "two streams")
check(mm.media[1].type == "audio" and mm.media[2].type == "video", "stream order")
check(mm.audio.port == 7000 and mm.audio.rejected == false, "audio accepted")
check(mm.video.port == 0 and mm.video.rejected == true, "zero port -> rejected")
check(mm.audio.rtpmap[0] ~= nil and mm.audio.rtpmap[99] == nil,
      "audio rtpmap not polluted by the video stream")
check(mm.video.rtpmap[99] ~= nil and mm.video.rtpmap[0] == nil,
      "video rtpmap not polluted by the audio stream")
check(mm.audio.dir == "sendrecv" and mm.video.dir == "inactive",
      "per-stream direction")
check(mm.audio.ptime == 20 and mm.video.ptime == nil,
      "ptime stays on the stream that declared it")

-- an answer shaped like rtpengine's (media relayed, address rewritten) --
local answer = table.concat({
    "v=0",
    "o=- 1596902400 1596902401 IN IP4 172.22.0.9",
    "s=-",
    "c=IN IP4 172.22.0.9",
    "t=0 0",
    "m=audio 30112 RTP/AVP 0",
    "a=rtpmap:0 PCMU/8000",
    "a=ptime:20",
    "a=sendrecv",
    "a=rtcp:30113",
}, "\r\n") .. "\r\n"
local ans = sdp.parse(answer)
check(ans.audio.addr == "172.22.0.9", "relay address read from the answer")
check(ans.audio.port == 30112, "relay RTP port read from the answer")
check(ans.audio.port + 1 == 30113, "RTCP is the next port (RFC 3550 §11)")
check(ans.audio.rtpmap[0].codec == "PCMU", "answer kept our codec")

-- not SDP -------------------------------------------------------------
check(not pcall(sdp.parse, "SIP/2.0 200 OK\r\n\r\n"), "non-SDP input raises")
check(not pcall(sdp.parse, ""), "empty body raises")
check(not pcall(sdp.parse, nil), "nil body raises")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
