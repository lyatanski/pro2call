#!/usr/bin/env lua
-- Tests for the sdp Lua module (bindings/swig/sdp.i over the sdpxx
-- facade and the C codec in sdp/).
--
-- Unprivileged and offline: nothing is bound, sent or received, so this
-- needs only LUA_CPATH. Covered:
--   - the one-call offer helper, from a table and from an sdp.Offer;
--   - the offer round-trips through the parser it will meet;
--   - liberal parsing: bare LF, an unterminated last line, line types
--     the codec ignores, extension attributes;
--   - the two rules the facade resolves so call sites do not: a
--     media-level c= overrides the session one, and m= port 0 is a
--     rejected stream rather than a silent zero;
--   - direction inheritance (media, else session, else sendrecv);
--   - payload-type access: the format list, rtpmap and fmtp;
--   - the fluent Builder, including that a chain does not free its
--     own Builder halfway through;
--   - errors arrive as Lua errors, not as return codes.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_sdp_bindings.lua

local sdp = require("sdp")

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
check(offer:find("o=- 42 1 IN IP4 10.45.0.2", 1, true), "o= carries id and address")
check(offer:find("s=-", 1, true), "s= placeholder (RFC 8866 wants it non-empty)")
check(offer:find("c=IN IP4 10.45.0.2", 1, true), "session c= is our address")
check(offer:find("t=0 0", 1, true), "t= unbounded")
check(offer:find("m=audio 40000 RTP/AVP 0", 1, true), "m= audio, PCMU")
check(offer:find("a=rtpmap:0 PCMU/8000", 1, true), "static pt 0 names itself")
check(offer:find("a=ptime:20", 1, true), "default ptime is 20ms")
check(offer:find("a=sendrecv", 1, true), "default direction is sendrecv")

-- The same thing through the struct the table shim fills in.
local o = sdp.Offer()
o.addr, o.port, o.id = "10.45.0.2", 40000, 42
check(sdp.offer(o) == offer, "table and sdp.Offer produce the same bytes")

-- Static payload types name themselves; a dynamic one has to be named.
local pcma = sdp.offer{ addr = "10.0.0.1", port = 6000, pt = 8 }
check(pcma:find("a=rtpmap:8 PCMA/8000", 1, true), "pt 8 resolves to PCMA/8000")
check(not pcall(sdp.offer, { addr = "10.0.0.1", port = 6000, pt = 96 }),
      "a dynamic pt with no codec raises rather than claiming PCMU")
local opus = sdp.offer{ addr = "10.0.0.1", port = 6000, pt = 96,
                        codec = "opus", rate = 48000 }
check(opus:find("a=rtpmap:96 opus/48000", 1, true), "a named dynamic pt is fine")

local recvonly = sdp.offer{ addr = "10.0.0.1", port = 1, dir = sdp.DIR_RECVONLY }
check(recvonly:find("a=recvonly", 1, true), "direction follows the enum")

check(not pcall(sdp.offer, { port = 40000 }), "offer without addr raises")
check(not pcall(sdp.offer, { addr = "10.0.0.1" }), "offer without port raises")
check(not pcall(sdp.offer, { addr = "10.0.0.1", port = 1, prt = 2 }),
      "a typo'd field raises instead of silently doing nothing")

-- parse ---------------------------------------------------------------

local m = sdp.parse(offer)
check(m.version == 0, "v=0")
check(m.has_origin and m.origin.sess_id == 42, "o= session id")
check(m.origin.addr == "10.45.0.2", "o= address")
check(m.has_conn and m.conn.addr == "10.45.0.2", "session c=")
check(m.has_time and m.t_start == 0 and m.t_stop == 0, "t=")
check(m:media_count() == 1, "one media section")
check(m:has_audio(), "it is audio")

local a = m:audio()
check(a.type == sdp.M_AUDIO, "media type is an enum")
check(a.type_name == "audio", "wire token kept beside the enum")
check(a.port == 40000, "media port")
check(a.proto == sdp.P_RTP_AVP, "transport protocol is an enum")
check(not a:rejected(), "a non-zero port is not a rejection")
check(a.addr == "10.45.0.2", "media address resolved from the session c=")
check(a.dir == sdp.DIR_SENDRECV, "direction resolved")
check(a:ptime() == 20, "a=ptime read as a number")
check(a:pt_count() == 1 and a:pt_at(0) == 0, "one payload type, PCMU")
check(a:has_pt(0) and not a:has_pt(8), "has_pt")
check(a:has_rtpmap(0), "rtpmap present")
check(a:rtpmap(0).enc == "PCMU" and a:rtpmap(0).clock == 8000, "rtpmap fields")
check(not pcall(function() return a:rtpmap(8) end), "a missing rtpmap raises")

-- The answer as it comes back through rtpengine: bare LF, the media
-- address moved onto a media-level c=, a rejected video stream, an
-- attribute with no enum, and no terminator on the last line.
local answer = table.concat({
    "v=0",
    "o=- 42 2 IN IP4 172.20.0.9",
    "s=-",
    "c=IN IP4 1.1.1.1",
    "b=AS:64",
    "t=0 0",
    "a=sendonly",
    "m=audio 30002 RTP/AVP 0 101",
    "c=IN IP4 172.20.0.9",
    "a=rtpmap:0 PCMU/8000",
    "a=rtpmap:101 telephone-event/8000",
    "a=fmtp:101 0-15",
    "a=ptime:20",
    "a=rtcp:30003",
    "a=X-Vendor-Thing:1",
    "m=video 0 RTP/AVP 96",
    "a=rtpmap:96 VP8/90000",
    "a=inactive",
}, "\n")

local r = sdp.parse(answer)
check(r:media_count() == 2, "two media sections")
local au = r:audio()
check(au.addr == "172.20.0.9", "media-level c= overrides the session one")
check(au.port == 30002, "relay RTP port")
check(au.port + 1 == 30003, "RTCP is the next port (RFC 3550 §11)")
check(au:attr(sdp.A_RTCP) == "30003", "a=rtcp read by enum")
check(au.dir == sdp.DIR_SENDONLY, "media with no direction inherits the session's")
check(r.dir == sdp.DIR_SENDONLY, "session direction")
check(au:pt_count() == 2 and au:pt_at(1) == 101, "both payload types")
check(au:rtpmap(101).enc == "telephone-event", "second rtpmap")
check(au:fmtp(101) == "0-15", "fmtp of one payload type")
check(au:fmtp(0) == "", "no fmtp for pt 0")
check(au:attr_name("x-vendor-thing") == "1", "extension attribute, case-insensitive")
check(au:has_attr(sdp.A_PTIME) and not au:has_attr(sdp.A_MAXPTIME), "has_attr")
check(au:attr_count() == 6, "the audio section's attributes only")

local vid = r:media_at(1)
check(vid.type == sdp.M_VIDEO, "second section is video")
check(vid:rejected(), "m= port 0 is a rejected stream")
check(vid.addr == "1.1.1.1", "a section with no c= inherits the session's")
check(vid.dir == sdp.DIR_INACTIVE, "the unterminated last line still parsed")
check(not r:has_media(sdp.M_TEXT), "has_media says no")
check(not pcall(function() return r:media(sdp.M_TEXT) end), "media() raises when absent")

check(r:bw_count() == 1 and r:bw("AS") == 64, "session bandwidth")
check(r:attr_count() == 1, "session attributes are a separate run")

-- Line types the codec has no use for are skipped, not fatal.
local extra = sdp.parse("v=0\r\ne=a@b.c\r\nz=1 -1h\r\nQ=?\r\nm=audio 1 RTP/AVP 0\r\n")
check(extra:media_count() == 1, "unmodelled and unknown line types ignored")

-- errors --------------------------------------------------------------

check(not pcall(sdp.parse, "SIP/2.0 200 OK\r\n\r\n"), "non-SDP input raises")
check(not pcall(sdp.parse, ""), "empty body raises")
check(not pcall(sdp.parse, "v=0\r\nc=IN IP4\r\n"), "a truncated c= raises")
check(not pcall(sdp.parse, "v=0\r\nm=audio x RTP/AVP 0\r\n"), "a bad m= port raises")
check(not pcall(function() return m:media_at(9) end), "media_at out of range raises")
check(not pcall(function() return m:media_at(-1) end), "negative index raises")

-- builder -------------------------------------------------------------

-- The whole point of the fluent typemap: the constructor's userdata is
-- the only owning handle, so if the chain handed back a fresh non-owning
-- one the Builder would be collectable mid-chain. Force a collection in
-- the middle and keep writing.
local b = sdp.Builder():version()
collectgarbage("collect")
local wire = b:origin("-", 7, 1, "10.0.0.1")
    :name("call")
    :conn("10.0.0.1")
    :bw("AS", 64)
    :time(0, 0)
    :media(sdp.M_AUDIO, 6000, sdp.P_RTP_AVP, "8")
    :attr(sdp.A_RTPMAP, "8 PCMA/8000")
    :attr(sdp.A_SENDRECV)
    :line("k", "clear:x")
    :done()
check(#wire > 0, "the chain survived a GC and produced bytes")

local back = sdp.parse(wire)
check(back.origin.username == "-" and back.origin.sess_id == 7, "o= round-trips")
check(back.name == "call", "s= round-trips")
check(back:bw("AS") == 64, "b= round-trips")
check(back:audio().port == 6000, "m= round-trips")
check(back:audio():rtpmap(8).enc == "PCMA", "a=rtpmap round-trips")
check(back:audio().dir == sdp.DIR_SENDRECV, "flag attribute round-trips")

-- done() resets, so one Builder builds many descriptions.
check(b:version():media(sdp.M_AUDIO, 1, sdp.P_RTP_AVP, "0"):done()
      == "v=0\r\nm=audio 1 RTP/AVP 0\r\n", "the Builder is reusable")

check(not pcall(function() return sdp.Builder():version():media(sdp.M_OTHER, 1, sdp.P_RTP_AVP) end),
      "an unnamed media type raises")
check(not pcall(function() return sdp.Builder():line("kk", "x") end),
      "a multi-character line type raises")

-- Overflow is reported, never truncated silently.
check(not pcall(function()
    local tiny = sdp.Builder(8)
    return tiny:version():conn("10.0.0.1"):done()
end), "a description that does not fit raises")

-- names ---------------------------------------------------------------

check(sdp.attr_name(sdp.A_RTPMAP) == "rtpmap", "attr_name")
check(sdp.mtype_name(sdp.M_AUDIO) == "audio", "mtype_name")
check(sdp.proto_name(sdp.P_RTP_AVP) == "RTP/AVP", "proto_name")
check(sdp.dir_name(sdp.DIR_INACTIVE) == "inactive", "dir_name")
check(sdp.pt_encoding(9) == "G722" and sdp.pt_clock(9) == 8000, "static pt table")
check(sdp.pt_encoding(96) == "" and sdp.pt_clock(96) == 0, "dynamic pt is unnamed")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
