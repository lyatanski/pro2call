#!/usr/bin/env lua
-- Tests for the SWIG Lua sms module (bindings/swig/sms.i).
--
-- Everything here runs unprivileged and offline: the module is a pure
-- codec. Covered:
--   - the module loads and exposes the enum constants and name tables;
--   - submit/deliver -> RPDU -> parse round-trips, both directions;
--   - the tagged-union flattening (one Tpdu, `type` as the tag) and the
--     direction handling Rpdu:tpdu() encapsulates;
--   - the content matrix: GSM-7, extension characters, UCS2 with an
--     emoji, 8-bit, and a concatenated message, all asserted byte-exact;
--   - binary bodies survive the SWIG typemap (embedded 0x00);
--   - errors raise a Lua error naming the operation.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_sms_bindings.lua

local sms = require("sms")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02X", c:byte()) end))
end

-- constants ---------------------------------------------------------------
check(sms.T_SUBMIT == 2 and sms.T_DELIVER == 0, "TPDU type constants")
check(sms.DIR_MS_TO_SC == 0 and sms.DIR_SC_TO_MS == 1, "direction constants")
check(sms.DIR_NEGATIVE == 2, "the RP-ERROR report modifier")
check(sms.ALPHA_AUTO == -1, "ALPHA_AUTO is not a wire value")
check(sms.ALPHA_GSM7 == 0 and sms.ALPHA_8BIT == 1 and sms.ALPHA_UCS2 == 2,
      "alphabet constants")
check(sms.TON_INTERNATIONAL == 1 and sms.TON_ALPHANUM == 5, "TON constants")
check(sms.RP_T_DATA == 0 and sms.RP_T_ACK == 1 and sms.RP_T_ERROR == 2,
      "RPDU type constants")
check(sms.RP_CAUSE_CONGESTION == 42, "RP-Cause constant")
check(sms.UD_MAX == 140 and sms.ADDR_MAX_DIGITS == 20, "limits")
check(sms.UDH_CONCAT8 == 0x00 and sms.UDH_CONCAT16 == 0x08, "UDH IEIs")

-- the two strings every SMS-over-IMS script needs spelled the same way
check(sms.CONTENT_TYPE == "application/vnd.3gpp.sms", "MIME type")
check(sms.FEATURE_TAG == "+g.3gpp.smsip", "REGISTER feature tag")

-- name tables -------------------------------------------------------------
check(sms.type_name(sms.T_SUBMIT) == "SMS-SUBMIT", "type_name")
check(sms.rp_type_name(sms.RP_T_ACK) == "RP-ACK", "rp_type_name")
check(sms.rp_cause_name(30) == "unknown subscriber", "rp_cause_name")
check(sms.status_name(0) == "delivered to SME", "status_name")
check(sms.failure_name(0xD0) == "(U)SIM SMS storage full", "failure_name")
check(sms.ton_name(sms.TON_INTERNATIONAL) == "international", "ton_name")
-- TS 24.011 §8.2.5.4: everything unassigned means temporary failure
check(sms.rp_cause_fold(22) == sms.RP_CAUSE_TEMPORARY_FAILURE, "cause fold")
check(sms.rp_cause_fold(42) == 42, "an assigned cause is left alone")

-- alphabet helpers --------------------------------------------------------
check(sms.gsm7_septets("abc") == 3, "septet count")
check(sms.gsm7_septets("a{b}") == 6, "extension characters count two")
check(sms.is_gsm7("Hello"), "plain text is GSM 7-bit")
check(not sms.is_gsm7("Привет"), "Cyrillic is not")
local ok, err = pcall(function() return sms.gsm7_septets("Привет") end)
check(not ok and err:find("alphabet"), "gsm7_septets raises, naming why")

check(sms.dcs_make(sms.ALPHA_UCS2, -1) == 0x08, "dcs_make UCS2")
check(sms.dcs_make(sms.ALPHA_GSM7, 0) == 0x10, "dcs_make with a class")
local d = sms.dcs_decode(0xD9)
check(d.mwi and d.mwi_active and d.mwi_type == 1, "dcs_decode message waiting")
check(sms.dcs_decode(0x20).alphabet == 3, "a compressed DCS is not readable")

-- TP-VP: four ranges with different steps, not a linear scale
check(sms.vp_seconds(0) == 300, "vp_seconds 5 minutes")
check(sms.vp_seconds(255) == 63 * 7 * 86400, "vp_seconds 63 weeks")
check(sms.vp_seconds(sms.vp_code(24 * 3600)) >= 24 * 3600, "vp_code covers")

-- MO submit ---------------------------------------------------------------
local body = sms.submit{ to = "+447700900123", text = "How are you?",
                         sc = "+123456789", srr = true, mr = 42,
                         validity = 24 * 3600 }
check(#body > 0, "submit builds an RPDU")

local rp = sms.parse_rpdu(body, sms.DIR_MS_TO_SC)
check(rp.type == sms.RP_T_DATA, "it is RP-DATA")
check(rp.from_ms, "travelling towards the network")
check(rp.mr == 42, "RP-MR")
check(rp.oa:empty(), "no originator towards the network")
check(rp.da.digits == "123456789", "the destination is the service centre")
check(rp.da:display() == "+123456789", "display() adds the plus")
check(rp:has_tpdu(), "it carries a TPDU")

local t = rp:tpdu()
check(t.type == sms.T_SUBMIT, "the TPDU is an SMS-SUBMIT")
check(t:type_name() == "SMS-SUBMIT", "and names itself")
check(t.mr == 42, "TP-MR")
check(t.srr, "TP-SRR was set")
check(t.addr.digits == "447700900123", "TP-DA, no plus on the wire")
check(t.addr.ton == sms.TON_INTERNATIONAL, "the plus picked the TON")
check(t.vpf == sms.VPF_RELATIVE, "TP-VPF")
check(t:vp_seconds() >= 24 * 3600, "TP-VP covers the validity asked for")
check(t:text() == "How are you?", "the text round-trips")
check(t:alphabet() == sms.ALPHA_GSM7, "and chose GSM 7-bit")
check(not t:binary(), "not binary")
check(not t:has_udh(), "no user data header")

-- re-encoding the parsed TPDU reproduces the bytes
check(t:encode() == rp.user_data, "Tpdu:encode() round-trips")
check(rp:encode() == body, "Rpdu:encode() round-trips")

-- the direction is checked, not guessed
ok, err = pcall(function() return sms.parse_rpdu(body, sms.DIR_SC_TO_MS) end)
check(not ok and err:find("message type"), "the wrong direction raises")

-- MT deliver --------------------------------------------------------------
local mt = sms.deliver{ from = "+447700900999", text = "Hi back",
                        sc = "+123456789", mr = 7, scts = 1780000000, tz = 8 }
local rp2 = sms.parse_rpdu(mt, sms.DIR_SC_TO_MS)
check(rp2.type == sms.RP_T_DATA and not rp2.from_ms, "RP-DATA towards the MS")
check(rp2.oa.digits == "123456789", "the originator is the service centre")
check(rp2.da:empty(), "and the destination is implicit")

local dt = rp2:tpdu()
check(dt.type == sms.T_DELIVER, "SMS-DELIVER")
check(dt.addr.digits == "447700900999", "TP-OA")
check(dt:text() == "Hi back", "the text")
check(dt.scts:valid(), "TP-SCTS is there")
check(dt.scts.tz == 8, "and keeps the offset")
check(dt.scts:unix_time() == 1780000000, "which converts back exactly")
check(dt.scts:iso8601():find("^20%d%d%-"), "and renders as ISO-8601")
-- TP-MMS is 1 for "no more waiting", so `more = false` sets it
check(dt.mms, "TP-MMS set when nothing more is queued")

-- RP-ACK / RP-ERROR / RP-SMMA ---------------------------------------------
local a = sms.ack(sms.DIR_MS_TO_SC, 42)
check(#a == 2, "a bare RP-ACK is two octets")
local ra = sms.parse_rpdu(a, sms.DIR_MS_TO_SC)
check(ra.type == sms.RP_T_ACK and ra.mr == 42, "RP-ACK round-trips")
check(not ra:has_tpdu(), "with no TPDU")
ok, err = pcall(function() return ra:tpdu() end)
check(not ok and err:find("present"), "asking for a TPDU that is not there raises")

local e = sms.error(sms.DIR_SC_TO_MS, 42, sms.RP_CAUSE_UNKNOWN_SUB)
local re = sms.parse_rpdu(e, sms.DIR_SC_TO_MS)
check(re.type == sms.RP_T_ERROR, "RP-ERROR")
check(re.cause == sms.RP_CAUSE_UNKNOWN_SUB, "the cause")
check(re:cause_name() == "unknown subscriber", "named")

local sm = sms.parse_rpdu(sms.smma(9), sms.DIR_MS_TO_SC)
check(sm.type == sms.RP_T_SMMA and sm.mr == 9, "RP-SMMA")

-- store and forward -------------------------------------------------------
-- What an SC does: SUBMIT -> DELIVER, keeping the payload byte for byte.
local sub_tpdu = sms.submit_tpdu{ to = "+447700900123", text = "How are you?" }
local del_tpdu = sms.deliver_from_submit(sub_tpdu, "+447700900999",
                                         1780000000, 8)
local st = sms.parse_tpdu(sub_tpdu, sms.DIR_MS_TO_SC)
local dl = sms.parse_tpdu(del_tpdu, sms.DIR_SC_TO_MS)
check(dl.type == sms.T_DELIVER, "the SC turned it into a DELIVER")
check(dl.addr.digits == "447700900999", "with the originator's address")
check(dl.user_data == st.user_data, "TP-UD copied byte for byte")
check(dl.dcs == st.dcs and dl.udl == st.udl, "and so were TP-DCS and TP-UDL")
check(dl:text() == "How are you?", "so the text is unchanged")
check(dl.scts:unix_time() == 1780000000, "stamped by the SC")

-- a status report, which is what TP-SRR asks for
local sr = sms.parse_tpdu(
    sms.status_report_tpdu("+447700900123", 42, 0, 1780000000, 1780000060, 0),
    sms.DIR_SC_TO_MS)
check(sr.type == sms.T_STATUS_REPORT, "SMS-STATUS-REPORT")
check(sr.mr == 42, "reports on the right TP-MR")
check(sr:delivered() and not sr:failed(), "TP-ST 0 means delivered")
check(sr.dt:unix_time() == 1780000060, "TP-DT")
check(sr:status_name() == "delivered to SME", "TP-ST named")

-- content matrix ----------------------------------------------------------
-- Every one of these must come back byte-identical. The interesting ones
-- are the extension characters (two septets each, so the packing shifts)
-- and the emoji (a UTF-16 surrogate pair on the wire).
-- The non-ASCII text is written as literal UTF-8 bytes, NOT as \u{...}:
-- Lua 5.1 (which this repo builds against) has no \u escape and silently
-- drops the backslash, so "5\u{20AC}" becomes the eight ASCII characters
-- "5u{20AC}". The test would still pass — both sides mangle identically —
-- while never once exercising the extension table or a surrogate pair.
local matrix = {
    { name = "GSM-7 plain",     text = "Hello, world",     alpha = sms.ALPHA_AUTO },
    { name = "GSM-7 extension", text = "cost 5€ {a|b} ~x", alpha = sms.ALPHA_AUTO },
    { name = "GSM-7 accents",   text = "èéùÇß§¤¡¿ÄÖÑÜàäöñü", alpha = sms.ALPHA_AUTO },
    { name = "UCS2 Cyrillic",   text = "Привет, мир",      alpha = sms.ALPHA_AUTO },
    { name = "UCS2 emoji",      text = "ok 🙂👍 done",      alpha = sms.ALPHA_AUTO },
    { name = "8-bit binary",    text = "\0\1\2\255\127\0", alpha = sms.ALPHA_8BIT },
    { name = "empty",           text = "",                 alpha = sms.ALPHA_AUTO },
}
for _, c in ipairs(matrix) do
    local w = sms.submit{ to = "+447700900123", text = c.text,
                         alphabet = c.alpha }
    local got = sms.parse_rpdu(w, sms.DIR_MS_TO_SC):tpdu()
    check(got:text() == c.text,
          string.format("%s round-trips byte-exact (%s vs %s)", c.name,
                        hex(got:text()), hex(c.text)))
end
-- the auto choice really did pick the cheaper alphabet where it could
local g = sms.parse_rpdu(sms.submit{ to = "+1", text = "5€" },
                         sms.DIR_MS_TO_SC):tpdu()
check(g:alphabet() == sms.ALPHA_GSM7, "the euro sign stays in GSM 7-bit")
local u = sms.parse_rpdu(sms.submit{ to = "+1", text = "Привет" },
                         sms.DIR_MS_TO_SC):tpdu()
check(u:alphabet() == sms.ALPHA_UCS2, "Cyrillic goes to UCS2")

-- binary bodies through the typemap ---------------------------------------
-- A GSM 7-bit '@' is septet 0, so this RPDU genuinely contains 0x00. If a
-- future typemap change ever went NUL-terminated, SMS would break
-- silently and nothing else in this suite would notice.
local at = sms.submit{ to = "+447700900123", text = "@@@@@@@@" }
check(at:find("\0", 1, true) ~= nil, "the RPDU really does contain a 0x00")
check(sms.parse_rpdu(at, sms.DIR_MS_TO_SC):tpdu():text() == "@@@@@@@@",
      "and it survives the round trip")

-- concatenation -----------------------------------------------------------
local long = string.rep("abcdefghij", 40) -- 400 septets
local parts = sms.parts(sms.submit_parts({ to = "+447700900123",
                                           text = long, mr = 10 }, 0x2A))
check(#parts == 3, "400 septets is three parts of 153")
local joined = ""
for i, w in ipairs(parts) do
    local p = sms.parse_rpdu(w, sms.DIR_MS_TO_SC):tpdu()
    check(p:has_udh(), "part " .. i .. " carries a header")
    check(p:has_concat(), "and a concatenation element")
    local c = p:concat()
    check(c.ref == 0x2A and c.total == 3 and c.seq == i,
          "part " .. i .. " is numbered " .. c.seq .. "/" .. c.total)
    check(p.mr == 10 + i - 1, "each part has its own TP-MR")
    -- the header is walkable
    check(p:udh_count() == 1, "one header element")
    check(p:udh_at(0).iei == sms.UDH_CONCAT8, "which is the 8-bit concat IE")
    joined = joined .. p:text()
end
check(joined == long, "reassembled byte-exact")

-- a text that fits gets no concatenation header at all
local one = sms.parts(sms.submit_parts({ to = "+1", text = "short" }, 1))
check(#one == 1, "a short text is one part")
check(not sms.parse_rpdu(one[1], sms.DIR_MS_TO_SC):tpdu():has_udh(),
      "with no header")

-- and the deliver direction splits the same way
local dparts = sms.parts(sms.deliver_parts({ from = "+447700900999",
                                             text = long }, 7, true))
check(#dparts == 3, "deliver_parts splits too")
local dj = ""
for _, w in ipairs(dparts) do
    local p = sms.parse_rpdu(w, sms.DIR_SC_TO_MS):tpdu()
    check(p:concat().ref16, "the 16-bit reference element was used")
    dj = dj .. p:text()
end
check(dj == long, "and reassembles")

-- report TPDUs ------------------------------------------------------------
-- An RP-ERROR's report TPDU has a TP-FCS the RP-ACK form does not, and
-- nothing in the TPDU says which — Rpdu:tpdu() adds the modifier.
local report = sms.Tpdu()
report.type    = sms.T_DELIVER_REPORT
report.has_fcs = true
report.fcs     = 0xD0 -- (U)SIM SMS storage full
local rbytes = report:encode()
check(#rbytes == 3, "the negative report is three octets")

local err_rp = sms.parse_rpdu(
    sms.error(sms.DIR_MS_TO_SC, 5, sms.RP_CAUSE_TEMPORARY_FAILURE, rbytes),
    sms.DIR_MS_TO_SC)
local rt = err_rp:tpdu()
check(rt.type == sms.T_DELIVER_REPORT, "the report parses")
check(rt.has_fcs and rt.fcs == 0xD0, "with its TP-FCS, because it rode an error")
check(rt:cause_name() == "(U)SIM SMS storage full", "named")

-- the same bytes inside an RP-ACK are read the other way, which is the
-- whole reason the modifier exists
local ack_rp = sms.parse_rpdu(sms.ack(sms.DIR_MS_TO_SC, 5, rbytes),
                              sms.DIR_MS_TO_SC)
check(not ack_rp:tpdu().has_fcs, "no TP-FCS inside an RP-ACK")

-- errors ------------------------------------------------------------------
ok, err = pcall(function() return sms.parse_rpdu("", sms.DIR_MS_TO_SC) end)
check(not ok and err:find("truncated"), "an empty RPDU raises")
ok, err = pcall(function() return sms.parse_rpdu("\7\0", sms.DIR_MS_TO_SC) end)
check(not ok and err:find("message type"), "an unassigned RP-MTI raises")
ok, err = pcall(function() return sms.submit{ text = "no destination" } end)
check(not ok and err:find("invalid"), "a submit with no destination raises")
ok, err = pcall(function() return sms.submit{ to = "+1", txt = "typo" } end)
check(not ok and err:find("unknown field"), "a typo'd field raises")
ok, err = pcall(function()
    return sms.submit{ to = "+1", text = "Привет", alphabet = sms.ALPHA_GSM7 }
end)
check(not ok and err:find("alphabet"), "text the alphabet cannot hold raises")
ok, err = pcall(function()
    return sms.submit{ to = "+1", text = string.rep("x", 200) }
end)
check(not ok and err:find("length"), "text too long for one message raises")
ok, err = pcall(function() return sms.parse_rpdu(body, sms.DIR_MS_TO_SC):tpdu():udh_at(0) end)
check(not ok, "udh_at out of range raises")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
