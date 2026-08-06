#!/usr/bin/env lua
-- Tests for the json Lua module (bindings/swig/json.i over the jsonxx
-- facade and the C codec in json/).
--
-- Unprivileged and offline: nothing is bound, sent or received, so this
-- needs only LUA_CPATH. Covered:
--   - json.decode / json.encode, which are hand-written Lua C rather
--     than SWIG output: every type both ways, and the four mappings
--     that have no obvious answer (null, empty table, array-or-object,
--     integral numbers);
--   - the shapes that must fail rather than be guessed at: a table with
--     both array and object keys, an array with a hole, a function;
--   - json.parse's Doc: pointers, defaults, absent members, the exact
--     digits of an integer no double holds;
--   - the fluent Builder, including that a chain does not free its own
--     Builder halfway through, and that it grows past its buffer;
--   - errors arrive as Lua errors, not as return codes;
--   - json loaded beside sip/sdp/diam/net in one interpreter, which is
--     the class-name collision check.
--
-- Note on string literals: this runs under Lua 5.1, where "\xC3" is the
-- three characters x, C, 3 — not one byte. Byte strings are built with
-- string.char.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_json_bindings.lua

local json = require("json")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end

-- An Nsmf_PDUSession create body, the shape these scripts meet.
local body = [[
{
  "supi": "imsi-001010000000001",
  "pduSessionId": 5,
  "dnn": "internet",
  "sNssai": { "sst": 1, "sd": "010203" },
  "qosFlows": [
    { "qfi": 5, "gbr": null, "default": true },
    { "qfi": 1, "gbr": "64 Kbps", "default": false }
  ],
  "ratio": 0.5,
  "volume": 1234567890123456789,
  "epsInterworkingInd": false
}]]

-- decode --------------------------------------------------------------

local t = json.decode(body)
check(t.supi == "imsi-001010000000001", "a string member")
check(t.pduSessionId == 5, "a number member")
check(t.sNssai.sst == 1, "a nested object")
check(t.ratio == 0.5, "a fractional number")
check(t.epsInterworkingInd == false, "false is false, not absent")
check(#t.qosFlows == 2, "an array is a 1-based Lua array")
check(t.qosFlows[1].qfi == 5 and t.qosFlows[2].qfi == 1, "array order kept")
check(t.qosFlows[1]["default"] == true, "true")
check(t.absent == nil, "an absent member is nil")

-- null is present-but-null, which is not the same as absent.
check(json.is_null(t.qosFlows[1].gbr), "null decodes to json.null")
check(t.qosFlows[1].gbr ~= nil, "and so is distinguishable from absent")
check(t.qosFlows[2].gbr == "64 Kbps", "a sibling that is not null")
check(tostring(json.null) == "null", "the sentinel prints as null")

-- The second argument replaces json.null; an explicit nil drops the
-- member, which is the other thing scripts want.
check(json.decode('{"a":null}', nil).a == nil, "decode(s, nil) drops nulls")
check(json.decode('{"a":null}', false).a == false, "decode(s, false) maps them")
check(json.decode('[null]', 0)[1] == 0, "in arrays too")

check(json.decode("42") == 42, "a bare number is a value")
check(json.decode('"hi"') == "hi", "a bare string")
check(json.decode("true") == true, "a bare true")
check(json.is_null(json.decode("null")), "a bare null")
check(next(json.decode("{}")) == nil, "an empty object is an empty table")
check(#json.decode("[]") == 0, "an empty array is an empty table")

-- Escapes come out as UTF-8 bytes.
local esc = json.decode([["a\"b\\c\/d\ne\tf"]])
check(esc == 'a"b\\c/d\ne\tf', "string escapes expanded")

-- A JSON string of hex escapes, assembled rather than written out: the
-- point is what the codec does with them, and a literal one in this file
-- would be at the mercy of whatever wrote the file.
local BS = string.char(92) -- backslash
local function uesc(...)
    local s = ""
    for _, hex in ipairs({ ... }) do s = s .. BS .. "u" .. hex end
    return '"' .. s .. '"'
end

check(json.decode(uesc("00e9")) == string.char(0xC3, 0xA9),
      "a hex escape becomes UTF-8")
check(json.decode(uesc("d83d", "de00")) ==
      string.char(0xF0, 0x9F, 0x98, 0x80),
      "a surrogate pair becomes the one character it encodes")
check(json.decode(uesc("d83d")) == string.char(0xEF, 0xBF, 0xBD),
      "a lone surrogate becomes U+FFFD rather than failing the decode")
check(json.decode(uesc("0000")) == string.char(0),
      "an escaped NUL is a byte, so values are byte strings")

-- A member name is a key, escapes and all.
local names = json.decode([[{"a\/b": 1, "c": 2}]])
check(names["a/b"] == 1 and names["c"] == 2, "member names are unescaped")

-- encode --------------------------------------------------------------

check(json.encode({}) == "{}", "an empty table is an empty object")
check(json.encode(json.array{}) == "[]", "json.array marks it as an array")
check(json.encode(json.object{}) == "{}", "json.object marks the other way")
check(json.encode{1, 2, 3} == "[1,2,3]", "keys 1..n make an array")
check(json.encode{ a = 1 } == '{"a":1}', "anything else makes an object")
check(json.encode("hi") == '"hi"', "a bare string")
check(json.encode(true) == "true", "a bare boolean")
check(json.encode(json.null) == "null", "the sentinel writes null")
check(json.encode(nil) == "null", "so does nil")

-- Numbers are all doubles in 5.1; an integral one must not go out as 5.0.
check(json.encode(5) == "5", "an integral number writes as an integer")
check(json.encode(-0.125) == "-0.125", "a fractional one keeps its digits")
check(json.encode(0.1) == "0.1", "shortest round trip, not 0.10000000000000001")
check(json.encode(2^53) == "9007199254740992", "a large integral double")

-- Escaping on the way out.
check(json.encode('a"b\\c\nd') == '"a\\"b\\\\c\\nd"', "escapes what it must")
check(json.encode("a/b") == '"a/b"', "and not '/', which needs none")
check(json.encode(string.char(0x01)) == '"\\u0001"', "control bytes as \\u")
check(json.encode(string.char(0xC3, 0xA9)) == '"' .. string.char(0xC3, 0xA9) .. '"',
      "UTF-8 passes through")

-- Round trip: what came in comes back out.
local again = json.decode(json.encode(t))
check(again.supi == t.supi, "round trip: string")
check(again.pduSessionId == 5, "round trip: number")
check(again.volume == t.volume, "round trip: big number as a double")
check(json.is_null(again.qosFlows[1].gbr), "round trip: null")
check(#again.qosFlows == 2, "round trip: array")
check(json.encode(json.decode("[]")) == "[]", "round trip: empty array stays []")
check(json.encode(json.decode("{}")) == "{}", "round trip: empty object stays {}")

-- pretty printing, and the indent option in both spellings.
check(json.encode({1}, 2) == "[\n  1\n]", "indent as a number")
check(json.encode({1}, { indent = 2 }) == "[\n  1\n]", "indent as an option")
check(json.pretty({1}) == "[\n  1\n]", "json.pretty defaults to 2")
check(json.encode({1}) == "[1]", "compact by default")

-- The shapes that must not be guessed at.
check(not pcall(json.encode, { 1, 2, x = 3 }),
      "a table with both array and object keys raises")
check(not pcall(json.encode, { [1] = "a", [3] = "c" }),
      "an array with a hole raises")
check(not pcall(json.encode, print), "a function raises")
check(not pcall(json.encode, { [true] = 1 }), "a boolean member name raises")
check(not pcall(json.encode, { a = print }), "a function value raises")

-- A cycle is caught by the nesting bound rather than by a stack overflow.
local cycle = {}
cycle.self = cycle
check(not pcall(json.encode, cycle), "a cycle raises")

-- decode errors -------------------------------------------------------

check(not pcall(json.decode, "{oops}"), "a syntax error raises")
check(not pcall(json.decode, ""), "an empty string raises")
check(not pcall(json.decode, "[1,2,]"), "a trailing comma raises")
check(not pcall(json.decode, '{"a":1} junk'), "trailing data raises")
check(not pcall(json.decode, "1e400"), "a number no double holds raises")
local ok, err = pcall(json.decode, '{"a":1,"b":x}')
check(not ok and err:find("byte 11", 1, true), "the error says where: " .. tostring(err))

-- Doc: query in place -------------------------------------------------

local d = json.parse(body)
check(d:str("/supi") == "imsi-001010000000001", "pointer to a string")
check(d:num("/pduSessionId") == 5, "pointer to a number")
check(d:integer("/pduSessionId") == 5, "read as an integer")
check(d:boolean("/epsInterworkingInd") == false, "read as a boolean")
check(d:num("/sNssai/sst") == 1, "a nested pointer")
check(d:num("/qosFlows/1/qfi") == 1, "an array index in a pointer")
check(d:is_null("/qosFlows/0/gbr"), "a null member")
check(not d:is_null("/qosFlows/1/gbr"), "a member that is not null")
check(d:has("/dnn") and not d:has("/nope"), "has")
check(d:type("/nope") == json.T_NONE, "an absent member has no type")
check(d:type("/sNssai") == json.T_OBJ, "types are enum constants")
check(d:type("/qosFlows") == json.T_ARR, "array")
check(d:type("/supi") == json.T_STR, "string")
check(d:type("/ratio") == json.T_NUM, "number")
check(d:type("/qosFlows/0/gbr") == json.T_NULL, "null")
check(d:type("/epsInterworkingInd") == json.T_BOOL, "boolean")
check(json.type_name(json.T_OBJ) == "object", "type_name")
check(json.type_name(json.T_NONE) == "none", "type_name of T_NONE")

check(d:count("") == 8, "members of the root")
check(d:count("/qosFlows") == 2, "elements of an array")
check(d:count("/supi") == 0, "a scalar has no children")
check(d:key_at("", 0) == "supi", "the first member's name")
check(d:child("/qosFlows", 1) == "/qosFlows/1", "pointer to an element")
check(d:child("", 0) == "/supi", "pointer to a member")

-- Defaults, for the optional members every schema has.
check(d:str_or("/dnn", "x") == "internet", "str_or when present")
check(d:str_or("/nope", "x") == "x", "str_or when absent")
check(d:str_or("/pduSessionId", "x") == "x", "str_or when another type")
check(d:num_or("/ratio", 1) == 0.5, "num_or")
check(d:num_or("/nope", 1) == 1, "num_or default")
check(d:int_or("/pduSessionId", 0) == 5, "int_or")
check(d:bool_or("/epsInterworkingInd", true) == false, "bool_or")
check(d:bool_or("/nope", true) == true, "bool_or default")

-- The exact digits of a value a double cannot hold.
check(d:text("/volume") == "1234567890123456789", "text keeps the literal")
check(d:num("/volume") ~= 0, "and it still reads as a double")
check(d:text("/sNssai") == '{ "sst": 1, "sd": "010203" }', "text of a subtree")
check(d:text("/nope") == "", "text of an absent member is empty")
check(d:size() == #body, "size is the bytes parsed")
check(d:nodes() > 8, "nodes is what the pool needed")

-- Reading the wrong type is a caller bug, so it raises.
check(not pcall(function() return d:num("/supi") end), "num of a string raises")
check(not pcall(function() return d:str("/nope") end), "str of an absent member raises")
check(not pcall(function() return d:integer("/ratio") end),
      "integer of a fraction raises")
check(not pcall(json.parse, "{oops}"), "parse of a bad body raises")

-- json.Doc is the same thing under its constructor.
check(json.Doc(body):str("/dnn") == "internet", "json.Doc(text)")

-- Builder -------------------------------------------------------------

-- The whole point of the fluent typemap: the constructor's userdata is
-- the only owning handle, so if the chain handed back a fresh non-owning
-- one the Builder would be collectable mid-chain. Force a collection in
-- the middle and keep writing.
local b = json.Builder():obj()
collectgarbage("collect")
local wire = b:field("supi", "imsi-1")
    :field_int("pduSessionId", 5)
    :field_num("ratio", 0.5)
    :field_bool("eps", false)
    :field_null("gbr")
    :field_frag("sNssai", d:text("/sNssai"))
    :key("qosFlows"):arr()
        :obj():field_int("qfi", 5):obj_end()
        :obj():field_int("qfi", 1):obj_end()
    :arr_end()
    :obj_end()
    :done()
check(#wire > 0, "the chain survived a GC and produced bytes")

local back = json.decode(wire)
check(back.supi == "imsi-1", "field round-trips")
check(back.pduSessionId == 5, "field_int")
check(back.ratio == 0.5, "field_num")
check(back.eps == false, "field_bool")
check(json.is_null(back.gbr), "field_null")
check(back.sNssai.sd == "010203", "field_frag embedded the subtree")
check(#back.qosFlows == 2 and back.qosFlows[2].qfi == 1, "nested containers")

-- done() resets, so one Builder writes many documents.
check(b:obj():field_int("a", 1):obj_end():done() == '{"a":1}', "reusable")

-- The buffer grows: a document far past the initial capacity is not
-- truncated and does not raise.
local big = json.Builder(16):arr()
for i = 1, 500 do big:integer(i) end
local bigwire = big:arr_end():done()
check(#json.decode(bigwire) == 500, "the buffer grew to fit 500 elements")

-- Misuse raises rather than producing JSON no peer can parse.
check(not pcall(function() return json.Builder():key("a") end),
      "a member name outside an object raises")
check(not pcall(function() return json.Builder():obj():arr_end() end),
      "a mismatched close raises")
check(not pcall(function() return json.Builder():obj():integer(1) end),
      "a value where a name belongs raises")
check(not pcall(function() return json.Builder():obj():done() end),
      "an unclosed document raises")
check(not pcall(function() return json.Builder():done() end),
      "an empty document raises")
check(not pcall(function() return json.Builder():integer(1):integer(2) end),
      "a second top-level value raises")

-- An indented Builder, for a fixture or a log line.
check(json.Builder(256, 2):obj():field_int("a", 1):obj_end():done() ==
      '{\n  "a": 1\n}', "the Builder indents too")

-- helpers -------------------------------------------------------------

check(json.utf8_valid("plain"), "utf8_valid: ascii")
check(json.utf8_valid(string.char(0xC3, 0xA9)), "utf8_valid: é")
check(not json.utf8_valid(string.char(0xC3)), "utf8_valid: truncated")
check(not json.utf8_valid(string.char(0xED, 0xA0, 0x80)), "utf8_valid: surrogate")

-- coexistence ---------------------------------------------------------

-- SWIG's Lua runtime keys wrapped classes in a registry shared by every
-- module in one lua_State, so a name this module introduces that another
-- already has would make one module's objects dispatch into the other's
-- methods — silently, at both build and load time. json renames Builder
-- to JsonBuilder for exactly that reason; Doc is unique. Load the four
-- modules a service script uses together and check that each side still
-- answers for itself.
local sip  = require("sip")
local sdp  = require("sdp")
local diam = require("diam")
local net  = require("net")

check(json.Builder():obj():field_int("a", 1):obj_end():done() == '{"a":1}',
      "json.Builder still works beside sip/sdp/diam/net")
check(sdp.Builder():version():done() == "v=0\r\n", "and sdp.Builder still does")
check(sip.Builder():request(sip.OPTIONS, "sip:a@b"):done("")
      :find("OPTIONS sip:a@b SIP/2.0", 1, true) == 1, "and sip.Builder")
check(diam.Msg ~= nil and net.Loop ~= nil, "diam and net loaded")
check(json.parse('{"a":1}'):num("/a") == 1, "json.Doc beside the others")

-- A JSON body as a SIP body: bytes in, same bytes out, escapes intact.
local jbody = json.encode{ text = 'a"b' .. string.char(0x00) .. "c" }
local msg = sip.parse(sip.Builder():request(sip.MESSAGE, "sip:a@b")
    :header(sip.H_VIA, "SIP/2.0/UDP h;branch=z9hG4bK1")
    :header(sip.H_CONTENT_TYPE, "application/json"):done(jbody))
check(msg.body == jbody, "a JSON body survives a SIP round trip")
check(json.decode(msg.body).text == 'a"b' .. string.char(0x00) .. "c",
      "including the escaped NUL")

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
