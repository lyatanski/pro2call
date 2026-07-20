#!/usr/bin/env lua
-- Dump a SIP message: start line, every header with its resolved enum
-- id (compact forms land on the same id as long forms), and the typed
-- views the codec offers (URI, addresses, Via, CSeq).
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua sip_dump.lua [file]
-- Without a file a sample REGISTER is dumped.

local sip = require("sip")

local wire
if arg[1] then
    local f = assert(io.open(arg[1], "rb"))
    wire = f:read("a")
    f:close()
else
    wire = table.concat({
        "REGISTER sip:registrar.biloxi.example.com SIP/2.0",
        "v: SIP/2.0/UDP bobspc.biloxi.example.com:5060;branch=z9hG4bKnashds7",
        "Max-Forwards: 70",
        "t: Bob <sip:bob@biloxi.example.com>",
        "f: Bob <sip:bob@biloxi.example.com>;tag=456248",
        "i: 843817637684230@998sdasdh09",
        "CSeq: 1826 REGISTER",
        "m: <sip:bob@192.0.2.4>",
        "Expires: 7200",
        "l: 0",
        "", "",
    }, "\r\n")
end

local m = sip.parse(wire)

if m.request then
    print(("request  %s (%d) %s"):format(m.method_name, m.method, m.uri))
    local u = sip.parse_uri(m.uri)
    print(("         uri: scheme=%s user=%s host=%s port=%s"):format(
        u.scheme, u.user ~= "" and u.user or "-", u.host,
        u.port ~= 0 and ("%d"):format(u.port) or "-"))
else
    print(("response %d %s"):format(m.status, m.reason))
end

print(("%d headers:"):format(m:header_count()))
for i = 0, m:header_count() - 1 do
    local h = m:header_at(i)
    local canon = h.id ~= sip.H_OTHER and sip.hdr_name(h.id) or h.name
    local note  = h.name ~= canon and (" (as %q)"):format(h.name) or ""
    print(("  %-20s %s%s"):format(canon, h.value, note))
end

-- Typed views ----------------------------------------------------------

local cseq = m:cseq()
print(("cseq     %d %s"):format(cseq.number, cseq.method_name))

local via = m:top_via()
print(("via      %s %s%s branch=%s"):format(via.transport, via.host,
    via.port ~= 0 and (":%d"):format(via.port) or "", via.branch))

local from, to = m:from_(), m:to_()
print(("from     %s <%s> tag=%s"):format(from.display, from.uri,
    from.tag ~= "" and from.tag or "-"))
print(("to       %s <%s> tag=%s"):format(to.display, to.uri,
    to.tag ~= "" and to.tag or "-"))

if #m.body > 0 then
    print(("body     %d bytes"):format(#m.body))
end
