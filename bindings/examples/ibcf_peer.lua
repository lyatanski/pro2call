#!/usr/bin/env lua
--
-- ibcf_peer.lua — another operator's network, as an IBCF sees it across Ici
-- (3GPP TS 23.228 Annex K, the II-NNI), plus a stand-in for the home network
-- behind that IBCF, so one script can drive the border from both sides and
-- check what crossed it.
--
-- The process sits on two networks:
--
--   Ici  PEER_ICI, the peer network's entry point: answers the calls the IBCF
--        sends out, echoes their media, keeps the IBCF's OPTIONS pings
--        answered, and originates calls into the home network
--   Mx   the address of the interface named by PEER_MX_IF: an S-CSCF of the
--        home network as far as the IBCF can tell — it hands the IBCF calls
--        for the peer, and is where those calls' in-dialog requests come back
--
-- What it checks, by TS 24.229 clause:
--
--   exit    an INVITE for the peer's number range leaves with the home
--           network's addresses hidden in Via, Record-Route, Contact and the
--           SDP (5.10.4), without the headers that stay in the trust domain
--           (4.4, 5.10.2.2), with privacy applied (5.10.8), the Call-ID kept
--           (5.10.1), and its media on the TrGW (5.10.5); the media flows
--           both ways through it, and a BYE from the peer finds its way back
--   entry   "orig" from an untrusted peer is refused (5.10.3.2); a call into
--           the home network gets an answer with nothing of its topology in
--           it
--   policy  an unknown source, a body type not let through (5.10.6.3), a
--           destination with no interconnect, and a peer that does not
--           answer (504, 5.10.2.1)
--   release a call whose media stops is ended towards both sides (5.10.2.4)
--   ports   the IBCF's HTTP port and the TrGW's ng socket are not the
--           peer's to use
--
-- Every check prints a line; the exit status is the number that failed.
--
-- Environment:
--   PEER_ICI       this side's Ici address (the IBCF's peers.list entry)
--   PEER_IBCF      the IBCF's Ici address
--   PEER_IBCF_MX   the IBCF's name or address inside the home network
--   PEER_MX_IF     the interface on the home network        (default mx0)
--   PEER_TRGW      the TrGW's Ici address, which an outgoing offer must name
--   PEER_TRGW_MX   the TrGW's home-side address, which the answer must name.
--                  Either can be a space-separated list, one address per TrGW
--                  node, paired by position: the offer's picks the answer's
--   PEER_TRGW_HTTP the TrGW's HTTP port, which takes ng too  (default 9090)
--   PEER_REALM     the home domain, e.g. mnc001.mcc001.3gppnetwork.org
--   PEER_DIAL      the peer's E.164 country code               (default 999)
--   PEER_HOME      a number in the home network's range, for the entry call
--   PEER_T_MS      per-step deadline                        (default 8000)
--   PEER_RTP       media packets per direction                 (default 20)
--   PEER_MEDIA_TIMEOUT_S  the TrGW's media timeout; 0 skips the check
--                         that waits it out                       (default 0)

local net = require("net")
local sip = require("sip")

local function env(k, d)
    local v = os.getenv(k)
    if v == nil or v == "" then
        if d == nil then io.stderr:write(k .. " is required\n"); os.exit(2) end
        return d
    end
    return v
end

local ICI      = env("PEER_ICI")
local IBCF     = env("PEER_IBCF")
local MX_IF    = env("PEER_MX_IF", "mx0")
local function words(s)
    local t = {}
    for w in s:gmatch("%S+") do t[#t + 1] = w end
    return t
end
local TRGWS    = words(env("PEER_TRGW"))
local TRGWS_MX = words(env("PEER_TRGW_MX"))
if #TRGWS ~= #TRGWS_MX then
    io.stderr:write("PEER_TRGW and PEER_TRGW_MX name a different number of nodes\n"); os.exit(2)
end
local TRGW_HTTP = tonumber(env("PEER_TRGW_HTTP", "9090"))
local REALM    = env("PEER_REALM")
local DIAL     = env("PEER_DIAL", "999")
local HOME     = env("PEER_HOME")
local T_MS     = tonumber(env("PEER_T_MS", "8000"))
local NRTP     = tonumber(env("PEER_RTP", "20"))

local MX = net.if_addr4(MX_IF)
if MX == "" then io.stderr:write(MX_IF .. " has no IPv4 address\n"); os.exit(2) end
local IBCF_MX = env("PEER_IBCF_MX")
if not IBCF_MX:match("^%d+%.%d+%.%d+%.%d+$") then
    IBCF_MX = net.Resolver():resolve4(IBCF_MX)
end

-- ---- reporting ----------------------------------------------------------

local failed, passed = 0, 0
local function check(ok, what, detail)
    if ok then
        passed = passed + 1
        print(("  ok    %s"):format(what))
    else
        failed = failed + 1
        print(("  FAIL  %s%s"):format(what, detail and ("  (" .. detail .. ")") or ""))
    end
    return ok
end
local function section(name) print(("== %s"):format(name)) end

-- ---- sockets ------------------------------------------------------------

local ici   = net.UdpSocket(ICI, 5060)   -- the peer's entry point
local mx    = net.UdpSocket(MX, 5060)    -- the home-side stand-in
local ici_m = net.UdpSocket(ICI, 40000)  -- the peer's media
local mx_m  = net.UdpSocket(MX, 40010)   -- the home side's media

-- ---- SIP helpers ---------------------------------------------------------

-- Every value of a header field, as a Lua list (header_values() hands back a
-- StringList, which ipairs and # do not walk)
local function vals(m, name)
    local v, t = m:header_values(name), {}
    for i = 0, v:size() - 1 do t[#t + 1] = v[i] end
    return t
end

local MIRROR = { "Via", "From", "Call-ID", "CSeq", "Record-Route" }

local function reply(req, status, extra, body)
    local b = sip.Builder():response(status)
    for _, name in ipairs(MIRROR) do
        for _, v in ipairs(vals(req, name)) do b:header_name(name, v) end
    end
    local to = req:header("To")
    if status > 100 and not to:find(";tag=") then to = to .. ";tag=peer" end
    b:header(sip.H_TO, to)
    for _, h in ipairs(extra or {}) do b:header_name(h[1], h[2]) end
    if body then b:header(sip.H_CONTENT_TYPE, "application/sdp") end
    return b:done(body or "")
end

local function request(method, uri, hdrs, body, ctype)
    local b = sip.Builder():request(method, uri)
    for _, h in ipairs(hdrs) do b:header_name(h[1], h[2]) end
    if body then b:header(sip.H_CONTENT_TYPE, ctype or "application/sdp") end
    return b:done(body or "")
end

local function sdp(addr, port)
    return ("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n" ..
            "m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")
           :format(addr, addr, port)
end

local function sdp_conn(body)
    return body:match("c=IN IP4 ([%d%.]+)"), tonumber(body:match("m=audio (%d+)") or "")
end

-- Receive on `sock` until a message `want` accepts, or the deadline. The
-- IBCF's OPTIONS pings to the peer are answered whenever they turn up, and
-- anything else unwanted (a 100 Trying, a retransmission) is passed over.
local function recv(sock, want, ms)
    local deadline = net.now_ms() + (ms or T_MS)
    while true do
        local left = deadline - net.now_ms()
        if left <= 0 then return nil end
        local dg = sock:recv(left)
        if dg.timed_out then return nil end
        local ok, m = pcall(sip.parse, dg.data)
        if ok then
            if m.request and m.method == sip.OPTIONS and sock == ici then
                ici:sendto(reply(m, 200), dg.host, dg.port)
            elseif want(m) then
                return m, dg
            end
        end
    end
end

local function is_req(method) return function(m) return m.request and m.method == method end end
local function is_final(m) return not m.request and m.status >= 200 end

-- Every header field that carries addresses, on one line each
local TOPOLOGY = { "Via", "Record-Route", "Route", "Contact", "Path", "Service-Route" }
local function leaks(m, markers)
    for _, name in ipairs(TOPOLOGY) do
        for _, v in ipairs(vals(m, name)) do
            for _, mark in ipairs(markers) do
                if v:find(mark, 1, true) then return ("%s: %s"):format(name, v) end
            end
        end
    end
    for _, mark in ipairs(markers) do
        if m.body:find(mark, 1, true) then return "SDP: " .. mark end
    end
    return nil
end

-- What the home network would not show the peer
local HOME_MARKS = { MX, IBCF_MX, "ims." .. REALM }
for _, a in ipairs(TRGWS_MX) do HOME_MARKS[#HOME_MARKS + 1] = a end

-- The TrGW node an Ici address is, by position; nil for none of them
local function node(addr)
    for k, a in ipairs(TRGWS) do if a == addr then return k end end
end

local function rtp(seq)
    return string.char(0x80, 0, math.floor(seq / 256) % 256, seq % 256,
                       0, 0, math.floor(seq * 160 / 256) % 256, (seq * 160) % 256,
                       0x11, 0x22, 0x33, 0x44) .. string.rep("\255", 160)
end

local n = 0
local function call_id(tag) n = n + 1; return ("ibcf-%s-%d@peer"):format(tag, n) end

-- ---- exit: home -> peer ---------------------------------------------------

-- An exit call up to the ACK: the home side's INVITE, the peer's 200, the
-- home side's ACK. Returns what the checks need, or nil (after a FAIL) when
-- it got no further than the INVITE or the 200.
local function exit_setup(tag, hdrs)
    local c = { cid = call_id(tag) }
    c.from = ("<tel:+359100000001>;tag=%s%d"):format(tag, n)
    local all = {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s-%d"):format(MX, tag, n) },
        { "Max-Forwards", "68" },
        { "Record-Route", ("<sip:mo@%s:5060;lr>"):format(MX) },
        { "From", c.from }, { "To", ("<tel:+%s100000001>"):format(DIAL) },
        { "Call-ID", c.cid }, { "CSeq", "1 INVITE" },
        { "Contact", ("<sip:home@%s:5060>"):format(MX) },
    }
    for _, h in ipairs(hdrs or {}) do all[#all + 1] = h end
    mx:sendto(request(sip.INVITE, ("tel:+%s100000001"):format(DIAL), all, sdp(MX, 40010)),
              IBCF_MX, 5060)

    c.inv, c.at = recv(ici, is_req(sip.INVITE))
    if not check(c.inv ~= nil, "the INVITE reaches the peer") then return nil end
    -- The peer answers, as a UAS: its route set is the Record-Route as received
    c.rr = vals(c.inv, "Record-Route")
    ici:sendto(reply(c.inv, 180), c.at.host, c.at.port)
    ici:sendto(reply(c.inv, 200, { { "Contact", ("<sip:peer@%s:5060>"):format(ICI) } },
                     sdp(ICI, 40000)), c.at.host, c.at.port)

    c.ok200 = recv(mx, function(m) return not m.request and m.status == 200 end)
    if not check(c.ok200 ~= nil, "the 200 reaches the home side") then return nil end
    c.ac, c.ap = sdp_conn(c.ok200.body)

    -- ACK from the home side along the route set: the UAC's is the
    -- Record-Route reversed, less the entry the home side wrote as the
    -- S-CSCF it stands in for
    local rset = vals(c.ok200, "Record-Route")
    local route = {}
    for i = #rset, 1, -1 do
        if not rset[i]:find("mo@" .. MX, 1, true) then route[#route + 1] = rset[i] end
    end
    local ack = { { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s-ack-%d"):format(MX, tag, n) },
                  { "Max-Forwards", "70" }, { "From", c.from }, { "To", c.ok200:header("To") },
                  { "Call-ID", c.cid }, { "CSeq", "1 ACK" } }
    -- The first entry is the one nearest the UAC: the next hop
    for i = #route, 1, -1 do table.insert(ack, 2, { "Route", route[i] }) end
    mx:sendto(request(sip.ACK, sip.parse_addr(c.ok200:header("Contact")).uri, ack), IBCF_MX, 5060)
    check(recv(ici, is_req(sip.ACK)) ~= nil, "the ACK reaches the peer")
    return c
end

-- Media from the home side to the peer's echo, and back; returns how many
-- made the round trip and where the peer saw them come from
local function media(c, count)
    local echoed, src = 0, nil
    for i = 1, count do
        mx_m:sendto(rtp(i), c.ac, c.ap)
        local dg = ici_m:recv(1000)
        if not dg.timed_out then
            src = src or dg.host
            ici_m:sendto(dg.data, dg.host, dg.port)
            if not mx_m:recv(1000).timed_out then echoed = echoed + 1 end
        end
    end
    return echoed, src
end

local function exit_call()
    section("exit: a call from the home network to the peer")
    local c = exit_setup("exit", {
        { "P-Asserted-Identity", "<tel:+359100000001>" },
        { "Privacy", "id;user" },
        { "P-Charging-Vector", "icid-value=exit1;orig-ioi=home;fe-identifier=scscf" },
        { "P-Charging-Function-Addresses", "ccf=cdf.home" },
        { "P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00101000100000001" },
        { "P-Served-User", "<tel:+359100000001>;sescase=orig;regstate=reg" },
        { "User-Agent", "Serving-CSCF" },
    })
    if not c then return end
    local inv = c.inv
    check(inv:call_id() == c.cid, "Call-ID unchanged", inv:call_id())
    local leak = leaks(inv, HOME_MARKS)
    check(leak == nil, "no home address or name in Via, Record-Route, Contact or SDP", leak)
    for _, h in ipairs({ "P-Charging-Vector", "P-Charging-Function-Addresses",
                         "P-Access-Network-Info", "P-Served-User", "P-Asserted-Identity" }) do
        check(not inv:has_header(h), "no " .. h .. " towards an untrusted peer", inv:header(h))
    end
    check(inv:header("User-Agent") == "", "no core node's User-Agent", inv:header("User-Agent"))
    check(inv:from_().uri == "sip:anonymous@anonymous.invalid", "From anonymous for Privacy: user", inv:header("From"))
    local k = node(sdp_conn(inv.body))
    check(k ~= nil, "the offer names the TrGW on Ici", sdp_conn(inv.body))
    check(c.ok200:header("From") == c.from, "From restored on the answer", c.ok200:header("From"))
    check(k ~= nil and c.ac == TRGWS_MX[k], "the answer names the TrGW inside", c.ac)

    local echoed, src = media(c, NRTP)
    check(k ~= nil and src == TRGWS[k], "media reaches the peer from the TrGW", src)
    check(echoed >= NRTP - 2, ("media echoed back through the TrGW (%d/%d)"):format(echoed, NRTP))

    -- BYE from the peer, along its route set back into the home network
    local bye = { { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-exit-bye-%d"):format(ICI, n) },
                  { "Max-Forwards", "70" }, { "From", inv:header("To") .. ";tag=peer" },
                  { "To", inv:header("From") }, { "Call-ID", c.cid }, { "CSeq", "1 BYE" } }
    for i = #c.rr, 1, -1 do table.insert(bye, 2, { "Route", c.rr[i] }) end
    ici:sendto(request(sip.BYE, sip.parse_addr(inv:header("Contact")).uri, bye), IBCF, 5060)
    local b, bat = recv(mx, is_req(sip.BYE))
    if check(b ~= nil, "the peer's BYE comes back to the home side") then
        check(b.uri:find(MX, 1, true) ~= nil, "its Request-URI is the home Contact again", b.uri)
        mx:sendto(reply(b, 200), bat.host, bat.port)
        check(recv(ici, is_final) ~= nil, "the BYE is answered")
    end
end

-- 5.10.2.4: a call whose media stops is released by the IBCF, towards both
-- sides, once the TrGW reports it (rtpengine's `timeout`, PEER_MEDIA_TIMEOUT_S)
local function exit_media_timeout()
    local wait_s = tonumber(env("PEER_MEDIA_TIMEOUT_S", "0"))
    if wait_s <= 0 then return end
    section(("exit: the media stops (%d s)"):format(wait_s))
    local c = exit_setup("quiet")
    if not c then return end
    check(media(c, 3) >= 1, "media flows at first")
    local deadline = net.now_ms() + (wait_s + 20) * 1000
    local at_peer, at_home
    while net.now_ms() < deadline and not (at_peer and at_home) do
        if not at_peer then
            local b, bat = recv(ici, is_req(sip.BYE), 500)
            if b then at_peer = true; ici:sendto(reply(b, 200), bat.host, bat.port) end
        end
        if not at_home then
            local b, bat = recv(mx, is_req(sip.BYE), 500)
            if b then at_home = true; mx:sendto(reply(b, 200), bat.host, bat.port) end
        end
    end
    check(at_peer, "the IBCF sends the peer a BYE")
    check(at_home, "and the home side one")
end

-- ---- the IBCF's other ports, from Ici -------------------------------------------

local function ici_ports()
    section("the IBCF's and the TrGW's control ports, from Ici")
    local ok, conn = pcall(net.stream_connect, IBCF, 9090, 0, 2000)
    if check(ok and conn, "the IBCF's 9090 accepts the connection", not ok and conn or nil) then
        conn:send("GET /metrics HTTP/1.1\r\nHost: ibcf\r\n\r\n", 2000)
        local r = conn:recv(2000)
        check(not r.timed_out and r.data:find("^HTTP/1%.1 403") ~= nil,
              "metrics refused on Ici", (r.data or ""):match("^[^\r\n]*"))
        conn:close()
    end
    -- rtpengine's ng protocol: a ping answered from inside, not from Ici
    local ng = "probe d7:command4:pinge"
    for k = 1, #TRGWS do
        local ping = net.UdpSocket(ICI, 0)
        ping:sendto(ng, TRGWS[k], 9910)
        check(ping:recv(1000).timed_out, "no ng control socket on the TrGW's Ici address " .. TRGWS[k])
        ping:close()
        -- and none over HTTP either: POST /ng-plain is the same protocol
        local ok, conn = pcall(net.stream_connect, TRGWS[k], TRGW_HTTP, 0, 2000)
        check(not (ok and conn), "no HTTP port on the TrGW's Ici address " .. TRGWS[k])
        if ok and conn then conn:close() end
        ping = net.UdpSocket(MX, 0)
        ping:sendto(ng, TRGWS_MX[k], 9910)
        local r = ping:recv(1000)
        check(not r.timed_out and r.data:find("pong", 1, true) ~= nil, "while inside it answers on " .. TRGWS_MX[k])
        ping:close()
    end
end

-- ---- exit: nobody home ------------------------------------------------------

local function exit_unanswered()
    section("exit: the peer does not answer")
    local cid = call_id("dead")
    mx:sendto(request(sip.INVITE, ("tel:+%s100000002"):format(DIAL), {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-dead-%d"):format(MX, n) },
        { "Max-Forwards", "70" }, { "From", "<tel:+359100000001>;tag=dead" },
        { "To", ("<tel:+%s100000002>"):format(DIAL) }, { "Call-ID", cid },
        { "CSeq", "1 INVITE" }, { "Contact", ("<sip:home@%s:5060>"):format(MX) },
    }, sdp(MX, 40010)), IBCF_MX, 5060)
    -- Swallow the INVITE and its retransmissions; keep answering pings
    local r = recv(mx, is_final, 3 * T_MS)
    check(r ~= nil and r.status == 504, "504 once no entry point answers", r and r.status)
    if r then
        mx:sendto(request(sip.ACK, ("tel:+%s100000002"):format(DIAL), {
            { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-dead-%d"):format(MX, n) },
            { "Max-Forwards", "70" }, { "From", "<tel:+359100000001>;tag=dead" },
            { "To", r:header("To") }, { "Call-ID", cid }, { "CSeq", "1 ACK" } }), IBCF_MX, 5060)
    end
end

local function exit_unrouted()
    section("exit: no interconnect for the destination")
    mx:sendto(request(sip.MESSAGE, "tel:+888100000001", {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-unrouted"):format(MX) },
        { "Max-Forwards", "70" }, { "From", "<tel:+359100000001>;tag=u" },
        { "To", "<tel:+888100000001>" }, { "Call-ID", call_id("unrouted") },
        { "CSeq", "1 MESSAGE" } }), IBCF_MX, 5060)
    local r = recv(mx, is_final)
    check(r ~= nil and r.status == 404, "404 for a number no interconnect serves", r and r.status)
end

-- ---- entry: peer -> home ------------------------------------------------------

local function entry_invite(tag, route, ctype, body)
    local cid = call_id(tag)
    local hdrs = {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s-%d"):format(ICI, tag, n) },
        { "Max-Forwards", "70" },
        { "From", ("<tel:+%s100000001>;tag=%s"):format(DIAL, tag) },
        { "To", ("<%s>"):format(HOME) }, { "Call-ID", cid }, { "CSeq", "1 INVITE" },
        { "Contact", ("<sip:peer@%s:5060>"):format(ICI) },
        { "P-Asserted-Identity", ("<tel:+%s100000001>"):format(DIAL) },
        { "P-Charging-Vector", "icid-value=peer1;orig-ioi=peer" },
        { "P-Charging-Function-Addresses", "ccf=cdf.peer" },
        { "Feature-Caps", "*;+g.3gpp.icsi-ref" },
    }
    if route then table.insert(hdrs, 2, { "Route", route }) end
    return request(sip.INVITE, HOME, hdrs, body or sdp(ICI, 40000), ctype), cid
end

local function ack_for(r, cid, tag)
    ici:sendto(request(sip.ACK, HOME, {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s-%d"):format(ICI, tag, n) },
        { "Max-Forwards", "70" }, { "From", ("<tel:+%s100000001>;tag=%s"):format(DIAL, tag) },
        { "To", r:header("To") }, { "Call-ID", cid }, { "CSeq", "1 ACK" } }), IBCF, 5060)
end

local function entry_orig()
    section("entry: orig from an untrusted peer")
    local inv, cid = entry_invite("orig", ("<sip:%s;lr;orig>"):format(IBCF))
    ici:sendto(inv, IBCF, 5060)
    local r = recv(ici, is_final)
    check(r ~= nil and r.status == 403, "403", r and r.status)
    if r then ack_for(r, cid, "orig") end
end

local function entry_call()
    section("entry: a call into the home network")
    local inv, cid = entry_invite("entry", ("<sip:%s;lr>"):format(IBCF))
    ici:sendto(inv, IBCF, 5060)
    local seen, leak = 0, nil
    local r = recv(ici, function(m)
        if m.request then return false end
        seen = seen + 1
        leak = leak or leaks(m, HOME_MARKS)
        return m.status >= 200
    end, 3 * T_MS)
    if not check(r ~= nil, "a final answer from the home network", r and r.status) then return end
    print(("        %d %s"):format(r.status, r.reason))
    check(r.status ~= 403 and r.status ~= 415, "past the IBCF's own refusals", r.status)
    check(leak == nil, "no home address or name in any response", leak)
    check(#vals(r, "Via") == 1, "only the peer's own Via comes back", #vals(r, "Via"))
    check(not r:header("Server"):find("CSCF", 1, true), "no core node's Server", r:header("Server"))
    check(not r:has_header("P-Charging-Function-Addresses"), "no P-Charging-Function-Addresses")
    if r.status >= 300 then ack_for(r, cid, "entry") end
end

local function entry_body()
    section("entry: a body the IBCF does not let through")
    local inv, cid = entry_invite("body", nil, "application/x-unknown", "hello")
    ici:sendto(inv, IBCF, 5060)
    local r = recv(ici, is_final)
    check(r ~= nil and r.status == 415, "415", r and r.status)
    if r then ack_for(r, cid, "body") end
end

local function entry_unknown()
    section("entry: a source with no agreement")
    -- From the Mx address, which is not in peers.list, through Ici
    mx:sendto(request(sip.OPTIONS, ("sip:%s"):format(IBCF), {
        { "Via", ("SIP/2.0/UDP %s:5060;branch=z9hG4bK-unknown"):format(MX) },
        { "Max-Forwards", "70" }, { "From", "<sip:rogue@example.net>;tag=r" },
        { "To", ("<sip:%s>"):format(IBCF) }, { "Call-ID", call_id("unknown") },
        { "CSeq", "1 OPTIONS" } }), IBCF, 5060)
    local r = recv(mx, is_final)
    check(r ~= nil and r.status == 403, "403", r and r.status)
end

print(("peer %s, home side %s, IBCF %s / %s, TrGW %s / %s")
      :format(ICI, MX, IBCF, IBCF_MX, table.concat(TRGWS, " "), table.concat(TRGWS_MX, " ")))
exit_call()
exit_media_timeout()
ici_ports()
exit_unrouted()
entry_orig()
entry_body()
entry_unknown()
entry_call()
exit_unanswered()
print(("== %d passed, %d failed"):format(passed, failed))
os.exit(failed == 0 and 0 or 1)
