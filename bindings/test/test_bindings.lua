#!/usr/bin/env lua
-- Tests for the SWIG Lua bindings (bindings/swig/ipsec.i).
--
-- The XFRM module is imperative, so there is no loopback exercise as in
-- the Python/gtp suite; instead these cover what runs without privilege:
--   - the module loads and exposes its constants;
--   - value-type Sa/Policy fields round-trip through the proxy, keys and
--     addresses included (binary strings survive the std::string bridge);
--   - opening the socket works unprivileged, but an actual SA add is
--     rejected with a raised error unless the process has CAP_NET_ADMIN.
--
-- Run: LUA_CPATH=<build>/bindings/lua/?.so lua test_bindings.lua

local ipsec = require("ipsec")

local tests, failed = 0, 0
local function check(cond, msg)
    tests = tests + 1
    if not cond then
        failed = failed + 1
        print(string.format("  FAIL %s", msg or "check"))
    end
end
local function is_root()
    local f = io.open("/proc/self/status")
    if not f then return false end
    for line in f:lines() do
        local uid = line:match("^Uid:%s+(%d+)")
        if uid then f:close(); return uid == "0" end
    end
    f:close()
    return false
end

-- constants -----------------------------------------------------------
check(ipsec.PROTO_ESP == 50, "PROTO_ESP")
check(ipsec.TUNNEL == 1, "TUNNEL mode")
check(ipsec.DIR_OUT == 1, "DIR_OUT")
check(ipsec.BLOCK == 1, "BLOCK action")

-- Sa value round-trip -------------------------------------------------
local sa = ipsec.Sa()
sa.src, sa.dst = "10.0.0.1", "10.0.0.2"
sa.spi = 0x1000
sa.proto = ipsec.PROTO_ESP
sa.mode = ipsec.TUNNEL
sa.reqid = 42
sa.enc_alg = "cbc(aes)"
sa.enc_key = string.rep("\0", 16)
sa.auth_alg = "hmac(sha256)"
sa.auth_key = ("\1\2\3"):rep(1) .. string.rep("\0", 29)  -- 32 raw bytes
check(sa.src == "10.0.0.1", "sa.src round-trip")
check(sa.spi == 0x1000, "sa.spi round-trip")
check(sa.mode == ipsec.TUNNEL, "sa.mode round-trip")
check(#sa.enc_key == 16, "enc_key length preserved")
check(#sa.auth_key == 32, "auth_key length preserved (embedded NULs)")
check(sa.auth_key:byte(1) == 1 and sa.auth_key:byte(3) == 3, "auth_key bytes intact")

-- Policy value round-trip ---------------------------------------------
local p = ipsec.Policy()
p.src, p.src_prefix = "10.1.0.0", 24
p.dst, p.dst_prefix = "10.2.0.0", 24
p.dir = ipsec.DIR_OUT
p.priority = 100
p.has_tmpl = true
p.tmpl_src, p.tmpl_dst = "10.0.0.1", "10.0.0.2"
p.tmpl_reqid = 42
p.tmpl_mode = ipsec.TUNNEL
check(p.src_prefix == 24, "policy prefix round-trip")
check(p.has_tmpl == true, "policy has_tmpl round-trip")
check(p.tmpl_dst == "10.0.0.2", "policy tmpl_dst round-trip")

-- socket + privilege --------------------------------------------------
local x = ipsec.Xfrm()   -- opening the netlink socket needs no privilege
check(x ~= nil, "Xfrm constructed")

if is_root() then
    -- Privileged: a real add/delete round-trip must succeed.
    x:sa_add(sa)
    local id = ipsec.SaId()
    id.dst, id.spi, id.proto = sa.dst, sa.spi, sa.proto
    x:sa_del(id)
    check(true, "privileged sa_add/sa_del round-trip")
else
    -- Unprivileged: the kernel rejects the add; the facade raises.
    local ok, err = pcall(function() x:sa_add(sa) end)
    check(not ok, "unprivileged sa_add raises")
    check(type(err) == "string" and err:find("sa_add"), "error names the operation")
end

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
