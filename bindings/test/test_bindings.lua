#!/usr/bin/env lua
-- Tests for the SWIG Lua bindings (bindings/swig/ipsec.i).
--
-- The XFRM module is imperative, so there is no loopback exercise as in
-- the Python/gtp suite; instead these cover what runs without privilege:
--   - the module loads and exposes its constants;
--   - value-type Sa/Policy fields round-trip through the proxy, keys and
--     addresses included (binary strings survive the std::string bridge);
--   - opening the socket works unprivileged, but an actual SA add is
--     rejected with a raised error unless the process has CAP_NET_ADMIN;
--   - ipsec.Esp (the four IMS-AKA SAs of TS 33.203 §6.3 as one object)
--     refuses a half-negotiated bundle before it touches the kernel, and
--     with privilege installs and releases all eight of its objects.
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
-- The live SA round-trip below needs CAP_NET_ADMIN, which uid 0 does not
-- imply: a container runs as root with that capability dropped (Docker's
-- default), so testing the uid sends an unprivileged process down the
-- privileged path and the suite fails on EPERM. Read the effective
-- capability set instead and look for bit 12, CAP_NET_ADMIN. Lua 5.1 has
-- no bitwise operators, hence the divide: the low 16 bits of CapEff are
-- read as a number and shifted down to bit 12 arithmetically.
local function can_net_admin()
    local f = io.open("/proc/self/status")
    if not f then return false end
    local caps
    for line in f:lines() do
        caps = line:match("^CapEff:%s+(%x+)")
        if caps then break end
    end
    f:close()
    if not caps then return false end
    local low = tonumber(caps:sub(-4), 16)
    return low ~= nil and math.floor(low / 4096) % 2 == 1
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

if can_net_admin() then
    -- Privileged: a real add/delete round-trip must succeed.
    x:sa_add(sa)
    local id = ipsec.SaId()
    id.dst, id.spi, id.proto = sa.dst, sa.spi, sa.proto
    x:sa_del(id)
    check(true, "privileged sa_add/sa_del round-trip")
else
    -- No CAP_NET_ADMIN (uid 0 in a default container counts): the kernel
    -- rejects the add with EPERM and the facade raises.
    local ok, err = pcall(function() x:sa_add(sa) end)
    check(not ok, "unprivileged sa_add raises")
    check(type(err) == "string" and err:find("sa_add"), "error names the operation")
end

-- Esp: the IMS-AKA SA set ---------------------------------------------
-- The defaults are the ealg=null offer TS 33.203 §6.3 permits: integrity
-- over IK, no cipher.
local e = ipsec.Esp()
check(e.auth_alg == "hmac(sha1)", "Esp defaults to HMAC-SHA-1 integrity")
check(e.enc_alg == "ecb(cipher_null)" and e.enc_key == "", "and to ESP-NULL")

-- A bundle missing half of the Security-Server is a caller bug, and is
-- refused with the field named rather than as a kernel EINVAL on one of
-- eight operations.
e.ue, e.pcscf = "10.45.0.2", "10.10.0.20"
e.port_uc, e.port_us = 5088, 5088
e.spi_uc, e.spi_us = 0x2001, 0x2002
e.auth_key = string.rep("\7", 20)
local ok, err = pcall(function() return e:establish(x) end)
check(not ok, "establish on a half-negotiated bundle raises")
check(type(err) == "string" and err:find("P%-CSCF's protected ports"),
      "and names the field that is unset")
check(e:sa_count() == 0 and e:policy_count() == 0, "nothing was installed")

e.port_pc, e.port_ps = 6100, 6101
e.spi_pc, e.spi_ps = 0x3001, 0x3002
if can_net_admin() then
    check(e:establish(x) == 0, "privileged establish refuses nothing")
    check(e:sa_count() == 4, "four SAs installed")
    check(e:policy_count() == 4, "four policies installed")
    check(e:error_count() == 0, "and no errors recorded")
    e:release(x)
    check(e:sa_count() == 0 and e:policy_count() == 0, "release empties both")
else
    -- Every one of the eight is refused, and each refusal names the SA or
    -- the policy it belongs to (that is what the caller reports).
    check(e:establish(x) == 8, "unprivileged establish reports 8 refusals")
    check(e:error_count() == 8, "one recorded message each")
    check(e:error_at(0):find("SA %(spi 0x3002%)"), "SA1 named by its SPI")
    check(e:error_at(4):find("policy %(out 10%.45%.0%.2:5088"),
          "and the policy by its selector")
    check(not pcall(function() return e:error_at(8) end), "error_at range checked")
    check(e:sa_count() == 0, "nothing the kernel refused is remembered")
    e:release(x)    -- a no-op, and must not raise
end

print(string.format("\n%d checks, %d failed", tests, failed))
os.exit(failed == 0 and 0 or 1)
