#!/usr/bin/env lua
-- Install a site-to-site IPsec tunnel with XFRM: an ESP SA in each
-- direction plus the outbound policy that steers traffic onto it, then
-- tear it all down. Manipulating SAs/policies needs CAP_NET_ADMIN;
-- opening the socket does not, so without privilege each kernel call is
-- reported as rejected rather than aborting the script.
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua ipsec_sa.lua [LOCAL PEER]

local ipsec = require("ipsec")

local local_ip = arg[1] or "10.0.0.1"
local peer_ip  = arg[2] or "10.0.0.2"

-- Demo keys: raw bytes, so any byte string works. AES-128 wants 16, and
-- HMAC-SHA-256 32 — build them however you like (here a fixed pattern).
local ENC_KEY  = ("\xA5"):rep(16)
local AUTH_KEY = ("\x5A"):rep(32)
local SPI_OUT, SPI_IN, REQID = 0x1000, 0x1001, 1

-- Run a kernel op, turning the CAP_NET_ADMIN rejection into one line.
local function attempt(what, fn)
    local ok, err = pcall(fn)
    if not ok then err = tostring(err):gsub("^SWIG_RuntimeError:%s*", "") end
    print(("%-24s %s"):format(what, ok and "ok" or ("skipped (" .. err .. ")")))
    return ok
end

local function esp_sa(src, dst, spi)
    local sa = ipsec.Sa()
    sa.src, sa.dst = src, dst
    sa.spi   = spi
    sa.proto = ipsec.PROTO_ESP
    sa.mode  = ipsec.TUNNEL
    sa.reqid = REQID
    sa.enc_alg,  sa.enc_key  = "cbc(aes)",     ENC_KEY
    sa.auth_alg, sa.auth_key = "hmac(sha256)", AUTH_KEY
    return sa
end

local function out_policy()
    local p = ipsec.Policy()
    p.src, p.dst   = local_ip, peer_ip
    p.dir          = ipsec.DIR_OUT
    p.action       = ipsec.ALLOW
    p.has_tmpl     = true            -- transform template = tunnel it
    p.tmpl_src     = local_ip
    p.tmpl_dst     = peer_ip
    p.tmpl_reqid   = REQID
    p.tmpl_proto   = ipsec.PROTO_ESP
    p.tmpl_mode    = ipsec.TUNNEL
    return p
end

local x = ipsec.Xfrm()               -- opens NETLINK_XFRM
print(("IPsec tunnel %s <-> %s (ESP, reqid %d)"):format(local_ip, peer_ip, REQID))

attempt("add outbound SA",  function() x:sa_add(esp_sa(local_ip, peer_ip, SPI_OUT)) end)
attempt("add inbound SA",   function() x:sa_add(esp_sa(peer_ip, local_ip, SPI_IN)) end)
attempt("add outbound policy", function() x:policy_add(out_policy()) end)

-- Tear down (leaves the kernel as we found it).
attempt("flush policies", function() x:flush_policy() end)
attempt("flush ESP SAs",  function() x:flush_sa(ipsec.PROTO_ESP) end)
