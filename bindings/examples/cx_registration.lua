#!/usr/bin/env lua
-- An IMS registration over the Cx interface (3GPP TS 29.229), both
-- sides, offline: the I-CSCF asks the HSS where to send the user
-- (UAR/UAA), the S-CSCF fetches authentication vectors (MAR/MAA) and
-- claims the registration (SAR/SAA, which also returns the user
-- profile). Wire in, wire out — point the send/receive at an SCTP
-- association and it is a CSCF skeleton.
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua cx_registration.lua

local diam = require("diam")

local IMPI  = "alice@ims.example.net"           -- private identity
local IMPU  = "sip:alice@ims.example.net"       -- public identity
local REALM = "ims.example.net"

local hbh, e2e = 0x1000, 0x8000
local function next_ids()
    hbh, e2e = hbh + 1, e2e + 1
    return hbh, e2e
end

local function show(who, wire)
    local m = diam.parse(wire)
    print(("--- %s: %s%s, %d bytes, %d AVPs"):format(
        who, m:name(), m.request and "-Request" or "-Answer",
        #wire, m:avp_count()))
end

-- Every Cx message opens the same way; requests are proxiable and the
-- session is stateless (TS 29.229 §6).
local function cx(b, session, origin)
    return b
        :ids(next_ids())
        :proxiable()
        :put_str(diam.AVP_SESSION_ID, session)
        :begin_group(diam.AVP_VENDOR_SPECIFIC_APPLICATION_ID)
            :put_u32(diam.AVP_VENDOR_ID, diam.VENDOR_3GPP)
            :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_CX)
        :end_group()
        :put_u32(diam.AVP_AUTH_SESSION_STATE,
                 diam.AUTH_SESSION_STATE_NO_STATE_MAINTAINED)
        :put_str(diam.AVP_ORIGIN_HOST, origin)
        :put_str(diam.AVP_ORIGIN_REALM, REALM)
        :put_str(diam.AVP_DESTINATION_REALM, REALM)
end

-- I-CSCF -> HSS: where should this registration go? ---------------------

local uar = cx(diam.Builder():request(diam.CMD_USER_AUTHORIZATION, diam.APP_CX),
               "icscf.ims.example.net;1;1", "icscf.ims.example.net")
    :put_str(diam.AVP_USER_NAME, IMPI)
    :put_str(diam.AVP_PUBLIC_IDENTITY, IMPU)
    :put_str(diam.AVP_VISITED_NETWORK_IDENTIFIER, REALM)
    :put_u32(diam.AVP_USER_AUTHORIZATION_TYPE,
             diam.USER_AUTHORIZATION_TYPE_REGISTRATION)
    :done()
show("I-CSCF sends UAR", uar)

-- HSS: first registration -> experimental result + capabilities.
local req = diam.parse(uar)
assert(req.cmd == diam.CMD_USER_AUTHORIZATION and req.request)
local uaa = cx(diam.Builder():answer(req.cmd, req.app),
               req:str(diam.AVP_SESSION_ID), "hss.ims.example.net")
    :begin_group(diam.AVP_EXPERIMENTAL_RESULT)
        :put_u32(diam.AVP_VENDOR_ID, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_EXPERIMENTAL_RESULT_CODE,
                 diam.EXPERIMENTAL_RESULT_CODE_DIAMETER_FIRST_REGISTRATION)
    :end_group()
    :put_str(diam.AVP_SERVER_NAME, "sip:scscf.ims.example.net")
    :done()
show("HSS answers UAA", uaa)

local ans = diam.parse(uaa)
local exp = ans:find(diam.AVP_EXPERIMENTAL_RESULT)
              :child(diam.AVP_EXPERIMENTAL_RESULT_CODE)
print(("I-CSCF: %s -> forward REGISTER to %s\n"):format(
    exp:value_name(), ans:str(diam.AVP_SERVER_NAME, diam.VENDOR_3GPP)))

-- S-CSCF -> HSS: authentication vectors ----------------------------------

local session = "scscf.ims.example.net;17;3"
local mar = cx(diam.Builder():request(diam.CMD_MULTIMEDIA_AUTH, diam.APP_CX),
               session, "scscf.ims.example.net")
    :put_str(diam.AVP_USER_NAME, IMPI)
    :put_str(diam.AVP_PUBLIC_IDENTITY, IMPU)
    :put_str(diam.AVP_SERVER_NAME, "sip:scscf.ims.example.net")
    :put_u32(diam.AVP_3GPP_SIP_NUMBER_AUTH_ITEMS, 1)
    :begin_group(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM)
        :put_str(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, "Digest-AKAv1-MD5")
    :end_group()
    :done()
show("S-CSCF sends MAR", mar)

req = diam.parse(mar)
local maa = cx(diam.Builder():answer(req.cmd, req.app),
               req:str(diam.AVP_SESSION_ID), "hss.ims.example.net")
    :put_u32(diam.AVP_RESULT_CODE, 2001)
    :put_str(diam.AVP_USER_NAME, IMPI)
    :put_u32(diam.AVP_3GPP_SIP_NUMBER_AUTH_ITEMS, 1)
    :begin_group(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM)
        :put_str(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, "Digest-AKAv1-MD5")
        :put_str(diam.AVP_3GPP_SIP_AUTHENTICATE,   "\x0a\x0b\x0c\x0d RAND||AUTN")
        :put_str(diam.AVP_3GPP_SIP_AUTHORIZATION,  "\x01\x02\x03\x04 XRES")
    :end_group()
    :done()
show("HSS answers MAA", maa)

ans = diam.parse(maa)
local vector = ans:find(diam.AVP_3GPP_SIP_AUTH_DATA_ITEM, diam.VENDOR_3GPP)
print(("S-CSCF: got %s vector (%d bytes challenge)\n"):format(
    vector:child(diam.AVP_3GPP_SIP_AUTHENTICATION_SCHEME, diam.VENDOR_3GPP):str(),
    #vector:child(diam.AVP_3GPP_SIP_AUTHENTICATE, diam.VENDOR_3GPP):str()))

-- S-CSCF -> HSS: claim the registration, pull the profile ----------------

local sar = cx(diam.Builder():request(diam.CMD_SERVER_ASSIGNMENT, diam.APP_CX),
               session, "scscf.ims.example.net")
    :put_str(diam.AVP_USER_NAME, IMPI)
    :put_str(diam.AVP_PUBLIC_IDENTITY, IMPU)
    :put_str(diam.AVP_SERVER_NAME, "sip:scscf.ims.example.net")
    :put_u32(diam.AVP_SERVER_ASSIGNMENT_TYPE,
             diam.SERVER_ASSIGNMENT_TYPE_REGISTRATION)
    :put_u32(diam.AVP_USER_DATA_ALREADY_AVAILABLE, 0)
    :done()
show("S-CSCF sends SAR", sar)

req = diam.parse(sar)
local profile = '<?xml version="1.0"?><IMSSubscription>...</IMSSubscription>'
local saa = cx(diam.Builder():answer(req.cmd, req.app),
               req:str(diam.AVP_SESSION_ID), "hss.ims.example.net")
    :put_u32(diam.AVP_RESULT_CODE, 2001)
    :put_str(diam.AVP_USER_NAME, IMPI)
    :put_str(diam.AVP_CX_USER_DATA, profile)
    :done()
show("HSS answers SAA", saa)

ans = diam.parse(saa)
assert(diam.enum_name(diam.AVP_RESULT_CODE, 0, ans:u32(diam.AVP_RESULT_CODE))
       == "DIAMETER_SUCCESS")
print(("S-CSCF: %s registered, profile %d bytes"):format(
    IMPU, #ans:str(diam.AVP_CX_USER_DATA, diam.VENDOR_3GPP)))
