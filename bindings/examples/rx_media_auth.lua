#!/usr/bin/env lua
-- A VoLTE call's media authorization over Rx (3GPP TS 29.214), both
-- sides, offline: the P-CSCF (acting as AF) pushes the negotiated SDP
-- media towards the PCRF with an AA-Request so dedicated bearers can
-- be set up, the PCRF authorizes it, and the call teardown ends the
-- Rx session with STR/STA. Wire in, wire out.
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua rx_media_auth.lua

local diam = require("diam")

local SESSION = "pcscf.ims.example.net;99;12"

local function show(who, wire)
    local m = diam.parse(wire)
    print(("--- %s: %s%s, %d bytes, %d AVPs"):format(
        who, m:name(), m.request and "-Request" or "-Answer",
        #wire, m:avp_count()))
end

-- P-CSCF/AF: authorize both directions of one audio stream ---------------

-- The 3GPP media AVPs share their 5xx codes with the RFC 5777
-- classifier AVPs, so the vendor is passed explicitly on those puts.
local aar = diam.Builder()
    :request(diam.CMD_AA, diam.APP_RX)
    :ids(0x51, 0x51)
    :proxiable()
    :put_str(diam.AVP_SESSION_ID, SESSION)
    :put_str(diam.AVP_ORIGIN_HOST, "pcscf.ims.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "ims.example.net")
    :put_str(diam.AVP_DESTINATION_REALM, "epc.example.net")
    :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_RX)
    :put_str(diam.AVP_AF_APPLICATION_IDENTIFIER, "IMS Services", diam.VENDOR_3GPP)
    :put_addr4(diam.AVP_FRAMED_IP_ADDRESS, "10.45.0.23")   -- the UE
    :begin_group(diam.AVP_MEDIA_COMPONENT_DESCRIPTION, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_MEDIA_COMPONENT_NUMBER, 1, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_MEDIA_TYPE, diam.MEDIA_TYPE_AUDIO, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_MAX_REQUESTED_BANDWIDTH_UL, 128000, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_MAX_REQUESTED_BANDWIDTH_DL, 128000, diam.VENDOR_3GPP)
        :put_u32(diam.AVP_FLOW_STATUS, diam.FLOW_STATUS_ENABLED, diam.VENDOR_3GPP)
        :begin_group(diam.AVP_MEDIA_SUB_COMPONENT, diam.VENDOR_3GPP)
            :put_u32(diam.AVP_FLOW_NUMBER, 1, diam.VENDOR_3GPP)
            :put_str(diam.AVP_FLOW_DESCRIPTION,
                     "permit out 17 from 192.0.2.10 49152 to 10.45.0.23 50000",
                     diam.VENDOR_3GPP)
            :put_str(diam.AVP_FLOW_DESCRIPTION,
                     "permit in 17 from 10.45.0.23 50000 to 192.0.2.10 49152",
                     diam.VENDOR_3GPP)
        :end_group()
    :end_group()
    :put_u32(diam.AVP_SPECIFIC_ACTION,
             diam.SPECIFIC_ACTION_INDICATION_OF_LOSS_OF_BEARER,
             diam.VENDOR_3GPP)
    :put_u32(diam.AVP_SPECIFIC_ACTION,
             diam.SPECIFIC_ACTION_INDICATION_OF_RELEASE_OF_BEARER,
             diam.VENDOR_3GPP)
    :done()
show("P-CSCF sends AAR", aar)

-- PCRF: check and authorize ----------------------------------------------

local req = diam.parse(aar)
assert(req.cmd == diam.CMD_AA and req.app == diam.APP_RX)

local media = req:find(diam.AVP_MEDIA_COMPONENT_DESCRIPTION, diam.VENDOR_3GPP)
local sub = media:child(diam.AVP_MEDIA_SUB_COMPONENT, diam.VENDOR_3GPP)
print(("PCRF: %s media, %d/%d bps, %d flow(s)"):format(
    media:child(diam.AVP_MEDIA_TYPE, diam.VENDOR_3GPP):value_name(),
    media:child(diam.AVP_MAX_REQUESTED_BANDWIDTH_UL, diam.VENDOR_3GPP):u32(),
    media:child(diam.AVP_MAX_REQUESTED_BANDWIDTH_DL, diam.VENDOR_3GPP):u32(),
    sub.children:size() - 1))             -- Flow-Number + the flows
for i = 0, req:avp_count() - 1 do
    local avp = req:avp_at(i)
    if avp.code == diam.AVP_SPECIFIC_ACTION then
        print("PCRF: will report " .. avp:value_name())
    end
end

local aaa = diam.Builder()
    :answer(diam.CMD_AA, diam.APP_RX)
    :ids(req.hbh, req.e2e)
    :put_str(diam.AVP_SESSION_ID, SESSION)
    :put_str(diam.AVP_ORIGIN_HOST, "pcrf.epc.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "epc.example.net")
    :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_RX)
    :put_u32(diam.AVP_RESULT_CODE, 2001)
    :done()
show("PCRF answers AAA", aaa)
assert(diam.parse(aaa):u32(diam.AVP_RESULT_CODE) == 2001)
print("P-CSCF: media authorized, dedicated bearer coming up\n")

-- Call ends: terminate the Rx session -------------------------------------

local str = diam.Builder()
    :request(diam.CMD_SESSION_TERMINATION, diam.APP_RX)
    :ids(0x52, 0x52)
    :proxiable()
    :put_str(diam.AVP_SESSION_ID, SESSION)
    :put_str(diam.AVP_ORIGIN_HOST, "pcscf.ims.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "ims.example.net")
    :put_str(diam.AVP_DESTINATION_REALM, "epc.example.net")
    :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_RX)
    :put_u32(diam.AVP_TERMINATION_CAUSE, 1)   -- DIAMETER_LOGOUT
    :done()
show("P-CSCF sends STR", str)

req = diam.parse(str)
local sta = diam.Builder()
    :answer(diam.CMD_SESSION_TERMINATION, diam.APP_RX)
    :ids(req.hbh, req.e2e)
    :put_str(diam.AVP_SESSION_ID, SESSION)
    :put_str(diam.AVP_ORIGIN_HOST, "pcrf.epc.example.net")
    :put_str(diam.AVP_ORIGIN_REALM, "epc.example.net")
    :put_u32(diam.AVP_RESULT_CODE, 2001)
    :done()
show("PCRF answers STA", sta)
print("P-CSCF: Rx session closed")
