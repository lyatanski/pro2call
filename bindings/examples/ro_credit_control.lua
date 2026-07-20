#!/usr/bin/env lua
-- An online-charging session over Ro (3GPP TS 32.299 on the RFC 4006
-- credit-control application), both sides, offline: a PGW-style
-- gateway opens a data session with CCR-Initial, the OCS grants quota
-- per rating group, the gateway reports usage with CCR-Update and gets
-- more, then closes with CCR-Termination. Wire in, wire out.
--
-- Usage: LUA_CPATH=<build>/bindings/lua/?.so lua ro_credit_control.lua

local diam = require("diam")

local SESSION = "pgw.example.net;1415;7"
local IMSI    = "001010123456789"
local RG_WEB  = 100                       -- rating group: web browsing

local hbh, e2e = 1, 1
local reqno = -1

local function show(who, wire)
    local m = diam.parse(wire)
    local kind = m.request and "CCR" or "CCA"
    local t = m:find(diam.AVP_CC_REQUEST_TYPE):value_name()
    print(("--- %s: %s [%s] #%d, %d bytes"):format(
        who, kind, t, m:u32(diam.AVP_CC_REQUEST_NUMBER), #wire))
end

-- Gateway side ----------------------------------------------------------

local function ccr(request_type)
    hbh, e2e, reqno = hbh + 1, e2e + 1, reqno + 1
    return diam.Builder()
        :request(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
        :ids(hbh, e2e)
        :proxiable()
        :put_str(diam.AVP_SESSION_ID, SESSION)
        :put_str(diam.AVP_ORIGIN_HOST, "pgw.example.net")
        :put_str(diam.AVP_ORIGIN_REALM, "example.net")
        :put_str(diam.AVP_DESTINATION_REALM, "example.net")
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_CREDIT_CONTROL)
        :put_str(diam.AVP_SERVICE_CONTEXT_ID, "32251@3gpp.org")   -- PS charging
        :put_u32(diam.AVP_CC_REQUEST_TYPE, request_type)
        :put_u32(diam.AVP_CC_REQUEST_NUMBER, reqno)
        :begin_group(diam.AVP_SUBSCRIPTION_ID)
            :put_u32(diam.AVP_SUBSCRIPTION_ID_TYPE,
                     diam.SUBSCRIPTION_ID_TYPE_END_USER_IMSI)
            :put_str(diam.AVP_SUBSCRIPTION_ID_DATA, IMSI)
        :end_group()
end

-- OCS side ---------------------------------------------------------------

local quota = 10 * 1024 * 1024            -- 10 MiB per grant
local balance = 25 * 1024 * 1024          -- the subscriber's account

local function ocs_answer(wire)
    local r = diam.parse(wire)
    assert(r.cmd == diam.CMD_CREDIT_CONTROL and r.request)
    local rtype = r:u32(diam.AVP_CC_REQUEST_TYPE)

    local a = diam.Builder()
        :answer(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
        :ids(r.hbh, r.e2e)
        :put_str(diam.AVP_SESSION_ID, r:str(diam.AVP_SESSION_ID))
        :put_str(diam.AVP_ORIGIN_HOST, "ocs.example.net")
        :put_str(diam.AVP_ORIGIN_REALM, "example.net")
        :put_u32(diam.AVP_AUTH_APPLICATION_ID, diam.APP_CREDIT_CONTROL)
        :put_u32(diam.AVP_RESULT_CODE, 2001)
        :put_u32(diam.AVP_CC_REQUEST_TYPE, rtype)
        :put_u32(diam.AVP_CC_REQUEST_NUMBER, r:u32(diam.AVP_CC_REQUEST_NUMBER))

    -- book reported usage
    if r:has(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL) then
        local mscc = r:find(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        if mscc:has_child(diam.AVP_USED_SERVICE_UNIT) then
            local used = mscc:child(diam.AVP_USED_SERVICE_UNIT)
                             :child(diam.AVP_CC_TOTAL_OCTETS):u64()
            balance = balance - used
            print(("    OCS: RG %d used %.1f MiB, balance %.1f MiB"):format(
                mscc:child(diam.AVP_RATING_GROUP):u32(),
                used / 1048576.0, balance / 1048576.0))
        end
    end

    -- grant the next slice while credit lasts
    if rtype ~= diam.CC_REQUEST_TYPE_TERMINATION_REQUEST then
        local grant = math.min(quota, balance)
        a:begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
            :put_u32(diam.AVP_RATING_GROUP, RG_WEB)
            :begin_group(diam.AVP_GRANTED_SERVICE_UNIT)
                :put_u64(diam.AVP_CC_TOTAL_OCTETS, grant)
            :end_group()
        if grant >= balance then          -- last money: say what happens next
            a:begin_group(diam.AVP_FINAL_UNIT_INDICATION)
                :put_u32(diam.AVP_FINAL_UNIT_ACTION,
                         diam.FINAL_UNIT_ACTION_TERMINATE)
            :end_group()
        end
        a:end_group()
    end
    return a:done()
end

-- The session ------------------------------------------------------------

-- CCR-I: open, ask for quota
local i = ccr(diam.CC_REQUEST_TYPE_INITIAL_REQUEST)
    :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :put_u32(diam.AVP_RATING_GROUP, RG_WEB)
        :begin_group(diam.AVP_REQUESTED_SERVICE_UNIT)
        :end_group()
    :end_group()
    :done()
show("PGW", i)
local ia = ocs_answer(i)
show("OCS", ia)
local cca = diam.parse(ia)
local granted = cca:find(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
                   :child(diam.AVP_GRANTED_SERVICE_UNIT)
                   :child(diam.AVP_CC_TOTAL_OCTETS):u64()
print(("PGW: session open, %.1f MiB granted\n"):format(granted / 1048576.0))

-- CCR-U: quota exhausted, report and ask again
local u = ccr(diam.CC_REQUEST_TYPE_UPDATE_REQUEST)
    :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :put_u32(diam.AVP_RATING_GROUP, RG_WEB)
        :begin_group(diam.AVP_USED_SERVICE_UNIT)
            :put_u64(diam.AVP_CC_TOTAL_OCTETS, granted)
        :end_group()
        :begin_group(diam.AVP_REQUESTED_SERVICE_UNIT)
        :end_group()
    :end_group()
    :done()
show("PGW", u)
local ua = ocs_answer(u)
show("OCS", ua)
cca = diam.parse(ua)
local mscc = cca:find(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
granted = mscc:child(diam.AVP_GRANTED_SERVICE_UNIT)
              :child(diam.AVP_CC_TOTAL_OCTETS):u64()
print(("PGW: %.1f MiB more%s\n"):format(granted / 1048576.0,
    mscc:has_child(diam.AVP_FINAL_UNIT_INDICATION)
        and ", final unit - terminate after this" or ""))

-- CCR-T: close, report the tail usage
local t = ccr(diam.CC_REQUEST_TYPE_TERMINATION_REQUEST)
    :put_u32(diam.AVP_TERMINATION_CAUSE, 1)   -- DIAMETER_LOGOUT
    :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        :put_u32(diam.AVP_RATING_GROUP, RG_WEB)
        :begin_group(diam.AVP_USED_SERVICE_UNIT)
            :put_u64(diam.AVP_CC_TOTAL_OCTETS, granted)   -- used it all
        :end_group()
    :end_group()
    :done()
show("PGW", t)
show("OCS", ocs_answer(t))
print("PGW: session closed")
