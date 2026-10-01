-- ims/cfg.lua — what the environment asked for.
--
-- The configuration the IMS UE tests share: the serving PLMN and the home
-- domain that follows from it, the IMSI range and the identities derived from
-- it, the USIM secret, the registration timers, and the per-subscriber
-- resource layout (protected ports and inbound SPIs).
--
-- Both bindings/examples/ims_test_gm.lua (registration over Gm alone) and
-- bindings/examples/ims_test_s5.lua (the same registration carried over an
-- S5/S8 PDN connection, plus every phase that follows it) read this, so a
-- knob means the same thing in both and an IMSI range provisioned for one is
-- provisioned for the other. Anything that belongs to one access only — the
-- P-CSCF address for Gm, the PGW and the datapath for S5/S8 — stays in the
-- script that owns it.
--
-- Everything here is decided once, at load, from the environment: this module
-- is a value, not a machine.

local M = {}

-- ---- reading the environment ------------------------------------------

-- An unset variable and an empty one mean the same thing (a compose file that
-- passes `FOO=` should not defeat a default).
local function str(k, d)
    local v = os.getenv(k)
    if v == nil or v == "" then return d end
    return v
end
-- nil `d` is a legitimate default: it is how "no limit" is spelled.
local function num(k, d) return tonumber(os.getenv(k) or "") or d end
local function flag(k, d)
    local v = os.getenv(k)
    if v == nil or v == "" then return d end
    return v ~= "0"
end
M.str, M.num, M.flag = str, num, flag

-- ---- raw bytes --------------------------------------------------------

-- The keys and every ESP quantity are byte strings, not numbers, so the two
-- conversions live with the keys they parse.
local function unhex(h) return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local function hex(s)   return (s:gsub(".",   function(c) return string.format("%02x", c:byte()) end)) end
M.hex, M.unhex = hex, unhex

-- ---- the network and the subscribers ----------------------------------

M.mcc       = str("IMS_MCC", "001")          -- serving PLMN (matches the IMSI
M.mnc       = str("IMS_MNC", "01")           -- and the mnc01.mcc001 core realm)
M.base_imsi = str("IMS_IMSI", "001010000000001")
M.nsubs     = math.max(1, math.floor(num("IMS_SUBS", 1)))

-- Home network domain (TS 23.003); the MNC is zero-padded to three digits.
local function mnc3(n) return (#n == 2) and ("0" .. n) or n end
M.realm = str("IMS_REALM", ("ims.mnc%s.mcc%s.3gppnetwork.org"):format(mnc3(M.mnc), M.mcc))

-- ---- the subscriber's number (MSISDN) ---------------------------------
--
-- These subscribers are generated from an IMSI range, so their number is
-- derived rather than provisioned: an E.164 country code (IMS_MSISDN_CC)
-- followed by the last IMS_MSISDN_DIGITS digits of the IMSI.
-- bindings/examples/cx_hss.lua applies the SAME rule to the SAME two
-- variables and returns the number as a public identity in the profile it
-- hands the S-CSCF, which is what makes a call dialled by number reach the
-- callee — see M.dial_uri. Against a real HSS, set these to match the MSISDNs
-- it provisions for the IMSI range, or CALL_URI=sip to dial the sip IMPU and
-- leave numbers out of it altogether.
M.msisdn_cc     = (str("IMS_MSISDN_CC", "+99")):gsub("^%+", "")
M.msisdn_digits = num("IMS_MSISDN_DIGITS", 10)

function M.msisdn_of(imsi)
    local tail = (M.msisdn_digits > 0) and imsi:sub(-M.msisdn_digits) or imsi
    return M.msisdn_cc .. tail
end

-- How OTHER subscribers address this one — the Request-URI and the To of an
-- INVITE, and the identity the reg-event phase looks for in a reg-info
-- document. A handset dials a number, so "tel" (tel:+<msisdn>, RFC 3966) is
-- the default and the thing worth exercising: it only works if the HSS
-- returned that number as a public identity, so the whole
-- MSISDN -> IMPU -> registered contact chain is under test rather than
-- assumed. The alternatives are for when it is not the chain being measured:
-- "phone" is the sip:+<msisdn>@<realm>;user=phone form (TS 23.003 §13.4) for a
-- core that will not route a tel: Request-URI, and "sip" dials the sip IMPU
-- the UE registered, which needs no number anywhere.
--
-- Caught at load rather than at the first INVITE: an unrecognised value would
-- otherwise silently fall through to one of the three forms and the run would
-- report the wrong thing as measured.
M.dial_uri = (str("CALL_URI", "tel")):lower()
if M.dial_uri ~= "tel" and M.dial_uri ~= "phone" and M.dial_uri ~= "sip" then
    io.stderr:write(("CALL_URI=%q is not one of tel|phone|sip\n"):format(M.dial_uri))
    os.exit(2)
end

-- USIM secret (raw 16-byte hex). Defaults are 3GPP TS 35.207 Milenage Test
-- Set 1; override IMS_K / IMS_OPC for a real USIM (OPc used directly, no OP
-- derivation). Shared by every subscriber, so the HSS must provision the whole
-- IMSI range with the one key set.
M.k   = unhex(str("IMS_K",   "3919F39741B626604B4BACE23ACFB094"))
M.opc = unhex(str("IMS_OPC", "177FAD988A964A3AD0421B4693257056"))

-- ---- registration ----------------------------------------------------

M.pcscf_port = num("PCSCF_PORT", 5060)   -- the P-CSCF's unprotected SIP port
M.sip_t_ms   = num("SIP_T_MS", 5000)     -- response deadline per REGISTER step
M.auth_cap   = 2                         -- give up after this many 401s
M.expires    = num("IMS_EXPIRES", 600000)  -- ~7 days
M.dereg      = flag("IMS_DEREG", true)
-- IMS_ABANDON=1 walks away at the 401: the challenge is read and verified,
-- and then nothing — no SAs on this side, no protected REGISTER. It is what
-- the network sees of a UE that lost coverage, crashed or rebooted mid-
-- registration, and the one case where the P-CSCF is left holding state for a
-- registration that never completes: the pending contact save_pending() wrote
-- at the first REGISTER, and the IPsec tunnel ipsec_create() built for it at
-- the 401. Only its own expiry is meant to remove them. The run then succeeds
-- when every subscriber was challenged and abandoned, and fails when any was
-- not challenged at all — nothing to abandon is not the case being tested.
M.abandon    = flag("IMS_ABANDON", false)

-- IMS_IPSEC=1 (the default) treats a 401 without a Security-Server as a
-- failure: these tests exist to exercise IMS-AKA *with* IPsec, and a P-CSCF
-- that offers no SAs would otherwise let a run report a clean pass for a
-- registration that never negotiated any security at all. =0 permits the
-- digest-only fallback, for a core with ipsec turned off.
M.require_ipsec = flag("IMS_IPSEC", true)

-- ---- the per-subscriber resource layout -------------------------------
--
-- Spaced by the zero-based subscriber index so concurrent subscribers — which
-- over Gm share the one UE address — never collide: the UE's protected
-- client/server ports and its two inbound ESP SPIs. A script that has more
-- per-subscriber resources to lay out (S5/S8-U TEIDs, RTP ports) uses the same
-- index with its own stride.
M.port_uc_base, M.port_us_base = 5060, 5090
M.spi_base = 0x100

M.IPPROTO_UDP = 17    -- unprotected REGISTER, and the ESP policies' inner selector
M.IPPROTO_ESP = 50    -- protected traffic (IMS-AKA IPsec, TS 33.203)

-- ---- what the run says about itself -----------------------------------

-- Per-event logging. The trace is ~8 lines per subscriber over Gm and ~18 in a
-- full S5/S8 run, at ~1.6 us of unbuffered write each, so past a few hundred
-- subscribers the tool spends a serious fraction of a core describing the run
-- rather than driving it — and far more of one against a terminal than a pipe.
-- IMS_VERBOSE=1 forces the trace on, =0 forces it off; unset keeps it on only
-- for a small run, where following one subscriber step by step is the point of
-- the tool. The per-run summary and the phase banners print either way.
M.verbose_max_subs = 20
M.verbose = flag("IMS_VERBOSE", M.nsubs <= M.verbose_max_subs)

-- IMS_DUMP=1 prints every SIP message, both directions, as text. Route sets,
-- tags and Record-Route ordering are what call routing turns on, and reasoning
-- about them from a summary line is guesswork; this is off by default because
-- at any real subscriber count it is far more output than the trace.
M.dump = flag("IMS_DUMP", false)

return M
