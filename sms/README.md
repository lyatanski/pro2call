# sms

SMS codec — 3GPP TS 23.040 (transfer layer, TPDUs), TS 24.011 (relay
layer, RPDUs) and TS 23.038 (data coding schemes and alphabets).

This is the payload half of SMS-over-IMS: a `MESSAGE` request with
`Content-Type: application/vnd.3gpp.sms` carries an RPDU, the RPDU
carries a TPDU, and the TPDU carries the text (TS 24.341 §5.3.2). The
SIP side is [`sip/`](../sip); the IP-SM-GW and SMSC emulators that put
the two together are `bindings/examples/{ipsmgw,smsc_stub}.lua`.

Decode is zero-copy for `TP-UD` and `RP-User-Data` — they come out as
pointer+length views into the caller's buffer. The small fixed fields
(addresses, timestamps) are copied into the struct, because slicing
them would buy nothing and cost every caller a semi-octet decode.
Encode writes into a caller-supplied buffer; no allocation anywhere.

SMS is bit-packed, not tag-length-value, so nothing here uses
`task/inc/tlv.h`.

Scripting bindings live in [`bindings/`](../bindings) (Lua via SWIG,
module `sms`).

## Build

```cmake
add_subdirectory(sms)
target_link_libraries(your_target PRIVATE sms)
```

Three headers, by layer:

```c
#include "sms.h"      /* TPDUs, addresses, timestamps, DCS, user data */
#include "sms_rp.h"   /* RP-DATA / RP-ACK / RP-ERROR / RP-SMMA        */
#include "sms_fsm.h"  /* the MO and MT transfer transactions          */
```

## Direction is an input, never a guess

The same `TP-MTI` value names a different TPDU depending on which way
the message travels (TS 23.040 §9.2.3.1): MTI `00` is an SMS-DELIVER
from the service centre and an SMS-DELIVER-REPORT towards it. Both
`sms_tpdu_decode` and `sms_rp_decode` therefore take the direction and
refuse to infer it. The RP decoder goes further and *checks* it — the
RP-MTI encodes the direction, so a caller that passes the wrong one gets
`SMS_E_MTI` rather than a PDU that will be misread one layer up.

One modifier goes with it. A report TPDU carried in an RP-ERROR has a
`TP-FCS` octet that the RP-ACK variant does not (§9.2.2.1a, §9.2.2.2a).
Nothing in the TPDU says which it is; the RP layer knows. Pass
`SMS_DIR_NEGATIVE` alongside the direction for the RP-ERROR form —
guessing shifts every following field by one octet.

## Decode

```c
sms_rp_pdu_t rp;
if (sms_rp_decode(body, blen, SMS_DIR_MS_TO_SC, &rp) < 0) { /* malformed */ }

sms_tpdu_t t;
if (rp.has_ud &&
    sms_tpdu_decode(rp.ud, rp.ud_len, SMS_DIR_MS_TO_SC, &t) > 0 &&
    t.type == SMS_T_SUBMIT) {
    const sms_submit_t* s = &t.u.submit;
    char text[SMS_UD_MAX * 4];
    sms_ud_to_utf8(s->dcs, s->udhi, s->ud.p, s->ud.len, s->ud.udl,
                   text, sizeof text);
    printf("to %s: %s\n", s->da.digits, text);
}
```

`sms_tpdu_decode` returns the octets it consumed, so a caller can tell a
TPDU with trailing padding from one that fits exactly.

## Encode

```c
sms_tpdu_t t;
sms_tpdu_init(&t, SMS_T_SUBMIT);           /* zeroes it, sets mti/dir */
sms_submit_t* s = &t.u.submit;
s->srr = true;                             /* ask for a status report */
s->mr  = mr++;
sms_addr_set(&s->da, "+447700900123", 0);  /* the '+' picks the TON   */
s->vp.fmt = SMS_VPF_RELATIVE;
s->vp.rel = sms_vp_rel_from_secs(24 * 3600);

uint8_t ud[SMS_UD_MAX];
int n = sms_ud_from_utf8(text, strlen(text), SMS_ALPHA_AUTO, NULL, 0,
                         ud, sizeof ud, &s->ud.udl, &s->dcs);
s->ud.p = ud; s->ud.len = (uint8_t)n;

uint8_t tpdu[SMS_TPDU_MAX], rpdu[SMS_RP_MAX];
int tn = sms_tpdu_encode(tpdu, sizeof tpdu, &t);
int rn = sms_rp_data(rpdu, sizeof rpdu, SMS_DIR_MS_TO_SC, mr,
                     "+123456789", tpdu, (size_t)tn);
/* rpdu[0 .. rn) is the SIP MESSAGE body */
```

`SMS_ALPHA_AUTO` picks GSM 7-bit when every character has a mapping and
UCS2 when one does not, which is what a handset does. The four
shorthands `sms_rp_data` / `sms_rp_ack` / `sms_rp_error` / `sms_rp_smma`
cover everything an endpoint sends.

## The four things that bite

These have their own tests, named after the failure they prevent.

**UDH fill bits.** With `TP-UDHI` set and 7-bit data, the text starts at
the first septet boundary *at or after* the end of the header, and the
0..6 bits in between are fill. A 6-octet concatenation header is 48
bits, so the text starts at septet 7 (bit 49) and the first character is
shifted left by one. Getting this wrong garbles the last character of
every part. `sms_gsm7_septet_off()` computes the offset and the pack and
unpack routines take it as a parameter, so it cannot be forgotten.

**TP-UDL units.** Septets for a 7-bit DCS, octets otherwise — and it
counts the header in both cases (§9.2.3.16). `sms_ud_from_utf8()` returns
the octet length and writes the wire-unit length separately, because
they are different numbers.

**The septet count is not derivable from the octet count.** Seven octets
hold seven septets with one bit spare, or eight septets exactly. Only
`TP-UDL` says which, and reading the spare bits as a septet is where the
phantom trailing `@` comes from. `sms_gsm7_unpack()` therefore takes the
count rather than deriving it.

**Timezone sign.** `TP-SCTS` is semi-octet BCD, but bit 3 of the seventh
octet — the top bit of the *tens* digit once the nibbles are swapped
back — is the algebraic sign (§9.2.3.11). A naive BCD decode reads -2 h
as +82 quarter-hours. `sms_ts_t.tz_qh` is a signed quarter-hour count.

Also handled, less dramatically: semi-octet addresses with their odd-
length `0xF` filler and the `0xA`–`0xE` symbol escapes (`*`, `#`, `a`,
`b`, `c`), the `TP-VPF`-dependent validity-period width, and the
alphanumeric TON whose "digits" are 7-bit packed text.

## Errors

Negative `sms_err_t`; `SMS_OK == 0`. Codecs return consumed or written
byte counts (positive) or an error.

| Code | Meaning |
| ---- | ------- |
| `SMS_E_SHORT`    | buffer ends inside a mandatory field |
| `SMS_E_LENGTH`   | a length field disagrees with the data, or the value exceeds what the field can hold |
| `SMS_E_OVERFLOW` | the **caller's** write buffer is too small |
| `SMS_E_INVAL`    | invalid argument |
| `SMS_E_ALPHABET` | the text has no encoding in this alphabet, or the DCS is compressed/reserved |
| `SMS_E_MTI`      | reserved or wrong-direction message type |

`SMS_E_OVERFLOW` always refers to a buffer the caller supplied. Text
that is too long for one message is `SMS_E_LENGTH`, never an overflow —
split it with `sms_concat_split()`.

## Concatenation

`sms_concat_split()` splits UTF-8 into parts under one alphabet and
builds each part's complete `TP-UD`, header included. Text that fits one
message comes back as a single part with **no** concatenation header at
all: a one-part message wrapped in a concatenation IE is legal but
wasteful, and some handsets render it as "1/1" clutter.

The budgets fall out of the header eating from the same 140 octets as
the text: 153 septets per part with an 8-bit reference, 152 with a
16-bit one, 134 octets for UCS2. A GSM 7-bit escape pair and a UTF-16
surrogate pair are never split across parts, because half of either
decodes as a different character.

```c
sms_part_t parts[8];
int n = sms_concat_split(text, strlen(text), SMS_ALPHA_AUTO,
                         ref++, false, parts, 8);
for (int i = 0; i < n; i++) { /* parts[i].ud / .ud_len / .udl / .dcs */ }
```

## Transfer transactions

`sms_fsm.h` carries the two TS 24.011 §8.3 transactions as tables on the
generic FSM engine (`task/inc/fsm.h`), the same shape as `sip_fsm.h`:
state only, no messages and no timers.

```c
fsm_t* t = sms_trans_fsm_mo();                    /* Idle             */
fsm_act(t, SMS_TR_EV_SEND_DATA, NULL, NULL);      /* -> WaitAck, TR1M */
fsm_act(t, SMS_TR_EV_RECV_ACK, NULL, NULL);       /* -> Delivered     */
fsm_destroy(t);
```

Over the radio interface these sit on a CP (connection management) layer
with its own establishment and timers. Over IMS there is no CP layer at
all — TS 24.341 puts the RPDU straight into a SIP body and SIP is the
reliable transport — so this module implements RP and stops there. The
SIP transaction underneath is `sip_fsm.h`'s business.

## Why there is no `sms/gen`

The other bulky registries in this repo are generated from the
specifications (`gtp/gen` from the TS 29.274 tables, `diam/gen` from the
Diameter dictionaries). SMS was assessed the same way and hand-written
instead, for two reasons.

**The codec.** Six TPDU types × ~13 fields, frozen since Rel-99. The
§9.2.2.x tables give field order and M/O presence but not the bit
offsets and widths, which live in §9.2.3.x prose — and the layout is
context-dependent in ways a table cannot express (`TP-VPF` selects the
validity-period width, `TP-UDHI` whether `TP-UD` starts with a header,
`TP-DCS` whether `TP-UDL` counts septets or octets). An extractor's
output would still need a hand-written codec per field type.

**The tables.** This is the part that looked generator-shaped, and the
source document says otherwise. In `23038-j00.docx` the default alphabet
(table 6.2.1.1) encodes its ten Greek letters as Word field codes —
`SYMBOL 68 \f "Symbol"` for Δ, `81` for Θ, `87` for Ω and so on — not as
Unicode characters, and marks the escape position with the footnote
reference `1)` rather than a mnemonic. An extractor would need its own
hand-written Symbol-font → Unicode table to produce the one table it was
supposed to save us writing, and the national language tables (§6.2.1.2)
add more of the same plus `∞`. `TP-ST` (§9.2.3.15) is prose, not a
table, so it is not extractable at all.

So the alphabet, extension and name tables here were transcribed from
the specification and checked against it cell by cell, and the
verification lives in the tests rather than in a build step: every
septet round-trips through both directions of the mapping, and the
published PDU vectors in `test/test_sms_tpdu.c` decode field by field to
values that were worked out by hand first.

If the national language single-shift and locking-shift tables are ever
needed (§6.2.1.2, ~13 more tables of the same shape), *that* is when a
`sms/gen` earns its keep — one Symbol-font table amortized over
thirteen. The IEIs are already reserved: `SMS_UDH_NL_SS` (0x24) and
`SMS_UDH_NL_LS` (0x25).

## Tests

```
ctest -R sms          # sms_tpdu, sms_ud, sms_rp, sms_fsm
```

`test_sms_tpdu.c` and `test_sms_rp.c` each assert that **every** prefix
of a valid PDU is refused, which under the `bld-vg` valgrind image (see
`bench/Dockerfile.valgrind`) is also the out-of-bounds test:

```
docker run --rm -v "$PWD":/src -w /src bld-vg \
    sh -c 'cd out && valgrind -q --error-exitcode=9 ./sms/test/test_sms_tpdu'
```

## Not implemented

Deliberately, with the reasons:

- **Compressed user data** (TS 23.038 §4 compression bit). `sms_dcs_decode`
  reports `SMS_ALPHA_RESERVED` for a compressed DCS rather than handing
  back text it cannot read.
- **National language shift tables** (§6.2.1.2). See above; the UDH
  elements that select them parse, the tables are absent.
- **EMS** and the other rich `TP-UD` header elements (§9.2.3.24.10 and
  friends). `sms_udh_next()` walks them; nothing interprets them.
- **The CP layer** of TS 24.011 §5. Absent from SMS-over-IMS by design.
