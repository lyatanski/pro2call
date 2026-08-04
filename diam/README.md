# diam — Diameter base codec and dictionary

Diameter (RFC 6733) message and AVP codec with a generated dictionary
covering the 3GPP application interfaces this project cares about:

| interface | application id                   | spec, at the pinned release |
|-----------|----------------------------------|-----------------------------|
| base      | 0                                | RFC 6733                    |
| Cx        | 16777216                         | TS 29.229 v19.0.0           |
| Sh        | 16777217                         | TS 29.329 v19.1.0           |
| Gx        | 16777238                         | TS 29.212 v19.1.0           |
| Rx        | 16777236                         | TS 29.214 v19.3.0           |
| S6c       | 16777312                         | TS 29.338 v19.3.0           |
| SGd       | 16777313                         | TS 29.338 v19.3.0           |
| Ro        | 4 (credit-control, RFC 4006)     | TS 32.299 v19.0.0           |
| Rf        | 3 (base accounting)              | TS 32.299 v19.0.0           |

## Layout

    inc/diam.h        header + AVP wire codec (hand-written)
    src/diam.c
    inc/diam_fsm.h    RFC 6733 §8.1 session state machines
    src/diam_fsm.c
    gen/              dictionary-layer generator (Go, runs at build
                      time; diam_dict.h/.c exist only in the build tree)
      specs/            the pinned specifications — source data
      main.go           source pinning and curation: which releases,
                        app ids, enum allowlist, labels
      docx.go           WordprocessingML reader (3GPP .docx)
      reg3gpp.go        AVP/command/enum extraction from the 29-series
      rfc.go            the same from the IETF RFCs
      templates/        C syntax of the generated dictionary layer
      dict/             Wireshark Diameter dictionaries — cross-check
      diff.go           the comparison against them
      testdata/         the reviewed baseline of that comparison

## Codec

The AVP layer binds the generic zero-copy TLV codec (`task/inc/tlv.h`,
profile `TLV_PROF_DIAMETER`) to Diameter's wire format. Decode yields
views over the caller's buffer — the iterator strips the optional
Vendor-ID from the value, so a view's `value/len` are always the bare
data. Encode writes into a caller-supplied buffer with sticky-overflow
semantics; grouped AVPs nest via `diam_avp_begin`/`diam_avp_end`, which
backfill the parent length and keep the 4-byte AVP alignment.

```c
uint8_t buf[512];
diam_wbuf_t w;
diam_wbuf_init(&w, buf, sizeof buf);

diam_hdr_t h = { .request = true, .cmd_code = DIAM_CMD_CREDIT_CONTROL,
                 .app_id = DIAM_APP_CREDIT_CONTROL, .hbh = 1, .e2e = 1 };
diam_hdr_encode(w.buf, w.cap, &h);
w.off = DIAM_HDR_LEN;

diam_avp_put_str(&w, DIAM_AVP_SESSION_ID, DIAM_AVP_F_MANDATORY, 0, "gw;1;1");
diam_avp_put_u32(&w, DIAM_AVP_CC_REQUEST_TYPE, DIAM_AVP_F_MANDATORY, 0,
                 DIAM_CC_REQUEST_TYPE_INITIAL_REQUEST);
int g = diam_avp_begin(&w, DIAM_AVP_MULTIPLE_SERVICES_CREDIT_CONTROL,
                       DIAM_AVP_F_MANDATORY, 0);
diam_avp_put_u32(&w, DIAM_AVP_RATING_GROUP, DIAM_AVP_F_MANDATORY, 0, 100);
diam_avp_end(&w, g);
diam_hdr_finalize(&w, 0);          /* backfill Message Length */
```

The dictionary is data only: `diam_dict_get(code, vendor)` returns the
data type, the flags the defining spec requires on the wire, and the
name; `diam_enum_name()` resolves curated Enumerated values. The codec
never consults it, so unknown AVPs still parse fine.

## Session state machine

`diam_fsm.h` carries the RFC 6733 §8.1 authorization session state
machines — one table for the client (the node sending the auth
request), one for the server — built on the generic FSM engine
(`task/inc/fsm.h`). A machine tracks state only; drive it from the
message flow and ask it what the session may do next:

```c
fsm_t* s = diam_sess_fsm_client();            /* Idle */
fsm_act(s, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL);   /* -> Pending */
fsm_act(s, DIAM_SESS_EV_ANSWER_OK, NULL, NULL);      /* -> Open    */
fsm_act(s, DIAM_SESS_EV_SEND_STR, NULL, NULL);       /* -> Discon  */
fsm_act(s, DIAM_SESS_EV_RECV_STA, NULL, NULL);       /* -> Closed  */
fsm_destroy(s);
```

Illegal moves return `FSM_E_NOMATCH` and leave the state alone; timer
expiry arrives from the caller as `DIAM_SESS_EV_TIMEOUT` (the codec
has no timers). Stateless applications (Cx, `AUTH_SESSION_STATE_NO_
STATE_MAINTAINED`) have nothing to track — do not create a machine.

## Dictionary generation

The dictionary layer (`diam_dict.h`/`diam_dict.c`) is generated into the
build tree by `gen/`, a dependency-free Go program that extracts the AVP
registries from the specifications themselves, pinned under `gen/specs/`:
the 3GPP `.docx` releases and the IETF RFCs. Generation runs
automatically as part of the build; building diam requires a Go
toolchain.

Every source names one exact release, so the dictionary is attributable
to a 3GPP release rather than to a third party's snapshot of one. The
3GPP filename encodes it — `29229-j00.docx` is TS 29.229 v19.0.0, each
character of the version code being one field (0-9 then a-z for 10-35).
To retarget a release, drop the new `.docx` in and bump its `ver` in the
`specSources` table in `gen/main.go`; generating two releases and
diffing the output shows exactly what changed.

What is read from where:

| construct         | source                                            |
|-------------------|---------------------------------------------------|
| AVP code, type, M | the registry table (`Value Type` / `Must` columns) |
| Enumerated values | the AVP's own subclause, in prose                 |
| command codes     | the command-code table                            |
| application ids   | stated in `gen/main.go` beside their spec         |

The curation — which releases, which registries, which AVPs get
Enumerated constants, labels — is the config block at the top of
`gen/main.go`. Extraction warns and skips rather than guessing: a
registry row whose type defers to an unpinned spec, or whose flag rules
cannot be read, is reported on stderr.

### The Wireshark cross-check

`gen/dict/` still holds the Wireshark Diameter dictionary files, no
longer as input but as an independent transcription of the same
standards. `go run . -diff` reports every AVP the two disagree about,
and `gen/testdata/wireshark.diff` is the reviewed baseline of that
report; `gen/diff_test.go` fails when it changes, which is also the
`diam_dict_cross_check` ctest. So a new disagreement — an extraction
bug, or a genuine change in a spec — has to be looked at rather than
passing silently. After reviewing one, accept it with:

```sh
cd diam/gen && go test -run TestWiresharkDiff -update
```

The differences are grouped `RENAME` / `TYPE` / `SPEC` / `DICT`. The
current baseline is ~1130 lines, and the bulk of it is not error: 759
`DICT` entries are AVPs from specs outside this profile (S6a, T6a, 5G)
that Wireshark keeps in one flat `<base>` registry, and most `TYPE`
entries are M-bit rules a spec states and the dictionary omits. Where
the two genuinely conflict the specification is authoritative — RFC 6733
§8.4 defines `Result-Code` as `Unsigned32`, not `Enumerated`.
