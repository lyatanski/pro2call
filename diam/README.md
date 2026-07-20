# diam — Diameter base codec and dictionary

Diameter (RFC 6733) message and AVP codec with a generated dictionary
covering the 3GPP application interfaces this project cares about:

| interface | application id                   | spec         |
|-----------|----------------------------------|--------------|
| base      | 0                                | RFC 6733     |
| Cx        | 16777216                         | TS 29.229    |
| Rx        | 16777236                         | TS 29.214    |
| Ro        | 4 (credit-control, RFC 4006)     | TS 32.299    |
| Rf        | 3 (base accounting)              | TS 32.299    |

## Layout

    inc/diam.h        header + AVP wire codec (hand-written)
    src/diam.c
    inc/diam_fsm.h    RFC 6733 §8.1 session state machines
    src/diam_fsm.c
    gen/              dictionary-layer generator (Go, runs at build
                      time; diam_dict.h/.c exist only in the build tree)
      dict/             Wireshark Diameter dictionary files (source data)
      main.go           curation: app selection, enum allowlist, labels
      templates/        C syntax of the generated dictionary layer

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

The dictionary layer (`diam_dict.h`/`diam_dict.c`) is generated into
the build tree by `gen/`, a dependency-free Go program that parses the
Wireshark project's Diameter dictionary files committed under
`gen/dict/` (field-by-field transcriptions of the standards' AVP
registries; refresh them from
<https://github.com/wireshark/wireshark/tree/master/resources/protocols/diameter>).
The curation — which applications to keep, which AVPs get Enumerated
constants, labels — is the config block at the top of `gen/main.go`.
Generation runs automatically as part of the build; building diam
requires a Go toolchain.
