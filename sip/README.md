# sip

SIP codec — RFC 3261 plus the standard method/header extensions.

Decode is zero-copy: `sip_msg_parse` fills a `sip_msg_t` whose every
string is a `sip_str_t` slice (pointer + length) into the caller's
buffer — nothing is allocated, nothing is copied. Encode writes
directly into a caller-supplied buffer; no allocation there either.

Methods and header-field names are resolved to enums during the parse,
so downstream dispatch is integer compares and a compact form (`v:`)
is indistinguishable from its long form (`Via:`) — both are
`SIP_H_VIA`. Extension headers come out as `SIP_H_OTHER` with the name
slice preserved and are matched by name.

Scripting bindings live in [`bindings/`](../bindings) (Lua via SWIG,
module `sip`).

## Build

Add as a CMake subdirectory and link the target:

```cmake
add_subdirectory(sip)
target_link_libraries(your_target PRIVATE sip)
```

Everything is in one header:

```c
#include "sip.h"
```

## Decode

`sip_msg_parse` consumes one message and returns the byte count it
used, so stream transports can call it repeatedly over a receive
buffer. `SIP_E_SHORT` means "a valid prefix — read more bytes"; with a
`Content-Length` the body is sliced exactly, without one it runs to
the end of the buffer (datagram semantics).

```c
sip_msg_t m;                 /* ~2 KiB, lives fine on the stack */
int n = sip_msg_parse(&m, buf, len);
if (n == SIP_E_SHORT) { /* grow buffer, try again */ }
if (n < 0)            { /* malformed */ }

if (m.is_request && m.method == SIP_M_INVITE) {
    const sip_hdr_view_t* via = sip_msg_find(&m, SIP_H_VIA);
    const sip_hdr_view_t* cid = sip_msg_find(&m, SIP_H_CALL_ID);
    printf("INVITE %.*s call %.*s\n",
           SIP_STR_ARG(m.ruri), SIP_STR_ARG(cid->value));

    for (; via; via = sip_msg_find_next(&m, via)) {  /* every Via */
        sip_via_t v;
        if (sip_via_parse(via->value, &v) == SIP_OK)
            printf("  via %.*s branch %.*s\n",
                   SIP_STR_ARG(v.host), SIP_STR_ARG(v.branch));
    }
}
```

The deep parsers slice further, still without copying:

| Parser | Input | Yields |
| ------ | ----- | ------ |
| `sip_uri_parse`  | Request-URI, Contact URI | scheme/user/host/port/params |
| `sip_addr_parse` | From/To/Contact value    | display, URI, params, `tag`  |
| `sip_via_parse`  | one Via value            | transport, sent-by, `branch` |
| `sip_cseq_parse` | CSeq value               | sequence number + method enum |
| `sip_param`      | any params slice         | one `;name=value` parameter  |

All parsed strings borrow from the wire buffer: keep it alive while
they are in use, and copy out anything that must outlive it.

## Encode

Initialize a `sip_wbuf_t` over a caller-supplied buffer, put the start
line, the headers, and finish with `sip_put_body` — it writes
`Content-Length`, the separator and the payload, and returns the total
message length. Errors on the write buffer are sticky, so individual
return codes can be ignored and checked once at the end:

```c
char out[1500];
sip_wbuf_t w;
sip_wbuf_init(&w, out, sizeof out);

sip_put_status(&w, 180, NULL, 0);            /* NULL = "Ringing" */
sip_put_hdr(&w, SIP_H_VIA,     via.p,  via.len);   /* copied from request */
sip_put_hdr(&w, SIP_H_FROM,    from.p, from.len);
sip_put_hdr(&w, SIP_H_TO,      to.p,   to.len);
sip_put_hdr(&w, SIP_H_CALL_ID, cid.p,  cid.len);
sip_put_hdr(&w, SIP_H_CSEQ,    cseq.p, cseq.len);

int n = sip_put_body(&w, NULL, 0);
if (n < 0) { /* SIP_E_OVERFLOW — buffer too small */ }
/* Wire bytes: out[0 .. n) */
```

`sip_put_request`/`sip_put_hdr` take enums and emit the canonical
long-form names; `sip_put_hdr_name` covers extension headers and
`sip_put_hdr_u32` integer-valued ones (Max-Forwards, Expires, ...).

## Errors

Negative `sip_err_t` values; `SIP_OK == 0`. Parse functions return
consumed byte counts (positive) or an error.

| Code | Meaning |
| ---- | ------- |
| `SIP_E_SHORT`    | message incomplete — feed more bytes |
| `SIP_E_LINE`     | malformed start line |
| `SIP_E_VERSION`  | version is not SIP/2.0 |
| `SIP_E_HEADER`   | malformed header field |
| `SIP_E_HEADERS`  | more than `SIP_MAX_HDRS` (default 48) header fields |
| `SIP_E_OVERFLOW` | write buffer too small (sticky) |
| `SIP_E_INVAL`    | invalid argument |
| `SIP_E_URI`      | malformed URI or address |
| `SIP_E_MISSING`  | expected element absent |

## Leniency

The parser is strict about structure but tolerant where real traffic
demands it: bare-LF line endings are accepted, obsolete header folding
is kept raw inside the value slice, keep-alive CRLFs before the start
line are skipped, and unknown methods/headers pass through as
`SIP_M_UNKNOWN`/`SIP_H_OTHER` tokens rather than errors.

## Transaction state machines

`sip_fsm.h` carries the four RFC 3261 §17 transaction machines
(INVITE/non-INVITE × client/server) as tables on the generic FSM
engine (`task/inc/fsm.h`). One machine instance tracks one
transaction; it neither builds messages nor runs timers — feed it what
happens and it answers with the state:

```c
fsm_t* t = sip_trans_fsm_invite_client();            /* Init */
fsm_act(t, SIP_TRANS_EV_SEND_REQUEST, NULL, NULL);   /* -> Calling    */
fsm_act(t, SIP_TRANS_EV_RECV_1XX, NULL, NULL);       /* -> Proceeding */
fsm_act(t, SIP_TRANS_EV_RECV_2XX, NULL, NULL);       /* -> Terminated */
fsm_destroy(t);
```

The RFC's timers arrive from the caller, collapsed by role:
`TIMER_RETRANSMIT` (A/E/G), `TIMER_TIMEOUT` (B/F/H) and
`TIMER_TERMINATE` (D/I/J/K). Illegal moves return `FSM_E_NOMATCH` and
leave the state alone; the retransmissions the RFC absorbs are legal
self-transitions.
