#ifndef XFRM_H
#define XFRM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPsec manipulation over the kernel's XFRM netlink interface
 * (NETLINK_XFRM, see RFC 4301 for the architecture and Linux
 * Documentation/networking/xfrm_*). Adds and removes Security
 * Associations (SAs) and policies the same way `ip xfrm state`/`ip xfrm
 * policy` do: by exchanging XFRM_MSG_* messages with the kernel.
 *
 * The wire format is a struct nlmsghdr, a message-specific fixed
 * payload, then a run of netlink attributes (struct nlattr). Those
 * attributes are encoded and parsed with the shared TLV codec
 * (task/inc/tlv.h) under its TLV_PROF_NETLINK profile — the same parser
 * the GTPv2-C and Diameter codecs use, pointed at the netlink layout.
 *
 * Two layers:
 *   - message builders (xfrm_*_msg): pure functions that render one
 *     netlink request into a caller buffer. No socket, no privilege —
 *     unit-testable on any host.
 *   - transactions (xfrm_sa_add, xfrm_policy_add, ...): open a socket,
 *     send a built message and read the kernel's ACK. These need
 *     CAP_NET_ADMIN (typically root) and a kernel with CONFIG_XFRM.
 *
 * Addresses are literal strings ("10.0.0.1", "fd00::1"); the family is
 * inferred from them and src/dst must agree. Keys are raw bytes.
 */

enum {
    XFRM_OK         = 0,
    XFRM_E_SYS      = -1, /* syscall failed; errno is set              */
    XFRM_E_INVAL    = -2, /* bad argument (e.g. unparseable address)   */
    XFRM_E_OVERFLOW = -3, /* request did not fit the supplied buffer   */
    XFRM_E_PROTO    = -4, /* malformed or unexpected netlink reply     */
    XFRM_E_ACK      = -5, /* kernel rejected the request (see nl_errno)*/
};

/* IP protocol numbers for the SA/template protocol field, so callers
 * need not pull in <netinet/in.h>. */
enum { XFRM_PROTO_ESP = 50, XFRM_PROTO_AH = 51, XFRM_PROTO_COMP = 108 };

/* Encapsulation mode (xfrm_usersa_info.mode, xfrm_user_tmpl.mode). */
typedef enum { XFRM_M_TRANSPORT = 0, XFRM_M_TUNNEL = 1 } xfrm_mode_t;

/* Policy direction (xfrm_userpolicy_info.dir). */
typedef enum { XFRM_DIR_IN = 0, XFRM_DIR_OUT = 1, XFRM_DIR_FWD = 2 } xfrm_dir_t;

/* Policy action (xfrm_userpolicy_info.action). */
typedef enum { XFRM_ACT_ALLOW = 0, XFRM_ACT_BLOCK = 1 } xfrm_action_t;

/* A Security Association. Encryption is either a cipher+auth pair
 * (enc_* / auth_*) or a single AEAD transform (aead_*); set one group.
 * AH SAs use auth_* only. Unset a group by leaving its algorithm name
 * NULL. Key lengths are in bytes; the kernel is told the bit length. */
typedef struct {
    const char* src;           /* tunnel/transport source, required   */
    const char* dst;           /* destination, required               */
    uint32_t    spi;           /* host byte order; sent big-endian    */
    uint8_t     proto;         /* XFRM_PROTO_ESP / _AH                 */
    uint8_t     mode;          /* xfrm_mode_t                          */
    uint32_t    reqid;         /* ties the SA to a policy template     */
    uint8_t     replay_window; /* anti-replay window, packets          */
    uint32_t    flags;         /* XFRM_STATE_* extra flags, usually 0  */

    const char*    enc_alg; /* e.g. "cbc(aes)"                      */
    const uint8_t* enc_key;
    uint16_t       enc_key_len;

    const char*    auth_alg; /* e.g. "hmac(sha256)"                  */
    const uint8_t* auth_key;
    uint16_t       auth_key_len;

    const char*    aead_alg; /* e.g. "rfc4106(gcm(aes))"             */
    const uint8_t* aead_key;
    uint16_t       aead_key_len;
    uint16_t       aead_icv_bits; /* ICV length in bits, e.g. 128     */

    /* Optional NAT-T UDP encapsulation (XFRMA_ENCAP). sport/dport in
     * host order; 0/0 means no encapsulation. */
    uint16_t    encap_sport;
    uint16_t    encap_dport;
    const char* encap_oaddr; /* original address, or NULL           */
} xfrm_sa;

/* Identifies an SA for deletion: the tuple the kernel keys on. */
typedef struct {
    const char* dst;
    uint32_t    spi;   /* host byte order */
    uint8_t     proto; /* XFRM_PROTO_ESP / _AH */
} xfrm_sa_id;

/* A policy: a traffic selector, a direction/action, and an optional
 * single transform template (the usual case for one IPsec tunnel). */
typedef struct {
    const char* src;        /* selector source prefix base, required  */
    const char* dst;        /* selector destination prefix base       */
    uint8_t     src_prefix; /* source prefix length in bits           */
    uint8_t     dst_prefix; /* destination prefix length in bits      */
    uint8_t     sel_proto;  /* upper-layer protocol, 0 = any          */
    uint16_t    sport;      /* selector source port, 0 = any          */
    uint16_t    dport;      /* selector destination port, 0 = any     */

    uint8_t  dir;      /* xfrm_dir_t                             */
    uint8_t  action;   /* xfrm_action_t                          */
    uint32_t priority; /* lower is preferred                     */
    uint32_t index;    /* 0 = kernel-assigned                    */

    /* Optional transform template. For a tunnel give the tunnel
     * endpoints in tmpl_src/tmpl_dst; for transport leave them NULL and
     * the kernel copies the packet addresses. */
    bool        has_tmpl;
    const char* tmpl_src;
    const char* tmpl_dst;
    uint32_t    tmpl_reqid;
    uint8_t     tmpl_proto; /* XFRM_PROTO_ESP / _AH */
    uint8_t     tmpl_mode;  /* xfrm_mode_t */
} xfrm_policy;

/* Identifies a policy for deletion. If index is non-zero the kernel
 * matches on (index, dir); otherwise it matches on the selector. */
typedef struct {
    const char* src;
    const char* dst;
    uint8_t     src_prefix;
    uint8_t     dst_prefix;
    uint8_t     sel_proto;
    uint16_t    sport;
    uint16_t    dport;
    uint8_t     dir;
    uint32_t    index;
} xfrm_policy_id;

/* ---- Message builders (no socket, no privilege) ---------------------
 *
 * Each renders one complete netlink request (nlmsghdr + fixed payload +
 * attributes) into buf. seq is the caller's sequence number, echoed in
 * the kernel's ACK. Returns the total byte length written, or a
 * negative XFRM_E_* code (XFRM_E_OVERFLOW if it would not fit, or
 * XFRM_E_INVAL on a bad address / missing field).
 */
API_EXPORT int xfrm_sa_msg(uint8_t* buf, size_t cap, uint32_t seq,
                           const xfrm_sa* sa);
API_EXPORT int xfrm_sa_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                               const xfrm_sa_id* id);
API_EXPORT int xfrm_policy_msg(uint8_t* buf, size_t cap, uint32_t seq,
                               const xfrm_policy* pol);
API_EXPORT int xfrm_policy_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                                   const xfrm_policy_id* id);
API_EXPORT int xfrm_flush_sa_msg(uint8_t* buf, size_t cap, uint32_t seq,
                                 uint8_t proto);
API_EXPORT int xfrm_flush_policy_msg(uint8_t* buf, size_t cap, uint32_t seq);

/* ---- Transactions (need CAP_NET_ADMIN) ------------------------------ */

typedef struct {
    int      fd;       /* AF_NETLINK / NETLINK_XFRM socket, -1 = closed */
    uint32_t seq;      /* next sequence number, auto-incremented        */
    uint32_t portid;   /* kernel-assigned local port id                 */
    int      nl_errno; /* last kernel-reported errno on XFRM_E_ACK      */
} xfrm_sock;

/* Open/close the XFRM netlink socket. xfrm_open returns XFRM_OK or
 * XFRM_E_SYS (errno set); EPERM/EACCES mean the process lacks
 * CAP_NET_ADMIN. */
API_EXPORT int  xfrm_open(xfrm_sock* s);
API_EXPORT void xfrm_close(xfrm_sock* s);

/* Add (create, failing if it exists) or replace an SA. */
API_EXPORT int xfrm_sa_add(xfrm_sock* s, const xfrm_sa* sa);
API_EXPORT int xfrm_sa_update(xfrm_sock* s, const xfrm_sa* sa);
API_EXPORT int xfrm_sa_del(xfrm_sock* s, const xfrm_sa_id* id);

/* Add or replace a policy; delete one by selector or index. */
API_EXPORT int xfrm_policy_add(xfrm_sock* s, const xfrm_policy* pol);
API_EXPORT int xfrm_policy_update(xfrm_sock* s, const xfrm_policy* pol);
API_EXPORT int xfrm_policy_del(xfrm_sock* s, const xfrm_policy_id* id);

/* Remove every SA of the given protocol (0 = all), or every policy. */
API_EXPORT int xfrm_flush_sa(xfrm_sock* s, uint8_t proto);
API_EXPORT int xfrm_flush_policy(xfrm_sock* s);

#ifdef __cplusplus
}
#endif

#endif /* XFRM_H */
