#ifndef IPSECXX_HPP
#define IPSECXX_HPP

#include <cstdint>
#include <stdexcept>
#include <string>

#include "xfrm.h"

/* ipsecxx — C++ facade over the C XFRM module (xfrm/inc/xfrm.h), written
 * to be wrapped by SWIG (bindings/swig/ipsec.i) and driven from a
 * scripting language. It follows the same rules as the gtpxx facade:
 *
 *   - value types: Sa/Policy carry their own copies of everything;
 *   - human-format fields: addresses are literal strings, keys are byte
 *     strings, algorithms are kernel names ("cbc(aes)", "hmac(sha256)");
 *   - errors are exceptions (ipsec::Error), never return codes.
 *
 * The scripting side keys and address strings live for the duration of
 * each call, so the thin C structs can borrow into them without copies.
 */

namespace ipsec
{

/* Every failure surfaces as one of these; code() keeps the XFRM_E_*
 * value and, for a kernel rejection, errno() the reported errno. */
class Error : public std::runtime_error
{
  public:
    explicit Error(const std::string& what, int code = 0, int err = 0)
        : std::runtime_error(what), code_(code), errno_(err)
    {
    }
    int code() const
    {
        return code_;
    }
    int err() const
    {
        return errno_;
    }

  private:
    int code_;
    int errno_;
};

/* IP protocol numbers, encapsulation mode, policy direction/action —
 * mirrored from xfrm.h so scripts get named constants. */
enum { PROTO_ESP = XFRM_PROTO_ESP, PROTO_AH = XFRM_PROTO_AH };
enum Mode { TRANSPORT = XFRM_M_TRANSPORT, TUNNEL = XFRM_M_TUNNEL };
enum Dir {
    DIR_IN  = XFRM_DIR_IN,
    DIR_OUT = XFRM_DIR_OUT,
    DIR_FWD = XFRM_DIR_FWD
};
enum Action { ALLOW = XFRM_ACT_ALLOW, BLOCK = XFRM_ACT_BLOCK };

/* ---- IMS-AKA authentication (Milenage, TS 35.205/206) ----
 *
 * The UE side of AKA: from the network's challenge (RAND, AUTN) and the
 * USIM secret it recovers the session keys, and those keys go straight
 * into the ESP SAs below — that is the whole reason AKA lives in this
 * module. Per TS 33.203 Annex I the integrity key is IK and, for AES-CBC
 * confidentiality, the cipher key is CK, both used unmodified (no key
 * expansion), so the ESP auth/enc keys are simply ik and ck here.
 *
 * All values are raw byte strings: K/OPc/RAND 16 bytes, SQN 6, AMF 2. */
struct AkaVector {
    std::string res; /* f2, 8 bytes — the RES returned in REGISTER    */
    std::string ck;  /* f3, 16 — confidentiality key (ESP enc key)    */
    std::string ik;  /* f4, 16 — integrity key (ESP auth key)         */
    std::string ak;  /* f5, 6  — anonymity key (masks SQN in AUTN)    */
    std::string mac; /* f1 (MAC-A), 8 — expected/derived AUTN MAC     */
    std::string sqn; /* 6 — the SQN in play (echoed or recovered)     */
};

/* OPc = OP XOR E_K(OP). Precompute once per USIM if you hold OP. */
std::string aka_opc(const std::string& k, const std::string& op);

/* Run Milenage f1-f5 for the given SQN/AMF. opc is the 16-byte OPc
 * (derive it from OP with aka_opc). Throws Error on a bad-length input. */
AkaVector aka_milenage(const std::string& k, const std::string& opc,
                       const std::string& rand, const std::string& sqn,
                       const std::string& amf);

/* Verify a received 16-byte AUTN (SQN^AK || AMF || MAC) against a fresh
 * Milenage run: recovers SQN via f5, checks MAC-A, and returns the
 * vector (with sqn filled in). Throws Error(code 1) on a MAC mismatch —
 * an authentication failure the UE would answer with AUTHENTICATION
 * FAILURE. */
AkaVector aka_verify(const std::string& k, const std::string& opc,
                     const std::string& rand, const std::string& autn);

/* Raw MD5 (16-byte digest) — the primitive HTTP Digest AKAv1-MD5
 * (RFC 3310) is built from, so a script can compute the REGISTER
 * Authorization response from RES without a second crypto binding. */
std::string md5(const std::string& data);

/* A Security Association. Set either enc_alg+auth_alg (cipher + HMAC)
 * or aead_alg (combined mode); AH SAs set auth_alg only. Keys are raw
 * bytes carried in a string. */
struct Sa {
    std::string src; /* local/source address, required   */
    std::string dst; /* peer/destination address         */
    uint32_t    spi   = 0;
    uint8_t     proto = PROTO_ESP;
    uint8_t     mode  = TRANSPORT; /* Mode                             */
    uint32_t    reqid = 0;
    uint8_t     replay_window = 0;

    std::string enc_alg;
    std::string enc_key;
    std::string auth_alg;
    std::string auth_key;
    std::string aead_alg;
    std::string aead_key;
    uint16_t    aead_icv_bits = 0;

    /* NAT-T UDP encapsulation; 0/0 = none. */
    uint16_t    encap_sport = 0;
    uint16_t    encap_dport = 0;
    std::string encap_oaddr;
};

/* Identifies an SA for deletion. */
struct SaId {
    std::string dst;
    uint32_t    spi   = 0;
    uint8_t     proto = PROTO_ESP;
};

/* A policy: a selector plus an optional transform template. */
struct Policy {
    std::string src;
    uint8_t     src_prefix = 0;
    std::string dst;
    uint8_t     dst_prefix = 0;
    uint8_t     sel_proto  = 0; /* 0 = any                         */
    uint16_t    sport      = 0;
    uint16_t    dport      = 0;

    uint8_t  dir      = DIR_OUT; /* Dir                             */
    uint8_t  action   = ALLOW;   /* Action                          */
    uint32_t priority = 0;
    uint32_t index    = 0; /* 0 = kernel-assigned             */

    bool        has_tmpl = false;
    std::string tmpl_src; /* tunnel endpoints; empty = transport */
    std::string tmpl_dst;
    uint32_t    tmpl_reqid = 0;
    uint8_t     tmpl_proto = PROTO_ESP;
    uint8_t     tmpl_mode  = TUNNEL;
};

/* Identifies a policy for deletion: by index+dir if index != 0, else by
 * selector+dir. */
struct PolicyId {
    std::string src;
    uint8_t     src_prefix = 0;
    std::string dst;
    uint8_t     dst_prefix = 0;
    uint8_t     sel_proto  = 0;
    uint16_t    sport      = 0;
    uint16_t    dport      = 0;
    uint8_t     dir        = DIR_OUT;
    uint32_t    index      = 0;
};

/* Owns the NETLINK_XFRM socket. Construction opens it (throws Error on
 * failure); each method builds one request and waits for the kernel's
 * ACK, throwing Error(code XFRM_E_ACK) with the reported errno when the
 * kernel rejects it. Manipulating SAs/policies needs CAP_NET_ADMIN. */
class Xfrm
{
  public:
    Xfrm();
    ~Xfrm();
    Xfrm(const Xfrm&)            = delete;
    Xfrm& operator=(const Xfrm&) = delete;

    void sa_add(const Sa& sa);
    void sa_update(const Sa& sa);
    void sa_del(const SaId& id);

    void policy_add(const Policy& pol);
    void policy_update(const Policy& pol);
    void policy_del(const PolicyId& id);

    void flush_sa(uint8_t proto = 0); /* 0 = every protocol */
    void flush_policy();

  private:
    xfrm_sock s_;
};

} /* namespace ipsec */

#endif /* IPSECXX_HPP */
