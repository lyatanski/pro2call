#ifndef IPSECXX_HPP
#define IPSECXX_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "xfrm.h"

/* ipsecxx — C++ facade over the C XFRM module (netlink/xfrm/inc/xfrm.h),
 * written to be wrapped by SWIG (bindings/swig/ipsec.i) and driven from a
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

/* HTTP Digest AKAv1-MD5 (RFC 3310 + RFC 2617): the `response` token for a
 * REGISTER Authorization header. `res` is the raw RES bytes recovered from
 * the AKA challenge (the digest password). An empty `qop` selects the
 * RFC 2069 (no-qop) form; otherwise the RFC 2617 form folds in
 * nc/cnonce/qop. Returns the 32-char lowercase hex digest. */
std::string aka_digest(const std::string& user, const std::string& realm,
                       const std::string& res, const std::string& method,
                       const std::string& uri, const std::string& nonce,
                       const std::string& nc, const std::string& cnonce,
                       const std::string& qop);

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

/* ---- the IMS-AKA security associations (TS 33.203 §6.3, Annex I) ----
 *
 * The four transport-mode ESP SAs a UE and its P-CSCF share once the AKA
 * challenge is answered, and the four policies that steer traffic onto
 * them — raised in one call from what the RFC 3329 Security-Client /
 * Security-Server exchange settled on, and taken down in another. This
 * is the reason AKA lives in this module: the keys the challenge yields
 * become these SAs.
 *
 * The four are TS 33.203 §6.3's, each unidirectional and named for the
 * SPI that protects it — the RECEIVER's, which the receiver chose:
 *
 *   SA1  UE:port_uc     -> P-CSCF:port_ps   spi_ps  (REGISTER and every
 *                                                    other MO request)
 *   SA2  P-CSCF:port_pc -> UE:port_us       spi_us  (MT requests)
 *   SA3  P-CSCF:port_ps -> UE:port_uc       spi_uc  (their responses)
 *   SA4  UE:port_us     -> P-CSCF:port_pc   spi_pc
 *
 * IK integrity-protects. Encryption with CK is OPTIONAL (§6.3 mandates
 * integrity only), so the defaults are ESP-NULL with HMAC-SHA-1 over IK,
 * which is what an ealg=null offer negotiates; set enc_alg/enc_key to
 * run a cipher instead. The selector protocol is UDP — the protected SIP
 * these SAs carry.
 *
 * Each SA's SPI doubles as its reqid, so the policy that must use a
 * given SA names it unambiguously even when every subscriber shares one
 * UE address. What went in is remembered here, so release() deletes
 * exactly that and nothing else — flushing the tables instead would take
 * out any other IPsec state in the namespace. */
class Esp
{
  public:
    /* The endpoints and what the two Security- headers settled on. The
     * suffixes are TS 33.203's: _uc/_us the UE's protected client and
     * server port, _pc/_ps the P-CSCF's; spi_uc/spi_us are the SPIs the
     * UE offered (they protect traffic INTO the UE), spi_pc/spi_ps the
     * ones the P-CSCF answered with. A UE that advertises one port in
     * both roles sets port_uc and port_us to it. */
    std::string ue;
    std::string pcscf;
    uint16_t    port_uc = 0;
    uint16_t    port_us = 0;
    uint16_t    port_pc = 0;
    uint16_t    port_ps = 0;
    uint32_t    spi_uc  = 0;
    uint32_t    spi_us  = 0;
    uint32_t    spi_pc  = 0;
    uint32_t    spi_ps  = 0;

    /* Algorithms as the kernel names them, keys as raw bytes. */
    std::string auth_alg = "hmac(sha1)";      /* mandatory (IK)        */
    std::string auth_key;                     /* IK                    */
    std::string enc_alg = "ecb(cipher_null)"; /* ealg=null by default  */
    std::string enc_key;                      /* CK, with a cipher     */

    /* Install the four SAs and the four policies, remembering what the
     * kernel accepted, and return how many of the eight operations it
     * refused. A refusal is reported rather than thrown because the
     * caller has a better answer for one than an aborted run: a
     * "protected" REGISTER that leaves in the clear is discarded by the
     * P-CSCF, so the report should name the missing CAP_NET_ADMIN rather
     * than a plain registration failure. error_at() has the details, and
     * release() still removes whatever did go in.
     *
     * Throws Error(XFRM_E_INVAL), before touching the kernel, when the
     * bundle is not fully negotiated — an address, a port, an SPI or the
     * integrity key left unset is a caller bug, not a refusal. */
    int establish(Xfrm& x);

    /* Delete exactly what establish() installed, policies first so that
     * nothing is steered at an SA that is already gone. Never throws:
     * teardown runs when the run is over and a refusal here leaves
     * nothing a caller could do about it. */
    void release(Xfrm& x);

    int         sa_count() const; /* installed and not yet released      */
    int         policy_count() const;
    int         error_count() const;   /* refusals from the last establish()  */
    std::string error_at(int i) const; /* throws on range            */

  private:
    std::vector<SaId>        sas_;
    std::vector<PolicyId>    pols_;
    std::vector<std::string> errs_;
};

} /* namespace ipsec */

#endif /* IPSECXX_HPP */
