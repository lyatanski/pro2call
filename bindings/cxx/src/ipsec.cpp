/* ipsecxx facade: translate the value-type Sa/Policy structs into the
 * borrowing C structs of xfrm.h and turn return codes into exceptions. */

#include "ipsecxx.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <netinet/in.h>

namespace ipsec
{

namespace
{

const uint8_t* key_ptr(const std::string& k)
{
    return k.empty() ? nullptr : reinterpret_cast<const uint8_t*>(k.data());
}

const char* opt(const std::string& s)
{
    return s.empty() ? nullptr : s.c_str();
}

[[noreturn]] void throw_xfrm(int rc, const xfrm_sock& s, const char* doing)
{
    std::string what = doing;
    switch (rc) {
    case XFRM_E_SYS:      what += ": system error"; break;
    case XFRM_E_INVAL:    what += ": invalid argument"; break;
    case XFRM_E_OVERFLOW: what += ": request too large"; break;
    case XFRM_E_PROTO:    what += ": malformed netlink reply"; break;
    case XFRM_E_ACK:
        what += std::string(": kernel rejected it (") +
                std::strerror(s.nl_errno) + ")";
        break;
    default: what += ": error"; break;
    }
    throw Error(what, rc, rc == XFRM_E_ACK ? s.nl_errno : 0);
}

/* Fill the C xfrm_sa; borrows into the Sa's strings (valid for the call). */
xfrm_sa sa_to_c(const Sa& sa)
{
    xfrm_sa c;
    std::memset(&c, 0, sizeof c);
    c.src           = sa.src.c_str();
    c.dst           = sa.dst.c_str();
    c.spi           = sa.spi;
    c.proto         = sa.proto;
    c.mode          = sa.mode;
    c.reqid         = sa.reqid;
    c.replay_window = sa.replay_window;

    if (!sa.enc_alg.empty()) {
        c.enc_alg     = sa.enc_alg.c_str();
        c.enc_key     = key_ptr(sa.enc_key);
        c.enc_key_len = static_cast<uint16_t>(sa.enc_key.size());
    }
    if (!sa.auth_alg.empty()) {
        c.auth_alg     = sa.auth_alg.c_str();
        c.auth_key     = key_ptr(sa.auth_key);
        c.auth_key_len = static_cast<uint16_t>(sa.auth_key.size());
    }
    if (!sa.aead_alg.empty()) {
        c.aead_alg      = sa.aead_alg.c_str();
        c.aead_key      = key_ptr(sa.aead_key);
        c.aead_key_len  = static_cast<uint16_t>(sa.aead_key.size());
        c.aead_icv_bits = sa.aead_icv_bits;
    }

    c.encap_sport = sa.encap_sport;
    c.encap_dport = sa.encap_dport;
    c.encap_oaddr = opt(sa.encap_oaddr);
    return c;
}

xfrm_policy policy_to_c(const Policy& p)
{
    xfrm_policy c;
    std::memset(&c, 0, sizeof c);
    c.src        = p.src.c_str();
    c.src_prefix = p.src_prefix;
    c.dst        = p.dst.c_str();
    c.dst_prefix = p.dst_prefix;
    c.sel_proto  = p.sel_proto;
    c.sport      = p.sport;
    c.dport      = p.dport;
    c.dir        = p.dir;
    c.action     = p.action;
    c.priority   = p.priority;
    c.index      = p.index;
    c.has_tmpl   = p.has_tmpl;
    c.tmpl_src   = opt(p.tmpl_src);
    c.tmpl_dst   = opt(p.tmpl_dst);
    c.tmpl_reqid = p.tmpl_reqid;
    c.tmpl_proto = p.tmpl_proto;
    c.tmpl_mode  = p.tmpl_mode;
    return c;
}

} /* namespace */

Xfrm::Xfrm()
{
    if (xfrm_open(&s_) != XFRM_OK)
        throw Error(std::string("xfrm_open: ") + std::strerror(errno),
                    XFRM_E_SYS, errno);
}

Xfrm::~Xfrm()
{
    xfrm_close(&s_);
}

void Xfrm::sa_add(const Sa& sa)
{
    xfrm_sa c  = sa_to_c(sa);
    int     rc = xfrm_sa_add(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "sa_add");
}

void Xfrm::sa_update(const Sa& sa)
{
    xfrm_sa c  = sa_to_c(sa);
    int     rc = xfrm_sa_update(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "sa_update");
}

void Xfrm::sa_del(const SaId& id)
{
    xfrm_sa_id c;
    std::memset(&c, 0, sizeof c);
    c.dst   = id.dst.c_str();
    c.spi   = id.spi;
    c.proto = id.proto;
    int rc  = xfrm_sa_del(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "sa_del");
}

void Xfrm::policy_add(const Policy& pol)
{
    xfrm_policy c  = policy_to_c(pol);
    int         rc = xfrm_policy_add(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "policy_add");
}

void Xfrm::policy_update(const Policy& pol)
{
    xfrm_policy c  = policy_to_c(pol);
    int         rc = xfrm_policy_update(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "policy_update");
}

void Xfrm::policy_del(const PolicyId& id)
{
    xfrm_policy_id c;
    std::memset(&c, 0, sizeof c);
    c.src        = opt(id.src);
    c.src_prefix = id.src_prefix;
    c.dst        = opt(id.dst);
    c.dst_prefix = id.dst_prefix;
    c.sel_proto  = id.sel_proto;
    c.sport      = id.sport;
    c.dport      = id.dport;
    c.dir        = id.dir;
    c.index      = id.index;
    int rc       = xfrm_policy_del(&s_, &c);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "policy_del");
}

void Xfrm::flush_sa(uint8_t proto)
{
    int rc = xfrm_flush_sa(&s_, proto);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "flush_sa");
}

void Xfrm::flush_policy()
{
    int rc = xfrm_flush_policy(&s_);
    if (rc != XFRM_OK) throw_xfrm(rc, s_, "flush_policy");
}

/* ---- Esp: the four IMS-AKA SAs and their steering policies ---- */

namespace
{

/* One unidirectional SA, keyed by the receiver's SPI — which is also its
 * reqid, so a policy can name this SA and no other. */
Sa esp_sa(const Esp& e, const std::string& src, const std::string& dst,
          uint32_t spi)
{
    Sa sa;
    sa.src      = src;
    sa.dst      = dst;
    sa.spi      = spi;
    sa.proto    = PROTO_ESP;
    sa.mode     = TRANSPORT;
    sa.reqid    = spi;
    sa.enc_alg  = e.enc_alg;
    sa.enc_key  = e.enc_key;
    sa.auth_alg = e.auth_alg;
    sa.auth_key = e.auth_key;
    return sa;
}

/* /32 selectors: the policy is THIS UE's traffic to THIS P-CSCF on this
 * port pair, not "anything on those ports", which is what a zero prefix
 * length would mean to the kernel. */
Policy esp_policy(uint8_t dir, const std::string& src, const std::string& dst,
                  uint16_t sport, uint16_t dport, uint32_t reqid)
{
    Policy p;
    p.src        = src;
    p.src_prefix = 32;
    p.dst        = dst;
    p.dst_prefix = 32;
    p.sel_proto  = IPPROTO_UDP;
    p.sport      = sport;
    p.dport      = dport;
    p.dir        = dir;
    p.action     = ALLOW;
    p.has_tmpl   = true;
    p.tmpl_reqid = reqid;
    p.tmpl_proto = PROTO_ESP;
    p.tmpl_mode  = TRANSPORT;
    return p;
}

/* An unset field is a caller bug: say which one, before the first
 * netlink round trip rather than as a kernel EINVAL on one of eight. */
void need(bool ok, const char* what)
{
    if (!ok)
        throw Error(std::string("Esp::establish: ") + what + " not set",
                    XFRM_E_INVAL);
}

/* What was refused, in terms of the SA/policy rather than of the request:
 * "spi 0x2001" and the selector are what a reader can act on. */
std::string sa_refused(const Sa& sa, const Error& e)
{
    char pre[48];
    std::snprintf(pre, sizeof pre,
                  "SA (spi %#x) skipped: ", static_cast<unsigned>(sa.spi));
    return std::string(pre) + e.what();
}

std::string policy_refused(const Policy& p, const Error& e)
{
    char pre[128];
    std::snprintf(pre, sizeof pre, "policy (%s %s:%u -> %s:%u) skipped: ",
                  p.dir == DIR_IN ? "in" : "out", p.src.c_str(), p.sport,
                  p.dst.c_str(), p.dport);
    return std::string(pre) + e.what();
}

} /* namespace */

int Esp::establish(Xfrm& x)
{
    errs_.clear();
    need(!ue.empty(), "the UE address");
    need(!pcscf.empty(), "the P-CSCF address");
    need(port_uc != 0 && port_us != 0, "the UE's protected ports");
    need(port_pc != 0 && port_ps != 0, "the P-CSCF's protected ports");
    need(spi_uc != 0 && spi_us != 0, "the UE's SPIs");
    need(spi_pc != 0 && spi_ps != 0, "the P-CSCF's SPIs");
    need(!auth_alg.empty() && !auth_key.empty(), "the integrity key");

    /* TS 33.203 §6.3's SA1..SA4, and the policy that steers each. */
    const Sa sas[4] = {
        esp_sa(*this, ue, pcscf, spi_ps),
        esp_sa(*this, pcscf, ue, spi_us),
        esp_sa(*this, pcscf, ue, spi_uc),
        esp_sa(*this, ue, pcscf, spi_pc),
    };
    const Policy pols[4] = {
        esp_policy(DIR_OUT, ue, pcscf, port_uc, port_ps, spi_ps),
        esp_policy(DIR_IN, pcscf, ue, port_pc, port_us, spi_us),
        esp_policy(DIR_IN, pcscf, ue, port_ps, port_uc, spi_uc),
        esp_policy(DIR_OUT, ue, pcscf, port_us, port_pc, spi_pc),
    };

    int failed = 0;
    for (const Sa& sa : sas) {
        try {
            x.sa_add(sa);
            SaId id;
            id.dst   = sa.dst;
            id.spi   = sa.spi;
            id.proto = sa.proto;
            sas_.push_back(id);
        } catch (const Error& e) {
            ++failed;
            errs_.push_back(sa_refused(sa, e));
        }
    }
    for (const Policy& p : pols) {
        try {
            x.policy_add(p);
            PolicyId id;
            id.src        = p.src;
            id.src_prefix = p.src_prefix;
            id.dst        = p.dst;
            id.dst_prefix = p.dst_prefix;
            id.sel_proto  = p.sel_proto;
            id.sport      = p.sport;
            id.dport      = p.dport;
            id.dir        = p.dir;
            pols_.push_back(id);
        } catch (const Error& e) {
            ++failed;
            errs_.push_back(policy_refused(p, e));
        }
    }
    return failed;
}

void Esp::release(Xfrm& x)
{
    for (const PolicyId& id : pols_) {
        try {
            x.policy_del(id);
        } catch (const Error&) {
        }
    }
    for (const SaId& id : sas_) {
        try {
            x.sa_del(id);
        } catch (const Error&) {
        }
    }
    pols_.clear();
    sas_.clear();
}

int Esp::sa_count() const
{
    return (int)sas_.size();
}

int Esp::policy_count() const
{
    return (int)pols_.size();
}

int Esp::error_count() const
{
    return (int)errs_.size();
}

std::string Esp::error_at(int i) const
{
    if (i < 0 || (size_t)i >= errs_.size())
        throw Error("Esp::error_at: index out of range", XFRM_E_INVAL);
    return errs_[(size_t)i];
}

} /* namespace ipsec */
