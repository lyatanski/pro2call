/* ipsecxx facade: translate the value-type Sa/Policy structs into the
 * borrowing C structs of xfrm.h and turn return codes into exceptions. */

#include "ipsecxx.hpp"

#include <cerrno>
#include <cstring>

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

} /* namespace ipsec */
