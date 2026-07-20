#ifndef GTPXX_HPP
#define GTPXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "gtp2.h"
#include "gtp2_ie.h"
#include "netxx.hpp" /* net::Loop — the transport the session layer runs on */

/* gtpxx — C++ facade over the C GTP stack, written to be wrapped by
 * SWIG (bindings/swig/gtp.i) and used from scripting languages.
 *
 * Design rules, all driven by bindability:
 *   - value types everywhere: messages copy wire data into std::string /
 *     std::vector so nothing borrows from a decode buffer;
 *   - human-format fields: IMSI/MSISDN/MEI are digit strings, APN is a
 *     dotted name, addresses are literal strings — the BCD, label and
 *     inet_pton conversions happen at the encode/decode boundary;
 *   - optional scalars use -1 as "absent", optional structs a has_ flag;
 *   - callbacks are virtual methods on handler classes (SWIG directors),
 *     never function pointers;
 *   - errors are exceptions (gtp::Error), never return codes.
 *
 * The session layer (Endpoint/Session) drives GTPv2-C transactions over
 * a net_loop-registered UDP socket: sequence allocation, T3/N3
 * retransmission, response matching, and an on_user_plane() callback
 * that fires when a response carries the peer's data-plane F-TEID —
 * the moment the user-plane tunnel can be installed (gtp::UserPlane).
 */

struct gtpu_ebpf; /* opaque; gtpu_ebpf.h is not needed by users */

namespace gtp
{

using Bytes = std::vector<uint8_t>;

enum { GTPC_PORT = 2123, GTPU_UDP_PORT = 2152 };

/* Every failure surfaces as one of these; code() keeps the underlying
 * gtp2_err_t / gtpu_err_t / NET_* value when there is one. */
class Error : public std::runtime_error
{
  public:
    explicit Error(const std::string& what, int code = 0)
        : std::runtime_error(what), code_(code)
    {
    }
    int code() const
    {
        return code_;
    }

  private:
    int code_;
};

/* ---- Wire-format helpers (also useful standalone from scripts) ---- */

/* TBCD: "234150999999999" <-> low-nibble-first bytes, 0xF padded. */
Bytes       bcd_encode(const std::string& digits);
std::string bcd_decode(const Bytes& bcd);

/* APN: "internet.mnc015.mcc234.gprs" <-> length-prefixed labels. */
Bytes       apn_encode(const std::string& dotted);
std::string apn_decode(const Bytes& labels);

/* ---- Sub-IE value types (TS 29.274 §8) ---- */

/* F-TEID §8.22. addr4/addr6 are literal strings; empty = that family
 * absent. At least one must be set when encoding. */
struct Fteid {
    uint8_t     if_type = 0; /* gtp2_if_type_t */
    uint32_t    teid    = 0;
    std::string addr4;
    std::string addr6;
};

/* Bearer QoS §8.15; bitrates in kbps. */
struct BearerQos {
    uint8_t  qci    = 9;
    uint8_t  pl     = 15; /* priority level */
    uint8_t  pci    = 0;  /* pre-emption capability */
    uint8_t  pvi    = 0;  /* pre-emption vulnerability */
    uint64_t mbr_ul = 0, mbr_dl = 0;
    uint64_t gbr_ul = 0, gbr_dl = 0;
};

/* PDN Address Allocation §8.14. */
struct Paa {
    uint8_t     pdn_type = GTP2_PDN_IPV4; /* gtp2_pdn_t */
    std::string addr4;
    std::string addr6;
    uint8_t     prefix_len = 0; /* IPv6 only */
};

/* APN-AMBR §8.7. */
struct Ambr {
    uint32_t ul_kbps = 0;
    uint32_t dl_kbps = 0;
};

/* One F-TEID inside a Bearer Context; the instance carries its
 * per-message meaning (§7.2.x tables). */
struct FteidEntry {
    uint8_t instance = 0;
    Fteid   fteid;
};

/* Bearer Context grouped IE §8.28. instance selects the list the
 * context belongs to (0 = to be created/modified, 1 = to be removed). */
struct BearerContext {
    uint8_t                 instance    = 0;
    uint8_t                 ebi         = 5;
    int                     cause       = -1; /* response lists; -1 = absent */
    long                    charging_id = -1;
    bool                    has_qos     = false;
    BearerQos               qos;
    Bytes                   tft; /* raw TS 24.008 TFT, empty = absent */
    std::vector<FteidEntry> fteids;
    void                    add_fteid(uint8_t instance, const Fteid& f);
};

/* ---- Typed messages (session workflow, TS 29.274 §7.2) ----
 *
 * encode() returns the wire bytes; decode() parses them. Header TEID
 * and sequence live in the struct. Anything not covered by a typed
 * message is reachable through RawMessage below.
 */

struct CreateSessionRequest { /* §7.2.1 */
    uint32_t teid     = 0;    /* header TEID; 0 on initial attach */
    uint32_t sequence = 0;

    std::string imsi, msisdn, mei;         /* digit strings, "" = absent */
    Bytes       uli, serving_network, pco; /* raw, empty = absent */
    std::string apn;                       /* dotted name, mandatory */

    uint8_t rat_type = GTP2_RAT_EUTRAN;
    Fteid   sender_fteid; /* mandatory, instance 0 */
    bool    has_pgw_fteid = false;
    Fteid   pgw_fteid; /* instance 1 */

    int  selection_mode  = -1;
    int  pdn_type        = -1; /* gtp2_pdn_t */
    int  apn_restriction = -1;
    int  recovery        = -1;
    int  charging_char   = -1;
    bool has_paa         = false;
    Paa  paa;
    bool has_ambr = false;
    Ambr ambr;

    std::vector<BearerContext> bearers;
    void                       add_bearer(const BearerContext& b)
    {
        bearers.push_back(b);
    }

    Bytes                       encode() const;
    static CreateSessionRequest decode(const Bytes& wire);
};

struct CreateSessionResponse { /* §7.2.2 */
    uint32_t teid     = 0;
    uint32_t sequence = 0;

    uint8_t cause            = GTP2_CAUSE_REQUEST_ACCEPTED;
    bool    has_sender_fteid = false;
    Fteid   sender_fteid; /* instance 0 */
    bool    has_pgw_fteid = false;
    Fteid   pgw_fteid; /* instance 1 */
    bool    has_paa = false;
    Paa     paa;
    bool    has_ambr = false;
    Ambr    ambr;
    int     apn_restriction = -1;
    int     recovery        = -1;
    Bytes   pco;

    std::vector<BearerContext> bearers;
    void                       add_bearer(const BearerContext& b)
    {
        bearers.push_back(b);
    }

    Bytes                        encode() const;
    static CreateSessionResponse decode(const Bytes& wire);
};

struct ModifyBearerRequest { /* §7.2.7 */
    uint32_t teid     = 0;
    uint32_t sequence = 0;

    std::string mei;
    Bytes       uli, serving_network;

    int   rat_type         = -1;
    bool  has_sender_fteid = false;
    Fteid sender_fteid;
    bool  has_ambr = false;
    Ambr  ambr;
    int   delay_dl_pn = -1;
    int   recovery    = -1;

    std::vector<BearerContext> bearers;
    void                       add_bearer(const BearerContext& b)
    {
        bearers.push_back(b);
    }

    Bytes                      encode() const;
    static ModifyBearerRequest decode(const Bytes& wire);
};

struct ModifyBearerResponse { /* §7.2.8 */
    uint32_t teid     = 0;
    uint32_t sequence = 0;

    uint8_t     cause = GTP2_CAUSE_REQUEST_ACCEPTED;
    std::string msisdn;
    int         linked_ebi      = -1;
    int         apn_restriction = -1;
    bool        has_ambr        = false;
    Ambr        ambr;
    int         recovery = -1;
    Bytes       pco;

    std::vector<BearerContext> bearers;
    void                       add_bearer(const BearerContext& b)
    {
        bearers.push_back(b);
    }

    Bytes                       encode() const;
    static ModifyBearerResponse decode(const Bytes& wire);
};

struct DeleteSessionRequest { /* §7.2.9 */
    uint32_t teid     = 0;
    uint32_t sequence = 0;

    Bytes uli, indication, pco;
    int   cause            = -1;
    int   linked_ebi       = -1;
    bool  has_sender_fteid = false;
    Fteid sender_fteid;

    Bytes                       encode() const;
    static DeleteSessionRequest decode(const Bytes& wire);
};

struct DeleteSessionResponse { /* §7.2.10 */
    uint32_t teid     = 0;
    uint32_t sequence = 0;

    uint8_t cause    = GTP2_CAUSE_REQUEST_ACCEPTED;
    int     recovery = -1;
    Bytes   pco;

    Bytes                        encode() const;
    static DeleteSessionResponse decode(const Bytes& wire);
};

/* ---- Raw message (full protocol coverage) ----
 *
 * Any GTPv2-C message as a header plus an IE tree. decode() recurses
 * into the grouped IE types it knows (Bearer Context, PDN Connection,
 * Overload/Load Control Information, Remote UE Context); for anything
 * else call ie_children() on the value yourself.
 */

struct Ie {
    uint8_t         type     = 0;
    uint8_t         instance = 0;
    Bytes           value; /* ignored on encode when children set */
    std::vector<Ie> children;
    Ie() = default;
    Ie(uint8_t type_, const Bytes& value_, uint8_t instance_ = 0)
        : type(type_), instance(instance_), value(value_)
    {
    }
    void add_child(const Ie& child)
    {
        children.push_back(child);
    }
};

std::vector<Ie> ie_children(const Bytes& grouped_value);

struct RawMessage {
    uint8_t         message_type = 0;
    bool            has_teid     = true;
    uint32_t        teid         = 0;
    uint32_t        sequence     = 0;
    bool            piggyback    = false; /* decode only */
    std::vector<Ie> ies;
    void            add_ie(const Ie& ie)
    {
        ies.push_back(ie);
    }

    /* First IE of the given type/instance, or throws Error. */
    const Ie& find(uint8_t type, uint8_t instance = 0) const;
    bool      has(uint8_t type, uint8_t instance = 0) const;

    Bytes             encode() const;
    static RawMessage decode(const Bytes& wire);
};

/* ---- GTPv2-C session layer ----
 *
 * The event loop and UDP transport live in the net module
 * (bindings/cxx/inc/netxx.hpp): an Endpoint registers its socket and
 * timers with a net::Loop, so scripts drive it with net.Loop and share
 * one dispatcher across the gtp/sip/diam stacks. */

/* What on_user_plane() delivers: one bearer's data-plane tunnel as told
 * by the peer. local_teid is taken from the matching bearer F-TEID of
 * our own request (0 when we sent none). */
struct UserPlaneTunnel {
    uint8_t     ebi         = 0;
    uint8_t     if_type     = 0; /* the peer F-TEID's interface type */
    uint32_t    local_teid  = 0;
    uint32_t    remote_teid = 0;
    std::string remote_addr;
};

class Session;
class Endpoint;

/* Subclass this (works from Python — SWIG director) and pass it to
 * Endpoint::set_handler(). All methods default to no-ops; requests the
 * endpoint cannot type land in on_message() as raw bytes. */
class EndpointHandler
{
  public:
    virtual ~EndpointHandler() = default;

    /* Transaction completions (client role). */
    virtual void on_create_session_response(Session&                     s,
                                            const CreateSessionResponse& rsp);
    virtual void on_modify_bearer_response(Session&                    s,
                                           const ModifyBearerResponse& rsp);
    virtual void on_delete_session_response(Session&                     s,
                                            const DeleteSessionResponse& rsp);

    /* Fired once per bearer F-TEID carried by an accepted Create
     * Session / Modify Bearer Response — the point where the user
     * plane needs to be created (e.g. UserPlane::add_tunnel()). */
    virtual void on_user_plane(Session& s, const UserPlaneTunnel& t);

    /* N3 retransmissions exhausted; message_type is the request's. */
    virtual void on_timeout(Session& s, int message_type);

    /* Path management. Echo Requests are answered automatically. */
    virtual void on_echo_request(const std::string& host, uint16_t port,
                                 int recovery);
    virtual void on_echo_response(const std::string& host, uint16_t port,
                                  int recovery);

    /* Incoming requests (server role): decode, then answer with the
     * matching Endpoint::send_*_response(), echoing rsp.sequence and
     * addressing rsp.teid to the peer's control TEID. */
    virtual void on_create_session_request(const CreateSessionRequest& req,
                                           const std::string&          host,
                                           uint16_t                    port);
    virtual void on_modify_bearer_request(const ModifyBearerRequest& req,
                                          const std::string&         host,
                                          uint16_t                   port);
    virtual void on_delete_session_request(const DeleteSessionRequest& req,
                                           const std::string&          host,
                                           uint16_t                    port);

    /* Anything else (and responses matching no transaction). */
    virtual void on_message(int message_type, const Bytes& wire,
                            const std::string& host, uint16_t port);
};

/* One PDN connection created through Endpoint::create_session().
 * Owned by the Endpoint; pointers stay valid until purge() or endpoint
 * destruction. */
class Session
{
  public:
    enum State { CREATING, ACTIVE, DELETING, DELETED, FAILED };

    State state() const
    {
        return state_;
    }
    uint32_t local_teid() const
    {
        return local_teid_;
    }
    uint32_t remote_teid() const
    {
        return remote_teid_;
    }
    std::string imsi() const
    {
        return req_.imsi;
    }
    std::string apn() const
    {
        return req_.apn;
    }
    std::string peer_host() const
    {
        return peer_host_;
    }
    uint16_t peer_port() const
    {
        return peer_port_;
    }
    uint8_t default_ebi() const;

    const CreateSessionRequest& request() const
    {
        return req_;
    }

    /* Tunnels extracted from the last accepted response. */
    std::vector<UserPlaneTunnel> user_plane() const
    {
        return tunnels_;
    }

    /* TEID and sequence are filled in; the rest is the caller's. */
    void modify_bearer(const ModifyBearerRequest& req);

    /* Plain teardown: DSReq with the linked EBI of the first bearer. */
    void delete_session();
    void delete_session_req(const DeleteSessionRequest& req);

  private:
    friend class Endpoint;
    Endpoint*                    ep_         = nullptr;
    State                        state_      = CREATING;
    uint32_t                     local_teid_ = 0, remote_teid_ = 0;
    std::string                  peer_host_;
    uint16_t                     peer_port_ = 0;
    CreateSessionRequest         req_;
    std::vector<UserPlaneTunnel> tunnels_;
};

/* A GTPv2-C UDP endpoint bound to local_host:local_port and registered
 * with the Loop. Client side: create_session() / Session methods, with
 * automatic sequence numbers, T3/N3 retransmission and response
 * matching. Server side: on_*_request() callbacks answered through
 * send_*_response(). Echo Requests are answered automatically with the
 * configured recovery counter. */
class Endpoint
{
  public:
    Endpoint(net::Loop& loop, const std::string& local_host,
             uint16_t local_port = GTPC_PORT);
    ~Endpoint();
    Endpoint(const Endpoint&)            = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    void set_handler(EndpointHandler* h)
    {
        handler_ = h;
    }

    /* Sends a Create Session Request and returns the tracking Session.
     * Fills in what was left unset: sequence, sender F-TEID TEID (a
     * fresh local control TEID) and address (the bound local address);
     * a fully-default sender_fteid also gets if_type S11 MME. */
    Session* create_session(const CreateSessionRequest& req,
                            const std::string&          peer_host,
                            uint16_t                    peer_port = GTPC_PORT);

    /* Fire-and-forget Echo Request (no retransmission). */
    void send_echo(const std::string& peer_host,
                   uint16_t           peer_port = GTPC_PORT);

    /* Server-role responses; set rsp.sequence from the request and
     * rsp.teid to the peer's control TEID. */
    void send_create_session_response(const CreateSessionResponse& rsp,
                                      const std::string& host, uint16_t port);
    void send_modify_bearer_response(const ModifyBearerResponse& rsp,
                                     const std::string& host, uint16_t port);
    void send_delete_session_response(const DeleteSessionResponse& rsp,
                                      const std::string& host, uint16_t port);
    void send_raw(const Bytes& wire, const std::string& host, uint16_t port);

    /* Retransmission (TS 29.274 §7.6): T3-RESPONSE wait, N3 sends. */
    void set_t3_ms(unsigned ms)
    {
        t3_ms_ = ms;
    }
    void set_n3(unsigned n)
    {
        n3_ = n;
    }
    void set_recovery(uint8_t restart_counter)
    {
        recovery_ = restart_counter;
    }

    std::string local_host() const;
    uint16_t    local_port() const;

    Session*              session_by_teid(uint32_t local_teid);
    std::vector<Session*> sessions();

    /* Frees DELETED/FAILED sessions — invalidates their pointers. */
    void purge();

  private:
    friend class Session;
    struct Txn;
    struct Impl;
    Impl*            impl_;
    EndpointHandler* handler_ = nullptr;
    unsigned         t3_ms_ = 3000, n3_ = 3;
    uint8_t          recovery_ = 0;

    void     send_to(const Bytes& wire, const std::string& host, uint16_t port);
    void     start_txn(uint32_t seq, uint8_t mt, const Bytes& wire,
                       uint32_t session_teid, const std::string& host,
                       uint16_t port);
    uint32_t next_seq();
    void     on_readable();
    void     on_txn_timer(Txn& t);
    void handle_datagram(const uint8_t* buf, size_t len, const net_addr& from);
    void dispatch(const uint8_t* msg, size_t len, const gtp2_hdr_t& h,
                  const std::string& host, uint16_t port);
    bool handle_response(const Bytes& wire, const gtp2_hdr_t& h,
                         const std::string& host, uint16_t port);
};

/* ---- GTP-U user plane (eBPF TC datapath, gtp/u) ---- */

/* One bearer's forwarding entry. Addresses are literal strings;
 * ue_addr is the inner (UE) side, remote_addr the outer GTP-U peer.
 * MACs ("aa:bb:cc:dd:ee:ff") are only needed when the kernel FIB
 * cannot resolve the next hop. */
struct Tunnel {
    uint32_t    local_teid  = 0;
    uint32_t    remote_teid = 0;
    uint8_t     ebi         = 0;
    std::string ue_addr;
    uint8_t     prefix_len = 0; /* 0 = host route */
    std::string remote_addr;
    uint16_t    remote_port = 0; /* 0 = 2152 */
    uint32_t    rx_ifindex  = 0; /* decap redirect target; 0 = local stack */
    uint32_t    tx_ifindex  = 0; /* encap uplink; 0 = config uplink */
    std::string dst_mac, src_mac;
    bool        static_mac = false;
    int         qfi        = -1; /* >= 0: 5G PDU Session Container ext */
};

/* Dedicated bearer: its own tunnel plus the traffic filter steering
 * inner packets onto it. 0 = wildcard port. */
struct TrafficFilter {
    Tunnel   tunnel;
    uint8_t  proto       = 0; /* inner IPPROTO_*, required */
    uint16_t ue_port     = 0;
    uint16_t remote_port = 0;
};

struct TunnelStats {
    uint64_t rx_pkts = 0, rx_bytes = 0, tx_pkts = 0, tx_bytes = 0;
    uint64_t err_unknown_teid = 0, err_malformed = 0;
    uint64_t err_tx_no_neigh = 0, err_ringbuf_full = 0, err_abi = 0;
};

struct UserPlaneConfig {
    std::string pin_dir        = "/sys/fs/bpf/gtpu"; /* "" = no pinning */
    uint32_t    max_bearers    = 0;                  /* 0 = default (1M) */
    uint32_t    uplink_ifindex = 0;
    std::string local_v4, local_v6; /* outer source addresses */
};

class UserPlaneEventHandler
{
  public:
    virtual ~UserPlaneEventHandler() = default;
    /* kind is a gtpu_event_kind: 1 unknown TEID, 2 end marker,
     * 3 malformed, 4 ABI mismatch. */
    virtual void on_event(int kind, uint32_t teid, const std::string& src_addr,
                          uint16_t src_port) = 0;
};

/* Wraps the gtp/u loader: loads and pins the TC programs and keeps the
 * kernel forwarding table in sync with the control plane. Needs
 * CAP_BPF + CAP_NET_ADMIN; the constructor throws Error (code
 * GTPU_E_UNSUPPORTED = -2) when the datapath is unavailable. */
class UserPlane
{
  public:
    static bool supported();

    explicit UserPlane(const UserPlaneConfig& cfg);
    ~UserPlane();
    UserPlane(const UserPlane&)            = delete;
    UserPlane& operator=(const UserPlane&) = delete;

    /* Ingress decap on gtpu_ifindex, egress encap on inner_ifindex;
     * either may be 0 to skip that direction. */
    void attach(uint32_t gtpu_ifindex, uint32_t inner_ifindex);
    void detach();

    void add_tunnel(const Tunnel& t);
    void update_tunnel(const Tunnel& t);
    void del_tunnel(const Tunnel& t);

    void add_filter(const TrafficFilter& f);
    void del_filter(const TrafficFilter& f);

    TunnelStats stats(uint32_t local_teid);

    /* Ring-buffer events; events_fd() is pollable — hand it to
     * Loop::add_fd() and call poll_events(0, h) from on_io(). */
    int events_fd() const;
    int poll_events(int timeout_ms, UserPlaneEventHandler* h);

  private:
    gtpu_ebpf* bpf_;
};

} /* namespace gtp */

#endif /* GTPXX_HPP */
