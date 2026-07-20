#ifndef DIAMXX_HPP
#define DIAMXX_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "diam.h"
#include "diam_dict.h"
#include "diam_fsm.h"

/* diamxx — C++ facade over the C Diameter codec (diam/inc/diam.h) and
 * its generated dictionary (diam/gen/inc/diam_dict.h), written to be
 * wrapped by SWIG (bindings/swig/diam.i) and driven from a scripting
 * language. It follows the same rules as the other facades:
 *
 *   - value types: Msg/Avp own copies of everything, so no lifetime
 *     coupling to the wire buffer (the C layer's zero-copy views are
 *     materialized exactly once, here); grouped AVPs are parsed into
 *     children eagerly, guided by the dictionary;
 *   - enums, not magic numbers: scripts use the generated dictionary
 *     constants (diam.AVP_SESSION_ID, diam.CMD_CREDIT_CONTROL, ...);
 *   - errors are exceptions (diam::Error), never return codes.
 */

namespace diam
{

/* Every failure surfaces as one of these; code() keeps the DIAM_E_*
 * value that caused it. */
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

/* One AVP. data holds the bare value bytes (Vendor-ID already
 * stripped); when the dictionary marks the AVP Grouped and the data
 * parses cleanly, children holds the nested AVPs (data stays valid
 * either way). Typed accessors throw Error when the data length does
 * not fit the type. */
struct Avp {
    uint32_t         code      = 0;
    uint32_t         vendor_id = 0;
    unsigned         flags     = 0; /* DIAM_AVP_F_* */
    std::string      data;
    std::vector<Avp> children;

    bool grouped() const
    {
        return !children.empty();
    }
    std::string name() const; /* dictionary name; "" if unknown */
    int         type() const; /* diam_avp_type_t; -1 if unknown */

    uint32_t    u32() const;
    uint64_t    u64() const;
    int32_t     i32() const;
    int64_t     i64() const;
    std::string str() const
    {
        return data;
    }
    std::string value_name() const; /* enum value name; "" if unknown */

    /* First child with the given code; throws Error(DIAM_E_MISSING). */
    Avp  child(uint32_t code, uint32_t vendor_id = 0) const;
    bool has_child(uint32_t code, uint32_t vendor_id = 0) const;
};

/* A parsed message. Top-level AVPs are in avps; find()/u32()/str()
 * are shortcuts over them. */
class Msg
{
  public:
    bool     request    = false;
    bool     proxiable  = false;
    bool     error      = false;
    bool     retransmit = false;
    uint32_t cmd        = 0; /* command code */
    uint32_t app        = 0; /* application id */
    uint32_t hbh        = 0; /* Hop-by-Hop identifier */
    uint32_t e2e        = 0; /* End-to-End identifier */

    std::vector<Avp> avps;

    std::string name() const; /* command name; "" if unknown */

    int avp_count() const
    {
        return (int)avps.size();
    }
    Avp  avp_at(int i) const; /* throws on range */
    bool has(uint32_t code, uint32_t vendor_id = 0) const;
    Avp  find(uint32_t code, uint32_t vendor_id = 0) const; /* throws */

    /* Typed shortcuts over find(). */
    uint32_t    u32(uint32_t code, uint32_t vendor_id = 0) const;
    std::string str(uint32_t code, uint32_t vendor_id = 0) const;
};

/* Parse one wire message; throws Error on anything but a complete,
 * well-formed message (a truncated one raises code DIAM_E_SHORT). */
Msg parse(const std::string& wire);

/* "Resolve the vendor from the dictionary" marker for Builder puts. */
enum : uint32_t { VENDOR_AUTO = 0xFFFFFFFFu };

/* Builds one message into an internal fixed buffer (64 KiB); done()
 * backfills the Message Length and returns the wire bytes.
 *
 * AVP vendor and flags come from the dictionary: put_str(AVP_PUBLIC_
 * IDENTITY, ...) writes V+M and the 3GPP Vendor-ID by itself. When a
 * code exists in both the standard and a vendor registry (the RFC 5777
 * classifier AVPs share the 5xx codes with the 3GPP media AVPs), the
 * standard entry wins — pass the vendor explicitly to disambiguate:
 * put_u32(AVP_MEDIA_TYPE, v, VENDOR_3GPP). Unknown codes are written
 * with no flags; put_raw() overrides everything. Grouped AVPs nest
 * with begin_group()/end_group() pairs.
 *
 * Calls chain: Builder():request(...):put_str(...):done(). */
class Builder
{
  public:
    Builder();

    Builder& request(uint32_t cmd, uint32_t app);
    Builder& answer(uint32_t cmd, uint32_t app);

    Builder& ids(uint32_t hbh, uint32_t e2e);
    Builder& proxiable(bool on = true);
    Builder& error(bool on = true); /* answers only */
    Builder& retransmit(bool on = true);

    Builder& put_str(uint32_t code, const std::string& data,
                     uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_u32(uint32_t code, uint32_t v,
                     uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_u64(uint32_t code, uint64_t v,
                     uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_i32(uint32_t code, int32_t v,
                     uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_i64(uint32_t code, int64_t v,
                     uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_addr4(uint32_t code, const std::string& dotted,
                       uint32_t vendor_id = VENDOR_AUTO);
    Builder& put_raw(uint32_t code, uint32_t vendor_id, unsigned flags,
                     const std::string& data);

    Builder& begin_group(uint32_t code, uint32_t vendor_id = VENDOR_AUTO);
    Builder& end_group();

    /* Finish: backfills the header length and returns the message.
     * The Builder resets and can build the next message. */
    std::string done();

  private:
    void ensure_started(const char* op);

    std::vector<uint8_t> buf_;
    diam_wbuf_t          w_;
    diam_hdr_t           hdr_;
    bool                 started_ = false;
    std::vector<int>     groups_;
};

/* ---- Session state machines (RFC 6733 §8.1) ---- */

/* Machine kinds — scripts write diam.Session(diam.SESS_CLIENT). */
enum SessKind {
    SESS_CLIENT = 0, /* the node sending the auth request (AF, CTF) */
    SESS_SERVER = 1
};

enum SessState {
    SS_IDLE    = DIAM_SESS_ST_IDLE,
    SS_PENDING = DIAM_SESS_ST_PENDING,
    SS_OPEN    = DIAM_SESS_ST_OPEN,
    SS_DISCON  = DIAM_SESS_ST_DISCON,
    SS_CLOSED  = DIAM_SESS_ST_CLOSED
};

/* Non-message events for event(); message events come from
 * send()/recv(). */
enum SessEvent {
    SE_SEND_REQUEST = DIAM_SESS_EV_SEND_REQUEST,
    SE_RECV_REQUEST = DIAM_SESS_EV_RECV_REQUEST,
    SE_ANSWER_OK    = DIAM_SESS_EV_ANSWER_OK,
    SE_ANSWER_FAIL  = DIAM_SESS_EV_ANSWER_FAIL,
    SE_REAUTH       = DIAM_SESS_EV_REAUTH,
    SE_SEND_STR     = DIAM_SESS_EV_SEND_STR,
    SE_RECV_STR     = DIAM_SESS_EV_RECV_STR,
    SE_RECV_STA     = DIAM_SESS_EV_RECV_STA,
    SE_ABORT        = DIAM_SESS_EV_ABORT,
    SE_TIMEOUT      = DIAM_SESS_EV_TIMEOUT
};

/* One authorization session's state machine over the task FSM engine
 * (diam/inc/diam_fsm.h). Tracks state only — no messages, no timers.
 * send(msg)/recv(msg) derive the event from a parsed message: STR/STA
 * and ASR steer termination, RAR/RAA are re-authorization, any other
 * request opens the session, and answers split on a 2xxx Result-Code
 * (Experimental-Result-Code counts too). event() injects the rest
 * (SE_TIMEOUT). An illegal move throws Error and leaves the state
 * alone.
 *
 *   local s = diam.Session(diam.SESS_CLIENT)
 *   s:send(diam.parse(aar))         -- Idle -> Pending
 *   s:recv(diam.parse(aaa))         -- Pending -> Open
 *   s:send(diam.parse(str))         -- Open -> Discon
 *   s:recv(diam.parse(sta))         -- Discon -> Closed
 */
class Session
{
  public:
    explicit Session(int kind);
    ~Session();
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    int kind() const
    {
        return kind_;
    }
    int         state() const;
    std::string state_name() const;
    bool        open() const;
    bool        closed() const;

    /* Inject a raw SE_* event. Throws Error on an illegal move. */
    Session& event(int ev);

    /* Derive the event from a message this side sends / receives. */
    Session& send(const Msg& m);
    Session& recv(const Msg& m);

  private:
    fsm_t* fsm_;
    int    kind_;
};

} /* namespace diam */

#endif /* DIAMXX_HPP */
