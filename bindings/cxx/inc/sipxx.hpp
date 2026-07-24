#ifndef SIPXX_HPP
#define SIPXX_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "sip.h"
#include "sip_dialog.h"
#include "sip_fsm.h"

/* sipxx — C++ facade over the C SIP codec (sip/inc/sip.h), written to
 * be wrapped by SWIG (bindings/swig/sip.i) and driven from a scripting
 * language. It follows the same rules as the other facades:
 *
 *   - value types: Msg/Header/Uri/Addr/Via own copies of everything,
 *     so no lifetime coupling to the wire buffer (the C layer's
 *     zero-copy slices are materialized exactly once, here);
 *   - enums, not strings: methods and header fields keep the C
 *     library's numeric ids, so scripts dispatch on sip.INVITE or
 *     sip.H_VIA and a compact "v:" is indistinguishable from "Via:";
 *   - errors are exceptions (sip::Error), never return codes.
 */

namespace sip
{

/* Every failure surfaces as one of these; code() keeps the SIP_E_*
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

/* Methods and header fields — mirrored from sip.h so scripts get
 * named constants (sip.INVITE, sip.H_CALL_ID, ...). */
enum Method {
    M_UNKNOWN = SIP_M_UNKNOWN,
    INVITE    = SIP_M_INVITE,
    ACK       = SIP_M_ACK,
    BYE       = SIP_M_BYE,
    CANCEL    = SIP_M_CANCEL,
    OPTIONS   = SIP_M_OPTIONS,
    REGISTER  = SIP_M_REGISTER,
    PRACK     = SIP_M_PRACK,
    SUBSCRIBE = SIP_M_SUBSCRIBE,
    NOTIFY    = SIP_M_NOTIFY,
    PUBLISH   = SIP_M_PUBLISH,
    INFO      = SIP_M_INFO,
    REFER     = SIP_M_REFER,
    MESSAGE   = SIP_M_MESSAGE,
    UPDATE    = SIP_M_UPDATE
};

enum Hdr {
    H_OTHER                = SIP_H_OTHER,
    H_ACCEPT               = SIP_H_ACCEPT,
    H_ACCEPT_ENCODING      = SIP_H_ACCEPT_ENCODING,
    H_ACCEPT_LANGUAGE      = SIP_H_ACCEPT_LANGUAGE,
    H_ALERT_INFO           = SIP_H_ALERT_INFO,
    H_ALLOW                = SIP_H_ALLOW,
    H_ALLOW_EVENTS         = SIP_H_ALLOW_EVENTS,
    H_AUTHENTICATION_INFO  = SIP_H_AUTHENTICATION_INFO,
    H_AUTHORIZATION        = SIP_H_AUTHORIZATION,
    H_CALL_ID              = SIP_H_CALL_ID,
    H_CALL_INFO            = SIP_H_CALL_INFO,
    H_CONTACT              = SIP_H_CONTACT,
    H_CONTENT_DISPOSITION  = SIP_H_CONTENT_DISPOSITION,
    H_CONTENT_ENCODING     = SIP_H_CONTENT_ENCODING,
    H_CONTENT_LANGUAGE     = SIP_H_CONTENT_LANGUAGE,
    H_CONTENT_LENGTH       = SIP_H_CONTENT_LENGTH,
    H_CONTENT_TYPE         = SIP_H_CONTENT_TYPE,
    H_CSEQ                 = SIP_H_CSEQ,
    H_DATE                 = SIP_H_DATE,
    H_ERROR_INFO           = SIP_H_ERROR_INFO,
    H_EVENT                = SIP_H_EVENT,
    H_EXPIRES              = SIP_H_EXPIRES,
    H_FROM                 = SIP_H_FROM,
    H_IN_REPLY_TO          = SIP_H_IN_REPLY_TO,
    H_MAX_FORWARDS         = SIP_H_MAX_FORWARDS,
    H_MIME_VERSION         = SIP_H_MIME_VERSION,
    H_MIN_EXPIRES          = SIP_H_MIN_EXPIRES,
    H_MIN_SE               = SIP_H_MIN_SE,
    H_ORGANIZATION         = SIP_H_ORGANIZATION,
    H_P_ASSERTED_IDENTITY  = SIP_H_P_ASSERTED_IDENTITY,
    H_P_PREFERRED_IDENTITY = SIP_H_P_PREFERRED_IDENTITY,
    H_PRIORITY             = SIP_H_PRIORITY,
    H_PRIVACY              = SIP_H_PRIVACY,
    H_PROXY_AUTHENTICATE   = SIP_H_PROXY_AUTHENTICATE,
    H_PROXY_AUTHORIZATION  = SIP_H_PROXY_AUTHORIZATION,
    H_PROXY_REQUIRE        = SIP_H_PROXY_REQUIRE,
    H_RACK                 = SIP_H_RACK,
    H_RECORD_ROUTE         = SIP_H_RECORD_ROUTE,
    H_REFER_TO             = SIP_H_REFER_TO,
    H_REFERRED_BY          = SIP_H_REFERRED_BY,
    H_REPLY_TO             = SIP_H_REPLY_TO,
    H_REQUIRE              = SIP_H_REQUIRE,
    H_RETRY_AFTER          = SIP_H_RETRY_AFTER,
    H_ROUTE                = SIP_H_ROUTE,
    H_RSEQ                 = SIP_H_RSEQ,
    H_SERVER               = SIP_H_SERVER,
    H_SESSION_EXPIRES      = SIP_H_SESSION_EXPIRES,
    H_SUBJECT              = SIP_H_SUBJECT,
    H_SUBSCRIPTION_STATE   = SIP_H_SUBSCRIPTION_STATE,
    H_SUPPORTED            = SIP_H_SUPPORTED,
    H_TIMESTAMP            = SIP_H_TIMESTAMP,
    H_TO                   = SIP_H_TO,
    H_UNSUPPORTED          = SIP_H_UNSUPPORTED,
    H_USER_AGENT           = SIP_H_USER_AGENT,
    H_VIA                  = SIP_H_VIA,
    H_WARNING              = SIP_H_WARNING,
    H_WWW_AUTHENTICATE     = SIP_H_WWW_AUTHENTICATE
};

/* One header field. id is a Hdr value; H_OTHER for extension headers,
 * which are matched by name instead. */
struct Header {
    int         id = H_OTHER;
    std::string name; /* as it appeared on the wire */
    std::string value;
};

/* Parsed sip/sips/tel URI. */
struct Uri {
    std::string scheme;
    std::string user;
    std::string host;
    int         port = 0; /* 0 = absent */
    std::string params;
    std::string headers;
};

/* From/To/Contact style address. */
struct Addr {
    std::string display;
    std::string uri;
    std::string params;
    std::string tag;
};

/* One Via value. */
struct Via {
    std::string transport;
    std::string host;
    int         port = 0;
    std::string params;
    std::string branch;
};

/* CSeq value. */
struct CSeq {
    unsigned    number = 0;
    int         method = M_UNKNOWN;
    std::string method_name;
};

/* A parsed message. Field access never throws; the typed shortcuts
 * (cseq/from_/to_/top_via) throw Error(SIP_E_MISSING) when the header
 * is absent and Error(SIP_E_HEADER) when it does not parse. */
class Msg
{
  public:
    bool        request = false;
    int         method  = M_UNKNOWN; /* Method (requests)      */
    std::string method_name;
    std::string uri;        /* Request-URI (requests) */
    int         status = 0; /* responses              */
    std::string reason;
    std::string body;

    int         header_count() const;
    Header      header_at(int i) const; /* throws on range   */
    bool        has_header(const std::string& name) const;
    std::string header(const std::string& name) const; /* first, "" if none */
    std::vector<std::string> header_values(const std::string& name) const;

    std::string call_id() const
    {
        return header("Call-ID");
    }
    CSeq cseq() const;
    Addr from_() const; /* 'from' is unreserved but reads
                           poorly next to to_() in Lua   */
    Addr to_() const;
    Via  top_via() const;

    std::vector<Header> hdrs; /* hidden from scripts */
};

/* Parse one wire message; throws Error on anything but a complete,
 * well-formed message (a truncated one raises code SIP_E_SHORT). */
Msg parse(const std::string& wire);

Uri  parse_uri(const std::string& s);
Addr parse_addr(const std::string& value);
Via  parse_via(const std::string& value);

/* ---- auth-header helpers (RFC 2617 / RFC 3329) ---- */

/* Pull one parameter out of an auth-style header value — WWW-Authenticate
 * / Authorization (key="quoted" or key=bare) or a Security-Client /
 * Security-Server list (spi-s=1234, port-c=5090). The key is matched only
 * at a parameter boundary, so "nc" does not match inside "cnonce".
 * Returns "" when the parameter is absent. */
std::string auth_param(const std::string& header_value, const std::string& key);

/* base64 decode (RFC 4648); non-alphabet bytes and '=' padding are
 * ignored, so it handles the AKA nonce (base64 RAND||AUTN) in a 401
 * WWW-Authenticate challenge. */
std::string b64decode(const std::string& s);

/* Name tables, for pretty-printing in scripts. */
std::string method_name(int method);
std::string hdr_name(int hdr);
std::string status_phrase(int status);

/* Builds one message into an internal fixed buffer (64 KiB — the
 * practical ceiling for a SIP message); done() returns the wire bytes.
 * Calls chain: Builder():request(...):header(...):body(...):done(). */
class Builder
{
  public:
    Builder();

    Builder& request(int method, const std::string& uri);
    Builder& response(int status, const std::string& reason = "");

    Builder& header(int hdr, const std::string& value);
    Builder& header_name(const std::string& name, const std::string& value);
    Builder& header_u32(int hdr, unsigned value);

    /* Finish: writes Content-Length + separator + body and returns the
     * message. The Builder resets and can build the next message. */
    std::string done(const std::string& body = "");

  private:
    std::vector<char> buf_;
    sip_wbuf_t        w_;
};

/* ---- Transaction state machines (RFC 3261 §17) ---- */

/* The four machine kinds — mirrored from sip_fsm.h so scripts write
 * sip.Transaction(sip.INVITE_CLIENT). */
enum TransKind {
    INVITE_CLIENT     = 0, /* §17.1.1 */
    INVITE_SERVER     = 1, /* §17.2.1 */
    NON_INVITE_CLIENT = 2, /* §17.1.2 */
    NON_INVITE_SERVER = 3  /* §17.2.2 */
};

enum TransState {
    TS_INIT       = SIP_TRANS_ST_INIT,
    TS_CALLING    = SIP_TRANS_ST_CALLING,
    TS_TRYING     = SIP_TRANS_ST_TRYING,
    TS_PROCEEDING = SIP_TRANS_ST_PROCEEDING,
    TS_COMPLETED  = SIP_TRANS_ST_COMPLETED,
    TS_CONFIRMED  = SIP_TRANS_ST_CONFIRMED,
    TS_TERMINATED = SIP_TRANS_ST_TERMINATED
};

/* Timer events for event(); message events come from send()/recv(). */
enum TransEvent {
    TE_SEND_REQUEST     = SIP_TRANS_EV_SEND_REQUEST,
    TE_RECV_REQUEST     = SIP_TRANS_EV_RECV_REQUEST,
    TE_RECV_1XX         = SIP_TRANS_EV_RECV_1XX,
    TE_RECV_2XX         = SIP_TRANS_EV_RECV_2XX,
    TE_RECV_3XX_6XX     = SIP_TRANS_EV_RECV_3XX_6XX,
    TE_SEND_1XX         = SIP_TRANS_EV_SEND_1XX,
    TE_SEND_2XX         = SIP_TRANS_EV_SEND_2XX,
    TE_SEND_3XX_6XX     = SIP_TRANS_EV_SEND_3XX_6XX,
    TE_RECV_ACK         = SIP_TRANS_EV_RECV_ACK,
    TE_TIMER_RETRANSMIT = SIP_TRANS_EV_TIMER_RETRANSMIT,
    TE_TIMER_TIMEOUT    = SIP_TRANS_EV_TIMER_TIMEOUT,
    TE_TIMER_TERMINATE  = SIP_TRANS_EV_TIMER_TERMINATE,
    TE_TRANSPORT_ERR    = SIP_TRANS_EV_TRANSPORT_ERR
};

/* One transaction's state machine over the task FSM engine
 * (sip/inc/sip_fsm.h). Tracks state only — it neither sends messages
 * nor runs timers. Feed it the traffic: send(msg)/recv(msg) derive the
 * event from the message (request/ACK/response class), event() injects
 * timers and transport errors. An illegal move throws Error and leaves
 * the state alone.
 *
 *   local t = sip.Transaction(sip.INVITE_CLIENT)
 *   t:send(sip.parse(invite))       -- Init -> Calling
 *   t:recv(sip.parse(ringing))      -- Calling -> Proceeding
 *   t:recv(sip.parse(ok200))        -- Proceeding -> Terminated
 */
class Transaction
{
  public:
    explicit Transaction(int kind);
    ~Transaction();
    Transaction(const Transaction&)            = delete;
    Transaction& operator=(const Transaction&) = delete;

    int kind() const
    {
        return kind_;
    }
    int         state() const;
    std::string state_name() const;
    bool        terminated() const;

    /* Inject a raw TE_* event. Throws Error on an illegal move. */
    Transaction& event(int ev);

    /* Derive the event from a message this side sends / receives. The
     * ACK a client transaction owes for a non-2xx final is generated
     * below the TU, so send(ACK) on a client machine is a no-op; the
     * ACK for a 2xx is a separate transaction (RFC 3261 §17.1.1.3). */
    Transaction& send(const Msg& m);
    Transaction& recv(const Msg& m);

  private:
    fsm_t* fsm_;
    int    kind_;
};

/* ---- Dialog state machine (RFC 3261 §12) ---- */

enum DialogState {
    DS_INIT       = SIP_DIALOG_ST_INIT,
    DS_EARLY      = SIP_DIALOG_ST_EARLY,
    DS_CONFIRMED  = SIP_DIALOG_ST_CONFIRMED,
    DS_TERMINATED = SIP_DIALOG_ST_TERMINATED
};

/* Non-message events for event(); message events come from
 * send()/recv(). */
enum DialogEvent {
    DE_EARLY     = SIP_DIALOG_EV_EARLY,
    DE_CONFIRM   = SIP_DIALOG_EV_CONFIRM,
    DE_TERMINATE = SIP_DIALOG_EV_TERMINATE
};

/* A §12 dialog's lifecycle over the task FSM engine
 * (sip/inc/sip_dialog.h): Init -> Early -> Confirmed -> Terminated.
 * Tracks state only — the dialog id, CSeq, route set and remote target
 * are yours to keep. send(msg)/recv(msg) derive the event from a parsed
 * message: an INVITE's dialog-forming 1xx (a to-tag present) opens the
 * early dialog, its 2xx confirms it, a non-2xx final ends a not-yet-
 * confirmed dialog, and a BYE ends a confirmed one — every other message
 * is a no-op. event() injects a raw DE_*. An illegal move throws Error.
 *
 *   local d = sip.Dialog()
 *   d:recv(sip.parse(ringing_with_totag))  -- Init -> Early
 *   d:recv(sip.parse(ok200))               -- Early -> Confirmed
 *   d:send(sip.parse(bye))                 -- Confirmed -> Terminated
 */
class Dialog
{
  public:
    Dialog();
    ~Dialog();
    Dialog(const Dialog&)            = delete;
    Dialog& operator=(const Dialog&) = delete;

    int         state() const;
    std::string state_name() const;
    bool        early() const;
    bool        confirmed() const;
    bool        terminated() const;

    /* Inject a raw DE_* event. Throws Error on an illegal move. */
    Dialog& event(int ev);

    /* Derive the event from a message this side sends / receives. */
    Dialog& send(const Msg& m);
    Dialog& recv(const Msg& m);

  private:
    fsm_t* fsm_;
};

/* ---- Registration usage (RFC 3261 §10, 3GPP TS 24.229 §5.1) ---- */

enum RegState {
    RS_IDLE           = SIP_REG_ST_IDLE,
    RS_REGISTERING    = SIP_REG_ST_REGISTERING,
    RS_CHALLENGED     = SIP_REG_ST_CHALLENGED,
    RS_AUTHENTICATING = SIP_REG_ST_AUTHENTICATING,
    RS_REGISTERED     = SIP_REG_ST_REGISTERED,
    RS_REFRESHING     = SIP_REG_ST_REFRESHING,
    RS_DEREGISTERING  = SIP_REG_ST_DEREGISTERING,
    RS_DONE           = SIP_REG_ST_DONE,
    RS_FAILED         = SIP_REG_ST_FAILED
};

enum RegEvent {
    RE_SEND       = SIP_REG_EV_SEND,
    RE_CHALLENGE  = SIP_REG_EV_CHALLENGE,
    RE_AUTH       = SIP_REG_EV_AUTH,
    RE_OK         = SIP_REG_EV_OK,
    RE_FAIL       = SIP_REG_EV_FAIL,
    RE_REFRESH    = SIP_REG_EV_REFRESH,
    RE_DEREGISTER = SIP_REG_EV_DEREGISTER
};

/* The UAC registration procedure over the task FSM engine
 * (sip/inc/sip_dialog.h): idle -> registering -> challenged ->
 * authenticating -> registered, then refresh or de-register. Tracks
 * state only. send(msg) reads the current state to place a REGISTER:
 * the first one registers, one after a challenge carries credentials,
 * and one while registered refreshes — unless it de-registers (Expires:0,
 * Contact "*", or a Contact with expires=0). recv(msg) splits the reply:
 * 401/407 challenges, a 2xx advances, any other final fails. Compose the
 * challenge with sip.AuthChallenge and the transaction with
 * sip.Transaction(sip.NON_INVITE_CLIENT). event() injects a raw RE_*.
 *
 *   local r = sip.Registration()
 *   r:send(sip.parse(register1))  -- Idle -> Registering
 *   r:recv(sip.parse(challenge))  -- Registering -> Challenged
 *   r:send(sip.parse(register2))  -- Challenged -> Authenticating
 *   r:recv(sip.parse(ok200))      -- Authenticating -> Registered
 */
class Registration
{
  public:
    Registration();
    ~Registration();
    Registration(const Registration&)            = delete;
    Registration& operator=(const Registration&) = delete;

    int         state() const;
    std::string state_name() const;
    bool        registered() const;  /* a live binding                  */
    bool        done() const;        /* de-registered cleanly           */
    bool        failed() const;      /* terminal failure                */

    /* Inject a raw RE_* event. Throws Error on an illegal move. */
    Registration& event(int ev);

    /* Derive the event from a message this side sends / receives. */
    Registration& send(const Msg& m);
    Registration& recv(const Msg& m);

  private:
    fsm_t* fsm_;
};

/* ---- Digest authentication (RFC 3261 §22, RFC 2617 / RFC 7616) ---- */

enum AuthState {
    AS_INIT          = SIP_AUTH_ST_INIT,
    AS_PENDING       = SIP_AUTH_ST_PENDING,
    AS_CHALLENGED    = SIP_AUTH_ST_CHALLENGED,
    AS_AUTHENTICATED = SIP_AUTH_ST_AUTHENTICATED,
    AS_FAILED        = SIP_AUTH_ST_FAILED
};

enum AuthEvent {
    AE_SEND      = SIP_AUTH_EV_SEND,
    AE_CHALLENGE = SIP_AUTH_EV_CHALLENGE,
    AE_SUCCESS   = SIP_AUTH_EV_SUCCESS,
    AE_FAILURE   = SIP_AUTH_EV_FAILURE,
    AE_GIVE_UP   = SIP_AUTH_EV_GIVE_UP
};

/* The digest challenge-response sub-FSM over the task FSM engine
 * (sip/inc/sip_dialog.h): a request, a 401/407, the same request re-sent
 * with credentials, a final. The reusable core of any authenticated
 * request — a registration delegates its challenge to it. send(msg)
 * marks a request going out, recv(msg) reads the reply (401/407
 * challenges, 2xx authenticates, any other final fails); a repeated
 * challenge returns to Challenged so the caller can retry a stale nonce,
 * and event(sip.AE_GIVE_UP) aborts when a retry cap is hit. IMS-AKA
 * (RFC 3310) drives this same machine — only the credential the caller
 * derives from the challenge differs. An illegal move throws Error.
 *
 *   local a = sip.AuthChallenge()
 *   a:send(sip.parse(req))        -- Init -> Pending
 *   a:recv(sip.parse(challenge))  -- Pending -> Challenged
 *   a:send(sip.parse(req_creds))  -- Challenged -> Pending
 *   a:recv(sip.parse(ok200))      -- Pending -> Authenticated
 */
class AuthChallenge
{
  public:
    AuthChallenge();
    ~AuthChallenge();
    AuthChallenge(const AuthChallenge&)            = delete;
    AuthChallenge& operator=(const AuthChallenge&) = delete;

    int         state() const;
    std::string state_name() const;
    bool        challenged() const;
    bool        authenticated() const;
    bool        failed() const;

    /* Inject a raw AE_* event. Throws Error on an illegal move. */
    AuthChallenge& event(int ev);

    /* Derive the event from a message this side sends / receives. */
    AuthChallenge& send(const Msg& m);
    AuthChallenge& recv(const Msg& m);

  private:
    fsm_t* fsm_;
};

} /* namespace sip */

#endif /* SIPXX_HPP */
