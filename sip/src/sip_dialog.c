#include <stddef.h>

#include "sip_dialog.h"

/* Dialog- and usage-layer state machines. Each table transcribes one
 * specification (cited beside its builder) onto the generic FSM engine,
 * exactly as sip_fsm.c does for the four §17 transaction machines: the
 * caller feeds message and timer events, the table answers with the
 * state. Timers are collapsed to a single failure/expiry event per
 * machine, since the codec has no timer wheel of its own. */

/* ---- Dialog — RFC 3261 §12 ----------------------------------------
 *
 * A UAC forms a dialog on the first dialog-establishing response: a
 * provisional (1xx above 100) carrying a to-tag opens an *early* dialog,
 * a 2xx confirms it (or forms it directly when no provisional came
 * first). The dialog is destroyed by a BYE while confirmed, or by a
 * non-2xx final / error while still early (§12.3). The dialog id, local
 * and remote CSeq, route set and remote target are data the caller keeps
 * alongside this machine — the FSM tracks only the lifecycle. */
fsm_t* sip_dialog_fsm(void) /* §12 */
{
    fsm_t* fsm = fsm_create(SIP_DIALOG_ST_INIT, SIP_DIALOG_ST_TERMINATED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_INIT, SIP_DIALOG_EV_EARLY,
                           SIP_DIALOG_ST_EARLY, fsm_exec_nothing,
                           "dialog: init -1xx with to-tag-> early"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_INIT, SIP_DIALOG_EV_CONFIRM,
                           SIP_DIALOG_ST_CONFIRMED, fsm_exec_nothing,
                           "dialog: init -2xx-> confirmed"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_INIT, SIP_DIALOG_EV_TERMINATE,
                           SIP_DIALOG_ST_TERMINATED, fsm_exec_nothing,
                           "dialog: init -non-2xx final / error-> terminated"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_EARLY, SIP_DIALOG_EV_EARLY,
                           SIP_DIALOG_ST_EARLY, fsm_exec_nothing,
                           "dialog: early -another 1xx-> early"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_EARLY, SIP_DIALOG_EV_CONFIRM,
                           SIP_DIALOG_ST_CONFIRMED, fsm_exec_nothing,
                           "dialog: early -2xx-> confirmed"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_EARLY, SIP_DIALOG_EV_TERMINATE,
                           SIP_DIALOG_ST_TERMINATED, fsm_exec_nothing,
                           "dialog: early -non-2xx final / error-> terminated"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_CONFIRMED, SIP_DIALOG_EV_CONFIRM,
                           SIP_DIALOG_ST_CONFIRMED, fsm_exec_nothing,
                           "dialog: confirmed -2xx retransmission-> confirmed"),
            FSM_ADD_ALWAYS(SIP_DIALOG_ST_CONFIRMED, SIP_DIALOG_EV_TERMINATE,
                           SIP_DIALOG_ST_TERMINATED, fsm_exec_nothing,
                           "dialog: confirmed -BYE / error-> terminated"),
            0);
    return fsm;
}

/* ---- Registration usage — RFC 3261 §10, 3GPP TS 24.229 §5.1 -------
 *
 * The UAC registration procedure, generalizing bindings/examples/
 * ims_test_s5.lua: REGISTER -> (401/407 challenge -> credentialed
 * REGISTER) -> 200 registered, then the live binding is refreshed before
 * its Expires (§10.2.4) or torn down with Expires:0 (§10.2.2). It rides
 * non-INVITE client transactions (sip_fsm.h) and hands the challenge to
 * the digest machine below. REGISTERED is a resting state, not terminal;
 * a clean de-registration ends in DONE and any rejection or timeout in
 * FAILED. A challenge may reappear on a refresh (stale nonce), so those
 * paths route back through CHALLENGED — the caller bounds the loop. */
fsm_t* sip_reg_fsm(void) /* §10, TS 24.229 §5.1 */
{
    fsm_t* fsm = fsm_create(SIP_REG_ST_IDLE, SIP_REG_ST_FAILED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(
        fsm,
        FSM_ADD_ALWAYS(SIP_REG_ST_IDLE, SIP_REG_EV_SEND, SIP_REG_ST_REGISTERING,
                       fsm_exec_nothing,
                       "register: idle -REGISTER out-> registering"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REGISTERING, SIP_REG_EV_CHALLENGE,
                       SIP_REG_ST_CHALLENGED, fsm_exec_nothing,
                       "register: registering -401/407-> challenged"),
        FSM_ADD_ALWAYS(
            SIP_REG_ST_REGISTERING, SIP_REG_EV_OK, SIP_REG_ST_REGISTERED,
            fsm_exec_nothing,
            "register: registering -200 (no challenge)-> registered"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REGISTERING, SIP_REG_EV_FAIL,
                       SIP_REG_ST_FAILED, fsm_exec_nothing,
                       "register: registering -rejected-> failed"),
        FSM_ADD_ALWAYS(SIP_REG_ST_CHALLENGED, SIP_REG_EV_AUTH,
                       SIP_REG_ST_AUTHENTICATING, fsm_exec_nothing,
                       "register: challenged -credentialed REGISTER out-> "
                       "authenticating"),
        FSM_ADD_ALWAYS(SIP_REG_ST_CHALLENGED, SIP_REG_EV_FAIL,
                       SIP_REG_ST_FAILED, fsm_exec_nothing,
                       "register: challenged -retry cap / bad credentials-> "
                       "failed"),
        FSM_ADD_ALWAYS(SIP_REG_ST_AUTHENTICATING, SIP_REG_EV_OK,
                       SIP_REG_ST_REGISTERED, fsm_exec_nothing,
                       "register: authenticating -200-> registered"),
        FSM_ADD_ALWAYS(
            SIP_REG_ST_AUTHENTICATING, SIP_REG_EV_CHALLENGE,
            SIP_REG_ST_CHALLENGED, fsm_exec_nothing,
            "register: authenticating -stale-nonce 401-> challenged"),
        FSM_ADD_ALWAYS(SIP_REG_ST_AUTHENTICATING, SIP_REG_EV_FAIL,
                       SIP_REG_ST_FAILED, fsm_exec_nothing,
                       "register: authenticating -rejected-> failed"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REGISTERED, SIP_REG_EV_REFRESH,
                       SIP_REG_ST_REFRESHING, fsm_exec_nothing,
                       "register: registered -re-REGISTER out-> refreshing"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REGISTERED, SIP_REG_EV_DEREGISTER,
                       SIP_REG_ST_DEREGISTERING, fsm_exec_nothing,
                       "register: registered -REGISTER Expires:0 out-> "
                       "deregistering"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REFRESHING, SIP_REG_EV_OK,
                       SIP_REG_ST_REGISTERED, fsm_exec_nothing,
                       "register: refreshing -200-> registered"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REFRESHING, SIP_REG_EV_CHALLENGE,
                       SIP_REG_ST_CHALLENGED, fsm_exec_nothing,
                       "register: refreshing -stale-nonce 401-> challenged"),
        FSM_ADD_ALWAYS(SIP_REG_ST_REFRESHING, SIP_REG_EV_FAIL,
                       SIP_REG_ST_FAILED, fsm_exec_nothing,
                       "register: refreshing -rejected-> failed"),
        FSM_ADD_ALWAYS(SIP_REG_ST_DEREGISTERING, SIP_REG_EV_OK, SIP_REG_ST_DONE,
                       fsm_exec_nothing, "register: deregistering -200-> done"),
        FSM_ADD_ALWAYS(SIP_REG_ST_DEREGISTERING, SIP_REG_EV_FAIL,
                       SIP_REG_ST_FAILED, fsm_exec_nothing,
                       "register: deregistering -rejected-> failed"),
        0);
    return fsm;
}

/* ---- Digest authentication — RFC 3261 §22, RFC 2617 / RFC 7616 ----
 *
 * request -> 401/407 -> resend once with credentials -> final. A repeated
 * challenge after the credentialed request (a stale nonce, RFC 2617
 * §3.2.1) sends the machine back through CHALLENGED so the caller can
 * recompute against the fresh nonce; the caller counts attempts and
 * injects SIP_AUTH_EV_GIVE_UP when the cap is reached. AUTHENTICATED is a
 * resting state, not terminal — an authenticated request can be re-sent
 * (e.g. a REGISTER refresh) and re-challenged, so SEND is legal from it.
 * IMS-AKA (RFC 3310) reuses this table verbatim; only the credential the
 * caller derives from the challenge differs (RES vs a shared secret). */
fsm_t* sip_auth_fsm(void) /* §22, RFC 2617/7616 */
{
    fsm_t* fsm = fsm_create(SIP_AUTH_ST_INIT, SIP_AUTH_ST_FAILED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(
        fsm,
        FSM_ADD_ALWAYS(SIP_AUTH_ST_INIT, SIP_AUTH_EV_SEND, SIP_AUTH_ST_PENDING,
                       fsm_exec_nothing, "auth: init -request out-> pending"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_PENDING, SIP_AUTH_EV_CHALLENGE,
                       SIP_AUTH_ST_CHALLENGED, fsm_exec_nothing,
                       "auth: pending -401/407-> challenged"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_PENDING, SIP_AUTH_EV_SUCCESS,
                       SIP_AUTH_ST_AUTHENTICATED, fsm_exec_nothing,
                       "auth: pending -2xx-> authenticated"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_PENDING, SIP_AUTH_EV_FAILURE,
                       SIP_AUTH_ST_FAILED, fsm_exec_nothing,
                       "auth: pending -non-auth rejection-> failed"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_CHALLENGED, SIP_AUTH_EV_SEND,
                       SIP_AUTH_ST_PENDING, fsm_exec_nothing,
                       "auth: challenged -credentialed request out-> pending"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_CHALLENGED, SIP_AUTH_EV_GIVE_UP,
                       SIP_AUTH_ST_FAILED, fsm_exec_nothing,
                       "auth: challenged -retry cap / stale loop-> failed"),
        FSM_ADD_ALWAYS(SIP_AUTH_ST_AUTHENTICATED, SIP_AUTH_EV_SEND,
                       SIP_AUTH_ST_PENDING, fsm_exec_nothing,
                       "auth: authenticated -re-auth request out-> pending"),
        0);
    return fsm;
}

const char* sip_dialog_state_name(fsm_state_id state)
{
    switch (state) {
    case SIP_DIALOG_ST_INIT:       return "Init";
    case SIP_DIALOG_ST_EARLY:      return "Early";
    case SIP_DIALOG_ST_CONFIRMED:  return "Confirmed";
    case SIP_DIALOG_ST_TERMINATED: return "Terminated";
    default:                       return "?";
    }
}

const char* sip_dialog_event_name(fsm_action_id event)
{
    switch (event) {
    case SIP_DIALOG_EV_EARLY:     return "early (1xx with to-tag)";
    case SIP_DIALOG_EV_CONFIRM:   return "confirm (2xx)";
    case SIP_DIALOG_EV_TERMINATE: return "terminate";
    default:                      return "?";
    }
}

const char* sip_reg_state_name(fsm_state_id state)
{
    switch (state) {
    case SIP_REG_ST_IDLE:           return "Idle";
    case SIP_REG_ST_REGISTERING:    return "Registering";
    case SIP_REG_ST_CHALLENGED:     return "Challenged";
    case SIP_REG_ST_AUTHENTICATING: return "Authenticating";
    case SIP_REG_ST_REGISTERED:     return "Registered";
    case SIP_REG_ST_REFRESHING:     return "Refreshing";
    case SIP_REG_ST_DEREGISTERING:  return "Deregistering";
    case SIP_REG_ST_DONE:           return "Done";
    case SIP_REG_ST_FAILED:         return "Failed";
    default:                        return "?";
    }
}

const char* sip_reg_event_name(fsm_action_id event)
{
    switch (event) {
    case SIP_REG_EV_SEND:       return "REGISTER sent";
    case SIP_REG_EV_CHALLENGE:  return "401/407 challenge";
    case SIP_REG_EV_AUTH:       return "credentialed REGISTER sent";
    case SIP_REG_EV_OK:         return "200 OK";
    case SIP_REG_EV_FAIL:       return "rejected";
    case SIP_REG_EV_REFRESH:    return "refresh sent";
    case SIP_REG_EV_DEREGISTER: return "de-register sent";
    default:                    return "?";
    }
}

const char* sip_auth_state_name(fsm_state_id state)
{
    switch (state) {
    case SIP_AUTH_ST_INIT:          return "Init";
    case SIP_AUTH_ST_PENDING:       return "Pending";
    case SIP_AUTH_ST_CHALLENGED:    return "Challenged";
    case SIP_AUTH_ST_AUTHENTICATED: return "Authenticated";
    case SIP_AUTH_ST_FAILED:        return "Failed";
    default:                        return "?";
    }
}

const char* sip_auth_event_name(fsm_action_id event)
{
    switch (event) {
    case SIP_AUTH_EV_SEND:      return "request sent";
    case SIP_AUTH_EV_CHALLENGE: return "401/407 challenge";
    case SIP_AUTH_EV_SUCCESS:   return "2xx";
    case SIP_AUTH_EV_FAILURE:   return "rejection";
    case SIP_AUTH_EV_GIVE_UP:   return "give up";
    default:                    return "?";
    }
}
