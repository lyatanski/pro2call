#ifndef SIP_DIALOG_H
#define SIP_DIALOG_H

#include "fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SIP dialog- and usage-layer state machines.
 *
 * The transaction layer (sip_fsm.h, RFC 3261 §17) is the bottom of the
 * SIP state hierarchy; this header adds the two layers above it, built
 * the same way — tables on the generic FSM engine (task/inc/fsm.h), one
 * shared state/event vocabulary per machine:
 *
 *   - the *dialog* (RFC 3261 §12): the peer relationship an INVITE (or a
 *     SUBSCRIBE/REFER) creates — Early -> Confirmed -> Terminated;
 *   - the *usages* riding on transactions: the registration procedure
 *     (RFC 3261 §10, 3GPP TS 24.229 §5.1) and the digest challenge-
 *     response (RFC 3261 §22, RFC 2617 / RFC 7616) it delegates to.
 *
 * Strictly a REGISTER is a transaction-only *usage*, not a §12 dialog;
 * "dialog state machine" is used loosely here for "the multi-message
 * flow FSM above transactions" (see sip_state_machines.md). Each machine
 * carries the specification it transcribes in a comment beside its
 * builder.
 *
 * Like sip.Transaction, every machine tracks state only: it neither
 * builds messages nor runs timers, and the dialog id / route set / CSeq
 * / credentials are data the caller owns. Feed it what happens — a
 * message parsed, a timer fired — and it answers with the next state.
 * Illegal moves return FSM_E_NOMATCH and leave the state alone. Usages
 * compose downward: a registration drives non-INVITE client transactions
 * (sip_fsm.h) and delegates the 401/407 handshake to the digest machine.
 */

/* ---- Dialog — RFC 3261 §12 (plan B1) ------------------------------- */

typedef enum {
    SIP_DIALOG_ST_INIT       = 0, /* no dialog yet                       */
    SIP_DIALOG_ST_EARLY      = 1, /* dialog-forming provisional seen     */
    SIP_DIALOG_ST_CONFIRMED  = 2, /* 2xx established/confirmed the dialog */
    SIP_DIALOG_ST_TERMINATED = 3  /* terminal                            */
} sip_dialog_state_t;

typedef enum {
    SIP_DIALOG_EV_EARLY     = 0, /* 1xx (>100) carrying a to-tag         */
    SIP_DIALOG_EV_CONFIRM   = 1, /* 2xx final                            */
    SIP_DIALOG_EV_TERMINATE = 2  /* BYE, a non-2xx final, or an error    */
} sip_dialog_event_t;

/* ---- Registration usage — RFC 3261 §10, TS 24.229 §5.1 (plan D1) --- */

typedef enum {
    SIP_REG_ST_IDLE           = 0, /* nothing sent                        */
    SIP_REG_ST_REGISTERING    = 1, /* initial REGISTER out, no credentials */
    SIP_REG_ST_CHALLENGED     = 2, /* 401/407 in, credentials to compute  */
    SIP_REG_ST_AUTHENTICATING = 3, /* credentialed REGISTER out           */
    SIP_REG_ST_REGISTERED     = 4, /* 200 OK — a live binding             */
    SIP_REG_ST_REFRESHING     = 5, /* re-REGISTER before Expires          */
    SIP_REG_ST_DEREGISTERING  = 6, /* REGISTER Expires:0 out              */
    SIP_REG_ST_DONE           = 7, /* de-registered cleanly (sink)        */
    SIP_REG_ST_FAILED         = 8  /* terminal — registration failed      */
} sip_reg_state_t;

typedef enum {
    SIP_REG_EV_SEND       = 0, /* send the initial REGISTER              */
    SIP_REG_EV_CHALLENGE  = 1, /* 401/407 received                       */
    SIP_REG_EV_AUTH       = 2, /* send the credentialed REGISTER         */
    SIP_REG_EV_OK         = 3, /* 2xx received                           */
    SIP_REG_EV_FAIL       = 4, /* rejected / transport error / timeout   */
    SIP_REG_EV_REFRESH    = 5, /* send a refreshing re-REGISTER          */
    SIP_REG_EV_DEREGISTER = 6  /* send REGISTER with Expires:0           */
} sip_reg_event_t;

/* ---- Digest authentication — RFC 3261 §22, RFC 2617/7616 (plan C1) -
 *
 * The reusable core every authenticated request needs: request ->
 * 401/407 -> resend once with credentials -> final, with a caller-driven
 * retry cap and stale-nonce retry. IMS-AKA (plan C2, RFC 3310 / TS
 * 33.203) is a specialization: the same states, with the credential the
 * caller computes being RES from the AKA challenge rather than a shared
 * secret — the machine is identical, only the SIP_AUTH_EV_CHALLENGE
 * payload the caller processes differs.
 */

typedef enum {
    SIP_AUTH_ST_INIT          = 0, /* nothing sent                       */
    SIP_AUTH_ST_PENDING       = 1, /* a request is out, awaiting a reply */
    SIP_AUTH_ST_CHALLENGED    = 2, /* 401/407 in, credentials to compute */
    SIP_AUTH_ST_AUTHENTICATED = 3, /* 2xx — authenticated (may re-auth)  */
    SIP_AUTH_ST_FAILED        = 4  /* terminal — gave up / rejected      */
} sip_auth_state_t;

typedef enum {
    SIP_AUTH_EV_SEND      = 0, /* send a request (initial or credentialed) */
    SIP_AUTH_EV_CHALLENGE = 1, /* 401/407 received                        */
    SIP_AUTH_EV_SUCCESS   = 2, /* 2xx received                            */
    SIP_AUTH_EV_FAILURE   = 3, /* a non-auth final rejection              */
    SIP_AUTH_EV_GIVE_UP   = 4  /* retry cap hit / stale loop — abort      */
} sip_auth_event_t;

/* Each builder returns a machine in its first state (…_INIT / …_IDLE)
 * with its terminal as shown above. Free with fsm_destroy(). */
API_EXPORT fsm_t* sip_dialog_fsm(void); /* §12                          */
API_EXPORT fsm_t* sip_reg_fsm(void);    /* §10, TS 24.229 §5.1          */
API_EXPORT fsm_t* sip_auth_fsm(void);   /* §22, RFC 2617/7616           */

/* Names for debug output; "?" when out of range. */
API_EXPORT const char* sip_dialog_state_name(fsm_state_id state);
API_EXPORT const char* sip_dialog_event_name(fsm_action_id event);
API_EXPORT const char* sip_reg_state_name(fsm_state_id state);
API_EXPORT const char* sip_reg_event_name(fsm_action_id event);
API_EXPORT const char* sip_auth_state_name(fsm_state_id state);
API_EXPORT const char* sip_auth_event_name(fsm_action_id event);

#ifdef __cplusplus
}
#endif

#endif /* SIP_DIALOG_H */
