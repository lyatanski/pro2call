#ifndef SIP_FSM_H
#define SIP_FSM_H

#include "fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SIP transaction state machines — RFC 3261 §17.
 *
 * The four transaction machines (INVITE/non-INVITE × client/server),
 * built as tables on the generic FSM engine (task/inc/fsm.h). One
 * machine instance tracks one transaction; states and events share a
 * single vocabulary so callers can drive any of the four through the
 * same switch.
 *
 * The machine tracks state only; it neither builds messages nor runs
 * timers. Feed it what happens: the TU passing a request down, a
 * response arriving or being sent, a timer firing. The codec has no
 * timer wheel yet, so the RFC's timers arrive from the caller,
 * collapsed by role:
 *
 *   TIMER_RETRANSMIT  A (INVITE client), E (non-INVITE client),
 *                     G (INVITE server)  — retransmit, stay put
 *   TIMER_TIMEOUT     B, F, H            — give up, terminate
 *   TIMER_TERMINATE   D, I, J, K         — wait done, terminate
 *
 * Illegal moves return FSM_E_NOMATCH and leave the state alone;
 * retransmissions the RFC absorbs (a repeated request on the server
 * side, a repeated final response on the client side) are legal
 * self-transitions.
 */

typedef enum {
    SIP_TRANS_ST_INIT       = 0, /* nothing sent or received yet     */
    SIP_TRANS_ST_CALLING    = 1, /* INVITE client: request out       */
    SIP_TRANS_ST_TRYING     = 2, /* non-INVITE: request out/in       */
    SIP_TRANS_ST_PROCEEDING = 3, /* provisional response seen/sent   */
    SIP_TRANS_ST_COMPLETED  = 4, /* final response seen/sent         */
    SIP_TRANS_ST_CONFIRMED  = 5, /* INVITE server: ACK received      */
    SIP_TRANS_ST_TERMINATED = 6  /* terminal                         */
} sip_trans_state_t;

typedef enum {
    SIP_TRANS_EV_SEND_REQUEST     = 0, /* client: TU passes the request */
    SIP_TRANS_EV_RECV_REQUEST     = 1, /* server: request (or retrans.) */
    SIP_TRANS_EV_RECV_1XX         = 2,
    SIP_TRANS_EV_RECV_2XX         = 3,
    SIP_TRANS_EV_RECV_3XX_6XX     = 4,
    SIP_TRANS_EV_SEND_1XX         = 5,
    SIP_TRANS_EV_SEND_2XX         = 6,
    SIP_TRANS_EV_SEND_3XX_6XX     = 7,
    SIP_TRANS_EV_RECV_ACK         = 8,  /* INVITE server only            */
    SIP_TRANS_EV_TIMER_RETRANSMIT = 9,  /* timers A/E/G                  */
    SIP_TRANS_EV_TIMER_TIMEOUT    = 10, /* timers B/F/H                  */
    SIP_TRANS_EV_TIMER_TERMINATE  = 11, /* timers D/I/J/K                */
    SIP_TRANS_EV_TRANSPORT_ERR    = 12
} sip_trans_event_t;

/* Build a machine in SIP_TRANS_ST_INIT with SIP_TRANS_ST_TERMINATED as
 * the terminal state. Free with fsm_destroy(). */
API_EXPORT fsm_t* sip_trans_fsm_invite_client(void); /* §17.1.1 */
API_EXPORT fsm_t* sip_trans_fsm_invite_server(void); /* §17.2.1 */
API_EXPORT fsm_t* sip_trans_fsm_client(void);        /* §17.1.2 */
API_EXPORT fsm_t* sip_trans_fsm_server(void);        /* §17.2.2 */

/* Names for debug output; "?" when out of range. */
API_EXPORT const char* sip_trans_state_name(fsm_state_id state);
API_EXPORT const char* sip_trans_event_name(fsm_action_id event);

#ifdef __cplusplus
}
#endif

#endif /* SIP_FSM_H */
