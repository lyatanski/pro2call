#ifndef DIAM_FSM_H
#define DIAM_FSM_H

#include "fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Diameter session state machines — RFC 6733 §8.1.
 *
 * The authorization session state machines, one for the client (the
 * node that sends the service-specific auth request: an AF on Rx, a
 * CTF on Ro) and one for the server, built as tables on the generic
 * FSM engine (task/inc/fsm.h). The RFC's four machines collapse to
 * two here: the codec has no timers yet, so the caller feeds timer
 * expiry as DIAM_SESS_EV_TIMEOUT, and the stateless variants simply
 * never leave IDLE (nothing to track — do not create a machine).
 *
 * The machine tracks state only; it does not build or send messages.
 * Drive it from the message flow: fsm_act(m, DIAM_SESS_EV_..., NULL,
 * NULL) as each request/answer is sent or received, then ask
 * fsm_get_current_state() / diam_sess_state_name() when deciding what
 * the session may do next. Illegal moves return FSM_E_NOMATCH and
 * leave the state alone.
 *
 *   client                              server
 *   IDLE   -SEND_REQUEST-> PENDING      IDLE    -RECV_REQUEST-> PENDING
 *   PENDING -ANSWER_OK--->  OPEN        PENDING -ANSWER_OK---->  OPEN
 *   PENDING -ANSWER_FAIL-> CLOSED       PENDING -ANSWER_FAIL-> CLOSED
 *   OPEN   -REAUTH-------> OPEN         OPEN    -REAUTH-------> OPEN
 *   OPEN   -SEND_STR-----> DISCON       OPEN    -ABORT--------> DISCON
 *   OPEN   -ABORT--------> DISCON       OPEN    -RECV_STR-----> CLOSED
 *   OPEN   -TIMEOUT------> CLOSED       OPEN    -TIMEOUT------> CLOSED
 *   DISCON -RECV_STA-----> CLOSED       DISCON  -RECV_STR-----> CLOSED
 *   PENDING/DISCON -TIMEOUT-> CLOSED    PENDING/DISCON -TIMEOUT-> CLOSED
 */

typedef enum {
    DIAM_SESS_ST_IDLE    = 0,
    DIAM_SESS_ST_PENDING = 1, /* auth request out/in, no answer yet   */
    DIAM_SESS_ST_OPEN    = 2, /* successful answer; service delivered */
    DIAM_SESS_ST_DISCON  = 3, /* termination under way (STR/ASR out)  */
    DIAM_SESS_ST_CLOSED  = 4  /* terminal                             */
} diam_sess_state_t;

typedef enum {
    DIAM_SESS_EV_SEND_REQUEST = 0, /* client: auth request sent        */
    DIAM_SESS_EV_RECV_REQUEST = 1, /* server: auth request received    */
    DIAM_SESS_EV_ANSWER_OK    = 2, /* answer with a 2xxx Result-Code   */
    DIAM_SESS_EV_ANSWER_FAIL  = 3, /* answer with a failure Result-Code*/
    DIAM_SESS_EV_REAUTH       = 4, /* RAR/RAA exchange while open      */
    DIAM_SESS_EV_SEND_STR     = 5, /* client sends Session-Termination */
    DIAM_SESS_EV_RECV_STR     = 6, /* server receives it (sends STA)   */
    DIAM_SESS_EV_RECV_STA     = 7, /* client gets the STA              */
    DIAM_SESS_EV_ABORT        = 8, /* ASR seen (client) / sent (server)*/
    DIAM_SESS_EV_TIMEOUT      = 9  /* Tx / session timer expiry        */
} diam_sess_event_t;

/* Build a machine in DIAM_SESS_ST_IDLE with DIAM_SESS_ST_CLOSED as the
 * terminal state. Free with fsm_destroy(). */
API_EXPORT fsm_t* diam_sess_fsm_client(void);
API_EXPORT fsm_t* diam_sess_fsm_server(void);

/* Names for debug output; "?" when out of range. */
API_EXPORT const char* diam_sess_state_name(fsm_state_id state);
API_EXPORT const char* diam_sess_event_name(fsm_action_id event);

#ifdef __cplusplus
}
#endif

#endif /* DIAM_FSM_H */
