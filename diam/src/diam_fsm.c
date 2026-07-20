#include <stddef.h>

#include "diam_fsm.h"

/* RFC 6733 §8.1 authorization session state machines. Both machines
 * share the vocabulary of diam_fsm.h; only the transition tables
 * differ. Timer expiry arrives as DIAM_SESS_EV_TIMEOUT from the
 * caller. */

fsm_t* diam_sess_fsm_client(void)
{
    fsm_t* fsm = fsm_create(DIAM_SESS_ST_IDLE, DIAM_SESS_ST_CLOSED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(DIAM_SESS_ST_IDLE, DIAM_SESS_EV_SEND_REQUEST,
                           DIAM_SESS_ST_PENDING, fsm_exec_nothing,
                           "client: idle -auth request sent-> pending"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_PENDING, DIAM_SESS_EV_ANSWER_OK,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "client: pending -successful answer-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_PENDING, DIAM_SESS_EV_ANSWER_FAIL,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: pending -failed answer-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_PENDING, DIAM_SESS_EV_TIMEOUT,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: pending -Tx expired-> closed"),
            /* Re-authorization keeps the session open; a mid-session auth
             * request (RAR-triggered or client-initiated) is again OPEN ->
             * OPEN on success and closes the session on failure. */
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_REAUTH,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "client: open -re-auth-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_SEND_REQUEST,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "client: open -auth request sent-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ANSWER_OK,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "client: open -successful answer-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ANSWER_FAIL,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: open -failed answer-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_SEND_STR,
                           DIAM_SESS_ST_DISCON, fsm_exec_nothing,
                           "client: open -STR sent-> discon"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ABORT,
                           DIAM_SESS_ST_DISCON, fsm_exec_nothing,
                           "client: open -ASR received, STR follows-> discon"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_TIMEOUT,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: open -session timer expired-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_DISCON, DIAM_SESS_EV_RECV_STA,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: discon -STA received-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_DISCON, DIAM_SESS_EV_TIMEOUT,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "client: discon -Tx expired-> closed"),
            0);
    return fsm;
}

fsm_t* diam_sess_fsm_server(void)
{
    fsm_t* fsm = fsm_create(DIAM_SESS_ST_IDLE, DIAM_SESS_ST_CLOSED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(DIAM_SESS_ST_IDLE, DIAM_SESS_EV_RECV_REQUEST,
                           DIAM_SESS_ST_PENDING, fsm_exec_nothing,
                           "server: idle -auth request received-> pending"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_PENDING, DIAM_SESS_EV_ANSWER_OK,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "server: pending -successful answer sent-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_PENDING, DIAM_SESS_EV_ANSWER_FAIL,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: pending -failed answer sent-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_REAUTH,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "server: open -re-auth-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_RECV_REQUEST,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "server: open -auth request received-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ANSWER_OK,
                           DIAM_SESS_ST_OPEN, fsm_exec_nothing,
                           "server: open -successful answer sent-> open"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ANSWER_FAIL,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: open -failed answer sent-> closed"),
            /* The server answers an STR with an STA at once, so the STR
             * closes the session in one step; the DISCON detour exists for
             * the server-initiated abort (ASR out, STR expected back). */
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_RECV_STR,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: open -STR received, STA sent-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_ABORT,
                           DIAM_SESS_ST_DISCON, fsm_exec_nothing,
                           "server: open -ASR sent-> discon"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_OPEN, DIAM_SESS_EV_TIMEOUT,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: open -session timer expired-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_DISCON, DIAM_SESS_EV_RECV_STR,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: discon -STR received, STA sent-> closed"),
            FSM_ADD_ALWAYS(DIAM_SESS_ST_DISCON, DIAM_SESS_EV_TIMEOUT,
                           DIAM_SESS_ST_CLOSED, fsm_exec_nothing,
                           "server: discon -no STR came-> closed"),
            0);
    return fsm;
}

const char* diam_sess_state_name(fsm_state_id state)
{
    switch (state) {
    case DIAM_SESS_ST_IDLE:    return "Idle";
    case DIAM_SESS_ST_PENDING: return "Pending";
    case DIAM_SESS_ST_OPEN:    return "Open";
    case DIAM_SESS_ST_DISCON:  return "Discon";
    case DIAM_SESS_ST_CLOSED:  return "Closed";
    default:                   return "?";
    }
}

const char* diam_sess_event_name(fsm_action_id event)
{
    switch (event) {
    case DIAM_SESS_EV_SEND_REQUEST: return "auth request sent";
    case DIAM_SESS_EV_RECV_REQUEST: return "auth request received";
    case DIAM_SESS_EV_ANSWER_OK:    return "successful answer";
    case DIAM_SESS_EV_ANSWER_FAIL:  return "failed answer";
    case DIAM_SESS_EV_REAUTH:       return "re-authorization";
    case DIAM_SESS_EV_SEND_STR:     return "STR sent";
    case DIAM_SESS_EV_RECV_STR:     return "STR received";
    case DIAM_SESS_EV_RECV_STA:     return "STA received";
    case DIAM_SESS_EV_ABORT:        return "session abort";
    case DIAM_SESS_EV_TIMEOUT:      return "timeout";
    default:                        return "?";
    }
}
