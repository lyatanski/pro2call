#include <stddef.h>

#include "sip_fsm.h"

/* RFC 3261 §17 transaction state machines. The tables transcribe the
 * four figures (5, 6, 7, 8); timer events come from the caller, named
 * by role rather than letter (see sip_fsm.h). */

fsm_t* sip_trans_fsm_invite_client(void) /* §17.1.1 */
{
    fsm_t* fsm = fsm_create(SIP_TRANS_ST_INIT, SIP_TRANS_ST_TERMINATED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(
        fsm,
        FSM_ADD_ALWAYS(SIP_TRANS_ST_INIT, SIP_TRANS_EV_SEND_REQUEST,
                       SIP_TRANS_ST_CALLING, fsm_exec_nothing,
                       "invite client: init -INVITE out-> calling"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CALLING, SIP_TRANS_EV_TIMER_RETRANSMIT,
                       SIP_TRANS_ST_CALLING, fsm_exec_nothing,
                       "invite client: calling -timer A, retransmit-> calling"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CALLING, SIP_TRANS_EV_RECV_1XX,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "invite client: calling -1xx-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CALLING, SIP_TRANS_EV_RECV_2XX,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite client: calling -2xx to TU-> terminated"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CALLING, SIP_TRANS_EV_RECV_3XX_6XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "invite client: calling -3xx-6xx, ACK out-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CALLING, SIP_TRANS_EV_TIMER_TIMEOUT,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite client: calling -timer B-> terminated"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_1XX,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "invite client: proceeding -1xx-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_2XX,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite client: proceeding -2xx to TU-> terminated"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_3XX_6XX,
            SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
            "invite client: proceeding -3xx-6xx, ACK out-> completed"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_3XX_6XX,
            SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
            "invite client: completed -retransmission, ACK again-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_TIMER_TERMINATE,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite client: completed -timer D-> terminated"),
        FSM_ADD_ALWAYS(fsm_state_any, SIP_TRANS_EV_TRANSPORT_ERR,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite client: transport error -> terminated"),
        0);
    return fsm;
}

fsm_t* sip_trans_fsm_invite_server(void) /* §17.2.1 */
{
    fsm_t* fsm = fsm_create(SIP_TRANS_ST_INIT, SIP_TRANS_ST_TERMINATED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(
        fsm,
        FSM_ADD_ALWAYS(SIP_TRANS_ST_INIT, SIP_TRANS_EV_RECV_REQUEST,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "invite server: init -INVITE in, 100 out-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_REQUEST,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "invite server: proceeding -retransmission, resend "
                       "provisional-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_1XX,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "invite server: proceeding -1xx out-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_2XX,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite server: proceeding -2xx out (TU owns "
                       "retransmissions)-> terminated"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_3XX_6XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "invite server: proceeding -3xx-6xx out-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_REQUEST,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "invite server: completed -retransmission, resend "
                       "final-> completed"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_TIMER_RETRANSMIT,
            SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
            "invite server: completed -timer G, retransmit final-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_ACK,
                       SIP_TRANS_ST_CONFIRMED, fsm_exec_nothing,
                       "invite server: completed -ACK-> confirmed"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_TIMER_TIMEOUT,
            SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
            "invite server: completed -timer H, no ACK-> terminated"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CONFIRMED, SIP_TRANS_EV_RECV_ACK,
                       SIP_TRANS_ST_CONFIRMED, fsm_exec_nothing,
                       "invite server: confirmed -ACK absorbed-> confirmed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_CONFIRMED, SIP_TRANS_EV_TIMER_TERMINATE,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite server: confirmed -timer I-> terminated"),
        FSM_ADD_ALWAYS(fsm_state_any, SIP_TRANS_EV_TRANSPORT_ERR,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "invite server: transport error -> terminated"),
        0);
    return fsm;
}

fsm_t* sip_trans_fsm_client(void) /* §17.1.2 */
{
    fsm_t* fsm = fsm_create(SIP_TRANS_ST_INIT, SIP_TRANS_ST_TERMINATED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(
        fsm,
        FSM_ADD_ALWAYS(SIP_TRANS_ST_INIT, SIP_TRANS_EV_SEND_REQUEST,
                       SIP_TRANS_ST_TRYING, fsm_exec_nothing,
                       "client: init -request out-> trying"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_TIMER_RETRANSMIT,
                       SIP_TRANS_ST_TRYING, fsm_exec_nothing,
                       "client: trying -timer E, retransmit-> trying"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_RECV_1XX,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "client: trying -1xx-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_RECV_2XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "client: trying -2xx-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_RECV_3XX_6XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "client: trying -3xx-6xx-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_TIMER_TIMEOUT,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "client: trying -timer F-> terminated"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_TIMER_RETRANSMIT,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "client: proceeding -timer E, retransmit-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_1XX,
                       SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                       "client: proceeding -1xx-> proceeding"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_2XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "client: proceeding -2xx-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_3XX_6XX,
                       SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                       "client: proceeding -3xx-6xx-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_TIMER_TIMEOUT,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "client: proceeding -timer F-> terminated"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_2XX,
            SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
            "client: completed -retransmission absorbed-> completed"),
        FSM_ADD_ALWAYS(
            SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_3XX_6XX,
            SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
            "client: completed -retransmission absorbed-> completed"),
        FSM_ADD_ALWAYS(SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_TIMER_TERMINATE,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "client: completed -timer K-> terminated"),
        FSM_ADD_ALWAYS(fsm_state_any, SIP_TRANS_EV_TRANSPORT_ERR,
                       SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                       "client: transport error -> terminated"),
        0);
    return fsm;
}

fsm_t* sip_trans_fsm_server(void) /* §17.2.2 */
{
    fsm_t* fsm = fsm_create(SIP_TRANS_ST_INIT, SIP_TRANS_ST_TERMINATED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(SIP_TRANS_ST_INIT, SIP_TRANS_EV_RECV_REQUEST,
                           SIP_TRANS_ST_TRYING, fsm_exec_nothing,
                           "server: init -request in, to TU-> trying"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_RECV_REQUEST,
                           SIP_TRANS_ST_TRYING, fsm_exec_nothing,
                           "server: trying -retransmission absorbed-> trying"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_SEND_1XX,
                           SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                           "server: trying -1xx out-> proceeding"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_SEND_2XX,
                           SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                           "server: trying -2xx out-> completed"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_TRYING, SIP_TRANS_EV_SEND_3XX_6XX,
                           SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                           "server: trying -3xx-6xx out-> completed"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_RECV_REQUEST,
                           SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                           "server: proceeding -retransmission, resend "
                           "provisional-> proceeding"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_1XX,
                           SIP_TRANS_ST_PROCEEDING, fsm_exec_nothing,
                           "server: proceeding -1xx out-> proceeding"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_2XX,
                           SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                           "server: proceeding -2xx out-> completed"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_PROCEEDING, SIP_TRANS_EV_SEND_3XX_6XX,
                           SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                           "server: proceeding -3xx-6xx out-> completed"),
            FSM_ADD_ALWAYS(
                SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_RECV_REQUEST,
                SIP_TRANS_ST_COMPLETED, fsm_exec_nothing,
                "server: completed -retransmission, resend final-> completed"),
            FSM_ADD_ALWAYS(SIP_TRANS_ST_COMPLETED, SIP_TRANS_EV_TIMER_TERMINATE,
                           SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                           "server: completed -timer J-> terminated"),
            FSM_ADD_ALWAYS(fsm_state_any, SIP_TRANS_EV_TRANSPORT_ERR,
                           SIP_TRANS_ST_TERMINATED, fsm_exec_nothing,
                           "server: transport error -> terminated"),
            0);
    return fsm;
}

const char* sip_trans_state_name(fsm_state_id state)
{
    switch (state) {
    case SIP_TRANS_ST_INIT:       return "Init";
    case SIP_TRANS_ST_CALLING:    return "Calling";
    case SIP_TRANS_ST_TRYING:     return "Trying";
    case SIP_TRANS_ST_PROCEEDING: return "Proceeding";
    case SIP_TRANS_ST_COMPLETED:  return "Completed";
    case SIP_TRANS_ST_CONFIRMED:  return "Confirmed";
    case SIP_TRANS_ST_TERMINATED: return "Terminated";
    default:                      return "?";
    }
}

const char* sip_trans_event_name(fsm_action_id event)
{
    switch (event) {
    case SIP_TRANS_EV_SEND_REQUEST:     return "request sent";
    case SIP_TRANS_EV_RECV_REQUEST:     return "request received";
    case SIP_TRANS_EV_RECV_1XX:         return "1xx received";
    case SIP_TRANS_EV_RECV_2XX:         return "2xx received";
    case SIP_TRANS_EV_RECV_3XX_6XX:     return "3xx-6xx received";
    case SIP_TRANS_EV_SEND_1XX:         return "1xx sent";
    case SIP_TRANS_EV_SEND_2XX:         return "2xx sent";
    case SIP_TRANS_EV_SEND_3XX_6XX:     return "3xx-6xx sent";
    case SIP_TRANS_EV_RECV_ACK:         return "ACK received";
    case SIP_TRANS_EV_TIMER_RETRANSMIT: return "retransmit timer";
    case SIP_TRANS_EV_TIMER_TIMEOUT:    return "timeout timer";
    case SIP_TRANS_EV_TIMER_TERMINATE:  return "terminate timer";
    case SIP_TRANS_EV_TRANSPORT_ERR:    return "transport error";
    default:                            return "?";
    }
}
