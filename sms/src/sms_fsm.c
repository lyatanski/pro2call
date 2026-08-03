#include <stddef.h>

#include "sms_fsm.h"

/* TS 24.011 §8.3 short message transfer transactions. Two tables, one
 * per direction; timer events come from the caller (see sms_fsm.h). */

fsm_t* sms_trans_fsm_mo(void) /* §8.3.2, TR1M */
{
    fsm_t* fsm = fsm_create(SMS_TR_ST_IDLE, SMS_TR_ST_ABORTED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(SMS_TR_ST_IDLE, SMS_TR_EV_SEND_DATA,
                           SMS_TR_ST_WAIT_ACK, fsm_exec_nothing,
                           "mo: idle -RP-DATA out, start TR1M-> wait-ack"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_RECV_ACK,
                           SMS_TR_ST_DELIVERED, fsm_exec_nothing,
                           "mo: wait-ack -RP-ACK-> delivered"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_RECV_ERROR,
                           SMS_TR_ST_FAILED, fsm_exec_nothing,
                           "mo: wait-ack -RP-ERROR-> failed"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_TIMER,
                           SMS_TR_ST_FAILED, fsm_exec_nothing,
                           "mo: wait-ack -TR1M expired-> failed"),
            /* §8.3.2: the relay layer sends one RP-DATA and waits. A
             * retransmission is the transport's business (over IMS, the SIP
             * transaction's), so a second SEND_DATA is not a legal move
             * here and says so rather than restarting the timer. */
            FSM_ADD_ALWAYS(fsm_state_any, SMS_TR_EV_ABORT, SMS_TR_ST_ABORTED,
                           fsm_exec_nothing, "mo: abort -> aborted"),
            0);
    return fsm;
}

fsm_t* sms_trans_fsm_mt(void) /* §8.3.3, TR2M */
{
    fsm_t* fsm = fsm_create(SMS_TR_ST_IDLE, SMS_TR_ST_ABORTED);
    if (!fsm) {
        return NULL;
    }
    fsm_set(fsm,
            FSM_ADD_ALWAYS(SMS_TR_ST_IDLE, SMS_TR_EV_RECV_DATA,
                           SMS_TR_ST_WAIT_ACK, fsm_exec_nothing,
                           "mt: idle -RP-DATA in, start TR2M-> wait-ack"),
            FSM_ADD_ALWAYS(SMS_TR_ST_IDLE, SMS_TR_EV_SEND_DATA,
                           SMS_TR_ST_WAIT_ACK, fsm_exec_nothing,
                           "mt: idle -RP-DATA out to the MS-> wait-ack"),
            /* A retransmitted RP-DATA is absorbed: the network may repeat it
             * while the receiver is still deciding, and answering it twice
             * is correct behaviour (§8.3.3). */
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_RECV_DATA,
                           SMS_TR_ST_WAIT_ACK, fsm_exec_nothing,
                           "mt: wait-ack -RP-DATA repeat-> wait-ack"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_SEND_ACK,
                           SMS_TR_ST_DELIVERED, fsm_exec_nothing,
                           "mt: wait-ack -RP-ACK out-> delivered"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_RECV_ACK,
                           SMS_TR_ST_DELIVERED, fsm_exec_nothing,
                           "mt: wait-ack -RP-ACK in-> delivered"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_SEND_ERROR,
                           SMS_TR_ST_FAILED, fsm_exec_nothing,
                           "mt: wait-ack -RP-ERROR out-> failed"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_RECV_ERROR,
                           SMS_TR_ST_FAILED, fsm_exec_nothing,
                           "mt: wait-ack -RP-ERROR in-> failed"),
            FSM_ADD_ALWAYS(SMS_TR_ST_WAIT_ACK, SMS_TR_EV_TIMER,
                           SMS_TR_ST_FAILED, fsm_exec_nothing,
                           "mt: wait-ack -TR2M expired-> failed"),
            FSM_ADD_ALWAYS(fsm_state_any, SMS_TR_EV_ABORT, SMS_TR_ST_ABORTED,
                           fsm_exec_nothing, "mt: abort -> aborted"),
            0);
    return fsm;
}

const char* sms_trans_state_name(fsm_state_id state)
{
    switch (state) {
    case SMS_TR_ST_IDLE:      return "idle";
    case SMS_TR_ST_WAIT_ACK:  return "wait-ack";
    case SMS_TR_ST_DELIVERED: return "delivered";
    case SMS_TR_ST_FAILED:    return "failed";
    case SMS_TR_ST_ABORTED:   return "aborted";
    default:                  return "?";
    }
}

const char* sms_trans_event_name(fsm_action_id event)
{
    switch (event) {
    case SMS_TR_EV_SEND_DATA:  return "send RP-DATA";
    case SMS_TR_EV_RECV_DATA:  return "recv RP-DATA";
    case SMS_TR_EV_SEND_ACK:   return "send RP-ACK";
    case SMS_TR_EV_RECV_ACK:   return "recv RP-ACK";
    case SMS_TR_EV_SEND_ERROR: return "send RP-ERROR";
    case SMS_TR_EV_RECV_ERROR: return "recv RP-ERROR";
    case SMS_TR_EV_TIMER:      return "timer";
    case SMS_TR_EV_ABORT:      return "abort";
    default:                   return "?";
    }
}
