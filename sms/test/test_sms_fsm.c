#include <string.h>

#include "sms_fsm.h"
#include "test.h"

/* TS 24.011 §8.3 short message transfer transactions. Same shape as
 * test_sip_fsm.c: drive the table and read the state. */

static int state(fsm_t* f)
{
    return fsm_get_current_state(f);
}

static int act(fsm_t* f, sms_trans_event_t ev)
{
    return fsm_act(f, ev, NULL, NULL);
}

spec ("sms fsm") {
    context ("MO transfer (TR1M)") {
        it ("reaches delivered on an RP-ACK") {
            fsm_t* f = sms_trans_fsm_mo();
            check(f != NULL);
            check(state(f) == SMS_TR_ST_IDLE);
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(state(f) == SMS_TR_ST_WAIT_ACK);
            check(act(f, SMS_TR_EV_RECV_ACK) == FSM_OK);
            check(state(f) == SMS_TR_ST_DELIVERED);
            check(!fsm_terminated(f));
            fsm_destroy(f);
        }

        it ("fails on an RP-ERROR") {
            fsm_t* f = sms_trans_fsm_mo();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_RECV_ERROR) == FSM_OK);
            check(state(f) == SMS_TR_ST_FAILED);
            fsm_destroy(f);
        }

        it ("fails when TR1M expires") {
            fsm_t* f = sms_trans_fsm_mo();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_TIMER) == FSM_OK);
            check(state(f) == SMS_TR_ST_FAILED);
            fsm_destroy(f);
        }

        it ("has no legal move for a repeated submit") {
            /* §8.3.2 sends one RP-DATA and waits; retransmission is the
             * transport's business, so a second one is a caller bug and
             * must not silently restart the transaction. */
            fsm_t* f = sms_trans_fsm_mo();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_E_NOMATCH);
            check(state(f) == SMS_TR_ST_WAIT_ACK); /* state untouched */
            fsm_destroy(f);
        }

        it ("ignores a report that arrives before anything was sent") {
            fsm_t* f = sms_trans_fsm_mo();
            check(act(f, SMS_TR_EV_RECV_ACK) == FSM_E_NOMATCH);
            check(state(f) == SMS_TR_ST_IDLE);
            fsm_destroy(f);
        }

        it ("aborts from any state and then refuses everything") {
            fsm_t* f = sms_trans_fsm_mo();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_ABORT) == FSM_OK);
            check(state(f) == SMS_TR_ST_ABORTED);
            check(fsm_terminated(f));
            check(act(f, SMS_TR_EV_RECV_ACK) == FSM_E_FINAL);
            fsm_destroy(f);
        }
    }

    context ("MT transfer (TR2M)") {
        it ("reaches delivered when the receiver acknowledges") {
            fsm_t* f = sms_trans_fsm_mt();
            check(f != NULL);
            check(act(f, SMS_TR_EV_RECV_DATA) == FSM_OK);
            check(state(f) == SMS_TR_ST_WAIT_ACK);
            check(act(f, SMS_TR_EV_SEND_ACK) == FSM_OK);
            check(state(f) == SMS_TR_ST_DELIVERED);
            fsm_destroy(f);
        }

        it ("also drives the delivering side") {
            /* An IP-SM-GW sends the RP-DATA towards the UE and waits for
             * the UE's RP-ACK — the same machine, the other events. */
            fsm_t* f = sms_trans_fsm_mt();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(state(f) == SMS_TR_ST_WAIT_ACK);
            check(act(f, SMS_TR_EV_RECV_ACK) == FSM_OK);
            check(state(f) == SMS_TR_ST_DELIVERED);
            fsm_destroy(f);
        }

        it ("absorbs a repeated RP-DATA") {
            fsm_t* f = sms_trans_fsm_mt();
            check(act(f, SMS_TR_EV_RECV_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_RECV_DATA) == FSM_OK);
            check(state(f) == SMS_TR_ST_WAIT_ACK);
            fsm_destroy(f);
        }

        it ("fails on an error or a TR2M expiry") {
            fsm_t* f = sms_trans_fsm_mt();
            check(act(f, SMS_TR_EV_RECV_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_SEND_ERROR) == FSM_OK);
            check(state(f) == SMS_TR_ST_FAILED);
            fsm_destroy(f);

            f = sms_trans_fsm_mt();
            check(act(f, SMS_TR_EV_SEND_DATA) == FSM_OK);
            check(act(f, SMS_TR_EV_TIMER) == FSM_OK);
            check(state(f) == SMS_TR_ST_FAILED);
            fsm_destroy(f);
        }
    }

    context ("names and timers") {
        it ("names every state and event") {
            check(strcmp(sms_trans_state_name(SMS_TR_ST_IDLE), "idle") == 0);
            check(strcmp(sms_trans_state_name(SMS_TR_ST_WAIT_ACK),
                         "wait-ack") == 0);
            check(strcmp(sms_trans_state_name(SMS_TR_ST_DELIVERED),
                         "delivered") == 0);
            check(strcmp(sms_trans_state_name(999), "?") == 0);
            check(strcmp(sms_trans_event_name(SMS_TR_EV_SEND_DATA),
                         "send RP-DATA") == 0);
            check(strcmp(sms_trans_event_name(999), "?") == 0);
        }

        it ("keeps the timers inside the spec's ranges") {
            /* TS 24.011 table 8.4: TR1M 35..45 s, TR2M 15..25 s. */
            check(SMS_TR1M_MS >= 35000 && SMS_TR1M_MS <= 45000);
            check(SMS_TR2M_MS >= 15000 && SMS_TR2M_MS <= 25000);
        }
    }
}
