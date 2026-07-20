#include "sip_fsm.h"
#include "test.h"

/* Feed a sequence of events, checking each is accepted. */
static int walk(fsm_t* m, const fsm_action_id* evs, int n)
{
    for (int i = 0; i < n; i++) {
        if (fsm_act(m, evs[i], NULL, NULL) != FSM_OK) {
            return 0;
        }
    }
    return 1;
}

spec ("sip_fsm") {
    context ("INVITE client transaction (RFC 3261 §17.1.1)") {
        it ("answers a 2xx from calling by terminating (TU owns the ACK)") {
            fsm_t*              m     = sip_trans_fsm_invite_client();
            const fsm_action_id evs[] = { SIP_TRANS_EV_SEND_REQUEST,
                                          SIP_TRANS_EV_RECV_1XX,
                                          SIP_TRANS_EV_RECV_2XX };
            check(fsm_get_current_state(m) == SIP_TRANS_ST_INIT);
            check(walk(m, evs, 3));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("completes on a final error and waits out timer D") {
            fsm_t*              m     = sip_trans_fsm_invite_client();
            const fsm_action_id evs[] = {
                SIP_TRANS_EV_SEND_REQUEST, SIP_TRANS_EV_RECV_3XX_6XX,
                SIP_TRANS_EV_RECV_3XX_6XX, /* retransmission */
                SIP_TRANS_EV_TIMER_TERMINATE
            };
            check(walk(m, evs, 4));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("retransmits on timer A and gives up on timer B") {
            fsm_t* m = sip_trans_fsm_invite_client();
            check(fsm_act(m, SIP_TRANS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_TIMER_RETRANSMIT, NULL, NULL) ==
                  FSM_OK);
            check(fsm_get_current_state(m) == SIP_TRANS_ST_CALLING);
            check(fsm_act(m, SIP_TRANS_EV_TIMER_TIMEOUT, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("rejects a response before the request went out") {
            fsm_t* m = sip_trans_fsm_invite_client();
            check(fsm_act(m, SIP_TRANS_EV_RECV_1XX, NULL, NULL) ==
                  FSM_E_NOMATCH);
            check(fsm_get_current_state(m) == SIP_TRANS_ST_INIT);
            fsm_destroy(m);
        }
    }

    context ("INVITE server transaction (RFC 3261 §17.2.1)") {
        it ("walks proceeding -> completed -> confirmed -> terminated") {
            fsm_t*              m     = sip_trans_fsm_invite_server();
            const fsm_action_id evs[] = { SIP_TRANS_EV_RECV_REQUEST,
                                          SIP_TRANS_EV_SEND_1XX,
                                          SIP_TRANS_EV_SEND_3XX_6XX,
                                          SIP_TRANS_EV_RECV_ACK,
                                          SIP_TRANS_EV_TIMER_TERMINATE };
            check(walk(m, evs, 5));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("a 2xx hands retransmission to the TU: transaction terminates") {
            fsm_t*              m     = sip_trans_fsm_invite_server();
            const fsm_action_id evs[] = { SIP_TRANS_EV_RECV_REQUEST,
                                          SIP_TRANS_EV_SEND_1XX,
                                          SIP_TRANS_EV_SEND_2XX };
            check(walk(m, evs, 3));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("absorbs INVITE retransmissions while proceeding") {
            fsm_t* m = sip_trans_fsm_invite_server();
            check(fsm_act(m, SIP_TRANS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_TRANS_ST_PROCEEDING);
            fsm_destroy(m);
        }

        it ("terminates on timer H when no ACK arrives") {
            fsm_t*              m     = sip_trans_fsm_invite_server();
            const fsm_action_id evs[] = { SIP_TRANS_EV_RECV_REQUEST,
                                          SIP_TRANS_EV_SEND_3XX_6XX,
                                          SIP_TRANS_EV_TIMER_RETRANSMIT,
                                          SIP_TRANS_EV_TIMER_TIMEOUT };
            check(walk(m, evs, 4));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }
    }

    context ("non-INVITE client transaction (RFC 3261 §17.1.2)") {
        it ("walks trying -> proceeding -> completed -> terminated") {
            fsm_t*              m     = sip_trans_fsm_client();
            const fsm_action_id evs[] = { SIP_TRANS_EV_SEND_REQUEST,
                                          SIP_TRANS_EV_RECV_1XX,
                                          SIP_TRANS_EV_RECV_2XX,
                                          SIP_TRANS_EV_TIMER_TERMINATE };
            check(walk(m, evs, 4));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("finals from trying go to completed, not terminated") {
            fsm_t* m = sip_trans_fsm_client();
            check(fsm_act(m, SIP_TRANS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_RECV_2XX, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_TRANS_ST_COMPLETED);
            check(!fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("gives up on timer F") {
            fsm_t* m = sip_trans_fsm_client();
            check(fsm_act(m, SIP_TRANS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_TIMER_TIMEOUT, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }
    }

    context ("non-INVITE server transaction (RFC 3261 §17.2.2)") {
        it ("walks trying -> proceeding -> completed -> terminated") {
            fsm_t*              m     = sip_trans_fsm_server();
            const fsm_action_id evs[] = {
                SIP_TRANS_EV_RECV_REQUEST, SIP_TRANS_EV_SEND_1XX,
                SIP_TRANS_EV_SEND_2XX,
                SIP_TRANS_EV_RECV_REQUEST, /* retransmission */
                SIP_TRANS_EV_TIMER_TERMINATE
            };
            check(walk(m, evs, 5));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("can answer straight from trying") {
            fsm_t* m = sip_trans_fsm_server();
            check(fsm_act(m, SIP_TRANS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_SEND_2XX, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_TRANS_ST_COMPLETED);
            fsm_destroy(m);
        }

        it ("rejects an ACK (that is the INVITE server's event)") {
            fsm_t* m = sip_trans_fsm_server();
            check(fsm_act(m, SIP_TRANS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_TRANS_EV_RECV_ACK, NULL, NULL) ==
                  FSM_E_NOMATCH);
            fsm_destroy(m);
        }
    }

    context ("common") {
        it ("every machine terminates on a transport error") {
            fsm_t* (*make[])(void)      = { sip_trans_fsm_invite_client,
                                            sip_trans_fsm_invite_server,
                                            sip_trans_fsm_client,
                                            sip_trans_fsm_server };
            const fsm_action_id start[] = { SIP_TRANS_EV_SEND_REQUEST,
                                            SIP_TRANS_EV_RECV_REQUEST,
                                            SIP_TRANS_EV_SEND_REQUEST,
                                            SIP_TRANS_EV_RECV_REQUEST };
            for (unsigned k = 0; k < sizeof make / sizeof make[0]; k++) {
                fsm_t* m = make[k]();
                check(fsm_act(m, start[k], NULL, NULL) == FSM_OK);
                check(fsm_act(m, SIP_TRANS_EV_TRANSPORT_ERR, NULL, NULL) ==
                      FSM_OK);
                check(fsm_terminated(m));
                fsm_destroy(m);
            }
        }

        it ("maps states and events to names") {
            check(sip_trans_state_name(SIP_TRANS_ST_CALLING)[0] == 'C');
            check(sip_trans_state_name(99)[0] == '?');
            check(sip_trans_event_name(SIP_TRANS_EV_RECV_ACK)[0] == 'A');
            check(sip_trans_event_name(99)[0] == '?');
        }
    }
}
