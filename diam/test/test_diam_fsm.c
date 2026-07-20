#include "diam_fsm.h"
#include "test.h"

spec ("diam_fsm") {
    context ("client session (RFC 6733 §8.1)") {
        it ("walks the happy path: idle -> pending -> open -> discon -> "
            "closed") {
            fsm_t* m = diam_sess_fsm_client();
            check(fsm_get_current_state(m) == DIAM_SESS_ST_IDLE);
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_PENDING);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_OPEN);
            check(fsm_act(m, DIAM_SESS_EV_SEND_STR, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_DISCON);
            check(fsm_act(m, DIAM_SESS_EV_RECV_STA, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_CLOSED);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("closes on a failed authorization answer") {
            fsm_t* m = diam_sess_fsm_client();
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_FAIL, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("stays open across re-authorization") {
            fsm_t* m = diam_sess_fsm_client();
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_REAUTH, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_OPEN);
            fsm_destroy(m);
        }

        it ("goes to discon on an abort and closes on the STA") {
            fsm_t* m = diam_sess_fsm_client();
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ABORT, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_DISCON);
            check(fsm_act(m, DIAM_SESS_EV_RECV_STA, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("rejects illegal moves and leaves the state alone") {
            fsm_t* m = diam_sess_fsm_client();
            check(fsm_act(m, DIAM_SESS_EV_RECV_STA, NULL, NULL) ==
                  FSM_E_NOMATCH);
            check(fsm_act(m, DIAM_SESS_EV_RECV_REQUEST, NULL, NULL) ==
                  FSM_E_NOMATCH);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_IDLE);
            fsm_destroy(m);
        }

        it ("times out from every non-terminal in-session state") {
            const fsm_action_id to_pending[] = { DIAM_SESS_EV_SEND_REQUEST };
            const fsm_action_id to_open[]    = { DIAM_SESS_EV_SEND_REQUEST,
                                                 DIAM_SESS_EV_ANSWER_OK };
            const fsm_action_id to_discon[]  = { DIAM_SESS_EV_SEND_REQUEST,
                                                 DIAM_SESS_EV_ANSWER_OK,
                                                 DIAM_SESS_EV_SEND_STR };
            const struct {
                const fsm_action_id* path;
                int                  len;
            } routes[] = { { to_pending, 1 },
                           { to_open, 2 },
                           { to_discon, 3 } };
            for (unsigned r = 0; r < sizeof routes / sizeof routes[0]; r++) {
                fsm_t* m = diam_sess_fsm_client();
                for (int s = 0; s < routes[r].len; s++) {
                    check(fsm_act(m, routes[r].path[s], NULL, NULL) == FSM_OK);
                }
                check(fsm_act(m, DIAM_SESS_EV_TIMEOUT, NULL, NULL) == FSM_OK);
                check(fsm_terminated(m));
                fsm_destroy(m);
            }
        }
    }

    context ("server session (RFC 6733 §8.1)") {
        it ("walks the happy path: idle -> pending -> open -> closed on STR") {
            fsm_t* m = diam_sess_fsm_server();
            check(fsm_act(m, DIAM_SESS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_PENDING);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_OPEN);
            check(fsm_act(m, DIAM_SESS_EV_RECV_STR, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("aborts: ASR out -> discon, STR back -> closed") {
            fsm_t* m = diam_sess_fsm_server();
            check(fsm_act(m, DIAM_SESS_EV_RECV_REQUEST, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ANSWER_OK, NULL, NULL) == FSM_OK);
            check(fsm_act(m, DIAM_SESS_EV_ABORT, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_DISCON);
            check(fsm_act(m, DIAM_SESS_EV_RECV_STR, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("rejects client-side events") {
            fsm_t* m = diam_sess_fsm_server();
            check(fsm_act(m, DIAM_SESS_EV_SEND_REQUEST, NULL, NULL) ==
                  FSM_E_NOMATCH);
            check(fsm_get_current_state(m) == DIAM_SESS_ST_IDLE);
            fsm_destroy(m);
        }
    }

    context ("names") {
        it ("maps states and events to names") {
            check(diam_sess_state_name(DIAM_SESS_ST_IDLE)[0] == 'I');
            check(diam_sess_state_name(DIAM_SESS_ST_CLOSED)[0] == 'C');
            check(diam_sess_state_name(99)[0] == '?');
            check(diam_sess_event_name(DIAM_SESS_EV_TIMEOUT)[0] == 't');
            check(diam_sess_event_name(99)[0] == '?');
        }
    }
}
