#include "sip_dialog.h"
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

spec ("sip_dialog") {
    context ("dialog (RFC 3261 §12)") {
        it ("walks init -> early -> confirmed -> terminated") {
            fsm_t*              m     = sip_dialog_fsm();
            const fsm_action_id evs[] = { SIP_DIALOG_EV_EARLY,
                                          SIP_DIALOG_EV_CONFIRM,
                                          SIP_DIALOG_EV_TERMINATE };
            check(fsm_get_current_state(m) == SIP_DIALOG_ST_INIT);
            check(walk(m, evs, 3));
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("forms directly on a 2xx with no provisional") {
            fsm_t* m = sip_dialog_fsm();
            check(fsm_act(m, SIP_DIALOG_EV_CONFIRM, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_DIALOG_ST_CONFIRMED);
            check(!fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("an early dialog dies on a non-2xx final") {
            fsm_t* m = sip_dialog_fsm();
            check(fsm_act(m, SIP_DIALOG_EV_EARLY, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_DIALOG_EV_EARLY, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_DIALOG_EV_TERMINATE, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("absorbs a 2xx retransmission while confirmed") {
            fsm_t* m = sip_dialog_fsm();
            check(fsm_act(m, SIP_DIALOG_EV_CONFIRM, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_DIALOG_EV_CONFIRM, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_DIALOG_ST_CONFIRMED);
            fsm_destroy(m);
        }
    }

    context ("registration usage (RFC 3261 §10, TS 24.229 §5.1)") {
        it ("REGISTER -> 401 -> auth -> 200 reaches Registered") {
            fsm_t*              m     = sip_reg_fsm();
            const fsm_action_id evs[] = { SIP_REG_EV_SEND, SIP_REG_EV_CHALLENGE,
                                          SIP_REG_EV_AUTH, SIP_REG_EV_OK };
            check(fsm_get_current_state(m) == SIP_REG_ST_IDLE);
            check(walk(m, evs, 4));
            check(fsm_get_current_state(m) == SIP_REG_ST_REGISTERED);
            check(!fsm_terminated(m)); /* Registered is a resting state */
            fsm_destroy(m);
        }

        it ("a registrar that does not challenge registers on the 200") {
            fsm_t* m = sip_reg_fsm();
            check(fsm_act(m, SIP_REG_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_REG_EV_OK, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_REG_ST_REGISTERED);
            fsm_destroy(m);
        }

        it ("refreshes and then de-registers cleanly to Done") {
            fsm_t*              m     = sip_reg_fsm();
            const fsm_action_id evs[] = {
                SIP_REG_EV_SEND,       SIP_REG_EV_OK, /* -> Registered      */
                SIP_REG_EV_REFRESH,    SIP_REG_EV_OK, /* -> Registered      */
                SIP_REG_EV_DEREGISTER, SIP_REG_EV_OK  /* -> Done            */
            };
            check(walk(m, evs, 6));
            check(fsm_get_current_state(m) == SIP_REG_ST_DONE);
            fsm_destroy(m);
        }

        it ("re-challenges a stale-nonce refresh, then registers again") {
            fsm_t*              m     = sip_reg_fsm();
            const fsm_action_id evs[] = {
                SIP_REG_EV_SEND,    SIP_REG_EV_OK, /* -> Registered      */
                SIP_REG_EV_REFRESH, SIP_REG_EV_CHALLENGE, /* stale nonce     */
                SIP_REG_EV_AUTH,    SIP_REG_EV_OK /* -> Registered      */
            };
            check(walk(m, evs, 6));
            check(fsm_get_current_state(m) == SIP_REG_ST_REGISTERED);
            fsm_destroy(m);
        }

        it ("a rejected challenge fails the registration") {
            fsm_t* m = sip_reg_fsm();
            check(fsm_act(m, SIP_REG_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_REG_EV_CHALLENGE, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_REG_EV_FAIL, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m)); /* Failed is the terminal state */
            fsm_destroy(m);
        }

        it ("rejects a refresh before the binding exists") {
            fsm_t* m = sip_reg_fsm();
            check(fsm_act(m, SIP_REG_EV_REFRESH, NULL, NULL) == FSM_E_NOMATCH);
            check(fsm_get_current_state(m) == SIP_REG_ST_IDLE);
            fsm_destroy(m);
        }
    }

    context ("digest authentication (RFC 3261 §22, RFC 2617/7616)") {
        it ("request -> 401 -> credentialed request -> 2xx authenticates") {
            fsm_t*              m     = sip_auth_fsm();
            const fsm_action_id evs[] = { SIP_AUTH_EV_SEND,
                                          SIP_AUTH_EV_CHALLENGE,
                                          SIP_AUTH_EV_SEND,
                                          SIP_AUTH_EV_SUCCESS };
            check(walk(m, evs, 4));
            check(fsm_get_current_state(m) == SIP_AUTH_ST_AUTHENTICATED);
            fsm_destroy(m);
        }

        it ("retries a stale nonce, then gives up at the cap") {
            fsm_t* m = sip_auth_fsm();
            check(fsm_act(m, SIP_AUTH_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_CHALLENGE, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_CHALLENGE, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_GIVE_UP, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }

        it ("an authenticated request may be re-sent (refresh)") {
            fsm_t* m = sip_auth_fsm();
            check(fsm_act(m, SIP_AUTH_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_SUCCESS, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_AUTH_ST_AUTHENTICATED);
            check(fsm_act(m, SIP_AUTH_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(m) == SIP_AUTH_ST_PENDING);
            fsm_destroy(m);
        }

        it ("a non-auth rejection fails immediately") {
            fsm_t* m = sip_auth_fsm();
            check(fsm_act(m, SIP_AUTH_EV_SEND, NULL, NULL) == FSM_OK);
            check(fsm_act(m, SIP_AUTH_EV_FAILURE, NULL, NULL) == FSM_OK);
            check(fsm_terminated(m));
            fsm_destroy(m);
        }
    }

    context ("common") {
        it ("maps states and events to names") {
            check(sip_dialog_state_name(SIP_DIALOG_ST_EARLY)[0] == 'E');
            check(sip_dialog_state_name(99)[0] == '?');
            check(sip_reg_state_name(SIP_REG_ST_REGISTERED)[0] == 'R');
            check(sip_reg_event_name(99)[0] == '?');
            check(sip_auth_state_name(SIP_AUTH_ST_AUTHENTICATED)[0] == 'A');
            check(sip_auth_event_name(99)[0] == '?');
        }
    }
}
