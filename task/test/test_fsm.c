#include "fsm.h"
#include "test.h"
#include <string.h>

/* A toy door: CLOSED -open-> OPEN -close-> CLOSED -lock-> LOCKED. */
enum { ST_CLOSED, ST_OPEN, ST_LOCKED, ST_BROKEN /* terminal */ };
enum { EV_OPEN, EV_CLOSE, EV_LOCK, EV_KICK };

static bool cond_has_key(const void* d1, const void* d2)
{
    (void)d2;
    return d1 && strcmp((const char*)d1, "key") == 0;
}

static int exec_count(va_list* app)
{
    int* counter = va_arg(*app, int*);
    if (counter) ++*counter;
    return 0;
}

static int exec_fail(va_list* app)
{
    (void)app;
    return -42;
}

static int term_count;
static int on_terminated(const void* data)
{
    (void)data;
    ++term_count;
    return 0;
}

static fsm_t* door(void)
{
    fsm_t* fsm = fsm_create(ST_CLOSED, ST_BROKEN);
    fsm_set(fsm,
            FSM_ADD(ST_CLOSED, EV_LOCK, cond_has_key, ST_LOCKED,
                    fsm_exec_nothing, "closed -lock(key)-> locked"),
            FSM_ADD_ALWAYS(ST_CLOSED, EV_OPEN, ST_OPEN, exec_count,
                           "closed -open-> open"),
            FSM_ADD_ALWAYS(ST_OPEN, EV_CLOSE, ST_CLOSED, fsm_exec_nothing,
                           "open -close-> closed"),
            FSM_ADD_ALWAYS(ST_OPEN, EV_KICK, ST_BROKEN, fsm_exec_nothing,
                           "open -kick-> broken"),
            FSM_ADD(ST_LOCKED, EV_KICK, fsm_cond_always, ST_LOCKED, exec_fail,
                    "locked -kick-> still locked, alarm"),
            0);
    return fsm;
}

spec ("fsm") {
    context ("transitions") {
        it ("starts in the initial state") {
            fsm_t* fsm = door();
            check(fsm_get_current_state(fsm) == ST_CLOSED);
            check(!fsm_terminated(fsm));
            fsm_destroy(fsm);
        }

        it ("follows matching entries") {
            fsm_t* fsm = door();
            check(fsm_act(fsm, EV_OPEN, NULL, NULL, (int*)NULL) == FSM_OK);
            check(fsm_get_current_state(fsm) == ST_OPEN);
            check(fsm_act(fsm, EV_CLOSE, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(fsm) == ST_CLOSED);
            fsm_destroy(fsm);
        }

        it ("rejects an action with no entry") {
            fsm_t* fsm = door();
            check(fsm_act(fsm, EV_CLOSE, NULL, NULL) == FSM_E_NOMATCH);
            check(fsm_get_current_state(fsm) == ST_CLOSED);
            fsm_destroy(fsm);
        }

        it ("guards entries with conditions") {
            fsm_t* fsm = door();
            check(fsm_act(fsm, EV_LOCK, "crowbar", NULL) == FSM_E_NOMATCH);
            check(fsm_get_current_state(fsm) == ST_CLOSED);
            check(fsm_act(fsm, EV_LOCK, "key", NULL) == FSM_OK);
            check(fsm_get_current_state(fsm) == ST_LOCKED);
            fsm_destroy(fsm);
        }

        it ("passes fsm_act extra arguments to the exec hook") {
            fsm_t* fsm     = door();
            int    counter = 0;
            check(fsm_act(fsm, EV_OPEN, NULL, NULL, &counter) == FSM_OK);
            check(counter == 1);
            fsm_destroy(fsm);
        }
    }

    context ("termination") {
        it ("reaching the terminal state fires the callback and closes the "
            "machine") {
            fsm_t* fsm = door();
            term_count = 0;
            fsm_set_callback_terminated(fsm, on_terminated, NULL);
            check(fsm_act(fsm, EV_OPEN, NULL, NULL, (int*)NULL) == FSM_OK);
            check(fsm_act(fsm, EV_KICK, NULL, NULL) == FSM_OK);
            check(term_count == 1);
            check(fsm_terminated(fsm));
            check(fsm_act(fsm, EV_OPEN, NULL, NULL) == FSM_E_FINAL);
            fsm_destroy(fsm);
        }

        it ("a failing exec hook terminates the machine") {
            fsm_t* fsm = door();
            term_count = 0;
            fsm_set_callback_terminated(fsm, on_terminated, NULL);
            check(fsm_act(fsm, EV_LOCK, "key", NULL) == FSM_OK);
            check(fsm_act(fsm, EV_KICK, NULL, NULL) == -42);
            check(term_count == 1);
            check(fsm_terminated(fsm));
            fsm_destroy(fsm);
        }
    }

    context ("wildcards and overrides") {
        it ("fsm_state_any matches every state; entry order decides") {
            fsm_t* fsm = fsm_create(ST_CLOSED, ST_BROKEN);
            fsm_set(fsm,
                    FSM_ADD_ALWAYS(ST_CLOSED, EV_OPEN, ST_OPEN,
                                   fsm_exec_nothing, "specific first"),
                    FSM_ADD_ALWAYS(fsm_state_any, fsm_action_any, ST_BROKEN,
                                   fsm_exec_nothing, "wildcard catch-all"),
                    0);
            check(fsm_act(fsm, EV_OPEN, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(fsm) == ST_OPEN);
            check(fsm_act(fsm, EV_LOCK, NULL, NULL) == FSM_OK);
            check(fsm_terminated(fsm));
            fsm_destroy(fsm);
        }

        it ("fsm_state_current as destination stays put") {
            fsm_t* fsm = fsm_create(ST_CLOSED, ST_BROKEN);
            fsm_set(fsm,
                    FSM_ADD_ALWAYS(fsm_state_any, EV_KICK, fsm_state_current,
                                   fsm_exec_nothing, "absorb"),
                    0);
            check(fsm_act(fsm, EV_KICK, NULL, NULL) == FSM_OK);
            check(fsm_get_current_state(fsm) == ST_CLOSED);
            fsm_destroy(fsm);
        }

        it ("fsm_set_current_state overrides the state") {
            fsm_t* fsm = door();
            check(fsm_set_current_state(fsm, ST_OPEN) == 0);
            check(fsm_get_current_state(fsm) == ST_OPEN);
            fsm_destroy(fsm);
        }
    }

    context ("argument checking") {
        it ("NULL self fails cleanly") {
            check(fsm_act(NULL, EV_OPEN, NULL, NULL) == FSM_E_INVAL);
            check(fsm_get_current_state(NULL) == fsm_state_none);
            check(fsm_set_current_state(NULL, ST_OPEN) == FSM_E_INVAL);
            check(fsm_set(NULL, 0) == FSM_E_INVAL);
            check(fsm_set_callback_terminated(NULL, NULL, NULL) == FSM_E_INVAL);
            check(fsm_terminated(NULL));
            fsm_destroy(NULL); /* no-op, must not crash */
        }
    }
}
