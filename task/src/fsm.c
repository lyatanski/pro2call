#include <stdlib.h>

#include "fsm.h"
#include "mesg.h"

typedef struct {
    fsm_state_id  from;
    fsm_action_id action;
    fsm_cond      cond;
    fsm_state_id  to;
    fsm_exec      exec;
    const char*   desc;
} fsm_entry_t;

struct fsm {
    bool         debug;
    fsm_state_id current;
    fsm_state_id term;

    fsm_entry_t* entries;
    size_t       count;
    size_t       cap;

    fsm_onterminated_f callback_term;
    const void*        callback_data;
};

int fsm_exec_nothing(va_list* app)
{
    (void)app;
    return 0 /*success*/;
}

bool fsm_cond_always(const void* data1, const void* data2)
{
    (void)data1;
    (void)data2;
    return true;
}

fsm_t* fsm_create(fsm_state_id state_curr, fsm_state_id state_term)
{
    fsm_t* self = calloc(1, sizeof(*self));
    if (!self) {
        MESG_FAIL("fsm: %s", "out of memory");
        return NULL;
    }
    self->current = state_curr;
    self->term    = state_term;
    return self;
}

void fsm_destroy(fsm_t* self)
{
    if (self) {
        free(self->entries);
        free(self);
    }
}

static fsm_entry_t* fsm_entry_add(fsm_t* self)
{
    if (self->count == self->cap) {
        size_t       cap     = self->cap ? self->cap * 2 : 16;
        fsm_entry_t* entries = realloc(self->entries, cap * sizeof(*entries));
        if (!entries) {
            return NULL;
        }
        self->entries = entries;
        self->cap     = cap;
    }
    return &self->entries[self->count++];
}

int fsm_set(fsm_t* self, ...)
{
    va_list args;
    int     guard;
    int     ret = 0;

    if (!self) {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return FSM_E_INVAL;
    }

    va_start(args, self);
    while ((guard = va_arg(args, int)) == 1) {
        fsm_entry_t* entry;
        if ((entry = fsm_entry_add(self))) {
            entry->from   = va_arg(args, fsm_state_id);
            entry->action = va_arg(args, fsm_action_id);
            entry->cond   = va_arg(args, fsm_cond);
            entry->to     = va_arg(args, fsm_state_id);
            entry->exec   = va_arg(args, fsm_exec);
            entry->desc   = va_arg(args, const char*);
        } else {
            MESG_FAIL("fsm: %s", "out of memory");
            ret = FSM_E_NOMEM;
            break;
        }
    }
    va_end(args);

    return ret;
}

int fsm_set_callback_terminated(fsm_t* self, fsm_onterminated_f callback,
                                const void* callbackdata)
{
    if (self) {
        self->callback_term = callback;
        self->callback_data = callbackdata;
        return 0;
    } else {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return FSM_E_INVAL;
    }
}

void fsm_set_debug(fsm_t* self, bool on)
{
    if (self) {
        self->debug = on;
    }
}

int fsm_act(fsm_t* self, fsm_action_id action, const void* cond_data1,
            const void* cond_data2, ...)
{
    va_list ap;
    bool    found      = false;
    bool    terminates = false;
    int     ret_exec   = 0; /* success */
    size_t  i;

    if (!self) {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return FSM_E_INVAL;
    }
    if (fsm_terminated(self)) {
        MESG_WARN("fsm: %s", "already in the terminal state");
        return FSM_E_FINAL;
    }

    va_start(ap, cond_data2);
    for (i = 0; i < self->count; i++) {
        const fsm_entry_t* entry = &self->entries[i];

        if (((entry->from != fsm_state_any) &&
             (entry->from != fsm_state_current)) &&
            (entry->from != self->current)) {
            continue;
        }
        if ((entry->action != fsm_action_any) && (entry->action != action)) {
            continue;
        }
        if (!entry->cond(cond_data1, cond_data2)) {
            continue;
        }

        if (self->debug) {
            MESG_INFO("State machine: %s", entry->desc);
        }

        /* Stay put when the destination is the Any/Current sentinel. */
        if (entry->to != fsm_state_any && entry->to != fsm_state_current) {
            self->current = entry->to;
        }

        if (entry->exec && (ret_exec = entry->exec(&ap))) {
            MESG_INFO("State machine: exec failed (%d). Moving to the terminal "
                      "state.",
                      ret_exec);
        }

        terminates = (ret_exec || (self->current == self->term));
        found      = true;
        break;
    }
    va_end(ap);

    if (terminates) {
        self->current = self->term;
        if (self->callback_term) {
            self->callback_term(self->callback_data);
        }
    }
    if (!found) {
        MESG_DBUG("State machine: no entry for state %d, action %d.",
                  self->current, action);
        return FSM_E_NOMATCH;
    }

    return ret_exec;
}

fsm_state_id fsm_get_current_state(fsm_t* self)
{
    if (!self) {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return fsm_state_none;
    }
    return self->current;
}

int fsm_set_current_state(fsm_t* self, fsm_state_id new_state)
{
    if (!self) {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return FSM_E_INVAL;
    }
    self->current = new_state;
    return 0;
}

bool fsm_terminated(fsm_t* self)
{
    if (self) {
        return (self->current == self->term);
    } else {
        MESG_FAIL("fsm: %s", "invalid parameter");
        return true;
    }
}
