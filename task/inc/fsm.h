#ifndef FSM_H_
#define FSM_H_

#include <stdarg.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Table-driven finite-state machine.
 *
 * A machine is a list of transition entries, each
 *
 *   (from-state, action, condition) -> (to-state, exec)
 *
 * built once with fsm_set() and the FSM_ADD* macros, then driven by
 * feeding actions to fsm_act(). The first entry that matches the
 * current state, the action and whose condition returns true fires:
 * the machine moves to the entry's to-state and runs its exec hook.
 * Entries match in the order they were added, so put specific rules
 * before wildcard (fsm_state_any / fsm_action_any) ones.
 *
 * exec hooks receive a va_list* over the extra arguments of the
 * fsm_act() call, so one table serves any number of machine instances
 * carrying per-call context. A non-zero exec return sends the machine
 * to its terminal state.
 *
 * Reaching the terminal state — by transition or by exec failure —
 * fires the on-terminated callback; after that every fsm_act() fails
 * with FSM_E_FINAL.
 *
 * State and action ids are small non-negative integers chosen by the
 * user (protocol modules define enums); negative values are reserved
 * for the sentinels below. Like the codecs, a machine is confined to
 * one thread (the event loop).
 */

#define fsm_state_any     -0xFFFF /* entry: matches every state      */
#define fsm_state_current -0xFFF0 /* entry to-state: do not move     */
#define fsm_state_none    -0xFF00 /* no valid state (error returns)  */
#define fsm_state_final   -0xF000 /* default terminal state id       */

#define fsm_action_any -0xFFFF /* entry: matches every action     */

enum {
    FSM_OK        = 0,
    FSM_E_INVAL   = -1, /* invalid argument                          */
    FSM_E_FINAL   = -2, /* the machine is in its terminal state      */
    FSM_E_NOMATCH = -3, /* no entry for (state, action, condition)   */
    FSM_E_NOMEM   = -4  /* allocation failure                        */
};

typedef int fsm_state_id;
typedef int fsm_action_id;

/* Transition guard over the two cond pointers of fsm_act(). */
typedef bool (*fsm_cond)(const void*, const void*);

/* Transition hook over the extra arguments of fsm_act(); non-zero
 * return terminates the machine and becomes fsm_act()'s return. */
typedef int (*fsm_exec)(va_list* app);

typedef int (*fsm_onterminated_f)(const void*);

/* Transition entries for fsm_set(); terminate the list with 0:
 *
 *   fsm_set(fsm,
 *       FSM_ADD(ST_IDLE, EV_OPEN, cond_ok, ST_OPEN, exec_open, "open"),
 *       FSM_ADD_ALWAYS_NOTHING(ST_OPEN, "ignore anything else"),
 *       0);
 */
#define FSM_ADD(from, action, cond, to, exec, desc)                     \
    1, (fsm_state_id)(from), (fsm_action_id)(action), (fsm_cond)(cond), \
        (fsm_state_id)(to), (fsm_exec)(exec), (const char*)(desc)
#define FSM_ADD_ALWAYS(from, action, to, exec, desc) \
    FSM_ADD(from, action, fsm_cond_always, to, exec, desc)
#define FSM_ADD_NOTHING(from, action, cond, desc) \
    FSM_ADD(from, action, cond, from, fsm_exec_nothing, desc)
#define FSM_ADD_ALWAYS_NOTHING(from, desc) \
    FSM_ADD(from, fsm_action_any, fsm_cond_always, from, fsm_exec_nothing, desc)

typedef struct fsm fsm_t;

API_EXPORT fsm_t* fsm_create(fsm_state_id state_curr, fsm_state_id state_term);
API_EXPORT void   fsm_destroy(fsm_t* self);

/* Stock entry pieces for the FSM_ADD* shorthands. */
API_EXPORT int  fsm_exec_nothing(va_list* app);
API_EXPORT bool fsm_cond_always(const void*, const void*);

API_EXPORT int fsm_set(fsm_t* self, ...);
API_EXPORT int fsm_set_callback_terminated(fsm_t*             self,
                                           fsm_onterminated_f callback,
                                           const void*        callbackdata);

/* Log every transition through MESG_INFO (the entry desc strings). */
API_EXPORT void fsm_set_debug(fsm_t* self, bool on);

/* Feed one action. cond_data1/2 go to the entries' condition guards;
 * anything after is handed to the fired entry's exec hook as a
 * va_list*. Returns the exec result (0 for success) or a negative
 * FSM_E_* when nothing fired. */
API_EXPORT int fsm_act(fsm_t* self, fsm_action_id action,
                       const void* cond_data1, const void* cond_data2, ...);

API_EXPORT fsm_state_id fsm_get_current_state(fsm_t* self);
API_EXPORT int  fsm_set_current_state(fsm_t* self, fsm_state_id new_state);
API_EXPORT bool fsm_terminated(fsm_t* self);

#ifdef __cplusplus
}
#endif

#endif /* FSM_H_ */
