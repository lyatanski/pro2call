#ifndef NET_LOOP_H
#define NET_LOOP_H

#include "net.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* epoll-based non-blocking event loop: the central dispatcher every
 * transport socket (UDP, TCP or SCTP) registers its fd with.
 * Level-triggered; sockets must be non-blocking
 * (every net_sock is). Single-threaded by design: callbacks run inside
 * net_loop_step and may freely add/del fds and timers.
 *
 * Timers are a binary min-heap; dispatch does no allocation. */

enum {
    NET_RD = 1, /* readable  — data ready to recv */
    NET_WR = 2, /* writable  — can send without blocking */
    NET_ER = 4, /* error/hangup, always reported */
};

typedef struct net_loop net_loop;
typedef void (*net_io_f)(void* ud, int fd, unsigned ev);
typedef void (*net_tmr_f)(void* ud);
typedef void (*net_pre_f)(void* ud);

API_EXPORT net_loop* net_loop_new(void);
API_EXPORT void      net_loop_free(net_loop*);

API_EXPORT int net_loop_add(net_loop*, int fd, unsigned ev, net_io_f cb,
                            void* ud);
API_EXPORT int net_loop_mod(net_loop*, int fd, unsigned ev);
API_EXPORT int net_loop_del(net_loop*, int fd);

/* Pre-poll hooks, run in registration order at the very top of every
 * net_loop_step — before the timeout is computed and before epoll_wait, so
 * a hook may queue work, arm a timer or change an fd's interest and have it
 * take effect in the same iteration. This is where output buffered during
 * the previous iteration is flushed (see net_txq), so a whole iteration's
 * datagrams leave in one batched syscall and nothing sits in a queue while
 * epoll_wait blocks. Identified by the (cb, ud) pair; adding the same pair
 * twice is a no-op.
 *
 * Both are safe to call from inside a hook — a hook that has no more work
 * drops itself, so the cost of the mechanism is the number of hooks with
 * something to do, not the number that could have. A hook added during
 * dispatch may run in the same iteration. */
API_EXPORT int net_loop_pre_add(net_loop*, net_pre_f cb, void* ud);
API_EXPORT int net_loop_pre_del(net_loop*, net_pre_f cb, void* ud);

/* One poll iteration: runs the pre-poll hooks, waits at most timeout_ms
 * (-1 = until next timer or event), fires due timers, dispatches ready fds.
 * Returns number of fd events dispatched or NET_ERR. */
API_EXPORT int  net_loop_step(net_loop*, int timeout_ms);
API_EXPORT int  net_loop_run(net_loop*); /* step until net_loop_stop */
API_EXPORT void net_loop_stop(net_loop*);

/* One-shot timer; returns id (never 0) or 0 on error. */
API_EXPORT uint64_t net_loop_after(net_loop*, uint64_t ms, net_tmr_f cb,
                                   void* ud);
API_EXPORT int      net_loop_cancel(net_loop*, uint64_t id);

API_EXPORT uint64_t net_now_ms(void); /* CLOCK_MONOTONIC */

#ifdef __cplusplus
}
#endif

#endif /* NET_LOOP_H */
