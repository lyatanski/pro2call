#ifndef NET_TXQ_H
#define NET_TXQ_H

#include "net.h"
#include "net_loop.h"
#include "net_sock.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Loop-driven transmit queue: a datagram socket's send side moved onto the
 * net_loop dispatcher.
 *
 * net_txq_send() copies the datagram into the queue and returns — no
 * syscall on the caller's path, so code that fires many messages from one
 * callback (a load generator attaching N subscribers, a server answering a
 * burst) never stops to enter the kernel between them. The loop drains the
 * queue from a pre-poll hook at the top of net_loop_step, pushing up to
 * NET_TXQ_BATCH datagrams per sendmmsg(2): everything queued during one
 * iteration leaves in ceil(n/NET_TXQ_BATCH) syscalls instead of n. Because
 * the hook runs before epoll_wait, nothing waits in the queue while the
 * loop sleeps; because it is registered only while the queue has something
 * in it, a process holding thousands of sockets pays for the ones with
 * output pending, not for the ones that exist.
 *
 * The queue also absorbs kernel back-pressure. An inline sendto() that hits
 * a full socket buffer or qdisc (EAGAIN/ENOBUFS) can only fail, and under
 * burst that failure is indistinguishable from a real error; here the
 * datagram stays queued, the socket's NET_WR interest is armed, and the
 * flush resumes when the buffer drains. Only a genuinely undeliverable
 * datagram (EMSGSIZE, ECONNREFUSED, ...) is dropped, and counted.
 *
 * Single-threaded, like the loop. The queue borrows the loop and the
 * socket; both must outlive it, or net_txq_detach() must be called first
 * (a garbage collector may tear the loop down before its dependents).
 * Datagram sockets only — a stream's partial writes need byte-level, not
 * message-level, accounting.
 */

#define NET_TXQ_BATCH 64 /* datagrams per sendmmsg() call */

typedef struct net_txq net_txq;

/* Create a queue for `s` on `l`. base_ev is the fd's steady-state loop
 * interest (typically NET_RD) — the queue adds NET_WR to it while it has a
 * backlog and restores it once drained, so it composes with the caller's
 * own net_loop_add for the same fd. max_bytes caps the queued payload
 * (0 = NET_TXQ_MAX_BYTES); a send over the cap is refused rather than
 * letting a producer that outruns the wire grow the queue without bound.
 * Returns NULL on allocation failure. */
#define NET_TXQ_MAX_BYTES (8u * 1024u * 1024u)

API_EXPORT net_txq* net_txq_new(net_loop* l, net_sock* s, unsigned base_ev,
                                size_t max_bytes);

/* Stop using the loop without freeing (the loop was destroyed first). */
API_EXPORT void net_txq_detach(net_txq*);
API_EXPORT void net_txq_free(net_txq*);

/* Queue one datagram; `to` NULL sends to the connected peer. Returns NET_OK,
 * or NET_ERR when the queue is at its byte cap (nothing is queued and the
 * drop is counted). */
API_EXPORT int net_txq_send(net_txq*, const void* buf, size_t len,
                            const net_addr* to);

/* Push what is queued now, in NET_TXQ_BATCH-sized sendmmsg() calls, until
 * the queue is empty or the kernel pushes back. Returns the number of
 * datagrams sent. Called for you by the loop; call it directly to force
 * output out without running the loop (e.g. before closing). */
API_EXPORT int net_txq_flush(net_txq*);

API_EXPORT size_t net_txq_pending(const net_txq*); /* datagrams queued */
API_EXPORT size_t net_txq_bytes(const net_txq*);   /* payload queued    */

/* Counters over the queue's life: datagrams handed to the kernel, sendmmsg
 * calls made (sent/calls is the batching ratio), datagrams the kernel
 * refused for good, and how often it pushed back. */
API_EXPORT uint64_t net_txq_sent(const net_txq*);
API_EXPORT uint64_t net_txq_calls(const net_txq*);
API_EXPORT uint64_t net_txq_dropped(const net_txq*);
API_EXPORT uint64_t net_txq_blocked(const net_txq*);

#ifdef __cplusplus
}
#endif

#endif /* NET_TXQ_H */
