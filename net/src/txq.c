#define _GNU_SOURCE
#include "net_txq.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* One queued datagram. The buffer is owned and reused: slots are recycled
 * as the ring turns, so a steady stream of same-sized messages settles into
 * zero allocation per send. */
struct txmsg {
    net_addr to;
    int      has_to;
    char*    buf;
    size_t   cap, len;
};

struct net_txq {
    net_loop* l;
    net_sock* s;
    unsigned  base_ev;
    int       wr_armed;
    uint64_t  retry_id; /* fallback timer when NET_WR cannot be armed */

    struct txmsg* q; /* ring of cap slots, q[(head + i) % cap] */
    size_t        cap, head, n;
    size_t        bytes, max_bytes;

    uint64_t sent, calls, dropped, blocked;
};

/* The loop's flush hook. Registered only while the queue has something in
 * it (see net_txq_send / net_txq_flush), so a process holding a socket per
 * subscriber does not pay a hook call per socket per iteration — the cost
 * tracks the queues with output pending, not the ones that exist. */
static void pre_tramp(void* ud)
{
    net_txq_flush((net_txq*)ud);
}

static void retry_tramp(void* ud)
{
    net_txq* q  = (net_txq*)ud;
    q->retry_id = 0;
    net_txq_flush(q);
}

net_txq* net_txq_new(net_loop* l, net_sock* s, unsigned base_ev,
                     size_t max_bytes)
{
    if (!l || !s || s->fd < 0) return NULL;
    net_txq* q = calloc(1, sizeof *q);
    if (!q) return NULL;
    q->cap = NET_TXQ_BATCH;
    q->q   = calloc(q->cap, sizeof *q->q);
    if (!q->q) {
        free(q);
        return NULL;
    }
    q->l         = l;
    q->s         = s;
    q->base_ev   = base_ev;
    q->max_bytes = max_bytes ? max_bytes : NET_TXQ_MAX_BYTES;
    return q;
}

void net_txq_detach(net_txq* q)
{
    if (!q) return;
    q->l        = NULL;
    q->wr_armed = 0;
    q->retry_id = 0;
}

void net_txq_free(net_txq* q)
{
    if (!q) return;
    if (q->l) {
        net_loop_pre_del(q->l, pre_tramp, q);
        if (q->retry_id) net_loop_cancel(q->l, q->retry_id);
        if (q->wr_armed) net_loop_mod(q->l, q->s->fd, q->base_ev);
    }
    for (size_t i = 0; i < q->cap; i++)
        free(q->q[i].buf);
    free(q->q);
    free(q);
}

/* Ask the loop to wake us when the socket accepts more. The fd is normally
 * registered by the owner of the queue; when it is not, epoll has nothing
 * to report on, so fall back to a 1 ms retry timer (which also bounds the
 * next epoll_wait). */
static void arm_wr(net_txq* q)
{
    if (!q->l || q->wr_armed) return;
    if (net_loop_mod(q->l, q->s->fd, q->base_ev | NET_WR) == NET_OK) {
        q->wr_armed = 1;
        return;
    }
    if (!q->retry_id) q->retry_id = net_loop_after(q->l, 1, retry_tramp, q);
}

static void disarm_wr(net_txq* q)
{
    if (!q->l || !q->wr_armed) return;
    net_loop_mod(q->l, q->s->fd, q->base_ev);
    q->wr_armed = 0;
}

static int grow(net_txq* q)
{
    size_t        cap = q->cap * 2;
    struct txmsg* nq  = calloc(cap, sizeof *nq);
    if (!nq) return NET_ERR;
    for (size_t i = 0; i < q->n; i++) /* re-linearise: head moves to 0 */
        nq[i] = q->q[(q->head + i) % q->cap];
    free(q->q);
    q->q    = nq;
    q->cap  = cap;
    q->head = 0;
    return NET_OK;
}

static void pop(net_txq* q, size_t k)
{
    for (size_t i = 0; i < k; i++)
        q->bytes -= q->q[(q->head + i) % q->cap].len;
    q->head = (q->head + k) % q->cap;
    q->n -= k;
}

int net_txq_send(net_txq* q, const void* buf, size_t len, const net_addr* to)
{
    if (q->bytes + len > q->max_bytes) {
        q->dropped++;
        return NET_ERR;
    }
    if (q->n == q->cap && grow(q) != NET_OK) {
        q->dropped++;
        return NET_ERR;
    }
    struct txmsg* m = &q->q[(q->head + q->n) % q->cap];
    if (len && m->cap < len) {
        char* b = realloc(m->buf, len);
        if (!b) {
            q->dropped++;
            return NET_ERR;
        }
        m->buf = b;
        m->cap = len;
    }
    if (len) memcpy(m->buf, buf, len);
    m->len    = len;
    m->has_to = to != NULL;
    if (to) m->to = *to;
    if (q->n == 0 && q->l) /* empty -> pending: ask the loop to flush us */
        net_loop_pre_add(q->l, pre_tramp, q);
    q->n++;
    q->bytes += len;
    return NET_OK;
}

/* EAGAIN/EWOULDBLOCK: socket buffer full. ENOBUFS: qdisc full — the socket
 * may report writable again straight away, so this can cost an extra loop
 * iteration or two, which is still preferable to failing the send. */
static int again(int e)
{
    return e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS;
}

int net_txq_flush(net_txq* q)
{
    const int v6    = q->s->local.sa.sa_family == AF_INET6;
    int       total = 0;

    while (q->n) {
        size_t         k = q->n < NET_TXQ_BATCH ? q->n : NET_TXQ_BATCH;
        struct mmsghdr mm[NET_TXQ_BATCH];
        struct iovec   iov[NET_TXQ_BATCH];
        net_addr       to[NET_TXQ_BATCH];

        memset(mm, 0, k * sizeof mm[0]);
        for (size_t i = 0; i < k; i++) {
            struct txmsg* m          = &q->q[(q->head + i) % q->cap];
            iov[i].iov_base          = m->buf;
            iov[i].iov_len           = m->len;
            mm[i].msg_hdr.msg_iov    = &iov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
            if (!m->has_to) continue;
            if (v6) net_addr_map6(&to[i], &m->to); /* dual-stack: v4-mapped */
            else to[i] = m->to;
            mm[i].msg_hdr.msg_name    = &to[i].sa;
            mm[i].msg_hdr.msg_namelen = net_addr_len(&to[i]);
        }

        int r;
        do
            r = sendmmsg(q->s->fd, mm, (unsigned)k,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        while (r < 0 && errno == EINTR);

        q->calls++;
        if (r > 0) {
            q->sent += (uint64_t)r;
            total += r;
            pop(q, (size_t)r);
            /* Short batch: the next datagram did not go out. sendmmsg does
             * not report why once anything was sent, so let the loop retry —
             * a permanent failure then surfaces as r < 0 with the datagram
             * at the head, and is dropped below. */
            if ((size_t)r < k) {
                q->blocked++;
                arm_wr(q);
                return total;
            }
            continue;
        }
        if (again(errno)) {
            q->blocked++;
            arm_wr(q);
            return total;
        }
        q->dropped++; /* undeliverable (EMSGSIZE, ECONNREFUSED, EPERM, ...) */
        pop(q, 1);
    }

    /* Drained: stop costing the loop anything until the next send. Safe to
     * drop from inside the hook — net_loop_pre_del defers the compaction. */
    disarm_wr(q);
    if (q->l) net_loop_pre_del(q->l, pre_tramp, q);
    return total;
}

size_t net_txq_pending(const net_txq* q)
{
    return q->n;
}

size_t net_txq_bytes(const net_txq* q)
{
    return q->bytes;
}

uint64_t net_txq_sent(const net_txq* q)
{
    return q->sent;
}

uint64_t net_txq_calls(const net_txq* q)
{
    return q->calls;
}

uint64_t net_txq_dropped(const net_txq* q)
{
    return q->dropped;
}

uint64_t net_txq_blocked(const net_txq* q)
{
    return q->blocked;
}
