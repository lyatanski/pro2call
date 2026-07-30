#define _GNU_SOURCE
#include "net_loop.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#define LOOP_BATCH  64
#define LOOP_MAX_MS 3600000

struct fdrec {
    net_io_f cb;
    void*    ud;
};

/* Timer handles.
 *
 * Cancel has to be O(1): scripts arm and disarm a protocol deadline on
 * every event, so scanning the heap for the id cost ~7 us per cancel at
 * 16k outstanding timers and got worse as concurrency rose.
 *
 * So a handle is not a bare counter but a (generation, slot) pair. The
 * slot indexes l->slot, which records where that timer currently sits in
 * the heap; every heap move writes the position back, so cancel decodes
 * the slot and removes the entry directly. The generation is bumped when
 * a slot is released, which keeps the handle of a cancelled or already
 * fired timer distinguishable from a live timer that has since reused
 * the slot — so a second cancel of the same id still reports NET_ERR.
 *
 * Generations start at 1 and skip 0 on wrap, so a handle is never 0
 * (net_loop_after reserves 0 for failure). */
#define TMR_NOPOS         ((size_t)-1)
#define TMR_NOSLOT        UINT32_MAX
#define TMR_SLOT(id)      ((uint32_t)((id) & 0xffffffffu))
#define TMR_GEN(id)       ((uint32_t)((id) >> 32))
#define TMR_ID(gen, slot) (((uint64_t)(gen) << 32) | (uint32_t)(slot))

struct tmr {
    uint64_t  due;
    uint32_t  slot; /* back-pointer into l->slot */
    net_tmr_f cb;
    void*     ud;
};

struct tmrslot {
    size_t   pos;  /* index in the heap, or TMR_NOPOS when not armed */
    uint32_t gen;  /* bumped on release; 0 is never live */
    uint32_t next; /* free-list link while not armed */
};

struct pre {
    net_pre_f cb;
    void*     ud;
};

struct net_loop {
    int             ep;
    int             stop;
    struct fdrec*   fds; /* indexed by fd: O(1) dispatch, no lifetime races */
    int             cap;
    struct tmr*     tmr; /* binary min-heap on due */
    size_t          ntmr, ctmr;
    struct tmrslot* slot; /* handle table: heap position + generation */
    size_t          cslot;
    uint32_t        freeslot; /* head of the free-slot list */
    struct pre*     pre;      /* pre-poll hooks, in registration order */
    size_t          npre, cpre;
    int             pre_gaps; /* a hook was dropped: compact after dispatch */
};

uint64_t net_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint32_t ep_events(unsigned ev)
{
    return (ev & NET_RD ? EPOLLIN : 0) | (ev & NET_WR ? EPOLLOUT : 0);
}

static unsigned ep_revents(uint32_t ev)
{
    return (ev & (EPOLLIN | EPOLLPRI) ? NET_RD : 0) |
           (ev & EPOLLOUT ? NET_WR : 0) |
           (ev & (EPOLLERR | EPOLLHUP) ? NET_ER : 0);
}

net_loop* net_loop_new(void)
{
    net_loop* l = calloc(1, sizeof *l);
    if (!l) return NULL;
    l->freeslot = TMR_NOSLOT; /* 0 is a valid slot index, so not calloc's 0 */
    l->ep       = epoll_create1(EPOLL_CLOEXEC);
    if (l->ep < 0) {
        free(l);
        return NULL;
    }
    return l;
}

void net_loop_free(net_loop* l)
{
    if (!l) return;
    close(l->ep);
    free(l->fds);
    free(l->tmr);
    free(l->slot);
    free(l->pre);
    free(l);
}

int net_loop_add(net_loop* l, int fd, unsigned ev, net_io_f cb, void* ud)
{
    if (fd < 0 || !cb) return NET_ERR;
    if (fd >= l->cap) {
        int cap = l->cap ? l->cap : 64;
        while (cap <= fd)
            cap *= 2;
        struct fdrec* fds = realloc(l->fds, (size_t)cap * sizeof *fds);
        if (!fds) return NET_ERR;
        memset(fds + l->cap, 0, (size_t)(cap - l->cap) * sizeof *fds);
        l->fds = fds;
        l->cap = cap;
    }
    struct epoll_event e = { .events = ep_events(ev), .data = { .fd = fd } };
    if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &e) < 0) return NET_ERR;
    l->fds[fd].cb = cb;
    l->fds[fd].ud = ud;
    return NET_OK;
}

int net_loop_mod(net_loop* l, int fd, unsigned ev)
{
    if (fd < 0 || fd >= l->cap || !l->fds[fd].cb) return NET_ERR;
    struct epoll_event e = { .events = ep_events(ev), .data = { .fd = fd } };
    return epoll_ctl(l->ep, EPOLL_CTL_MOD, fd, &e) < 0 ? NET_ERR : NET_OK;
}

int net_loop_del(net_loop* l, int fd)
{
    if (fd < 0 || fd >= l->cap || !l->fds[fd].cb) return NET_ERR;
    l->fds[fd].cb = NULL;
    l->fds[fd].ud = NULL;
    return epoll_ctl(l->ep, EPOLL_CTL_DEL, fd, NULL) < 0 ? NET_ERR : NET_OK;
}

/* --- pre-poll hooks --------------------------------------------------- */

int net_loop_pre_add(net_loop* l, net_pre_f cb, void* ud)
{
    if (!cb) return NET_ERR;
    for (size_t i = 0; i < l->npre; i++)
        if (l->pre[i].cb == cb && l->pre[i].ud == ud) return NET_OK;
    for (size_t i = 0; i < l->npre; i++) /* reuse a dropped slot */
        if (!l->pre[i].cb) {
            l->pre[i].cb = cb;
            l->pre[i].ud = ud;
            return NET_OK;
        }
    if (l->npre == l->cpre) {
        size_t      c = l->cpre ? l->cpre * 2 : 4;
        struct pre* p = realloc(l->pre, c * sizeof *p);
        if (!p) return NET_ERR;
        l->pre  = p;
        l->cpre = c;
    }
    l->pre[l->npre].cb = cb;
    l->pre[l->npre].ud = ud;
    l->npre++;
    return NET_OK;
}

/* Removal only clears the slot; dispatch compacts afterwards. A hook that
 * drops itself while it is running therefore cannot shift the entries the
 * dispatch loop has not reached yet. */
int net_loop_pre_del(net_loop* l, net_pre_f cb, void* ud)
{
    for (size_t i = 0; i < l->npre; i++) {
        if (l->pre[i].cb != cb || l->pre[i].ud != ud) continue;
        l->pre[i].cb = NULL;
        l->pre[i].ud = NULL;
        l->pre_gaps  = 1;
        return NET_OK;
    }
    return NET_ERR;
}

static void pre_compact(net_loop* l)
{
    size_t w = 0;
    for (size_t i = 0; i < l->npre; i++)
        if (l->pre[i].cb) l->pre[w++] = l->pre[i]; /* order is contractual */
    l->npre     = w;
    l->pre_gaps = 0;
}

/* --- timer heap ------------------------------------------------------ */

/* Record where heap entry i now lives, so its handle stays resolvable.
 * Every write to l->tmr[i] must be followed by one of these. */
static void tmr_place(net_loop* l, size_t i)
{
    l->slot[l->tmr[i].slot].pos = i;
}

static void tmr_up(net_loop* l, size_t i)
{
    struct tmr* h = l->tmr;
    struct tmr  t = h[i];
    for (; i && t.due < h[(i - 1) / 2].due; i = (i - 1) / 2) {
        h[i] = h[(i - 1) / 2];
        tmr_place(l, i);
    }
    h[i] = t;
    tmr_place(l, i);
}

static void tmr_down(net_loop* l, size_t n, size_t i)
{
    struct tmr* h = l->tmr;
    struct tmr  t = h[i];
    for (;;) {
        size_t c = 2 * i + 1;
        if (c >= n) break;
        if (c + 1 < n && h[c + 1].due < h[c].due) c++;
        if (t.due <= h[c].due) break;
        h[i] = h[c];
        tmr_place(l, i);
        i = c;
    }
    h[i] = t;
    tmr_place(l, i);
}

/* Pull heap entry i out, release its slot and restore the heap. */
static void tmr_remove(net_loop* l, size_t i)
{
    uint32_t s = l->tmr[i].slot;

    l->slot[s].pos = TMR_NOPOS;
    if (++l->slot[s].gen == 0) l->slot[s].gen = 1;
    l->slot[s].next = l->freeslot;
    l->freeslot     = s;

    l->tmr[i] = l->tmr[--l->ntmr]; /* self-assign when i was the last */
    if (i < l->ntmr) {
        tmr_place(l, i);
        tmr_down(l, l->ntmr, i);
        tmr_up(l, i);
    }
}

/* Take a free slot, growing the table when the free list runs dry. */
static uint32_t tmr_slot_alloc(net_loop* l)
{
    if (l->freeslot == TMR_NOSLOT) {
        size_t c = l->cslot ? l->cslot * 2 : 16;
        if (c >= TMR_NOSLOT) return TMR_NOSLOT;
        struct tmrslot* s = realloc(l->slot, c * sizeof *s);
        if (!s) return TMR_NOSLOT;
        l->slot = s;
        for (size_t i = l->cslot; i < c; i++) {
            l->slot[i].pos  = TMR_NOPOS;
            l->slot[i].gen  = 1;
            l->slot[i].next = i + 1 < c ? (uint32_t)(i + 1) : TMR_NOSLOT;
        }
        l->freeslot = (uint32_t)l->cslot;
        l->cslot    = c;
    }
    uint32_t s  = l->freeslot;
    l->freeslot = l->slot[s].next;
    return s;
}

uint64_t net_loop_after(net_loop* l, uint64_t ms, net_tmr_f cb, void* ud)
{
    if (!cb) return 0;
    if (l->ntmr == l->ctmr) {
        size_t      c = l->ctmr ? l->ctmr * 2 : 16;
        struct tmr* h = realloc(l->tmr, c * sizeof *h);
        if (!h) return 0;
        l->tmr  = h;
        l->ctmr = c;
    }
    uint32_t s = tmr_slot_alloc(l);
    if (s == TMR_NOSLOT) return 0;

    struct tmr* t  = &l->tmr[l->ntmr];
    t->due         = net_now_ms() + ms;
    t->slot        = s;
    t->cb          = cb;
    t->ud          = ud;
    l->slot[s].pos = l->ntmr;
    tmr_up(l, l->ntmr++);
    return TMR_ID(l->slot[s].gen, s);
}

int net_loop_cancel(net_loop* l, uint64_t id)
{
    uint32_t s = TMR_SLOT(id);
    if (s >= l->cslot) return NET_ERR;
    if (l->slot[s].gen != TMR_GEN(id)) return NET_ERR; /* stale handle */
    size_t i = l->slot[s].pos;
    if (i == TMR_NOPOS) return NET_ERR; /* not armed */
    tmr_remove(l, i);
    return NET_OK;
}

/* --- dispatch --------------------------------------------------------- */

int net_loop_step(net_loop* l, int timeout_ms)
{
    /* First: hand the iteration to the pre-poll hooks (queued output goes
     * out here), then compute the timeout — a hook may have armed a timer. */
    for (size_t i = 0; i < l->npre; i++)
        if (l->pre[i].cb) l->pre[i].cb(l->pre[i].ud); /* may drop itself */
    if (l->pre_gaps) pre_compact(l);

    int t = timeout_ms < 0 ? -1 : timeout_ms;
    if (l->ntmr) {
        uint64_t now   = net_now_ms();
        uint64_t d     = l->tmr[0].due > now ? l->tmr[0].due - now : 0;
        int      until = d > LOOP_MAX_MS ? LOOP_MAX_MS : (int)d;
        if (t < 0 || until < t) t = until;
    }

    struct epoll_event evs[LOOP_BATCH];
    int                n = epoll_wait(l->ep, evs, LOOP_BATCH, t);
    if (n < 0) {
        if (errno != EINTR) return NET_ERR;
        n = 0;
    }

    if (l->ntmr) {
        uint64_t now = net_now_ms();
        while (l->ntmr && l->tmr[0].due <= now) {
            struct tmr due = l->tmr[0];
            tmr_remove(l, 0);
            due.cb(due.ud); /* popped first: cb may re-arm or cancel */
        }
    }

    for (int i = 0; i < n; i++) {
        int fd = evs[i].data.fd;
        /* re-check the table: an earlier callback may have deleted fd */
        if (fd < l->cap && l->fds[fd].cb)
            l->fds[fd].cb(l->fds[fd].ud, fd, ep_revents(evs[i].events));
    }
    return n;
}

int net_loop_run(net_loop* l)
{
    while (!l->stop)
        if (net_loop_step(l, -1) == NET_ERR) return NET_ERR;
    l->stop = 0;
    return NET_OK;
}

void net_loop_stop(net_loop* l)
{
    l->stop = 1;
}
