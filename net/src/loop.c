#define _GNU_SOURCE
#include "net_loop.h"

#include <errno.h>
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

struct tmr {
    uint64_t  due;
    uint64_t  id;
    net_tmr_f cb;
    void*     ud;
};

struct net_loop {
    int           ep;
    int           stop;
    struct fdrec* fds; /* indexed by fd: O(1) dispatch, no lifetime races */
    int           cap;
    struct tmr*   tmr; /* binary min-heap on due */
    size_t        ntmr, ctmr;
    uint64_t      seq;
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
    l->ep = epoll_create1(EPOLL_CLOEXEC);
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

/* --- timer heap ------------------------------------------------------ */

static void tmr_up(struct tmr* h, size_t i)
{
    struct tmr t = h[i];
    for (; i && t.due < h[(i - 1) / 2].due; i = (i - 1) / 2)
        h[i] = h[(i - 1) / 2];
    h[i] = t;
}

static void tmr_down(struct tmr* h, size_t n, size_t i)
{
    struct tmr t = h[i];
    for (;;) {
        size_t c = 2 * i + 1;
        if (c >= n) break;
        if (c + 1 < n && h[c + 1].due < h[c].due) c++;
        if (t.due <= h[c].due) break;
        h[i] = h[c];
        i    = c;
    }
    h[i] = t;
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
    struct tmr* t = &l->tmr[l->ntmr];
    t->due        = net_now_ms() + ms;
    t->id         = ++l->seq;
    t->cb         = cb;
    t->ud         = ud;
    tmr_up(l->tmr, l->ntmr++);
    return l->seq;
}

int net_loop_cancel(net_loop* l, uint64_t id)
{
    for (size_t i = 0; i < l->ntmr; i++) {
        if (l->tmr[i].id != id) continue;
        l->tmr[i] = l->tmr[--l->ntmr];
        if (i < l->ntmr) {
            tmr_down(l->tmr, l->ntmr, i);
            tmr_up(l->tmr, i);
        }
        return NET_OK;
    }
    return NET_ERR;
}

/* --- dispatch --------------------------------------------------------- */

int net_loop_step(net_loop* l, int timeout_ms)
{
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
            l->tmr[0]      = l->tmr[--l->ntmr];
            if (l->ntmr) tmr_down(l->tmr, l->ntmr, 0);
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
