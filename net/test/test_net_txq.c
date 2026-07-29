#define _GNU_SOURCE
#include "net_txq.h"
#include "test.h"

#include <string.h>

/* Count the datagrams queued on `s`, discarding them. */
static int drain(net_sock* s)
{
    int  n = 0;
    char buf[2048];
    while (net_udp_recv(s, buf, sizeof buf, NULL, 100) >= 0)
        n++;
    return n;
}

/* An fd registered with the loop needs a callback; the queue only needs the
 * registration to exist so it can add NET_WR to the fd's interest. */
static void noop_io(void* ud, int fd, unsigned ev)
{
    (void)ud;
    (void)fd;
    (void)ev;
}

spec ("net_txq") {
    net_addr lo;
    net_addr_from(&lo, "127.0.0.1", 0);

    context ("queueing") {
        it ("sends nothing until the loop runs, then everything") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            char      buf[64] = { 0 };
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);
            check(q);

            check(net_txq_send(q, "one", 3, &b.local) == NET_OK);
            check(net_txq_send(q, "two", 3, &b.local) == NET_OK);
            check(net_txq_pending(q) == 2);
            check(net_txq_bytes(q) == 6);
            /* nothing on the caller's path: the peer has seen no datagram */
            check(net_udp_recv(&b, buf, sizeof buf, NULL, -1) == NET_TIMEOUT);

            net_loop_step(l, 0); /* the pre-poll hook flushes */
            check(net_txq_pending(q) == 0);
            check(net_txq_sent(q) == 2);
            check(net_txq_calls(q) == 1); /* both in ONE sendmmsg */
            check(net_udp_recv(&b, buf, sizeof buf, NULL, 500) == 3);
            check(!strcmp(buf, "one")); /* FIFO order preserved */
            check(net_udp_recv(&b, buf, sizeof buf, NULL, 500) == 3);
            check(!strcmp(buf, "two"));

            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }

        it ("batches a burst into ceil(n/NET_TXQ_BATCH) syscalls") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            /* a big receive buffer so the peer can hold the whole burst */
            int rb = 4 << 20;
            setsockopt(b.fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);

            const int N = NET_TXQ_BATCH * 3;
            for (int i = 0; i < N; i++)
                check(net_txq_send(q, "x", 1, &b.local) == NET_OK);
            check(net_txq_pending(q) == (size_t)N);
            check(net_txq_flush(q) == N);
            check(net_txq_sent(q) == (uint64_t)N);
            check(net_txq_calls(q) == 3); /* not N */
            check(drain(&b) == N);

            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }

        it ("connected socket queues without an address") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            char      buf[16] = { 0 };
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            net_udp_conn(&a, &b.local);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);
            check(net_txq_send(q, "hi", 2, NULL) == NET_OK);
            check(net_txq_flush(q) == 1);
            check(net_udp_recv(&b, buf, sizeof buf, NULL, 500) == 2);
            check(!strcmp(buf, "hi"));
            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }

        it ("refuses a send over the byte cap instead of growing") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            net_txq* q = net_txq_new(l, &a, NET_RD, 8); /* 8-byte cap */
            check(net_txq_send(q, "12345", 5, &b.local) == NET_OK);
            check(net_txq_send(q, "12345", 5, &b.local) == NET_ERR);
            check(net_txq_pending(q) == 1); /* the refused one is not queued */
            check(net_txq_dropped(q) == 1);
            check(net_txq_flush(q) == 1);
            check(net_txq_send(q, "12345", 5, &b.local) ==
                  NET_OK); /* drained */
            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }

        it ("keeps the backlog and arms NET_WR when the kernel pushes back") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            int sb = 4096; /* a tiny send buffer so a burst cannot all fit */
            setsockopt(a.fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
            net_loop_add(l, a.fd, NET_RD, noop_io, NULL);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);

            char big[1400];
            memset(big, 'x', sizeof big);
            for (int i = 0; i < 512; i++)
                net_txq_send(q, big, sizeof big, &b.local);
            net_txq_flush(q);
            /* Either the kernel took it all, or it pushed back and the
             * remainder is still queued — never a lost datagram or error. */
            check(net_txq_sent(q) + net_txq_pending(q) == 512);
            check(net_txq_dropped(q) == 0);

            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }
    }

    context ("lifetime") {
        it ("detach survives the loop being freed first") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);
            net_txq_send(q, "x", 1, &b.local);
            net_loop_free(l);  /* dependents may outlive the loop */
            net_txq_detach(q); /* so they stop touching it */
            net_txq_free(q);
            net_sock_close(&a);
            net_sock_close(&b);
        }

        it ("flushes once per step and drops its hook when freed") {
            net_loop* l = net_loop_new();
            net_sock  a, b;
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            net_txq* q = net_txq_new(l, &a, NET_RD, 0);
            net_txq_send(q, "x", 1, &b.local);
            net_loop_step(l, 0);
            check(net_txq_sent(q) == 1);
            check(net_txq_calls(q) == 1);
            net_loop_step(l, 0); /* empty queue: no extra syscall */
            check(net_txq_calls(q) == 1);
            net_txq_free(q);     /* drops the hook */
            net_loop_step(l, 0); /* must not touch the freed queue */
            net_sock_close(&a);
            net_sock_close(&b);
            net_loop_free(l);
        }
    }
}
