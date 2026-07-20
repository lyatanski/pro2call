#define _GNU_SOURCE
#include "net_loop.h"
#include "test.h"

#include <fcntl.h>
#include <unistd.h>

static int fired[8];
static int nfired;

static void mark(void* ud)
{
    fired[nfired++] = (int)(long)ud;
}

static void on_rd(void* ud, int fd, unsigned ev)
{
    char c;
    (void)read(fd, &c, 1);
    if (ev & NET_RD) (*(int*)ud)++;
}

static void stop_cb(void* ud)
{
    net_loop_stop(ud);
}

spec ("net_loop") {
    context ("io dispatch") {
        it ("dispatches readable fds") {
            net_loop* l = net_loop_new();
            int       p[2], got = 0;
            check(l);
            check(pipe2(p, O_NONBLOCK) == 0);
            check(net_loop_add(l, p[0], NET_RD, on_rd, &got) == NET_OK);
            check(write(p[1], "x", 1) == 1);
            check(net_loop_step(l, 100) == 1);
            check(got == 1);
            check(net_loop_step(l, 0) == 0); /* drained: level-triggered idle */
            net_loop_del(l, p[0]);
            close(p[0]);
            close(p[1]);
            net_loop_free(l);
        }

        it ("mod switches the event mask") {
            net_loop* l = net_loop_new();
            int       p[2], got = 0;
            pipe2(p, O_NONBLOCK);
            net_loop_add(l, p[0], NET_WR, on_rd, &got); /* wrong mask: silent */
            write(p[1], "x", 1);
            check(net_loop_step(l, 20) == 0);
            check(net_loop_mod(l, p[0], NET_RD) == NET_OK);
            check(net_loop_step(l, 100) == 1);
            check(got == 1);
            net_loop_del(l, p[0]);
            close(p[0]);
            close(p[1]);
            net_loop_free(l);
        }

        it ("del stops dispatch") {
            net_loop* l = net_loop_new();
            int       p[2], got = 0;
            pipe2(p, O_NONBLOCK);
            net_loop_add(l, p[0], NET_RD, on_rd, &got);
            check(net_loop_del(l, p[0]) == NET_OK);
            write(p[1], "x", 1);
            check(net_loop_step(l, 20) == 0);
            check(got == 0);
            check(net_loop_del(l, p[0]) == NET_ERR); /* already gone */
            close(p[0]);
            close(p[1]);
            net_loop_free(l);
        }
    }

    context ("timers") {
        it ("fires after the delay") {
            net_loop* l = net_loop_new();
            nfired      = 0;
            uint64_t t0 = net_now_ms();
            check(net_loop_after(l, 20, mark, (void*)1) != 0);
            while (!nfired)
                net_loop_step(l, -1);
            check(net_now_ms() - t0 >= 20);
            check(fired[0] == 1);
            net_loop_free(l);
        }

        it ("fires in due order") {
            net_loop* l = net_loop_new();
            nfired      = 0;
            net_loop_after(l, 30, mark, (void*)2);
            net_loop_after(l, 10, mark, (void*)1);
            net_loop_after(l, 50, mark, (void*)3);
            while (nfired < 3)
                net_loop_step(l, -1);
            check(fired[0] == 1 && fired[1] == 2 && fired[2] == 3);
            net_loop_free(l);
        }

        it ("cancel prevents firing") {
            net_loop* l = net_loop_new();
            nfired      = 0;
            uint64_t id = net_loop_after(l, 10, mark, (void*)1);
            net_loop_after(l, 30, mark, (void*)2);
            check(net_loop_cancel(l, id) == NET_OK);
            check(net_loop_cancel(l, id) == NET_ERR);
            while (nfired < 1)
                net_loop_step(l, -1);
            check(fired[0] == 2);
            net_loop_free(l);
        }
    }

    context ("run/stop") {
        it ("stop from a callback exits run") {
            net_loop* l = net_loop_new();
            net_loop_after(l, 5, stop_cb, l);
            check(net_loop_run(l) == NET_OK);
            net_loop_free(l);
        }
    }
}
