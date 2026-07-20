#define _GNU_SOURCE
#include "net_loop.h"
#include "net_sock.h"
#include "test.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

static int have_sctp(void)
{
    net_addr any;
    net_sock s;
    net_addr_any(&any, AF_INET, 0);
    if (net_sctp_bind(&s, &any, 4) != NET_OK) return 0;
    net_sock_close(&s);
    return 1;
}

static int have_v6(void)
{
    net_addr lo;
    net_sock s;
    net_addr_from(&lo, "::1", 0);
    if (net_udp_open(&s, &lo, 0) != NET_OK) return 0;
    net_sock_close(&s);
    return 1;
}

/* one echo round trip over a fresh conn+accept pair */
static int stream_echo(net_sock* cli, net_sock* srv)
{
    net_sock conn;
    char     buf[16] = { 0 };
    if (net_sock_accept(srv, &conn, 1000) != NET_OK) return -1;
    if (net_sock_send(cli, "ping", 4, 1000) != 4) return -2;
    if (net_sock_recv(&conn, buf, sizeof buf, 1000) != 4) return -3;
    if (net_sock_send(&conn, buf, 4, 1000) != 4) return -4;
    memset(buf, 0, sizeof buf);
    if (net_sock_recv(cli, buf, sizeof buf, 1000) != 4) return -5;
    net_sock_close(&conn);
    return strcmp(buf, "ping") ? -6 : 0;
}

spec ("net_sock") {
    net_addr lo;
    net_addr_from(&lo, "127.0.0.1", 0);

    context ("udp") {
        it ("sends and receives datagrams") {
            net_sock a, b;
            net_addr from;
            char     buf[32] = { 0 };
            check(net_udp_open(&a, &lo, 0) == NET_OK);
            check(net_udp_open(&b, &lo, 0) == NET_OK);
            check(net_addr_port(&a.local) != 0); /* ephemeral resolved */
            check(net_udp_send(&a, "hello", 5, &b.local) == 5);
            check(net_udp_recv(&b, buf, sizeof buf, &from, 1000) == 5);
            check(!strcmp(buf, "hello"));
            check(net_addr_eq(&from, &a.local));
            net_sock_close(&a);
            net_sock_close(&b);
        }

        it ("recv times out") {
            net_sock a;
            char     buf[8];
            net_udp_open(&a, &lo, 0);
            uint64_t t0 = net_now_ms();
            check(net_udp_recv(&a, buf, sizeof buf, NULL, 30) == NET_TIMEOUT);
            check(net_now_ms() - t0 >= 30);
            check(net_udp_recv(&a, buf, sizeof buf, NULL, -1) == NET_TIMEOUT);
            net_sock_close(&a);
        }

        it ("SO_REUSEPORT shares a port") {
            net_sock a, b, c;
            check(net_udp_open(&a, &lo, NET_REUSEPORT) == NET_OK);
            check(net_udp_open(&b, &a.local, NET_REUSEPORT) == NET_OK);
            check(net_addr_port(&a.local) == net_addr_port(&b.local));
            check(net_udp_open(&c, &a.local, 0) == NET_ERR); /* without flag */
            net_sock_close(&a);
            net_sock_close(&b);
        }

        it ("connected udp uses send/recv") {
            net_sock a, b;
            char     buf[8] = { 0 };
            net_udp_open(&a, &lo, 0);
            net_udp_open(&b, &lo, 0);
            check(net_udp_conn(&a, &b.local) == NET_OK);
            check(net_udp_send(&a, "hi", 2, NULL) == 2);
            check(net_udp_recv(&b, buf, sizeof buf, NULL, 1000) == 2);
            net_sock_close(&a);
            net_sock_close(&b);
        }
    }

    context ("tcp") {
        it ("connects, echoes, detects close") {
            net_sock srv, cli, conn;
            char     buf[8];
            check(net_tcp_bind(&srv, &lo, 8) == NET_OK);
            check(net_tcp_conn(&cli, NULL, &srv.local, 1000) == NET_OK);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            check(net_sock_send(&cli, "ab", 2, 1000) == 2);
            check(net_sock_recv(&conn, buf, sizeof buf, 1000) == 2);
            net_sock_close(&conn);
            check(net_sock_recv(&cli, buf, sizeof buf, 1000) == 0); /* EOF */
            net_sock_close(&cli);
            net_sock_close(&srv);
        }

        it ("accept times out") {
            net_sock srv, conn;
            net_tcp_bind(&srv, &lo, 8);
            check(net_sock_accept(&srv, &conn, 30) == NET_TIMEOUT);
            net_sock_close(&srv);
        }

        it ("non-blocking connect finishes via done") {
            net_sock srv, cli, conn;
            net_tcp_bind(&srv, &lo, 8);
            int r = net_tcp_conn(&cli, NULL, &srv.local, -1);
            check(r == NET_OK || r == NET_WANT_WR);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            check(net_sock_done(&cli, 1000) == NET_OK);
            char buf[4];
            check(net_sock_send(&cli, "x", 1, 1000) == 1);
            check(net_sock_recv(&conn, buf, sizeof buf, 1000) == 1);
            net_sock_close(&conn);
            net_sock_close(&cli);
            net_sock_close(&srv);
        }

        it ("reconnects after the peer drops") {
            net_sock srv, cli, conn;
            char     buf[8];
            net_tcp_bind(&srv, &lo, 8);
            check(net_tcp_conn(&cli, NULL, &srv.local, 1000) == NET_OK);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            net_sock_close(&conn);
            check(net_sock_recv(&cli, buf, sizeof buf, 1000) == 0);
            check(net_sock_reconn(&cli, 1000) == NET_OK);
            check(stream_echo(&cli, &srv) == 0);
            net_sock_close(&cli);
            net_sock_close(&srv);
        }

        it ("binds a caller-chosen source and keeps it on reconn") {
            net_sock srv, cli, conn;
            net_tcp_bind(&srv, &lo, 8);
            check(net_tcp_conn(&cli, &lo, &srv.local, 1000) == NET_OK);
            uint16_t port = net_addr_port(&cli.local);
            check(port != 0);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            check(net_addr_port(&conn.peer) == port);
            net_sock_close(&conn);
            check(net_sock_reconn(&cli, 1000) == NET_OK);
            check(net_addr_port(&cli.local) == port);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            net_sock_close(&conn);
            net_sock_close(&cli);
            net_sock_close(&srv);
        }

        it ("conn to a dead port fails") {
            net_sock srv, cli;
            net_tcp_bind(&srv, &lo, 8);
            net_addr dead = srv.local;
            net_sock_close(&srv);
            check(net_tcp_conn(&cli, NULL, &dead, 1000) == NET_ERR);
        }
    }

    context ("dual-stack") {
        it ("v6 any-listener accepts v4 clients", have_v6()) {
            net_addr any;
            net_sock srv, cli, conn;
            net_addr_from(&any, NULL, 0);
            check(net_tcp_bind(&srv, &any, 8) == NET_OK);
            net_addr peer;
            net_addr_from(&peer, "127.0.0.1", net_addr_port(&srv.local));
            check(net_tcp_conn(&cli, NULL, &peer, 1000) == NET_OK);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            check(conn.peer.sa.sa_family == AF_INET); /* unmapped for caller */
            net_sock_close(&conn);
            net_sock_close(&cli);
            net_sock_close(&srv);
        }

        it ("v6 any udp socket reaches v4 peers", have_v6()) {
            net_addr any;
            net_sock a, b;
            char     buf[8];
            net_addr_from(&any, NULL, 0);
            check(net_udp_open(&a, &any, 0) == NET_OK);
            check(net_udp_open(&b, &lo, 0) == NET_OK);
            check(net_udp_send(&a, "x", 1, &b.local) == 1); /* v4 dst mapped */
            check(net_udp_recv(&b, buf, sizeof buf, NULL, 1000) == 1);
            net_sock_close(&a);
            net_sock_close(&b);
        }
    }

    context ("sctp") {
        it ("connects, echoes, reconnects", have_sctp()) {
            net_sock srv, cli, conn;
            char     buf[8];
            check(net_sctp_bind(&srv, &lo, 8) == NET_OK);
            check(net_sctp_conn(&cli, NULL, &srv.local, 1000) == NET_OK);
            check(net_sock_accept(&srv, &conn, 1000) == NET_OK);
            check(net_sock_send(&cli, "diam", 4, 1000) == 4);
            check(net_sock_recv(&conn, buf, sizeof buf, 1000) == 4);
            net_sock_close(&conn);
            check(net_sock_recv(&cli, buf, sizeof buf, 1000) == 0);
            check(net_sock_reconn(&cli, 1000) == NET_OK);
            check(stream_echo(&cli, &srv) == 0);
            net_sock_close(&cli);
            net_sock_close(&srv);
        }
    }
}
