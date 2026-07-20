#define _GNU_SOURCE
#include "net_sock.h"
#include "net_tls.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERT "test_tls_cert.pem"
#define KEY  "test_tls_key.pem"

/* self-signed CN=localhost cert written next to the test binary */
static int make_cert(void)
{
    int       ok = 0;
    EVP_PKEY* key =
        EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); /* DTLS1.2-compatible */
    X509* x = X509_new();
    FILE* f = NULL;
    if (!key || !x) goto out;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
    X509_NAME* n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, n);
    X509_set_pubkey(x, key);
    if (!X509_sign(x, key, EVP_sha256())) goto out;
    if (!(f = fopen(KEY, "w")) ||
        !PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL))
        goto out;
    fclose(f);
    if (!(f = fopen(CERT, "w")) || !PEM_write_X509(f, x)) goto out;
    ok = 1;
out:
    if (f) fclose(f);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

/* drive two non-blocking handshakes against each other in one thread */
static int shake_pair(net_tls* cli, net_tls* srv)
{
    int c = -1, s = -1;
    for (int i = 0; i < 1000 && (c || s); i++) {
        if (c) c = net_tls_shake(cli, -1);
        if (s) s = net_tls_shake(srv, -1);
        if (c < 0 || s < 0) return -1;
    }
    return c || s ? -1 : 0;
}

spec ("net_tls") {
    net_addr lo;
    net_addr_from(&lo, "127.0.0.1", 0);
    int certs = make_cert();

    context ("tls over tcp") {
        it ("generates the test certificate") {
            check(certs);
        }

        it ("handshakes and moves data both ways", certs) {
            net_sock lst, cli, srv;
            char     buf[64] = { 0 };
            check(net_tcp_bind(&lst, &lo, 4) == NET_OK);
            int r = net_tcp_conn(&cli, NULL, &lst.local, -1);
            check(r == NET_OK || r == NET_WANT_WR);
            check(net_sock_accept(&lst, &srv, 1000) == NET_OK);
            check(net_sock_done(&cli, 1000) == NET_OK);

            net_tls_ctx* cc = net_tls_ctx_new(0, NULL, NULL, NULL);
            net_tls_ctx* sc = net_tls_ctx_new(NET_TLS_SERVER, CERT, KEY, NULL);
            check(cc && sc);
            net_tls* ct = net_tls_new(cc, &cli);
            net_tls* st = net_tls_new(sc, &srv);
            check(ct && st);
            check(shake_pair(ct, st) == 0);

            check(net_tls_send(ct, "REGISTER", 8, 1000) == 8);
            check(net_tls_recv(st, buf, sizeof buf, 1000) == 8);
            check(!strcmp(buf, "REGISTER"));
            check(net_tls_send(st, "200 OK", 6, 1000) == 6);
            memset(buf, 0, sizeof buf);
            check(net_tls_recv(ct, buf, sizeof buf, 1000) == 6);
            check(!strcmp(buf, "200 OK"));

            net_tls_free(ct);
            net_tls_free(st);
            net_tls_ctx_free(cc);
            net_tls_ctx_free(sc);
            net_sock_close(&cli);
            net_sock_close(&srv);
            net_sock_close(&lst);
        }

        it ("verifies the server against a trusted ca", certs) {
            net_sock lst, cli, srv;
            net_tcp_bind(&lst, &lo, 4);
            int r = net_tcp_conn(&cli, NULL, &lst.local, -1);
            check(r == NET_OK || r == NET_WANT_WR);
            check(net_sock_accept(&lst, &srv, 1000) == NET_OK);
            check(net_sock_done(&cli, 1000) == NET_OK);

            /* the self-signed server cert doubles as the trust anchor */
            net_tls_ctx* cc = net_tls_ctx_new(0, NULL, NULL, CERT);
            net_tls_ctx* sc = net_tls_ctx_new(NET_TLS_SERVER, CERT, KEY, NULL);
            check(cc && sc);
            net_tls* ct = net_tls_new(cc, &cli);
            net_tls* st = net_tls_new(sc, &srv);
            check(shake_pair(ct, st) == 0); /* trusted: handshake passes */
            net_tls_free(ct);
            net_tls_free(st);
            net_tls_ctx_free(cc);
            net_tls_ctx_free(sc);
            net_sock_close(&cli);
            net_sock_close(&srv);
            net_sock_close(&lst);
        }

        it ("recv reports close_notify as eof", certs) {
            net_sock lst, cli, srv;
            char     buf[8];
            net_tcp_bind(&lst, &lo, 4);
            int r = net_tcp_conn(&cli, NULL, &lst.local, -1);
            check(r == NET_OK || r == NET_WANT_WR);
            check(net_sock_accept(&lst, &srv, 1000) == NET_OK);
            check(net_sock_done(&cli, 1000) == NET_OK);
            net_tls_ctx* cc = net_tls_ctx_new(0, NULL, NULL, NULL);
            net_tls_ctx* sc = net_tls_ctx_new(NET_TLS_SERVER, CERT, KEY, NULL);
            net_tls*     ct = net_tls_new(cc, &cli);
            net_tls*     st = net_tls_new(sc, &srv);
            check(shake_pair(ct, st) == 0);
            net_tls_free(st); /* sends close_notify */
            check(net_tls_recv(ct, buf, sizeof buf, 1000) == 0);
            net_tls_free(ct);
            net_tls_ctx_free(cc);
            net_tls_ctx_free(sc);
            net_sock_close(&cli);
            net_sock_close(&srv);
            net_sock_close(&lst);
        }
    }

    context ("dtls over udp") {
        it ("handshakes and moves a datagram", certs) {
            net_sock a, b;
            char     buf[64] = { 0 };
            check(net_udp_open(&a, &lo, 0) == NET_OK);
            check(net_udp_open(&b, &lo, 0) == NET_OK);
            check(net_udp_conn(&a, &b.local) == NET_OK);
            check(net_udp_conn(&b, &a.local) == NET_OK);

            net_tls_ctx* cc = net_tls_ctx_new(NET_TLS_DTLS, NULL, NULL, NULL);
            net_tls_ctx* sc =
                net_tls_ctx_new(NET_TLS_SERVER | NET_TLS_DTLS, CERT, KEY, NULL);
            check(cc && sc);
            net_tls* ct = net_tls_new(cc, &a);
            net_tls* st = net_tls_new(sc, &b);
            check(ct && st);
            check(shake_pair(ct, st) == 0);

            check(net_tls_send(ct, "MESSAGE", 7, 1000) == 7);
            check(net_tls_recv(st, buf, sizeof buf, 1000) == 7);
            check(!strcmp(buf, "MESSAGE"));

            net_tls_free(ct);
            net_tls_free(st);
            net_tls_ctx_free(cc);
            net_tls_ctx_free(sc);
            net_sock_close(&a);
            net_sock_close(&b);
        }
    }
}
