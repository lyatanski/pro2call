#define _GNU_SOURCE
#include "net_tls.h"
#include "net_loop.h"

#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct net_tls_ctx {
    SSL_CTX* ctx;
    unsigned flags;
};

struct net_tls {
    SSL* ssl;
    int  fd;
};

net_tls_ctx* net_tls_ctx_new(unsigned flags, const char* cert, const char* key,
                             const char* ca)
{
    const SSL_METHOD* m = flags & NET_TLS_DTLS
                              ? (flags & NET_TLS_SERVER ? DTLS_server_method()
                                                        : DTLS_client_method())
                              : (flags & NET_TLS_SERVER ? TLS_server_method()
                                                        : TLS_client_method());
    net_tls_ctx*      c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->flags = flags;
    c->ctx   = SSL_CTX_new(m);
    if (!c->ctx) goto err;
    if (cert && SSL_CTX_use_certificate_chain_file(c->ctx, cert) != 1) goto err;
    if (key && SSL_CTX_use_PrivateKey_file(c->ctx, key, SSL_FILETYPE_PEM) != 1)
        goto err;
    if (ca) {
        if (SSL_CTX_load_verify_locations(c->ctx, ca, NULL) != 1) goto err;
        SSL_CTX_set_verify(
            c->ctx,
            SSL_VERIFY_PEER |
                (flags & NET_TLS_SERVER ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
            NULL);
    } else SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(c->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                                 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return c;
err:
    net_tls_ctx_free(c);
    return NULL;
}

void net_tls_ctx_free(net_tls_ctx* c)
{
    if (!c) return;
    SSL_CTX_free(c->ctx);
    free(c);
}

net_tls* net_tls_new(net_tls_ctx* c, const net_sock* s)
{
    net_tls* t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fd  = s->fd;
    t->ssl = SSL_new(c->ctx);
    if (!t->ssl) {
        free(t);
        return NULL;
    }
    if (c->flags & NET_TLS_DTLS) {
        BIO* b = BIO_new_dgram(s->fd, BIO_NOCLOSE);
        if (!b) {
            net_tls_free(t);
            return NULL;
        }
        if (s->peer.sa.sa_family)
            BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (void*)&s->peer.ss);
        SSL_set_bio(t->ssl, b, b);
    } else if (SSL_set_fd(t->ssl, s->fd) != 1) {
        net_tls_free(t);
        return NULL;
    }
    if (c->flags & NET_TLS_SERVER) SSL_set_accept_state(t->ssl);
    else SSL_set_connect_state(t->ssl);
    return t;
}

static int left(uint64_t due)
{
    uint64_t now = net_now_ms();
    return now >= due ? 0 : (int)(due - now);
}

int net_tls_shake(net_tls* t, int timeout_ms)
{
    uint64_t due = net_now_ms() + (timeout_ms > 0 ? (uint64_t)timeout_ms : 0);
    for (;;) {
        int r = SSL_do_handshake(t->ssl);
        if (r == 1) return NET_OK;
        int e = SSL_get_error(t->ssl, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            return NET_ERR;
        unsigned ev = e == SSL_ERROR_WANT_READ ? NET_RD : NET_WR;
        if (timeout_ms < 0) return ev == NET_RD ? NET_WANT_RD : NET_WANT_WR;
        int w = net_sock_wait(t->fd, ev, left(due));
        if (w != NET_OK) return w;
    }
}

ssize_t net_tls_send(net_tls* t, const void* buf, size_t len, int timeout_ms)
{
    size_t   off = 0;
    uint64_t due = net_now_ms() + (timeout_ms > 0 ? (uint64_t)timeout_ms : 0);
    while (off < len) {
        int r = SSL_write(t->ssl, (const char*)buf + off, (int)(len - off));
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        int e = SSL_get_error(t->ssl, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            return NET_ERR;
        int w = net_sock_wait(t->fd, e == SSL_ERROR_WANT_READ ? NET_RD : NET_WR,
                              timeout_ms < 0 ? -1 : left(due));
        if (w == NET_ERR) return NET_ERR;
        if (w == NET_TIMEOUT) break;
    }
    if (off || !len) return (ssize_t)off;
    return NET_TIMEOUT;
}

ssize_t net_tls_recv(net_tls* t, void* buf, size_t len, int timeout_ms)
{
    uint64_t due = net_now_ms() + (timeout_ms > 0 ? (uint64_t)timeout_ms : 0);
    for (;;) {
        int r = SSL_read(t->ssl, buf, (int)len);
        if (r > 0) return r;
        int e = SSL_get_error(t->ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            return NET_ERR;
        int w = net_sock_wait(t->fd, e == SSL_ERROR_WANT_READ ? NET_RD : NET_WR,
                              timeout_ms < 0 ? -1 : left(due));
        if (w != NET_OK) return w;
    }
}

void net_tls_free(net_tls* t)
{
    if (!t) return;
    if (t->ssl) {
        SSL_shutdown(t->ssl); /* best effort close_notify, non-blocking */
        SSL_free(t->ssl);
    }
    free(t);
}
