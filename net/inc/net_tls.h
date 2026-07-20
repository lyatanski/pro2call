#ifndef NET_TLS_H
#define NET_TLS_H

#include "net_sock.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS (over TCP) and DTLS (over connected UDP) via OpenSSL.
 *
 * A net_tls_ctx wraps one SSL_CTX and is shared by many sessions.
 * cert/key are PEM files (required for servers); ca enables peer
 * verification, NULL disables it (the usual mode for a test tool
 * talking to lab equipment).
 *
 * A net_tls session sits on top of an already connected net_sock and
 * never owns the fd. All calls follow the net_sock timeout convention;
 * with timeout_ms < 0 the handshake returns NET_WANT_RD/NET_WANT_WR so
 * it can be driven from the event loop. */

enum {
    NET_TLS_SERVER = 1,
    NET_TLS_DTLS   = 2,
};

typedef struct net_tls_ctx net_tls_ctx;
typedef struct net_tls     net_tls;

API_EXPORT net_tls_ctx* net_tls_ctx_new(unsigned flags, const char* cert,
                                        const char* key, const char* ca);
API_EXPORT void         net_tls_ctx_free(net_tls_ctx*);

API_EXPORT net_tls* net_tls_new(net_tls_ctx*, const net_sock*);
API_EXPORT int      net_tls_shake(net_tls*, int timeout_ms);
API_EXPORT ssize_t  net_tls_send(net_tls*, const void*, size_t, int timeout_ms);
API_EXPORT ssize_t  net_tls_recv(net_tls*, void*, size_t, int timeout_ms);
API_EXPORT void net_tls_free(net_tls*); /* sends close_notify, keeps the fd */

#ifdef __cplusplus
}
#endif

#endif /* NET_TLS_H */
