#define _GNU_SOURCE
#include "net.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int net_addr_any(net_addr* a, int family, uint16_t port)
{
    memset(a, 0, sizeof *a);
    if (family == AF_INET) {
        a->v4.sin_family      = AF_INET;
        a->v4.sin_addr.s_addr = htonl(INADDR_ANY);
        a->v4.sin_port        = htons(port);
        return NET_OK;
    }
    if (family == AF_INET6 || family == AF_UNSPEC) {
        a->v6.sin6_family = AF_INET6;
        a->v6.sin6_addr   = in6addr_any;
        a->v6.sin6_port   = htons(port);
        return NET_OK;
    }
    return NET_ERR;
}

int net_addr_from(net_addr* a, const char* host, uint16_t port)
{
    if (!host) return net_addr_any(a, AF_UNSPEC, port);
    memset(a, 0, sizeof *a);
    if (inet_pton(AF_INET, host, &a->v4.sin_addr) == 1) {
        a->v4.sin_family = AF_INET;
        a->v4.sin_port   = htons(port);
        return NET_OK;
    }
    if (inet_pton(AF_INET6, host, &a->v6.sin6_addr) == 1) {
        a->v6.sin6_family = AF_INET6;
        a->v6.sin6_port   = htons(port);
        return NET_OK;
    }
    return NET_ERR;
}

socklen_t net_addr_len(const net_addr* a)
{
    switch (a->sa.sa_family) {
    case AF_INET:  return sizeof a->v4;
    case AF_INET6: return sizeof a->v6;
    default:       return sizeof a->ss;
    }
}

uint16_t net_addr_port(const net_addr* a)
{
    if (a->sa.sa_family == AF_INET) return ntohs(a->v4.sin_port);
    if (a->sa.sa_family == AF_INET6) return ntohs(a->v6.sin6_port);
    return 0;
}

void net_addr_set_port(net_addr* a, uint16_t port)
{
    if (a->sa.sa_family == AF_INET) a->v4.sin_port = htons(port);
    if (a->sa.sa_family == AF_INET6) a->v6.sin6_port = htons(port);
}

int net_addr_eq(const net_addr* a, const net_addr* b)
{
    if (a->sa.sa_family != b->sa.sa_family) return 0;
    if (a->sa.sa_family == AF_INET)
        return a->v4.sin_port == b->v4.sin_port &&
               a->v4.sin_addr.s_addr == b->v4.sin_addr.s_addr;
    if (a->sa.sa_family == AF_INET6)
        return a->v6.sin6_port == b->v6.sin6_port &&
               !memcmp(&a->v6.sin6_addr, &b->v6.sin6_addr,
                       sizeof a->v6.sin6_addr);
    return 0;
}

const char* net_addr_str(const net_addr* a, char buf[NET_ADDR_STRLEN])
{
    char ip[INET6_ADDRSTRLEN] = "?";
    if (a->sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &a->v4.sin_addr, ip, sizeof ip);
        snprintf(buf, NET_ADDR_STRLEN, "%s:%u", ip, net_addr_port(a));
    } else if (a->sa.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &a->v6.sin6_addr, ip, sizeof ip);
        snprintf(buf, NET_ADDR_STRLEN, "[%s]:%u", ip, net_addr_port(a));
    } else snprintf(buf, NET_ADDR_STRLEN, "?");
    return buf;
}
