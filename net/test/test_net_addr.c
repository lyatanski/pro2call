#include "net.h"
#include "test.h"

#include <string.h>

spec ("net_addr") {
    context ("parsing") {
        it ("parses IPv4") {
            net_addr a;
            check(net_addr_from(&a, "192.168.1.2", 5060) == NET_OK);
            check(a.sa.sa_family == AF_INET);
            check(net_addr_port(&a) == 5060);
        }

        it ("parses IPv6") {
            net_addr a;
            check(net_addr_from(&a, "2001:db8::1", 3868) == NET_OK);
            check(a.sa.sa_family == AF_INET6);
            check(net_addr_port(&a) == 3868);
        }

        it ("rejects hostnames") {
            net_addr a;
            check(net_addr_from(&a, "not-an-ip", 80) == NET_ERR);
        }

        it ("NULL host is the dual-stack any-address") {
            net_addr a;
            check(net_addr_from(&a, NULL, 9) == NET_OK);
            check(a.sa.sa_family == AF_INET6);
        }

        it ("builds any-address per family") {
            net_addr a;
            check(net_addr_any(&a, AF_INET, 7) == NET_OK);
            check(a.sa.sa_family == AF_INET && net_addr_port(&a) == 7);
            check(net_addr_any(&a, AF_UNSPEC, 8) == NET_OK);
            check(a.sa.sa_family == AF_INET6 && net_addr_port(&a) == 8);
        }
    }

    context ("accessors") {
        it ("round-trips the port") {
            net_addr a;
            net_addr_from(&a, "10.0.0.1", 1);
            net_addr_set_port(&a, 65535);
            check(net_addr_port(&a) == 65535);
        }

        it ("compares addresses") {
            net_addr a, b;
            net_addr_from(&a, "10.0.0.1", 5060);
            net_addr_from(&b, "10.0.0.1", 5060);
            check(net_addr_eq(&a, &b));
            net_addr_set_port(&b, 5061);
            check(!net_addr_eq(&a, &b));
            net_addr_from(&b, "::1", 5060);
            check(!net_addr_eq(&a, &b));
        }

        it ("formats v4 and v6") {
            net_addr a;
            char     buf[NET_ADDR_STRLEN];
            net_addr_from(&a, "127.0.0.1", 5060);
            check(!strcmp(net_addr_str(&a, buf), "127.0.0.1:5060"));
            net_addr_from(&a, "::1", 5060);
            check(!strcmp(net_addr_str(&a, buf), "[::1]:5060"));
        }

        it ("reports sockaddr length") {
            net_addr a;
            net_addr_from(&a, "127.0.0.1", 1);
            check(net_addr_len(&a) == sizeof(struct sockaddr_in));
            net_addr_from(&a, "::1", 1);
            check(net_addr_len(&a) == sizeof(struct sockaddr_in6));
        }
    }
}
