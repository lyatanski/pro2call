#include "gtpu_ebpf.h"
#include "test.h"

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

/* Unprivileged checks: the map/wire ABI layout the BPF side compiled
 * against, and the API's behaviour without CAP_BPF. The datapath
 * itself is exercised by test_gtpu_bpf (needs privileges). */

spec ("gtpu") {
    context ("abi layout") {
        it ("keeps the GTP-U header at wire size") {
            check(sizeof(struct gtpu_hdr) == 8);
            check(offsetof(struct gtpu_hdr, msg_type) == 1);
            check(offsetof(struct gtpu_hdr, length) == 2);
            check(offsetof(struct gtpu_hdr, teid) == 4);
        }

        it ("keeps map value layouts stable across BPF and host") {
            check(sizeof(struct gtpu_rx_tun) == 24);
            check(offsetof(struct gtpu_rx_tun, inner_addr) == 2);
            check(offsetof(struct gtpu_rx_tun, ifindex) == 20);

            check(sizeof(struct gtpu_tx_tun) == 48);
            check(offsetof(struct gtpu_tx_tun, remote_addr) == 4);
            check(offsetof(struct gtpu_tx_tun, remote_port) == 32);
            check(offsetof(struct gtpu_tx_tun, remote_teid) == 36);
            check(offsetof(struct gtpu_tx_tun, ifindex) == 44);
        }

        it ("keeps the TFT key layout stable (hash key bytes)") {
            check(sizeof(struct gtpu_tft_key) == 24);
            check(offsetof(struct gtpu_tft_key, ue_port) == 2);
            check(offsetof(struct gtpu_tft_key, remote_port) == 4);
            check(offsetof(struct gtpu_tft_key, ue_addr) == 8);
        }

        it ("keeps LPM keys at kernel-expected sizes") {
            check(sizeof(struct gtpu_lpm4_key) == 8);
            check(sizeof(struct gtpu_lpm6_key) == 20);
        }

        it ("keeps stats, event and config layouts stable") {
            check(sizeof(struct gtpu_stats) == 9 * 8);
            check(sizeof(struct gtpu_event) == 28);
            check(offsetof(struct gtpu_event, src_addr) == 12);
            check(sizeof(struct gtpu_config) == 28);
        }

        it ("uses a power-of-two stats table") {
            check((GTPU_STATS_ENTRIES & (GTPU_STATS_ENTRIES - 1)) == 0);
            check(GTPU_STATS_MASK == GTPU_STATS_ENTRIES - 1);
        }
    }

    context ("capability fallback") {
        it ("open() degrades cleanly without privileges") {
            gtpu_ebpf_cfg_t cfg;
            memset(&cfg, 0, sizeof cfg);
            cfg.pin_dir     = ""; /* no bpffs dependency */
            cfg.max_bearers = 1024;

            gtpu_ebpf_t* g  = (gtpu_ebpf_t*)&cfg; /* must be reset */
            int          rc = gtpu_ebpf_open(&g, &cfg);
            if (gtpu_ebpf_supported()) {
                check(rc == GTPU_OK);
                check(g != NULL);
                gtpu_ebpf_close(g);
            } else {
                check(rc == GTPU_E_UNSUPPORTED);
                check(g == NULL);
            }
        }
    }

    context ("argument validation") {
        it ("rejects null handles") {
            gtpu_tunnel_t t;
            memset(&t, 0, sizeof t);
            int rc = gtpu_teid_add(NULL, &t);
            check(rc == GTPU_E_INVAL || rc == GTPU_E_UNSUPPORTED);
            rc = gtpu_stats_read(NULL, 0, NULL);
            check(rc == GTPU_E_INVAL || rc == GTPU_E_UNSUPPORTED);
            rc = gtpu_ebpf_detach(NULL);
            check(rc == GTPU_E_INVAL || rc == GTPU_E_UNSUPPORTED);
        }
    }
}
