/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <rte_ethdev.h>
#include <doca_log.h>

#include <geneve_demo.h>

DOCA_LOG_REGISTER(GENEVE_RSS);

static int
packet_parsing_example(const struct rte_mbuf *packet)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	uint16_t ether_type = htons(eth_hdr->ether_type);

	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		DOCA_LOG_DBG("Received IPV4");
	} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
		DOCA_LOG_DBG("received IPV6");
	}

	return 0;
}

#define MAX_RX_BURST_SIZE 256


int
lcore_pkt_proc_func(void *lcore_args)
{
	uint32_t lcore_id = rte_lcore_id();

    // Note lcore_id==0 is reserved for main()
    if (lcore_id == 0)
        rte_exit(EXIT_FAILURE, "Unexpectedly entered RSS handler from main thread");

    --lcore_id;

	uint16_t queue_id = lcore_id;

	struct rte_mbuf *rx_packets[MAX_RX_BURST_SIZE];

	double tsc_to_seconds = 1.0 / (double)rte_get_timer_hz();

	while (!force_quit) {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail(); port_id++) {
            uint64_t t_start = rte_rdtsc();

            uint16_t nb_rx_packets = rte_eth_rx_burst(port_id, queue_id, rx_packets, MAX_RX_BURST_SIZE);
            for (int i=0; i<nb_rx_packets; i++) {
                packet_parsing_example(rx_packets[i]);
            }

            if (nb_rx_packets > 0) {
                double sec = (double)(rte_rdtsc() - t_start) * tsc_to_seconds;
                printf("L-Core %d port %d: processed %d packets in %f seconds\n", 
                    lcore_id, port_id, nb_rx_packets, sec);
            }
        }
	}

	return 0;
}
