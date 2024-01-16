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
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <doca_log.h>

#include <geneve_demo.h>
#include <geneve_demo_vnet_conf.h>

DOCA_LOG_REGISTER(GENEVE_RSS);

static int
handle_arp(
    struct rte_mempool *mpool, 
    uint16_t port_id, 
    uint16_t queue_id, 
    const struct rte_mbuf *request_pkt)
{
    if (port_id != 1) {
        return 0;
    }

	const struct rte_ether_hdr *request_eth_hdr = rte_pktmbuf_mtod(request_pkt, struct rte_ether_hdr *);
    const struct rte_arp_hdr *request_arp_hdr = (const void*)&request_eth_hdr[1];
    uint16_t arp_op = RTE_BE16(request_arp_hdr->arp_opcode);
    if (arp_op != RTE_ARP_OP_REQUEST)
        return 0;
    
    struct rte_mbuf *response_pkt = rte_pktmbuf_alloc(mpool);
    if (!response_pkt) {
        DOCA_LOG_ERR("Out of memory for ARP response packets; exiting");
        force_quit = true;
        return -1;
    }

    uint32_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    response_pkt->data_len = pkt_size;
    response_pkt->pkt_len = pkt_size;

	struct rte_ether_hdr *response_eth_hdr = rte_pktmbuf_mtod(response_pkt, struct rte_ether_hdr *);
    struct rte_arp_hdr *response_arp_hdr = (void*)&response_eth_hdr[1];

    rte_eth_macaddr_get(port_id, &response_eth_hdr->src_addr);
    response_eth_hdr->dst_addr = request_eth_hdr->src_addr;
    response_eth_hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);

    response_arp_hdr->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
    response_arp_hdr->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    response_arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    response_arp_hdr->arp_plen = sizeof(uint32_t);
    response_arp_hdr->arp_opcode = RTE_BE16(RTE_ARP_OP_REPLY);
    rte_eth_macaddr_get(port_id, &response_arp_hdr->arp_data.arp_sha);
    response_arp_hdr->arp_data.arp_tha = request_arp_hdr->arp_data.arp_sha;
    response_arp_hdr->arp_data.arp_sip = request_arp_hdr->arp_data.arp_tip;
    response_arp_hdr->arp_data.arp_tip = request_arp_hdr->arp_data.arp_sip;

#if 0
    rte_pktmbuf_dump(stdout, request_pkt, request_pkt->data_len);
    rte_pktmbuf_dump(stdout, response_pkt, response_pkt->data_len);
#endif

    uint16_t nb_tx_packets = 0;
    while (nb_tx_packets < 1) {
        nb_tx_packets = rte_eth_tx_burst(port_id, queue_id, &response_pkt, 1);
        if (nb_tx_packets != 1) {
            DOCA_LOG_WARN("rte_eth_tx_burst returned %d", nb_tx_packets);
        }
    }
    
    char ip_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &request_arp_hdr->arp_data.arp_tip, ip_addr_str, INET_ADDRSTRLEN);
    DOCA_LOG_INFO("Handled ARP for IP %s", ip_addr_str);

    return 1;
}

#define ICMP6_NEIGHBOR_SOLICITATION 135
#define ICMP6_NEIGHBOR_ADVERTISEMENT 136

struct icmp6_neighbor_sol_hdr {
    struct rte_icmp_base_hdr base;
    rte_be32_t reserved;
    ipv6_addr_t tgt_addr;
    // options ignored
} __rte_packed;

struct icmp6_neighbor_adv_hdr {
    struct rte_icmp_base_hdr base;
    rte_be32_t r_s_o_res;
    ipv6_addr_t tgt_addr;
    // options ignored
} __rte_packed;

static int
handle_icmp6(
    struct geneve_demo_config *config, 
    uint16_t port_id, 
    uint16_t queue_id, 
    const struct rte_mbuf *request_pkt)
{
    if (port_id != 0) {
        return 0;
    }
	const struct rte_ether_hdr *request_eth_hdr = rte_pktmbuf_mtod(request_pkt, struct rte_ether_hdr *);
    const struct rte_ipv6_hdr *request_ip_hdr = (const void*)&request_eth_hdr[1];
    const struct rte_icmp_base_hdr *request_icmp_hdr = (const void*)(const char*)&request_ip_hdr[1];
    // DOCA_LOG_INFO("ICMP6: type=%d, code=%d",
    //     request_icmp_hdr->type, request_icmp_hdr->code);
    
    if (request_icmp_hdr->type==RTE_ICMP6_ECHO_REQUEST) {
        const struct rte_icmp_echo_hdr *request_icmp_echo_hdr = (const void*)request_icmp_hdr;
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, request_ip_hdr->dst_addr, dst_ip, INET6_ADDRSTRLEN);
        printf("ICMP6: seq = %d, dst = %s\n",
            request_icmp_echo_hdr->sequence, dst_ip);
    } else if (request_icmp_hdr->type==ICMP6_NEIGHBOR_SOLICITATION) {
        const struct icmp6_neighbor_sol_hdr *request_sol_hdr = (const void*)request_icmp_hdr;
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, request_sol_hdr->tgt_addr, dst_ip, INET6_ADDRSTRLEN);
        DOCA_LOG_INFO("ICMP6: Neighbor solicitation: %s", dst_ip);
        
        for (int i=0; i<config->self->num_nics; i++) {
            const struct nic_t *my_nic = &config->self->nics[i];
            const uint8_t *my_ip = my_nic->ip.ipv6;
            if (memcmp(my_ip, request_sol_hdr->tgt_addr, sizeof(ipv6_addr_t)) != 0) {
                continue;
            }

            struct rte_mbuf *response_pkt = rte_pktmbuf_alloc(config->dpdk_config.mbuf_pool);
            if (!response_pkt) {
                DOCA_LOG_ERR("Out of memory for ICMP6 response packets; exiting");
                force_quit = true;
                return -1;
            }

            uint32_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct icmp6_neighbor_adv_hdr);
            response_pkt->data_len = pkt_size;
            response_pkt->pkt_len = pkt_size;

            struct rte_ether_hdr *response_eth_hdr = rte_pktmbuf_mtod(response_pkt, struct rte_ether_hdr *);
            rte_ether_addr_copy(&my_nic->mac_addr, &response_eth_hdr->src_addr);
            rte_ether_addr_copy(&request_eth_hdr->src_addr, &response_eth_hdr->dst_addr);
            response_eth_hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);

            struct rte_ipv6_hdr *response_ipv6_hdr = (void*)&response_eth_hdr[1];
            memcpy(response_ipv6_hdr->src_addr, my_ip, sizeof(ipv6_addr_t));
            memcpy(response_ipv6_hdr->dst_addr, request_ip_hdr->src_addr, sizeof(ipv6_addr_t));
            response_ipv6_hdr->payload_len = RTE_BE16(sizeof(struct icmp6_neighbor_adv_hdr));
            response_ipv6_hdr->proto = DOCA_PROTO_ICMP6;

            struct icmp6_neighbor_adv_hdr *response_icmp6_hdr = (void*)&response_ipv6_hdr[1];
            response_icmp6_hdr->base.type = ICMP6_NEIGHBOR_ADVERTISEMENT;
            response_icmp6_hdr->r_s_o_res = 0x4; // solicited
            memcpy(response_icmp6_hdr->tgt_addr, my_ip, sizeof(ipv6_addr_t));            

#if 0
            rte_pktmbuf_dump(stdout, request_pkt, request_pkt->data_len);
            rte_pktmbuf_dump(stdout, response_pkt, response_pkt->data_len);
#endif

            uint16_t nb_tx_packets = 0;
            while (nb_tx_packets < 1) {
                nb_tx_packets = rte_eth_tx_burst(port_id, queue_id, &response_pkt, 1);
                if (nb_tx_packets != 1) {
                    DOCA_LOG_WARN("rte_eth_tx_burst returned %d", nb_tx_packets);
                }
            }
            
            DOCA_LOG_INFO("Sent ICMP6 Neighbor advertisement in response");
        }
    }

    return 0;
}

static int
handle_ipv6(
    struct geneve_demo_config *config, 
    uint16_t port_id, 
    uint16_t queue_id, 
    const struct rte_mbuf *packet)
{
	const struct rte_ether_hdr *request_eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    const struct rte_ipv6_hdr *request_ip_hdr = (const void*)&request_eth_hdr[1];
    //DOCA_LOG_DBG("IPv6 proto: %d", request_ip_hdr->proto);
    if (request_ip_hdr->proto == DOCA_PROTO_ICMP6) {
        return handle_icmp6(config, port_id, queue_id, packet);
    }
    return 0;
}

static int
handle_packet(
    struct geneve_demo_config *config, 
    uint16_t port_id, 
    uint16_t queue_id, 
    const struct rte_mbuf *packet)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	uint16_t ether_type = htons(eth_hdr->ether_type);
    if (ether_type > 1500 && ether_type != 0x88cc) { // ignore LLDP
        DOCA_LOG_INFO("Received ethertype 0x%x on port %d", ether_type, port_id);
    }

    if (ether_type == RTE_ETHER_TYPE_ARP) {
        handle_arp(config->dpdk_config.mbuf_pool, port_id, queue_id, packet);
	} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        handle_ipv6(config, port_id, queue_id, packet);
    } // TODO: handle outer ipv4 ICMP
	return 0;
}

#define MAX_RX_BURST_SIZE 256


int
lcore_pkt_proc_func(void *lcore_args)
{
    struct geneve_demo_config *config = lcore_args;

	uint32_t lcore_id = rte_lcore_id();

    // Note lcore_id==0 is reserved for main()
    if (lcore_id == 0) {
        rte_exit(EXIT_FAILURE, "Unexpectedly entered RSS handler from main thread\n");
    }

	uint16_t queue_id = lcore_id - 1;

	struct rte_mbuf *rx_packets[MAX_RX_BURST_SIZE];

	double tsc_to_seconds = 1.0 / (double)rte_get_timer_hz();

	while (!force_quit) {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail() && !force_quit; port_id++) {
            uint64_t t_start = rte_rdtsc();

            uint16_t nb_rx_packets = rte_eth_rx_burst(
                port_id, queue_id, rx_packets, MAX_RX_BURST_SIZE);

            for (int i=0; i<nb_rx_packets && !force_quit; i++) {
                handle_packet(config, port_id, queue_id, rx_packets[i]);
            }
            

            if (nb_rx_packets > 0) {
                rte_pktmbuf_free_bulk(rx_packets, nb_rx_packets);

                if (false) {
                    double sec = (double)(rte_rdtsc() - t_start) * tsc_to_seconds;
                    printf("L-Core %d port %d: processed %d packets in %f seconds\n", 
                        lcore_id, port_id, nb_rx_packets, sec);
                }
            }
        }
	}

	return 0;
}
