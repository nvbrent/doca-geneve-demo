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

#pragma once

#include <inttypes.h>
#include <rte_ether.h>
#include <offload_rules.h>

#define KEY_LEN 256

typedef uint8_t ipv6_addr_t[16];
typedef uint8_t crypto_key_t[KEY_LEN / 8];

extern volatile bool force_quit;

struct geneve_demo_config
{
	struct application_dpdk_config dpdk_config;

    uint16_t uplink_port_id; // always 0

    struct rte_ether_addr outer_smac;
    struct rte_ether_addr outer_dmac;
    ipv6_addr_t outer_src_ip;

    struct rte_ether_addr decap_dmac; // TODO: make this per-VF
    // TODO: per-VF smac, dmac configuration.
    // For now, just preserve the outer eth addresses.

    int test_machine_instance;
};

typedef uint64_t session_id_t;

struct session_def
{
    session_id_t session_id;
    uint16_t vf_port_id;
    uint16_t vnet_id;
    ipv6_addr_t virt_local_ip;
    ipv6_addr_t virt_remote_ip;
    ipv6_addr_t outer_remote_ip;

    crypto_key_t encrypt_key; // TODO: is it necessary to keep keys in memory?
    crypto_key_t decrypt_key;

    struct doca_flow_pipe_entry *encap_entry;
    struct doca_flow_pipe_entry *decap_entry;
};

int lcore_pkt_proc_func(void *lcore_args);

void geneve_demo_register_argp_params(void);
