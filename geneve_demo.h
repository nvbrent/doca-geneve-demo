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

#define ETH_MASK_ALL "\xFF\xFF\xFF\xFF\xFF\xFF"
#define IP6_MASK_ALL { UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX }
#define PORT_ID_ANY UINT16_MAX
#define PORT_META_ID_ANY UINT32_MAX
#define TUNNEL_ID_ANY UINT32_MAX

struct geneve_demo_config
{
	struct application_dpdk_config dpdk_config;

	// TODO: additional config fields here
};

struct tunnel_def
{
    uint64_t tunnel_id;
    uint8_t src_ip[16];
    uint8_t dest_ip[16];
};

struct session_def
{
    uint64_t session_id;
    uint64_t tunnel_id;
    uint16_t vf_port_id;
    uint16_t vnet_id;
	uint8_t dmac[RTE_ETHER_ADDR_LEN];
};

int lcore_pkt_proc_func(void *lcore_args);

void geneve_demo_register_argp_params(void);

extern volatile bool force_quit;
