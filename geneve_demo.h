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
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <dpdk_utils.h>
#include <doca_flow.h>

#define KEY_LEN 256

struct vnet_config_t;

typedef uint8_t ipv6_addr_t[16];
typedef uint8_t crypto_key_t[KEY_LEN / 8];

extern volatile bool force_quit;

union ip_addr
{
    rte_be32_t ipv4;
    ipv6_addr_t ipv6;
};

struct geneve_demo_config
{
	struct application_dpdk_config dpdk_config;

	struct doca_flow_port **ports;
    
    const char *vnet_config_file;

    uint16_t uplink_port_id; // always 0

	struct vnet_config_t *vnet_config;
};

typedef uint64_t session_id_t;

struct session_def
{
    session_id_t session_id;
    uint16_t vf_port_id;
    uint16_t vnet_id_ingress;
    uint16_t vnet_id_egress;

    struct rte_ether_addr outer_smac;
    struct rte_ether_addr outer_dmac;
    
    union ip_addr outer_local_ip;
    union ip_addr outer_remote_ip;

    // decap_smac will be the mac addr of the port representor
    struct rte_ether_addr decap_dmac;

    union ip_addr virt_local_ip;
    union ip_addr virt_remote_ip;

    crypto_key_t encrypt_key; // TODO: is it necessary to keep keys in memory?
    crypto_key_t decrypt_key;

    struct doca_flow_pipe_entry *encap_entry;
    struct doca_flow_pipe_entry *decap_entry;
};

/* user context struct that will be used in entries process callback */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

int lcore_pkt_proc_func(void *lcore_args);

void geneve_demo_register_argp_params(void);

struct rte_hash;

int load_vnet_conf_sessions(
    struct geneve_demo_config *demo_config,
    struct rte_hash *session_ht,
	struct doca_flow_pipe *encap_pipe, 
	struct doca_flow_pipe *decap_pipe);
