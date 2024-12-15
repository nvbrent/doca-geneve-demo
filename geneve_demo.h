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
struct vnet_host_t;

typedef uint8_t ipv6_addr_t[16];
typedef uint8_t crypto_key_t[KEY_LEN / 8];

extern volatile bool force_quit;

enum sample_direction_indicator {
    SAMPLE_DIRECTION_EGRESS = 1234,
    SAMPLE_DIRECTION_INGRESS = 4321,
};

enum { max_num_pf = 8, max_vf_per_pf = 2, max_num_ports = max_num_pf * max_vf_per_pf };

struct flows_and_stats
{
	struct doca_flow_port *pf_port;

	uint16_t uplink_port_id;
	uint16_t vf_port_id;

	struct doca_flow_pipe_entry *sampling_entry_list[4];

	struct doca_flow_pipe *rss_pipe;
	struct doca_flow_pipe *fwd_to_uplink_pipe;

	struct doca_flow_pipe *decap_pipe;

	struct doca_flow_pipe *ingr_sampl_pipe;

	struct doca_flow_pipe *egr_sampl_pipe;

	struct doca_flow_pipe *encap_pipe;

	struct doca_flow_pipe_entry **root_pipe_entry_list;

	struct doca_flow_pipe_entry *arp_response_entry_list[2];

	int64_t prev_root_pipe_total_count;
	int64_t prev_arp_resp_pipe_total_count;
	int64_t prev_sampling_total_count;
};

typedef uint64_t session_id_t;

struct geneve_demo_config
{
	struct application_dpdk_config dpdk_config;

	uint32_t core_mask;
	
	uint32_t num_pfs;

	struct doca_flow_port *ports[max_num_ports];
	bool port_is_pf[max_num_ports];
	struct doca_dev *pf_dev[max_num_ports];

	uint32_t mirror_id_ingress_to_rss[max_num_pf];
	uint32_t mirror_id_egress_to_rss[max_num_pf];
	uint32_t sample_mask; // 0 for 1:1 sampling, UINT32_MAX to disable

	const char *vnet_config_file;

	session_id_t next_session_id;
	struct vnet_config_t *vnet_config;
	const struct vnet_host_t *self[max_num_pf];

	uint32_t arp_response_meta_flag;

	bool enable_uplink_icmp_handling;

	struct flows_and_stats flows[max_num_pf];
};

struct session_def
{
    session_id_t session_id;
    uint16_t pf_port_id;
    uint16_t vf_port_id;
    uint16_t vnet_id_ingress;
    uint16_t vnet_id_egress;

    struct rte_ether_addr outer_smac;
    struct rte_ether_addr outer_dmac;
    
    struct doca_flow_ip_addr outer_local_ip;
    struct doca_flow_ip_addr outer_remote_ip;

    // decap_smac will be the mac addr of the port representor
    struct rte_ether_addr decap_dmac;

    struct doca_flow_ip_addr virt_local_ip;
    struct doca_flow_ip_addr virt_remote_ip;

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

// Prepares argc,argv for parsing by DPDK by first removing all
// -a arguments, so that DOCA can create the verbs device before
// opening the port, as required by switch mode.
int disable_dpdk_accept_args(
	int argc, 
	char *argv[], 
	char *dpdk_argv[], 
	char *pci_addr_arg[max_num_pf]);

void geneve_demo_register_argp_params(void);

struct rte_hash;

int load_vnet_conf_sessions(
    struct geneve_demo_config *demo_config,
    uint32_t uplink_port_id,
    uint32_t vf_port_id,
    struct rte_hash *session_ht,
	struct doca_flow_pipe *encap_pipe, 
	struct doca_flow_pipe *decap_pipe);
