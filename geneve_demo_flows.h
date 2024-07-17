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

#include <doca_flow.h>
#include <geneve_demo.h>

#define ETH_MASK_ALL "\xFF\xFF\xFF\xFF\xFF\xFF"
#define IP6_MASK_ALL { UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX }
#define PORT_ID_ANY UINT16_MAX
#define PORT_META_ID_ANY UINT32_MAX
#define TUNNEL_ID_ANY UINT32_MAX

int
flow_init(
	struct geneve_demo_config *dpdk_config);

struct doca_flow_pipe*
create_encap_tunnel_pipe(struct doca_flow_port *port, struct doca_flow_pipe *next_pipe, struct geneve_demo_config *config);

struct doca_flow_pipe*
create_decap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config);

struct doca_flow_pipe_entry*
create_encap_entry(
	struct doca_flow_pipe *encap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue,
	struct geneve_demo_config *config);

struct doca_flow_pipe_entry*
create_decap_entry(
	struct doca_flow_pipe *decap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue,
	struct geneve_demo_config *config);

struct doca_flow_pipe*
create_rss_pipe(
	uint16_t nr_queues,
	struct doca_flow_port *port);

struct doca_flow_pipe_entry**
create_root_pipe(
	struct doca_flow_port *port, 
	uint16_t uplink_port_id,
	uint16_t vf_port_id,
	struct doca_flow_pipe *decap_pipe,
	struct doca_flow_pipe *encap_pipe,
	struct doca_flow_pipe *rss_pipe,
	struct geneve_demo_config *config);

struct doca_flow_pipe_entry*
create_arp_response_pipe(
	struct doca_flow_port *port,
	uint16_t port_id,
	uint32_t arp_response_meta_flag);

struct doca_flow_pipe *
create_sampling_pipe(
	enum doca_flow_pipe_domain domain,
	uint32_t random_mask, 
	uint32_t pkt_meta, 
	struct doca_flow_port *port, 
	uint32_t mirror_id, 
	struct doca_flow_pipe *next_pipe,
	struct doca_flow_pipe *miss_pipe,
	struct doca_flow_pipe_entry **sampling_entry);

struct doca_flow_pipe *
create_fwd_to_port_pipe(struct doca_flow_port *port, uint32_t port_id, struct doca_flow_pipe_entry **fwd_entry);

doca_error_t configure_mirror(uint32_t mirror_id, enum doca_flow_pipe_domain domain, struct doca_flow_pipe *next_pipe, struct doca_flow_port *owner_port);
