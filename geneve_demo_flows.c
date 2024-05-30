#include <doca_flow.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include <geneve_demo_flows.h>
#include <geneve_demo_vnet_conf.h>

#ifndef BUILD_VNI
// see samples/doca_flow/flow_common.h
#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))		/* create VNI */
#endif

#define IF_SUCCESS(result, expr) \
	if (result == DOCA_SUCCESS) { \
		result = expr; \
		if (likely(result == DOCA_SUCCESS)) { \
			DOCA_LOG_DBG("Success: %s", #expr); \
		} else { \
			DOCA_LOG_ERR("Error: %s: %s", #expr, doca_error_get_descr(result)); \
		} \
	} else { /* skip this expr */ \
	}

DOCA_LOG_REGISTER(GENEVE_FLOWS);

static const uint16_t priority_uplink_to_vf = 2;
static const uint16_t priority_vf_to_uplink = 3;

static const uint32_t ENTRY_TIMEOUT_USEC = 100;

struct doca_flow_monitor monitor_count = {
	.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
};

#define MAC_ADDR_BYTES(b) b[0], b[1], b[2], b[3], b[4], b[5]

static struct doca_flow_port *
port_init(uint16_t port_id, struct doca_dev *dev)
{
	char port_id_str[128];
	snprintf(port_id_str, sizeof(port_id_str), "%d", port_id);

	struct doca_flow_port_cfg *port_cfg;
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, doca_flow_port_cfg_create(&port_cfg));
	IF_SUCCESS(result, doca_flow_port_cfg_set_devargs(port_cfg, port_id_str));
	IF_SUCCESS(result, doca_flow_port_cfg_set_dev(port_cfg, dev));

	struct doca_flow_port * port = NULL;
	IF_SUCCESS(result, doca_flow_port_start(port_cfg, &port));
	if (port_cfg) {
		doca_flow_port_cfg_destroy(port_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)\n", result, doca_error_get_descr(result));
	}

	struct rte_ether_addr mac_addr;
	rte_eth_macaddr_get(port_id, &mac_addr);

	DOCA_LOG_INFO("\nStarted port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
		port_id,
		MAC_ADDR_BYTES(mac_addr.addr_bytes));

	return port;
}

/*
 * Entry processing callback
 *
 * @entry [in]: entry pointer
 * @pipe_queue [in]: queue identifier
 * @status [in]: DOCA Flow entry status
 * @op [in]: DOCA Flow entry operation
 * @user_ctx [out]: user context
 */
static void
check_for_valid_entry(struct doca_flow_pipe_entry *entry, uint16_t pipe_queue,
		      enum doca_flow_entry_status status, enum doca_flow_entry_op op, void *user_ctx)
{
	(void)entry;
	(void)pipe_queue;

	struct entries_status *entry_status = (struct entries_status *)user_ctx;

	if (entry_status == NULL || op != DOCA_FLOW_ENTRY_OP_ADD)
		return;
	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		//DOCA_LOG_WARN("%s: status = %d, wanted %d", __FUNCTION__, status, DOCA_FLOW_ENTRY_STATUS_SUCCESS);
		entry_status->failure = true; /* set failure to true if processing failed */
	}
	entry_status->nb_processed++;
	entry_status->entries_in_queue--;
}

static enum doca_flow_l3_type get_inner_l3_type(struct geneve_demo_config *config)
{
	return config->vnet_config->inner_addr_fam == AF_INET6 ? DOCA_FLOW_L3_TYPE_IP6 : DOCA_FLOW_L3_TYPE_IP4;
}

static enum doca_flow_l3_type get_outer_l3_type(struct geneve_demo_config *config)
{
	return config->vnet_config->outer_addr_fam == AF_INET6 ? DOCA_FLOW_L3_TYPE_IP6 : DOCA_FLOW_L3_TYPE_IP4;
}

static enum doca_flow_l3_meta get_inner_l3_meta(struct geneve_demo_config *config)
{
	return config->vnet_config->inner_addr_fam == AF_INET6 ? DOCA_FLOW_L3_META_IPV6 : DOCA_FLOW_L3_META_IPV4;
}

static enum doca_flow_l3_meta get_outer_l3_meta(struct geneve_demo_config *config)
{
	return config->vnet_config->outer_addr_fam == AF_INET6 ? DOCA_FLOW_L3_META_IPV6 : DOCA_FLOW_L3_META_IPV4;
}

/*
 * Process entries and check the returned status
 *
 * @port [in]: the port we want to process in
 * @status [in]: the entries status that was sent to the pipe
 * @timeout [in]: timeout for the entries process function
 */
static doca_error_t
process_all_entries(
	const char *pipe_name,
	struct doca_flow_port *port, 
	struct entries_status *status, 
	int timeout_usec)
{
	DOCA_LOG_DBG("Pipe %s: processing %d entries...\n", pipe_name, status->entries_in_queue);
	do {
		doca_error_t result = doca_flow_entries_process(
			port, 0, timeout_usec, status->entries_in_queue);
		if (result != DOCA_SUCCESS || status->failure) {
			DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
			return result;
		}
	} while (status->entries_in_queue > 0 && !force_quit);
	return DOCA_SUCCESS;
}

int
flow_init(
	struct geneve_demo_config *config,
	struct doca_dev *pf_dev)
{
	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_cfg *flow_cfg;
	IF_SUCCESS(result, doca_flow_cfg_create(&flow_cfg));
	IF_SUCCESS(result, doca_flow_cfg_set_pipe_queues(flow_cfg, config->dpdk_config.port_config.nb_queues));
	IF_SUCCESS(result, doca_flow_cfg_set_nr_counters(flow_cfg, 1024));
	IF_SUCCESS(result, doca_flow_cfg_set_mode_args(flow_cfg, "switch,hws,isolated"));
	IF_SUCCESS(result, doca_flow_cfg_set_cb_entry_process(flow_cfg, check_for_valid_entry));
	IF_SUCCESS(result, doca_flow_init(flow_cfg));
	if (flow_cfg) {
		doca_flow_cfg_destroy(flow_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to init DOCA Flow: %d (%s)\n", result, doca_error_get_descr(result));
	}
	DOCA_LOG_DBG("DOCA Flow init done");

	for (uint16_t port_id = 0; port_id < config->dpdk_config.port_config.nb_ports; port_id++) {
		config->ports[port_id] = port_init(port_id,
			port_id==0 ? pf_dev : NULL); // cannot return null
	}

	return 0;
}

struct doca_flow_match encap_pipe_match_ipv4 = {
	.parser_meta = {
		.port_meta = PORT_META_ID_ANY,
		.outer_l3_type = DOCA_FLOW_L3_META_IPV4,
	},
	.outer = {
		.l3_type = DOCA_FLOW_L3_TYPE_IP4,
		.ip4.dst_ip = UINT32_MAX,
	},
};

struct doca_flow_match encap_pipe_match_ipv6 = {
	.parser_meta = {
		.port_meta = PORT_META_ID_ANY,
		.outer_l3_type = DOCA_FLOW_L3_META_IPV6,
	},
	.outer = {
		.l3_type = DOCA_FLOW_L3_TYPE_IP6,
		.ip6.dst_ip = IP6_MASK_ALL,
	},
};

struct doca_flow_header_format encap_pipe_action_outer_ipv4 = {
	.eth = {
		.src_mac = ETH_MASK_ALL,
		.dst_mac = ETH_MASK_ALL,
	},
	.l3_type = DOCA_FLOW_L3_TYPE_IP4,
	.ip4 = {
		.src_ip = UINT32_MAX,
		.dst_ip = UINT32_MAX,
		.ttl = UINT8_MAX,
	},
	.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP,
	.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_GENEVE_DEFAULT_PORT),
};

struct doca_flow_header_format encap_pipe_action_outer_ipv6 = {
	.eth = {
		.src_mac = ETH_MASK_ALL,
		.dst_mac = ETH_MASK_ALL,
	},
	.l3_type = DOCA_FLOW_L3_TYPE_IP6,
	.ip6 = {
		.src_ip = IP6_MASK_ALL,
		.dst_ip = IP6_MASK_ALL,
		.hop_limit = UINT8_MAX,
	},
	.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP,
	.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_GENEVE_DEFAULT_PORT),
};

struct doca_flow_pipe*
create_encap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	int outer_addr_fam = config->vnet_config->outer_addr_fam;
	
	struct doca_flow_match match = inner_addr_fam==AF_INET ? 
		encap_pipe_match_ipv4 : 
		encap_pipe_match_ipv6;

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = PORT_ID_ANY,
	};
	struct doca_flow_actions actions = {
		.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.encap_cfg = {
			.is_l2 = false,
			.encap = {
				.outer = outer_addr_fam==AF_INET ? 
					encap_pipe_action_outer_ipv4 : 
					encap_pipe_action_outer_ipv6,
				.tun = {
					.type = DOCA_FLOW_TUN_GENEVE,
					.geneve = {
						.vni = TUNNEL_ID_ANY,
						.next_proto = UINT16_MAX,
					},
				},
			},
		}
	};
	struct doca_flow_actions *actions_ptr_arr[] = { &actions };

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_pipe *pipe = NULL;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, doca_flow_port_switch_get(port)));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "GENEVE_ENCAP_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_HOST_TO_NETWORK));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1024));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_ptr_arr, NULL, NULL, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &pipe));
	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			"GENEVE_ENCAP_PIPE", result, doca_error_get_descr(result));
	}
	return pipe;
}


struct doca_flow_pipe_entry*
create_encap_entry(
	struct doca_flow_pipe *encap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue,
	struct geneve_demo_config *config)
{
	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	int outer_addr_fam = config->vnet_config->outer_addr_fam;
	
	struct entries_status entries_status = {};
	struct doca_flow_match match = {
		.parser_meta.port_meta = session->vf_port_id,
	};
	if (inner_addr_fam==AF_INET6) {
		memcpy(match.outer.ip6.dst_ip, session->virt_remote_ip.ipv6, 16);
	} else {
		match.outer.ip4.dst_ip = session->virt_remote_ip.ipv4;
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = config->uplink_port_id,
	};

	uint16_t next_proto = inner_addr_fam==AF_INET6 ? DOCA_FLOW_ETHER_TYPE_IPV6 : DOCA_FLOW_ETHER_TYPE_IPV4;
	struct doca_flow_actions actions = {
		.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.encap_cfg = {
			.is_l2 = false,
			.encap = {
				.outer = {
					// .eth and .ip6 set below
					.l3_type = get_outer_l3_type(config),
				},
				.tun = {
					.type = DOCA_FLOW_TUN_GENEVE,
					.geneve = {
						.vni = BUILD_VNI(session->vnet_id_egress),
						.next_proto = rte_cpu_to_be_16(next_proto),
					},
				},
			},
		},
	};
	if (outer_addr_fam==AF_INET6) {
		memcpy(actions.encap_cfg.encap.outer.ip6.src_ip, session->outer_local_ip.ipv6, 16);
		memcpy(actions.encap_cfg.encap.outer.ip6.dst_ip, session->outer_remote_ip.ipv6, 16);
		actions.encap_cfg.encap.outer.ip6.hop_limit = 100;
	} else {
		actions.encap_cfg.encap.outer.ip4.src_ip = session->outer_local_ip.ipv4;
		actions.encap_cfg.encap.outer.ip4.dst_ip = session->outer_remote_ip.ipv4;
		actions.encap_cfg.encap.outer.ip4.ttl = 100;
	}
	memcpy(actions.encap_cfg.encap.outer.eth.src_mac, session->outer_smac.addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(actions.encap_cfg.encap.outer.eth.dst_mac, session->outer_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);

	if (doca_log_level_get_global_lower_limit() >= DOCA_LOG_LEVEL_INFO) {
		char match_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(inner_addr_fam, &session->virt_remote_ip, match_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Encap-Pipe Match: Session-ID: %ld, port %d, match-dst-ip: %s",
			session->session_id, match.parser_meta.port_meta, match_dst_ip);

		char encap_smac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_dmac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_src_ip[INET6_ADDRSTRLEN];
		char encap_dst_ip[INET6_ADDRSTRLEN];
		rte_ether_format_addr(encap_smac, RTE_ETHER_ADDR_FMT_SIZE, &session->outer_smac);
		rte_ether_format_addr(encap_dmac, RTE_ETHER_ADDR_FMT_SIZE, &session->outer_dmac);
		inet_ntop(outer_addr_fam, &session->outer_local_ip, encap_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(outer_addr_fam, &session->outer_remote_ip, encap_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Encap-Pipe Action: src-mac: %s, dst-mac: %s", 
			encap_smac, encap_dmac);
		DOCA_LOG_INFO("Encap-Pipe Action: VNI: %d, src-ip: %s, dst-ip: %s", 
			session->vnet_id_egress, encap_src_ip, encap_dst_ip);
	}

	int flags = DOCA_FLOW_NO_WAIT;
	++entries_status.entries_in_queue;
	struct doca_flow_pipe_entry *entry = NULL;
	doca_error_t res = doca_flow_pipe_add_entry(
		pipe_queue, encap_pipe, &match, &actions, NULL, &fwd, flags, &entries_status, &entry);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to insert decap flow for session %ld", session->session_id);
		return NULL;
	}
	process_all_entries("ENCAP", config->ports[config->uplink_port_id], &entries_status, ENTRY_TIMEOUT_USEC);

	return entry;
}

struct doca_flow_pipe*
create_decap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	int outer_addr_fam = config->vnet_config->outer_addr_fam;

	struct doca_flow_match match = {
		.parser_meta = {
			.outer_l3_type = get_outer_l3_meta(config),
			.inner_l3_type = get_inner_l3_meta(config),
		},
		.outer = {
			.l3_type = get_outer_l3_type(config),
		},
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = TUNNEL_ID_ANY,
			},
		},
		.inner = {
			.l3_type = get_inner_l3_type(config),
		},
	};

	if (outer_addr_fam==AF_INET) {
		match.outer.ip4.src_ip = UINT32_MAX;
	} else {
		memset(match.outer.ip6.src_ip, 0xFF, sizeof(match.outer.ip6.src_ip));
	}

	if (inner_addr_fam==AF_INET) {
		match.inner.ip4.dst_ip = UINT32_MAX;
	} else {
		memset(match.outer.ip6.dst_ip, 0xFF, sizeof(match.outer.ip6.dst_ip));
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = PORT_ID_ANY,
	};
	struct doca_flow_actions decap_action = {
		.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.decap_cfg = {
			.is_l2 = false,
			.eth = {
				.src_mac = ETH_MASK_ALL,
				.dst_mac = ETH_MASK_ALL,
				.type = UINT16_MAX,
			},
		},
	};
	struct doca_flow_actions *actions_arr[] = { &decap_action };

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_pipe *pipe = NULL;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, doca_flow_port_switch_get(port)));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "GENEVE_DECAP_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_NETWORK_TO_HOST));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1024));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &pipe));
	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			"GENEVE_DECAP_PIPE", result, doca_error_get_descr(result));
	}

	return pipe;
}

struct doca_flow_pipe_entry*
create_decap_entry(
	struct doca_flow_pipe *decap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue,
	struct geneve_demo_config *config)
{
	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	int outer_addr_fam = config->vnet_config->outer_addr_fam;

	struct entries_status entries_status = {};
	struct doca_flow_match match = {
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = BUILD_VNI(session->vnet_id_ingress),
			},
		},
	};
	if (outer_addr_fam==AF_INET6) {
		memcpy(match.outer.ip6.src_ip, session->outer_remote_ip.ipv6, 16);
	} else {
		match.outer.ip4.src_ip = session->outer_remote_ip.ipv4;
	}
	if (inner_addr_fam==AF_INET6) {
		memcpy(match.inner.ip6.dst_ip, session->virt_local_ip.ipv6, 16);
	} else {
		match.inner.ip4.dst_ip = session->virt_local_ip.ipv4;
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = session->vf_port_id,
	};
	struct doca_flow_actions actions = {
		.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.decap_cfg = {
			.is_l2 = false,
			.eth.type = RTE_BE16(inner_addr_fam==AF_INET ? RTE_ETHER_TYPE_IPV4 : RTE_ETHER_TYPE_IPV6),
		},
	};
	memcpy(actions.outer.eth.dst_mac, session->decap_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);
	struct rte_ether_addr* p_decap_src_mac = (struct rte_ether_addr*)actions.outer.eth.src_mac;
	rte_eth_macaddr_get(session->vf_port_id, p_decap_src_mac);
	
	if (doca_log_level_get_global_lower_limit() >= DOCA_LOG_LEVEL_INFO) {
		char outer_src_ip[INET6_ADDRSTRLEN];
		char outer_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(outer_addr_fam, &session->outer_remote_ip, outer_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(outer_addr_fam, &session->outer_local_ip, outer_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Decap-Pipe Match: Session-ID: %ld, VNI %d, match-src-ip: %s match-dst-ip: %s",
			session->session_id, session->vnet_id_ingress, outer_src_ip, outer_dst_ip);

		char decap_smac[RTE_ETHER_ADDR_FMT_SIZE];
		char decap_dmac[RTE_ETHER_ADDR_FMT_SIZE];
		rte_ether_format_addr(decap_smac, RTE_ETHER_ADDR_FMT_SIZE, p_decap_src_mac);
		rte_ether_format_addr(decap_dmac, RTE_ETHER_ADDR_FMT_SIZE, &session->decap_dmac);
		DOCA_LOG_INFO("Decap-Pipe Action: VF: %d, smac: %s, dmac: %s", 
			session->vf_port_id, decap_smac, decap_dmac);
	}

	int flags = DOCA_FLOW_NO_WAIT;
	++entries_status.entries_in_queue;
	struct doca_flow_pipe_entry *entry = NULL;
	doca_error_t res = doca_flow_pipe_add_entry(
		pipe_queue, decap_pipe, &match, &actions, NULL, &fwd, flags, &entries_status, &entry);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to insert decap flow for session %ld", session->session_id);
		return NULL;
	}
	process_all_entries("DECAP", config->ports[config->uplink_port_id], &entries_status, ENTRY_TIMEOUT_USEC);
	return entry;
}

struct doca_flow_pipe*
create_rss_pipe(
	struct doca_flow_port *port)
{
	doca_error_t res;

	struct doca_flow_pipe *rss_pipe;
	struct doca_flow_match null_match = {};
	uint16_t rss_queues[1] = { 0 };
	struct doca_flow_fwd fwd_rss = {
		.type = DOCA_FLOW_FWD_RSS,
		.num_of_queues = 1,
		.rss_queues = rss_queues,
		.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6,
	};

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, doca_flow_port_switch_get(port)));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RSS_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &null_match, &null_match));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_rss, NULL, &rss_pipe));
	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			"GENEVE_DECAP_PIPE", result, doca_error_get_descr(result));
	}

    struct doca_flow_pipe_entry *entry = NULL;
	res = doca_flow_pipe_add_entry(0, rss_pipe, &null_match, 
		NULL, NULL, NULL, 0, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add default entry to RSS pipe: %d (%s)\n",
			res, doca_error_get_descr(res));
	}

	return rss_pipe;
}

struct doca_flow_pipe_entry**
create_root_pipe(struct doca_flow_port *port,
    struct doca_flow_pipe *decap_pipe,
    struct doca_flow_pipe *encap_pipe,
	struct doca_flow_pipe *rss_pipe,
    struct geneve_demo_config *config)
{
	// NOTE: in Switch mode, we cannot create an explicit flow to send packets to target=kernel.
	// (Target type kernel is not supported in switch mode)
	// The kernel must be reached by missing all entries in the root ingress table.

	struct doca_flow_pipe_entry **entry_list = malloc(64 * sizeof(void*));
	int n_entries = 0;

	doca_error_t res;
    struct doca_flow_pipe_entry *entry = NULL;
	struct doca_flow_pipe *ctrl_pipe = NULL;

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, doca_flow_port_switch_get(port)));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 3));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, NULL, NULL, &ctrl_pipe));
	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			"ROOT", result, doca_error_get_descr(result));
	}

    struct doca_flow_match from_uplink_match_mask = {
        .parser_meta.port_meta = PORT_META_ID_ANY,
		.tun.type = DOCA_FLOW_TUN_GENEVE,
    };
    struct doca_flow_match from_uplink_match = {
        .parser_meta.port_meta = 0,
		.tun.type = DOCA_FLOW_TUN_GENEVE,
    };
    struct doca_flow_fwd from_uplink_fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = decap_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, priority_uplink_to_vf, ctrl_pipe, &from_uplink_match, &from_uplink_match_mask, 
		NULL, NULL, NULL, NULL, &monitor_count, &from_uplink_fwd, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			"ROOT", res, doca_error_get_descr(res));
	}
	entry_list[n_entries++] = entry;

	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	
	struct doca_flow_match from_vf_match_mask = {
		.parser_meta.port_meta = PORT_META_ID_ANY,
		.outer.eth.type = UINT16_MAX,
	};
	struct doca_flow_match from_vf_match = {
		.parser_meta.port_meta = 1,
		.outer.eth.type = RTE_BE16(inner_addr_fam==AF_INET ? DOCA_FLOW_ETHER_TYPE_IPV4 : DOCA_FLOW_ETHER_TYPE_IPV6),
	};
    struct doca_flow_fwd from_vf_fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = encap_pipe,
    };

    res = doca_flow_pipe_control_add_entry(
        0, priority_vf_to_uplink, ctrl_pipe, &from_vf_match, &from_vf_match_mask, 
		NULL, NULL, NULL, NULL, &monitor_count, &from_vf_fwd, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			"ROOT", res, doca_error_get_descr(res));
	}
	entry_list[n_entries++] = entry;

	from_vf_match.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_ARP);
	from_vf_fwd.type = DOCA_FLOW_FWD_PIPE;
	from_vf_fwd.next_pipe = rss_pipe;
    res = doca_flow_pipe_control_add_entry(
        0, priority_vf_to_uplink, ctrl_pipe, &from_vf_match, &from_vf_match_mask, 
		NULL, NULL, NULL, NULL, &monitor_count, &from_vf_fwd, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			"ROOT", res, doca_error_get_descr(res));
	}
	entry_list[n_entries++] = entry;

	entry_list[n_entries++] = NULL;

	// Non-tunneled IPv6 from the uplink will by default go to the kernel
	// due to running in Isolated Mode

	return entry_list;
}

struct doca_flow_pipe_entry*
create_arp_response_pipe(
	struct doca_flow_port *port,
	uint32_t arp_response_meta_flag)
{
	doca_error_t res;
	struct doca_flow_pipe *pipe;
    struct doca_flow_pipe_entry *entry = NULL;
	int flags = DOCA_FLOW_NO_WAIT;
	struct entries_status entries_status = {};

	struct doca_flow_match arp_response_match_mask = {
		.meta.pkt_meta = UINT32_MAX,
		.outer.eth.type = UINT16_MAX,
	};
	struct doca_flow_match arp_response_match = {
		.meta.pkt_meta = UINT32_MAX,
		.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_ARP),
	};

	struct doca_flow_fwd arp_response_fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = 1,
	};

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, doca_flow_port_switch_get(port)));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "ARP_RESPONSE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &arp_response_match, &arp_response_match_mask));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &arp_response_fwd, NULL, &pipe));
	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			"ARP_RESPONSE", result, doca_error_get_descr(result));
	}

	arp_response_match.meta.pkt_meta = arp_response_meta_flag;
	++entries_status.entries_in_queue;
    res = doca_flow_pipe_add_entry(
        0, pipe, &arp_response_match, NULL, NULL, NULL, flags, &entries_status,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			"ARP_RESPONSE", res, doca_error_get_descr(res));
	}

	process_all_entries("ARP_RESPONSE", port, &entries_status, ENTRY_TIMEOUT_USEC);

	return entry;
}
