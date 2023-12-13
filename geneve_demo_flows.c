#include <doca_flow.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include <geneve_demo_flows.h>
#include <geneve_demo_vnet_conf.h>

#ifndef BUILD_VNI
// see samples/doca_flow/flow_common.h
#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))		/* create VNI */
#endif

DOCA_LOG_REGISTER(GENEVE_FLOWS);

static const uint16_t priority_arp = 1;
static const uint16_t priority_uplink_to_vf = 3;
static const uint16_t priority_vf_to_uplink = 2;

static const uint32_t ENTRY_TIMEOUT_USEC = 100;

struct doca_flow_monitor monitor_count = {
	.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
};

static struct doca_flow_port *
port_init(uint16_t port_id)
{
	char port_id_str[128];
	snprintf(port_id_str, sizeof(port_id_str), "%d", port_id);

	struct doca_flow_port_cfg port_cfg = {
		.port_id = port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str,
	};
	struct doca_flow_port * port = NULL;
	doca_error_t res = doca_flow_port_start(&port_cfg, &port);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)\n", res, doca_error_get_descr(res));
	}

	struct rte_ether_addr mac_addr;
	rte_eth_macaddr_get(port_id, &mac_addr);

	DOCA_LOG_INFO("\nStarted port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
		port_id,
		mac_addr.addr_bytes[0],
		mac_addr.addr_bytes[1],
		mac_addr.addr_bytes[2],
		mac_addr.addr_bytes[3],
		mac_addr.addr_bytes[4],
		mac_addr.addr_bytes[5]);

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
	//(void)pipe_queue;

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
	struct geneve_demo_config *config)
{
	struct doca_flow_cfg flow_cfg = {
		.mode_args = "switch,hws",
		.queues = config->dpdk_config.port_config.nb_queues,
		.resource.nb_counters = 1024,
		.cb = check_for_valid_entry,
	};

	doca_error_t res = doca_flow_init(&flow_cfg);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to init DOCA Flow: %d (%s)\n", res, doca_error_get_descr(res));
	}
	DOCA_LOG_DBG("DOCA Flow init done");

	for (uint16_t port_id = 0; port_id < config->dpdk_config.port_config.nb_ports; port_id++) {
		config->ports[port_id] = port_init(port_id); // cannot return null
	}

	return 0;
}

struct doca_flow_pipe*
create_encap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	struct doca_flow_match match = {
		.parser_meta.port_meta = PORT_META_ID_ANY,
		.outer = {
			.l3_type = get_inner_l3_type(config),
			.ip6.dst_ip = IP6_MASK_ALL,
		},
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = PORT_ID_ANY,
	};
	struct doca_flow_actions actions = {
		.has_encap = true,
		.encap = {
			.outer = {
				.eth = {
					.src_mac = ETH_MASK_ALL,
					.dst_mac = ETH_MASK_ALL,
				},
				.l3_type = get_outer_l3_type(config),
				.ip4 = {
					.src_ip = UINT32_MAX,
					.dst_ip = UINT32_MAX,
				},
				.ip6 = {
					.src_ip = IP6_MASK_ALL,
					.dst_ip = IP6_MASK_ALL,
				},
			},
			.tun = {
				.type = DOCA_FLOW_TUN_GENEVE,
				.geneve = {
					.vni = TUNNEL_ID_ANY,
                    .next_proto = UINT16_MAX,
				},
			},
		}
	};
	struct doca_flow_actions *actions_ptr_arr[] = { &actions };

	struct doca_flow_action_desc encap_action_desc = {
		.type = DOCA_FLOW_ACTION_DECAP_ENCAP,
		.decap_encap.is_l2 = true,
	};
	struct doca_flow_action_descs encap_action_descs = {
		.nb_action_desc = 1,
		.desc_array = &encap_action_desc,
	};
	struct doca_flow_action_descs *action_descs_arr[] = { &encap_action_descs };

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_ENCAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.nb_actions = sizeof(actions_ptr_arr) / sizeof(actions_ptr_arr[0]),
			.enable_strict_matching = true,
		},
		.port = doca_flow_port_switch_get(port),
		.match = &match,
		.monitor = &monitor_count,
		.actions = actions_ptr_arr,
		.action_descs = action_descs_arr,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_error_get_descr(res));
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
	struct entries_status entries_status = {};
	struct doca_flow_match match = {
		.parser_meta.port_meta = session->vf_port_id,
		.outer.l3_type = get_inner_l3_type(config),
	};
	if (config->vnet_config->inner_addr_fam==AF_INET6) {
		memcpy(match.outer.ip6.dst_ip, session->virt_remote_ip.ipv6, 16);
	} else {
		match.outer.ip4.dst_ip = session->virt_remote_ip.ipv4;
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = config->uplink_port_id,
	};
	struct doca_flow_actions actions = {
		.has_encap = true,
		.encap = {
			.outer = {
				// .eth and .ip6 set below
				.l3_type = get_outer_l3_type(config),
			},
			.tun = {
				.type = DOCA_FLOW_TUN_GENEVE,
				.geneve = {
					.vni = BUILD_VNI(session->vnet_id_egress),
                    .next_proto = rte_cpu_to_be_16(DOCA_ETHER_TYPE_IPV6),
				},
			},
		},
	};
	if (config->vnet_config->outer_addr_fam==AF_INET6) {
		memcpy(actions.encap.outer.ip6.src_ip, session->outer_local_ip.ipv6, 16);
		memcpy(actions.encap.outer.ip6.dst_ip, session->outer_remote_ip.ipv6, 16);
	} else {
		actions.encap.outer.ip4.src_ip = session->outer_local_ip.ipv4;
		actions.encap.outer.ip4.dst_ip = session->outer_remote_ip.ipv4;
	}
	memcpy(actions.encap.outer.eth.src_mac, session->outer_smac.addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(actions.encap.outer.eth.dst_mac, session->outer_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);

	if (doca_log_level_get_global_lower_limit() >= DOCA_LOG_LEVEL_INFO) {
		char match_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(config->vnet_config->inner_addr_fam, &session->virt_remote_ip, match_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Encap-Pipe Match: Session-ID: %ld, VF %d, match-dst-ip: %s",
			session->session_id, match.parser_meta.port_meta, match_dst_ip);

		char encap_smac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_dmac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_src_ip[INET6_ADDRSTRLEN];
		char encap_dst_ip[INET6_ADDRSTRLEN];
		rte_ether_format_addr(encap_smac, RTE_ETHER_ADDR_FMT_SIZE, &session->outer_smac);
		rte_ether_format_addr(encap_dmac, RTE_ETHER_ADDR_FMT_SIZE, &session->outer_dmac);
		inet_ntop(config->vnet_config->outer_addr_fam, &session->outer_local_ip, encap_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(config->vnet_config->outer_addr_fam, &session->outer_remote_ip, encap_dst_ip, INET6_ADDRSTRLEN);
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
	struct doca_flow_match match = {
		.outer = {
			.l3_type = get_outer_l3_type(config),
			.ip4 = {
				.src_ip = UINT32_MAX,
			},
			.ip6 = {
				.src_ip = IP6_MASK_ALL,
			},
		},
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = TUNNEL_ID_ANY,
				.next_proto = rte_cpu_to_be_16(DOCA_ETHER_TYPE_IPV6),
			},
		},
		.inner = {
			.l3_type = get_inner_l3_type(config),
			.ip4 = {
				.dst_ip = UINT32_MAX,
			},
			.ip6 = {
				.dst_ip = IP6_MASK_ALL,
			},
		},
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = PORT_ID_ANY,
	};
	struct doca_flow_actions decap_action = {
		.decap = true,
		.outer.eth = {
			.src_mac = ETH_MASK_ALL,
			.dst_mac = ETH_MASK_ALL,
		},
	};
	struct doca_flow_actions *actions_arr[] = { &decap_action };

	struct doca_flow_action_desc decap_action_desc = {
		.type = DOCA_FLOW_ACTION_DECAP_ENCAP,
		.decap_encap.is_l2 = true,
	};
	struct doca_flow_action_descs decap_action_descs = {
		.nb_action_desc = 1,
		.desc_array = &decap_action_desc,
	};
	struct doca_flow_action_descs *action_descs_arr[] = { &decap_action_descs };
	
	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_DECAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.nb_actions = sizeof(actions_arr) / sizeof(actions_arr[0]),
			.enable_strict_matching = true,
		},
		.port = port,
		.match = &match,
		.monitor = &monitor_count,
		.actions = actions_arr,
		.action_descs = action_descs_arr,
	};
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_error_get_descr(res));
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
	struct entries_status entries_status = {};
	struct doca_flow_match match = {
		.outer.l3_type = get_outer_l3_type(config),
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = BUILD_VNI(session->vnet_id_ingress),
			},
		},
		.inner.l3_type = get_inner_l3_type(config),
	};
	if (config->vnet_config->outer_addr_fam==AF_INET6) {
		memcpy(match.outer.ip6.src_ip, session->outer_remote_ip.ipv6, 16);
	} else {
		match.outer.ip4.src_ip = session->outer_remote_ip.ipv4;
	}
	if (config->vnet_config->inner_addr_fam==AF_INET6) {
		memcpy(match.inner.ip6.dst_ip, session->virt_local_ip.ipv6, 16);
	} else {
		match.inner.ip4.dst_ip = session->virt_local_ip.ipv4;
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = session->vf_port_id,
	};
	struct doca_flow_actions actions = {
		.decap = true,
	};
	memcpy(actions.outer.eth.dst_mac, session->decap_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);
	struct rte_ether_addr* p_decap_src_mac = (struct rte_ether_addr*)actions.outer.eth.src_mac;
	rte_eth_macaddr_get(session->vf_port_id, p_decap_src_mac);
	
	if (doca_log_level_get_global_lower_limit() >= DOCA_LOG_LEVEL_INFO) {
		char outer_src_ip[INET6_ADDRSTRLEN];
		char outer_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(config->vnet_config->outer_addr_fam, &session->outer_remote_ip, outer_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(config->vnet_config->outer_addr_fam, &session->outer_local_ip, outer_dst_ip, INET6_ADDRSTRLEN);
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

void forward_arp_ping(
	const char *entry_name,
	struct doca_flow_pipe *pipe,
	int addr_fam,
	bool is_arp, // else ping
	struct doca_flow_pipe_entry **ingress_entry,
	struct doca_flow_pipe_entry **egress_entry)
{
	struct doca_flow_match mask = { .parser_meta.port_meta = UINT32_MAX };
	struct doca_flow_match match = mask;
	if (addr_fam==AF_INET) {
		if (is_arp) {
			match.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_ARP);
		} else {
			mask.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
			mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
			mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP;
		}
	} else {
		mask.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV6;
		mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6;
		mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP6;
	}

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
	};

	match.parser_meta.port_meta = 0;
	fwd.port_id = 1;

	doca_error_t res = doca_flow_pipe_control_add_entry(
		0, priority_arp, pipe, &match, &mask, NULL, NULL, NULL, &monitor_count, &fwd, NULL,
		ingress_entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry Ingress-%s: %d (%s)\n",
			entry_name, res, doca_error_get_descr(res));
	}

	match.parser_meta.port_meta = 1;
	fwd.port_id = 0;

	res = doca_flow_pipe_control_add_entry(
		0, priority_arp, pipe, &match, &mask, NULL, NULL, NULL, &monitor_count, &fwd, NULL,
		egress_entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry Egress-%s: %d (%s)\n",
			entry_name, res, doca_error_get_descr(res));
	}
}

struct doca_flow_pipe*
create_root_pipe(struct doca_flow_port *port,
    struct doca_flow_pipe *decap_pipe,
    struct doca_flow_pipe *encap_pipe,
    struct geneve_demo_config *config)
{
	struct doca_flow_pipe *pipe = NULL;

    struct doca_flow_pipe_cfg cfg = {
        .attr = {
            .name = "ROOT",
            .is_root = true,
            .type = DOCA_FLOW_PIPE_CONTROL,
        },
        .port = port,
    };

	doca_error_t res = doca_flow_pipe_create(&cfg, NULL, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_error_get_descr(res));
	}
    struct doca_flow_pipe_entry *entry = NULL;

    struct doca_flow_match match_mask = {
        .parser_meta.port_meta = PORT_META_ID_ANY,
		.tun.type = DOCA_FLOW_TUN_GENEVE,
    };
    struct doca_flow_match match_uplink = {
        .parser_meta.port_meta = 0,
    };
    struct doca_flow_fwd fwd_uplink = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = decap_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, priority_vf_to_uplink, pipe, &match_uplink, &match_mask, NULL, NULL, NULL, NULL, &fwd_uplink, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_error_get_descr(res));
	}

    struct doca_flow_fwd fwd_vf = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = encap_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, priority_uplink_to_vf, pipe, NULL, NULL, NULL, NULL, NULL, NULL, &fwd_vf, NULL,
		&entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_error_get_descr(res));
	}

	int inner_addr_fam = config->vnet_config->inner_addr_fam;
	forward_arp_ping("ARP", pipe, inner_addr_fam, false, &config->arp_ingress_entry, &config->arp_egress_entry);
	if (inner_addr_fam == AF_INET) {
		forward_arp_ping("PING", pipe, inner_addr_fam, true, &config->ping_ingress_entry, &config->ping_egress_entry);
	} else {
		// IPv6 uses ICMP for both discovery and for ping
		config->ping_ingress_entry = config->arp_ingress_entry;
		config->ping_egress_entry = config->arp_egress_entry;
	}

	// TODO: DHCP

	return pipe;
}