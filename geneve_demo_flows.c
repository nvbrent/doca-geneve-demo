#include <doca_flow.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include <geneve_demo_flows.h>

#ifndef BUILD_VNI
// see samples/doca_flow/flow_common.h
#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))		/* create VNI */
#endif

DOCA_LOG_REGISTER(GENEVE_FLOWS);

static const uint16_t priority_arp = 1;
static const uint16_t priority_uplink_to_vf = 3;
static const uint16_t priority_vf_to_uplink = 2;

static const uint32_t ENTRY_TIMEOUT_USEC = 100;

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
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)\n", res, doca_get_error_name(res));
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
check_for_valid_entry(struct doca_flow_pipe_entry *entry, /*uint16_t pipe_queue,*/
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
			DOCA_LOG_ERR("Failed to process entries: %s", doca_get_error_string(result));
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
		rte_exit(EXIT_FAILURE, "Failed to init DOCA Flow: %d (%s)\n", res, doca_get_error_name(res));
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
		.meta.port_meta = PORT_META_ID_ANY,
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
			.ip6.dst_ip = IP6_MASK_ALL,
		},
	};
	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
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
				.l3_type = DOCA_FLOW_L3_TYPE_IP6,
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

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_ENCAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.nb_actions = sizeof(actions_ptr_arr) / sizeof(actions_ptr_arr[0]),
		},
		//.port = doca_flow_port_switch_get(port), // DOCA 2.2+
		.port = doca_flow_port_switch_get(),
		.match = &match,
		.monitor = &mon,
		.actions = actions_ptr_arr,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
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
		.meta.port_meta = session->vf_port_id,
		.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6,
	};
	memcpy(match.outer.ip6.dst_ip, session->virt_remote_ip, 16);

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = config->uplink_port_id,
	};
	struct doca_flow_actions actions = {
		.has_encap = true,
		.encap = {
			.outer = {
				// .eth and .ip6 set below
				.l3_type = DOCA_FLOW_L3_TYPE_IP6,
			},
			.tun = {
				.type = DOCA_FLOW_TUN_GENEVE,
				.geneve = {
					.vni = BUILD_VNI(session->vnet_id),
                    .next_proto = rte_cpu_to_be_16(DOCA_ETHER_TYPE_IPV6),
				},
			},
		},
	};
	memcpy(actions.encap.outer.ip6.src_ip, config->outer_src_ip, 16);
	memcpy(actions.encap.outer.ip6.dst_ip, session->outer_remote_ip, 16);
	memcpy(actions.encap.outer.eth.src_mac, config->outer_smac.addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(actions.encap.outer.eth.dst_mac, config->outer_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);

	if (doca_log_global_level_get() >= DOCA_LOG_LEVEL_INFO) {
		char match_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, session->virt_remote_ip, match_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Encap-Pipe Match: Session-ID: %ld, VF %d, match-dst-ip: %s",
			session->session_id, match.meta.port_meta, match_dst_ip);

		char encap_smac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_dmac[RTE_ETHER_ADDR_FMT_SIZE];
		char encap_src_ip[INET6_ADDRSTRLEN];
		char encap_dst_ip[INET6_ADDRSTRLEN];
		rte_ether_format_addr(encap_smac, RTE_ETHER_ADDR_FMT_SIZE, &config->outer_smac);
		rte_ether_format_addr(encap_dmac, RTE_ETHER_ADDR_FMT_SIZE, &config->outer_dmac);
		inet_ntop(AF_INET6, config->outer_src_ip, encap_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, session->outer_remote_ip, encap_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Encap-Pipe Action: src-mac: %s, dst-mac: %s", 
			encap_smac, encap_dmac);
		DOCA_LOG_INFO("Encap-Pipe Action: VNI: %d, src-ip: %s, dst-ip: %s", 
			session->vnet_id, encap_src_ip, encap_dst_ip);
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
			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
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
			// .l3_type = DOCA_FLOW_L3_TYPE_IP6,
			.ip6 = {
				.dst_ip = IP6_MASK_ALL,
			},
		},
	};
	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
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
	
	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_DECAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.nb_actions = sizeof(actions_arr) / sizeof(actions_arr[0]),
		},
		.port = port,
		.match = &match,
		.monitor = &mon,
		.actions = actions_arr,
	};
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
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
		.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6,
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = BUILD_VNI(session->vnet_id),
			},
		},
		.inner.l3_type = DOCA_FLOW_L3_TYPE_IP6,
	};
	memcpy(match.outer.ip6.src_ip, session->outer_remote_ip, 16);
	memcpy(match.inner.ip6.dst_ip, session->virt_local_ip, 16);

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = session->vf_port_id,
	};
	struct doca_flow_actions actions = {
		.decap = true,
	};
	memcpy(actions.outer.eth.dst_mac, config->decap_dmac.addr_bytes, RTE_ETHER_ADDR_LEN);
	struct rte_ether_addr* p_decap_src_mac = (struct rte_ether_addr*)actions.outer.eth.src_mac;
	rte_eth_macaddr_get(session->vf_port_id, p_decap_src_mac);
	
	if (doca_log_global_level_get() >= DOCA_LOG_LEVEL_INFO) {
		char outer_src_ip[INET6_ADDRSTRLEN];
		char outer_dst_ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, session->outer_remote_ip, outer_src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, config->outer_src_ip, outer_dst_ip, INET6_ADDRSTRLEN);
		DOCA_LOG_INFO("Decap-Pipe Match: Session-ID: %ld, VNI %d, match-src-ip: %s match-dst-ip: %s",
			session->session_id, session->vnet_id, outer_src_ip, outer_dst_ip);

		char decap_smac[RTE_ETHER_ADDR_FMT_SIZE];
		char decap_dmac[RTE_ETHER_ADDR_FMT_SIZE];
		rte_ether_format_addr(decap_smac, RTE_ETHER_ADDR_FMT_SIZE, p_decap_src_mac);
		rte_ether_format_addr(decap_dmac, RTE_ETHER_ADDR_FMT_SIZE, &config->decap_dmac);
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
create_arp_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	struct entries_status entries_status = {};
	struct doca_flow_match mask = {
		.meta = {
			.port_meta = UINT32_MAX,
		},
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
			.ip6.next_proto = UINT8_MAX,
		}
	};
	struct doca_flow_match match = {
		.meta = {
			.port_meta = UINT32_MAX,
		},
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
			.ip6.next_proto = DOCA_PROTO_ICMP6,
		}
	};

	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT,
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = PORT_ID_ANY,
	};
	
	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "ARP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
		},
		.port = port,
		.match = &match,
		.match_mask = &mask,
		.monitor = &mon,
	};
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	struct doca_flow_pipe_entry *entry = NULL;
	match.meta.port_meta = 0;
	
	fwd.port_id = 1; // TODO: for now, just forward to the first VF

	++entries_status.entries_in_queue;
	res = doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, 0, &entries_status, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	match.meta.port_meta = 1; // TODO: for now, just forward from the first VF
	fwd.port_id = 0;
	++entries_status.entries_in_queue;
	res = doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, 0, &entries_status, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	process_all_entries(cfg.attr.name, port, &entries_status, ENTRY_TIMEOUT_USEC);
	
	return pipe;
}

struct doca_flow_pipe*
create_root_pipe(struct doca_flow_port *port,
    struct doca_flow_pipe *decap_pipe,
    struct doca_flow_pipe *encap_pipe,
	struct doca_flow_pipe *arp_pipe,
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
			cfg.attr.name, res, doca_get_error_name(res));
	}

    struct doca_flow_pipe_entry *entry = NULL;

    struct doca_flow_match match_mask = {
        .meta.port_meta = PORT_META_ID_ANY,
		.tun.type = DOCA_FLOW_TUN_GENEVE,
    };
    struct doca_flow_match match_uplink = {
        .meta.port_meta = 0,
    };
    struct doca_flow_fwd fwd_uplink = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = decap_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, priority_vf_to_uplink, pipe, &match_uplink, &match_mask, NULL, NULL, NULL, &fwd_uplink, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

    struct doca_flow_fwd fwd_vf = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = encap_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, priority_uplink_to_vf, pipe, NULL, NULL, NULL, NULL, NULL, &fwd_vf, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	struct doca_flow_match match_icmp = {
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP6,
			.ip6.next_proto = DOCA_PROTO_ICMP6,
		}
	};
	struct doca_flow_fwd fwd_to_arp_pipe = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = arp_pipe,
	};
	res = doca_flow_pipe_control_add_entry(
        0, priority_arp, pipe, &match_icmp, NULL, NULL, NULL, NULL, &fwd_to_arp_pipe, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)\n",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	// TODO: DHCP

	return pipe;
}