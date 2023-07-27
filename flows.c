#include <doca_flow.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include <geneve_demo.h>

#ifndef BUILD_VNI
// see samples/doca_flow/flow_common.h
#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))		/* create VNI */
#endif

DOCA_LOG_REGISTER(GENEVE_FLOWS);

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
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)", res, doca_get_error_name(res));
	}
	DOCA_LOG_INFO("Started port %d", port_id);
	return port;
}

int
flow_init(
	struct application_dpdk_config *dpdk_config,
	struct doca_flow_port *ports[])
{
	struct doca_flow_cfg arp_sc_flow_cfg = {
		.mode_args = "switch,hws",
		.queues = dpdk_config->port_config.nb_queues,
		.resource.nb_counters = 1024,
	};

	doca_error_t res = doca_flow_init(&arp_sc_flow_cfg);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to init DOCA Flow: %d (%s)", res, doca_get_error_name(res));
	}
	DOCA_LOG_DBG("DOCA Flow init done");

	for (uint16_t port_id = 0; port_id < dpdk_config->port_config.nb_ports; port_id++) {
		ports[port_id] = port_init(port_id); // cannot return null
	}

	return 0;
}

struct doca_flow_pipe*
create_encap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	struct doca_flow_match match = {
		.meta.port_meta = PORT_META_ID_ANY,
		// ignore all other fields
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
					//.src_mac = ETH_MASK_ALL,
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
            .is_root = !config->use_empty_root_pipe,
		},
		.port = doca_flow_port_switch_get(port),
		.match = &match,
		.monitor = &mon,
		.actions = actions_ptr_arr,
	};

	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)",
			cfg.attr.name, res, doca_get_error_name(res));
	}
	return pipe;
}


struct doca_flow_pipe_entry*
create_encap_entry(
	struct doca_flow_pipe *encap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue)
{
	struct doca_flow_match match = {
		.meta.port_meta = session->vf_port_id,
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = 0, // uplink port ID
	};
	struct doca_flow_actions actions = {
		.has_encap = true,
		.encap = {
			.outer = {
				.eth = {
					.dst_mac = "\xee\x00\x00\x00\x00\x22", // TODO (tunnel_def)
				},
				.l3_type = DOCA_FLOW_L3_TYPE_IP6,
				.ip6 = {
					.src_ip = { 0x1, 0x2, 0x3, 0x4 }, // TODO (tunnel_def)
					.dst_ip = { 0x5, 0x6, 0x7, 0x8 },
				},
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
	struct rte_ether_addr port_mac_addr;
	rte_eth_macaddr_get(0, &port_mac_addr);
	memcpy(actions.encap.outer.eth.src_mac, port_mac_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

	int flags = DOCA_FLOW_NO_WAIT;
	struct doca_flow_pipe_entry *entry = NULL;
	doca_error_t res = doca_flow_pipe_add_entry(
		pipe_queue, encap_pipe, &match, &actions, NULL, &fwd, flags, NULL, &entry);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to insert decap flow for session %ld", session->session_id);
		return NULL;
	}
	return entry;
}

struct doca_flow_pipe*
create_decap_tunnel_pipe(struct doca_flow_port *port, struct geneve_demo_config *config)
{
	struct doca_flow_match match = {
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = TUNNEL_ID_ANY,
			},
		}
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
			//.src_mac = ETH_MASK_ALL,
			.dst_mac = ETH_MASK_ALL,
		},
	};
	struct doca_flow_actions *actions_arr[] = { &decap_action };
	
	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_DECAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.nb_actions = sizeof(actions_arr) / sizeof(actions_arr[0]),
            .is_root = !config->use_empty_root_pipe,
		},
		.port = port,
		.match = &match,
		.monitor = &mon,
		.actions = actions_arr,
	};
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t res = doca_flow_pipe_create(&cfg, &fwd, NULL, &pipe);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)",
			cfg.attr.name, res, doca_get_error_name(res));
	}
	return pipe;
}

struct doca_flow_pipe_entry*
create_decap_entry(
	struct doca_flow_pipe *decap_pipe, 
	struct session_def *session,
	uint32_t pipe_queue)
{
	struct doca_flow_match match = {
		.tun = {
			.type = DOCA_FLOW_TUN_GENEVE,
			.geneve = {
				.vni = BUILD_VNI(session->vnet_id),
			},
		}
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = session->vf_port_id,
	};
	struct doca_flow_actions actions = {
		.decap = true,
	};
	memcpy(actions.outer.eth.dst_mac, session->dmac, RTE_ETHER_ADDR_LEN);
	rte_eth_macaddr_get(session->vf_port_id, (struct rte_ether_addr*)actions.outer.eth.src_mac);
	
	int flags = DOCA_FLOW_NO_WAIT;
	struct doca_flow_pipe_entry *entry = NULL;
	doca_error_t res = doca_flow_pipe_add_entry(
		pipe_queue, decap_pipe, &match, &actions, NULL, &fwd, flags, NULL, &entry);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to insert decap flow for session %ld", session->session_id);
		return NULL;
	}
	return entry;
}

struct doca_flow_pipe*
create_empty_root_pipe(struct doca_flow_port *port,
    struct doca_flow_pipe *uplink_next_pipe,
    struct doca_flow_pipe *vf_next_pipe)
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
		rte_exit(EXIT_FAILURE, "Failed to create Pipe %s: %d (%s)",
			cfg.attr.name, res, doca_get_error_name(res));
	}

    struct doca_flow_pipe_entry *entry = NULL;

    struct doca_flow_match match_mask = {
        .meta.port_meta = PORT_META_ID_ANY,
    };
    struct doca_flow_match match_uplink = {
        .meta.port_meta = 0,
    };
    struct doca_flow_fwd fwd_uplink = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = uplink_next_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, 1, pipe, &match_uplink, &match_mask, NULL, NULL, NULL, NULL, &fwd_uplink, NULL, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)",
			cfg.attr.name, res, doca_get_error_name(res));
	}

    struct doca_flow_fwd fwd_vf = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = vf_next_pipe,
    };
    res = doca_flow_pipe_control_add_entry(
        0, 2, pipe, NULL, NULL, NULL, NULL, NULL, NULL, &fwd_vf, NULL, &entry);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to add Pipe Entry %s: %d (%s)",
			cfg.attr.name, res, doca_get_error_name(res));
	}

	return pipe;
}