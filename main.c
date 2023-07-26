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

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>

#include <dpdk_utils.h>
#include <doca_argp.h>
#include <doca_log.h>
#include <doca_flow.h>

#include "geneve_demo.h"

DOCA_LOG_REGISTER(GENEVE_DEMO);

#ifndef BUILD_VNI
// see samples/doca_flow/flow_common.h
#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))		/* create VNI */
#endif

////////////////////////////////////////////////////////////////////////////////
// Signal Handling

volatile bool force_quit = false;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void install_signal_handler(void)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

////////////////////////////////////////////////////////////////////////////////
// DOCA Flow

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
		.mode_args = "switch,hws,isolated",
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
create_encap_tunnel_pipe(struct doca_flow_port *port)
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
				},
			},
		}
	};
	struct doca_flow_actions *actions_ptr_arr[] = { &actions };

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = "GENEVE_ENCAP_PIPE",
			.type = DOCA_FLOW_PIPE_BASIC,
			.is_root = true,
			.nb_actions = sizeof(actions_ptr_arr) / sizeof(actions_ptr_arr[0]),
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

struct doca_flow_pipe*
create_decap_tunnel_pipe(struct doca_flow_port *port)
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
			.is_root = true,
			.nb_actions = sizeof(actions_arr) / sizeof(actions_arr[0]),
		},
		.port = port,
		.match = &match,
		.monitor = &mon,
		.actions = actions_arr,
		.actions_masks = actions_arr,
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

int
main(int argc, char **argv)
{
	struct geneve_demo_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 2,
				.nb_queues = 1,
				.nb_hairpin_q = 1,
			},
		},
	};

	struct doca_logger_backend *stdout_logger = NULL;
	doca_log_create_file_backend(stdout, &stdout_logger);
	
	/* Parse cmdline/json arguments */
	doca_argp_init("doca-geneve-demo", &config);
	doca_argp_set_dpdk_program(dpdk_init);
	geneve_demo_register_argp_params();
	doca_argp_start(argc, argv);

	install_signal_handler();

	dpdk_queues_and_ports_init(&config.dpdk_config);

	uint16_t nb_ports = config.dpdk_config.port_config.nb_ports;
	uint16_t uplink_port_id = 0;

	struct doca_flow_port **ports = malloc(nb_ports * sizeof(struct doca_flow_port*));

	flow_init(&config.dpdk_config, ports);

	// struct doca_flow_parser *parser = NULL;
	// doca_error_t res = doca_flow_parser_geneve_opt_create(ports[uplink_port_id], NULL, 0, &parser);
	// if (res != DOCA_SUCCESS)
	// 	rte_exit(EXIT_FAILURE, "Port %d: Failed to doca_flow_parser_geneve_opt_create(): %d (%s)",
	// 		uplink_port_id, res, doca_get_error_name(res));

	struct doca_flow_pipe *decap_pipe = create_decap_tunnel_pipe(ports[uplink_port_id]);
	struct doca_flow_pipe *encap_pipe = create_encap_tunnel_pipe(ports[uplink_port_id]);

	for (int test=0; test<2; test++) {
		struct session_def session = {
			.session_id = 1234 + test,
			.tunnel_id = 1, 
			.vf_port_id = 1 + test, 
			.vnet_id = 201 + test,
			.dmac = { "\xee\x00\x00\x00\x00\x11" },
		};
		uint32_t pipe_queue = 0;
		create_decap_entry(decap_pipe, &session, pipe_queue);
		create_encap_entry(encap_pipe, &session, pipe_queue);
	}
	
	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(lcore_pkt_proc_func, &config, lcore_id);
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}
	
	for (int i = 0; i < nb_ports; i++) {
		doca_flow_port_stop(ports[i]);
	}
	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}
