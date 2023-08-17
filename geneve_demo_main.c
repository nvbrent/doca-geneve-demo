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
#include <rte_malloc.h>

#include <dpdk_utils.h>
#include <doca_log.h>
#include <doca_argp.h>

#include <geneve_demo.h>
#include <geneve_demo_flows.h>
#include <geneve_demo_session_hashtable.h>
#include <geneve_demo_vnet_conf.h>

DOCA_LOG_REGISTER(GENEVE_DEMO);

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

int
main(int argc, char **argv)
{
	struct geneve_demo_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 0, // updated after dpdk_init()
				.nb_queues = 1,
				.nb_hairpin_q = 1,
			},
		},
		.uplink_port_id = 0,
	};

	struct doca_logger_backend *stdout_logger = NULL;
	doca_log_create_file_backend(stdout, &stdout_logger);
	
	/* Parse cmdline/json arguments */
	doca_argp_init("doca-geneve-demo", &config);
	doca_argp_set_dpdk_program(dpdk_init);
	geneve_demo_register_argp_params();
	doca_argp_start(argc, argv);

	struct vnet_config_t vnet_config = {};
	doca_error_t result = load_vnet_config(config.vnet_config_file, &vnet_config);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to load config file");
	}

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail(); // attach to the PF and all the available VFs

	install_signal_handler();

	dpdk_queues_and_ports_init(&config.dpdk_config);

	struct rte_hash *session_ht = session_ht_create();

	uint16_t nb_ports = config.dpdk_config.port_config.nb_ports;

	struct doca_flow_port **ports = malloc(nb_ports * sizeof(struct doca_flow_port*));

	flow_init(&config.dpdk_config, ports);

	// Create Geneve Option List here, if desired
	// struct doca_flow_parser *parser = NULL;
	// doca_error_t res = doca_flow_parser_geneve_opt_create(ports[config.uplink_port_id], NULL, 0, &parser);
	// if (res != DOCA_SUCCESS)
	// 	rte_exit(EXIT_FAILURE, "Port %d: Failed to doca_flow_parser_geneve_opt_create(): %d (%s)\n",
	// 		config.uplink_port_id, res, doca_get_error_name(res));

	struct doca_flow_pipe *decap_pipe = create_decap_tunnel_pipe(ports[config.uplink_port_id], &config);
	struct doca_flow_pipe *encap_pipe = create_encap_tunnel_pipe(ports[config.uplink_port_id], &config);
	struct doca_flow_pipe *arp_pipe = create_arp_pipe(ports[config.uplink_port_id], &config);
	create_root_pipe(ports[config.uplink_port_id], decap_pipe, encap_pipe, arp_pipe, &config);

	load_vnet_conf_sessions(&config, &vnet_config, session_ht, encap_pipe, decap_pipe);
	
#if 0
	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(lcore_pkt_proc_func, &config, lcore_id);
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}
#else
	while (!force_quit) sleep(1);
#endif
	
	for (int i = 0; i < nb_ports; i++) {
		doca_flow_port_stop(ports[i]);
	}
	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}
