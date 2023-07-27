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
	config.use_empty_root_pipe = true; // TODO

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

	struct doca_flow_pipe *decap_pipe = create_decap_tunnel_pipe(ports[uplink_port_id], &config);
	struct doca_flow_pipe *encap_pipe = create_encap_tunnel_pipe(ports[uplink_port_id], &config);
	if (config.use_empty_root_pipe)
		(void)create_empty_root_pipe(ports[uplink_port_id], decap_pipe, encap_pipe);

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
