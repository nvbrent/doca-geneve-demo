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

static int64_t max64(int64_t x, int64_t y)
{
	return x > y ? x : y;
}

static int64_t show_counters(
	struct rte_hash *session_ht,
	struct geneve_demo_config *config, 
	bool display)
{
	session_id_t *session_id = NULL;
	struct session_def *session = NULL;
	uint32_t session_itr = 0;
	int64_t total_hits = 0;

	while (rte_hash_iterate(session_ht, (const void**)&session_id, (void**)&session, &session_itr) >= 0) {
		doca_error_t res;
		struct doca_flow_query flow_stats = {};
		
		res = doca_flow_query_entry(session->encap_entry, &flow_stats);
		int64_t encap_hits = (res==DOCA_SUCCESS) ? flow_stats.total_pkts : -1;
		
		res = doca_flow_query_entry(session->decap_entry, &flow_stats);
		int64_t decap_hits = (res==DOCA_SUCCESS) ? flow_stats.total_pkts : -1;
		
		if (display)
			DOCA_LOG_INFO("Session %ld encap: %ld hits, decap: %ld hits", 
				session->session_id, encap_hits, decap_hits);
		
		total_hits += max64(0, encap_hits) + max64(0, decap_hits);
	}
	return total_hits;
}

int
main(int argc, char **argv)
{
	struct vnet_config_t vnet_config = {};
	struct geneve_demo_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 0, // updated after dpdk_init()
				.nb_queues = 1,
				.nb_hairpin_q = 1,
			},
		},
		.uplink_port_id = 0,
		.vnet_config = &vnet_config,
	};

	/* Register a logger backend */
	struct doca_log_backend *sdk_log;
	doca_error_t result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		exit(1);

	/* Register a logger backend for internal SDK errors and warnings */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		exit(1);
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		exit(1);
	
	/* Parse cmdline/json arguments */
	doca_argp_init("doca-geneve-demo", &config);
	doca_argp_set_dpdk_program(dpdk_init);
	geneve_demo_register_argp_params();
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to parse args\n");
	}

	result = load_vnet_config(config.vnet_config_file, &vnet_config);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to load config file\n");
	}

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail(); // attach to the PF and all the available VFs

	if (config.dpdk_config.port_config.nb_ports < 2) {
		rte_exit(EXIT_FAILURE, "Num ports probed: %d, min: %d\n", config.dpdk_config.port_config.nb_ports, 2);
	} else {
		DOCA_LOG_INFO("Starting %d ports...", config.dpdk_config.port_config.nb_ports);
	}

	install_signal_handler();

	dpdk_queues_and_ports_init(&config.dpdk_config);

	struct rte_hash *session_ht = session_ht_create();

	uint16_t nb_ports = config.dpdk_config.port_config.nb_ports;

	config.ports = malloc(nb_ports * sizeof(struct doca_flow_port*));

	flow_init(&config);

	// Create Geneve Option List here, if desired
	// struct doca_flow_parser *parser = NULL;
	// doca_error_t res = doca_flow_parser_geneve_opt_create(ports[config.uplink_port_id], NULL, 0, &parser);
	// if (res != DOCA_SUCCESS)
	// 	rte_exit(EXIT_FAILURE, "Port %d: Failed to doca_flow_parser_geneve_opt_create(): %d (%s)\n",
	// 		config.uplink_port_id, res, doca_error_get_descr(res));

	struct doca_flow_pipe *decap_pipe = create_decap_tunnel_pipe(config.ports[config.uplink_port_id], &config);
	struct doca_flow_pipe *encap_pipe = create_encap_tunnel_pipe(config.ports[config.uplink_port_id], &config);
	create_root_pipe(config.ports[config.uplink_port_id], decap_pipe, encap_pipe, &config);

	load_vnet_conf_sessions(&config, session_ht, encap_pipe, decap_pipe);
	
	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(lcore_pkt_proc_func, &config, lcore_id);
	}

	int64_t prev_total_count = -1;
	while (!force_quit) {
		sleep(2);

		if (show_counters(session_ht, &config, false) != prev_total_count) {
			prev_total_count = show_counters(session_ht, &config, true);
		}
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
		rte_eal_wait_lcore(lcore_id);
	}
	
	for (int i = 1; i < nb_ports; i++) {
		DOCA_LOG_INFO("Stopping Port %d...", i);
		doca_flow_port_stop(config.ports[i]);
	}
	DOCA_LOG_INFO("Stopping Port %d...", 0);
	doca_flow_port_stop(config.ports[0]); // stop the switch port last

	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}
