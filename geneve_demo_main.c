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

static void
insert_test_sessions(
	struct rte_hash *session_ht,
	struct doca_flow_pipe *encap_pipe,
	struct doca_flow_pipe *decap_pipe,
	struct geneve_demo_config *config)
{
	// Define a macro which sets the inner 12 digits of an IPv6 address to zero,
	// leaving 2 digits before and after.
	#define ZEROS_X_4 "\x00\x00\x00\x00"
	#define ZEROS_X_12 ZEROS_X_4 ZEROS_X_4 ZEROS_X_4
	
	#define MACHINE1_VNET1_ADDR "\x00\x11" ZEROS_X_12 "\xca\xfe"
	#define MACHINE2_VNET1_ADDR "\x00\x11" ZEROS_X_12 "\xbe\xef"

	#define MACHINE1_VNET2_ADDR "\x00\x22" ZEROS_X_12 "\xca\xfe"
	#define MACHINE2_VNET2_ADDR "\x00\x22" ZEROS_X_12 "\xbe\xef"

	struct session_def sessions_instance1[] = {
		{
			.session_id = 101,
			.vf_port_id = 1,
			.vnet_id = 201,
			.virt_local_ip   = MACHINE1_VNET1_ADDR,
			.virt_remote_ip  = MACHINE2_VNET1_ADDR,
			.outer_remote_ip = "\x00\x99" ZEROS_X_12 "\x00\x22",
		},
		{
			.session_id = 102,
			.vf_port_id = 2,
			.vnet_id = 202,
			.virt_local_ip   = MACHINE1_VNET2_ADDR,
			.virt_remote_ip  = MACHINE2_VNET2_ADDR,
			.outer_remote_ip = "\x00\x99" ZEROS_X_12 "\x00\x22",
		},
	};
	struct session_def sessions_instance2[] = {
		{
			.session_id = 103,
			.vf_port_id = 1,
			.vnet_id = 201,
			.virt_local_ip   = MACHINE2_VNET1_ADDR,
			.virt_remote_ip  = MACHINE1_VNET1_ADDR,
			.outer_remote_ip = "\x00\x99" ZEROS_X_12 "\x00\x11",
		},
		{
			.session_id = 104,
			.vf_port_id = 2,
			.vnet_id = 202,
			.virt_local_ip   = MACHINE2_VNET2_ADDR,
			.virt_remote_ip  = MACHINE1_VNET2_ADDR,
			.outer_remote_ip = "\x00\x99" ZEROS_X_12 "\x00\x11",
		},
	};

	struct session_def *sessions = NULL;
	if (config->test_machine_instance == 1)
		sessions = sessions_instance1;
	else if (config->test_machine_instance == 2)
		sessions = sessions_instance2;
	else
		return;

	int num_sessions = 2;

	for (int i=0; i<num_sessions; i++) {
		struct session_def * session = rte_zmalloc(NULL, sizeof(struct session_def), 0);
		*session = sessions[i];

		uint32_t pipe_queue = 0;
		session->decap_entry = create_decap_entry(decap_pipe, &sessions[i], pipe_queue, config);
		session->encap_entry = create_encap_entry(encap_pipe, &sessions[i], pipe_queue, config);
		
		add_session(session_ht, session);
	}
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

		// outer_smac auto-detected below
		// outer_dmac set by argp
		// outer_src_ip set by argp
	};

	struct doca_logger_backend *stdout_logger = NULL;
	doca_log_create_file_backend(stdout, &stdout_logger);
	
	/* Parse cmdline/json arguments */
	doca_argp_init("doca-geneve-demo", &config);
	doca_argp_set_dpdk_program(dpdk_init);
	geneve_demo_register_argp_params();
	doca_argp_start(argc, argv);

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail(); // attach to the PF and all the available VFs

	install_signal_handler();

	dpdk_queues_and_ports_init(&config.dpdk_config);

	if (rte_eth_macaddr_get(0, &config.outer_smac) != 0)
		rte_exit(EXIT_FAILURE, "Failed to obtain mac addrs for port 0\n");

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

	insert_test_sessions(session_ht, encap_pipe, decap_pipe, &config);
	
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
