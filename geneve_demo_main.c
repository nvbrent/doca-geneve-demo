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

#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <dpdk_utils.h>
#include <doca_log.h>
#include <doca_dev.h>
#include <doca_dpdk.h>
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

typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

doca_error_t
open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t is_addr_equal = 0;
	int res;
	size_t i;
	char *pci_addr_lowercase = strdup(pci_addr);
	int pci_addr_len = strlen(pci_addr);

	for (int i=0; i<pci_addr_len; i++) {
		pci_addr_lowercase[i] = tolower(pci_addr[i]);
	}

	/* Set default return value */
	*retval = NULL;

	res = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", res);
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr_lowercase, &is_addr_equal);
		if (res == DOCA_SUCCESS && is_addr_equal) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS) {
				doca_devinfo_destroy_list(dev_list);
				free(pci_addr_lowercase);
				return res;
			}
		}
	}

	DOCA_LOG_WARN("Matching device not found: %s", pci_addr);
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_destroy_list(dev_list);
	free(pci_addr_lowercase);
	return res;
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
		struct doca_flow_resource_query flow_stats = {};
		
		res = doca_flow_resource_query_entry(session->encap_entry, &flow_stats);
		int64_t encap_hits = (res==DOCA_SUCCESS) ? flow_stats.counter.total_pkts : -1;
		
		res = doca_flow_resource_query_entry(session->decap_entry, &flow_stats);
		int64_t decap_hits = (res==DOCA_SUCCESS) ? flow_stats.counter.total_pkts : -1;
		
		if (display && (encap_hits || decap_hits))
			DOCA_LOG_INFO("Session %ld encap: %ld hits, decap: %ld hits", 
				session->session_id, encap_hits, decap_hits);
		
		total_hits += max64(0, encap_hits) + max64(0, decap_hits);
	}
	return total_hits;
}

static int64_t show_entry_list_counters(
	const char *entry_list_name,
	struct doca_flow_pipe_entry **entry_list,
	struct geneve_demo_config *config, 
	bool display)
{
	int64_t total_hits = 0;

	for (int entry_idx = 0; entry_list[entry_idx] != NULL; entry_idx++) {
		doca_error_t res;
		struct doca_flow_resource_query flow_stats = {};
		
		res = doca_flow_resource_query_entry(entry_list[entry_idx], &flow_stats);
		int64_t hits = (res==DOCA_SUCCESS) ? flow_stats.counter.total_pkts : -1;
		
		if (display && hits)
			DOCA_LOG_INFO("%s entry[%d]: %ld hits", 
				entry_list_name, entry_idx, hits);
		
		total_hits += max64(0, hits);
	}
	return total_hits;
}

void stop_ports(struct geneve_demo_config *config, bool is_stopping_pfs)
{
	for (int i = 0; i < config->dpdk_config.port_config.nb_ports; i++) {
		if (config->port_is_pf[i] == is_stopping_pfs) {
			DOCA_LOG_INFO("Stopping Port %d...", i);
			doca_flow_port_stop(config->ports[i]);
		}
	}
}

struct flows_and_stats default_flows_and_stats = {
	.prev_root_pipe_total_count = -1,
	.prev_arp_resp_pipe_total_count = -1,
	.prev_sampling_total_count = -1
};

int
main(int argc, char **argv)
{
	char **dpdk_argv = malloc(argc * sizeof(void*)); // same as argv but without -a arguments	
	char *pci_addr_arg[max_num_pf] = {NULL};

	struct vnet_config_t vnet_config = {};
	struct geneve_demo_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 0, // updated after dpdk_init()
				.nb_queues = 1,
				.nb_hairpin_q = 1,
				.isolated_mode = 1,
			},
		},
		.sample_mask = UINT32_MAX, // disabled, by default
		.vnet_config = &vnet_config,
		.arp_response_meta_flag = 0x50, // any arbitrary non-zero value
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

	config.num_pfs = disable_dpdk_accept_args(argc, argv, dpdk_argv, pci_addr_arg);

	DOCA_LOG_INFO("Num PFs from command line via -a: %d", config.num_pfs);
	for (int i=0; i<config.num_pfs; i++) {
		DOCA_LOG_INFO("pf[%d]: %s", i, pci_addr_arg[i]);
	}

	if (!config.num_pfs) {
		rte_exit(EXIT_FAILURE, "Requires one device specified via -a argument");
	}

	for (uint32_t i=0; i<config.num_pfs; i++) {
		config.mirror_id_ingress_to_rss[i] = 2 * i + 1;
		config.mirror_id_egress_to_rss[i] = 2 * i + 2;
	}

	doca_argp_init("doca-geneve-demo", &config);
	doca_argp_set_dpdk_program(dpdk_init);
	geneve_demo_register_argp_params();

	result = doca_argp_start(argc, dpdk_argv);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to parse args\n");
	}

	result = load_vnet_config(config.vnet_config_file, &vnet_config);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to load config file\n");
	}

	rte_flow_dynf_metadata_register();

	for (uint16_t pf_idx = 0; pf_idx < config.num_pfs; pf_idx++) {		
		uint16_t port_id = rte_eth_dev_count_avail();
		result = open_doca_device_with_pci(pci_addr_arg[pf_idx], NULL, &config.pf_dev[port_id]);
		if (result != DOCA_SUCCESS) {
			rte_exit(EXIT_FAILURE, "Failed to open doca device: %s", pci_addr_arg[pf_idx]);
		}
		config.port_is_pf[port_id] = true;
		DOCA_LOG_INFO("Port %d is a PF", port_id);

		// Note: ignoring devarg and hard-coding it as follows:
		result = doca_dpdk_port_probe(config.pf_dev[port_id], 
			"dv_flow_en=2,"
			"dv_xmeta_en=4,"
			"fdb_def_rule_en=0,"
			"vport_match=1,"
			"repr_matching_en=0,"
			"representor=vf0");

		if (result != DOCA_SUCCESS) {
			rte_exit(EXIT_FAILURE, "Failed to probe doca device");
		}
	}

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();

	if (config.dpdk_config.port_config.nb_ports < 2) {
		rte_exit(EXIT_FAILURE, "Num ports probed: %d, min: %d\n", config.dpdk_config.port_config.nb_ports, 2);
	} else {
		DOCA_LOG_INFO("Starting %d ports...", config.dpdk_config.port_config.nb_ports);
	}

	install_signal_handler();

	dpdk_queues_and_ports_init(&config.dpdk_config);

	struct rte_hash *session_ht = session_ht_create();

	flow_init(&config);

	for (uint16_t port_id = 0, pf_idx = 0; port_id < config.dpdk_config.port_config.nb_ports; port_id++) {
		if (!config.port_is_pf[port_id]) {
			continue; // pf_idx is not incremented
		}
		
		DOCA_LOG_INFO("Creating flows for port_id %d", port_id);
		
		struct flows_and_stats *flows = &config.flows[pf_idx];
		*flows = default_flows_and_stats;

		flows->pf_port = config.ports[port_id];

		flows->rss_pipe = create_rss_pipe(flows->pf_port);
		flows->fwd_to_uplink_pipe = create_fwd_to_port_pipe(flows->pf_port, port_id, &flows->sampling_entry_list[0]);

		configure_mirror(config.mirror_id_ingress_to_rss[pf_idx], DOCA_FLOW_PIPE_DOMAIN_DEFAULT, flows->rss_pipe, flows->pf_port);
		configure_mirror(config.mirror_id_egress_to_rss[pf_idx], DOCA_FLOW_PIPE_DOMAIN_EGRESS, flows->rss_pipe, flows->pf_port);

		flows->decap_pipe = create_decap_tunnel_pipe(
			flows->pf_port, 
			&config);

		flows->ingr_sampl_pipe = create_sampling_pipe(
			DOCA_FLOW_PIPE_DOMAIN_DEFAULT,
			config.sample_mask, // log2(sample-rate)
			SAMPLE_DIRECTION_INGRESS, // pkt_meta to assign
			flows->pf_port, // port for this pipe
			config.mirror_id_ingress_to_rss[pf_idx], // mirror dest when sampled
			flows->decap_pipe, // dest after sampling
			flows->decap_pipe, // dest after not sampling
			&flows->sampling_entry_list[1]);
		
		flows->egr_sampl_pipe = create_sampling_pipe(
			DOCA_FLOW_PIPE_DOMAIN_EGRESS,
			config.sample_mask, // log2(sample-rate)
			SAMPLE_DIRECTION_EGRESS, // pkt_meta to assign
			flows->pf_port, // port for this pipe
			config.mirror_id_egress_to_rss[pf_idx], // mirror dest when sampled
			flows->fwd_to_uplink_pipe, // dest after sampling
			flows->fwd_to_uplink_pipe, // dest after not sampling
			&flows->sampling_entry_list[2]);

		flows->encap_pipe = create_encap_tunnel_pipe(
			flows->pf_port, 
			flows->egr_sampl_pipe, 
			&config);

		flows->root_pipe_entry_list = create_root_pipe(
			flows->pf_port, 
			flows->ingr_sampl_pipe, 
			flows->encap_pipe, 
			flows->rss_pipe, 
			&config);

		flows->arp_response_entry_list[0] = create_arp_response_pipe(flows->pf_port, config.arp_response_meta_flag);

		if (!flows->rss_pipe || 
			!flows->decap_pipe || 
			!flows->encap_pipe || 
			!flows->ingr_sampl_pipe ||
			!flows->egr_sampl_pipe ||
			!flows->root_pipe_entry_list[0] || 
			!flows->arp_response_entry_list[0]) {
			rte_exit(EXIT_FAILURE, "Failed to init doca flow for port_id %d\n", port_id);
		}
		
		load_vnet_conf_sessions(&config, port_id, session_ht, flows->encap_pipe, flows->decap_pipe);

		++pf_idx;
	}
	
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

		for (uint32_t pf_idx=0; pf_idx < config.num_pfs; pf_idx++) {
			struct flows_and_stats *flows = &config.flows[pf_idx];
			if (show_entry_list_counters(NULL, flows->root_pipe_entry_list, &config, false) != flows->prev_root_pipe_total_count) {
				flows->prev_root_pipe_total_count = show_entry_list_counters("Root pipe", flows->root_pipe_entry_list, &config, true);
			}

			if (show_entry_list_counters(NULL, flows->arp_response_entry_list, &config, false) != flows->prev_arp_resp_pipe_total_count) {
				flows->prev_arp_resp_pipe_total_count = show_entry_list_counters("ARP Resp pipe", flows->arp_response_entry_list, &config, true);
			}

			if (show_entry_list_counters(NULL, flows->sampling_entry_list, &config, false) != flows->prev_sampling_total_count) {
				flows->prev_sampling_total_count = show_entry_list_counters("Sampling pipe", flows->sampling_entry_list, &config, true);
			}
		}
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
		rte_eal_wait_lcore(lcore_id);
	}

	// Stop VFs before PFs	
	stop_ports(&config, false);
	stop_ports(&config, true);

	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}
