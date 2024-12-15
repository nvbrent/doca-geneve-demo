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

doca_error_t open_doca_device_with_iface_name(const char *value,
					      size_t val_size,
					      tasks_check func,
					      struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	char buf[DOCA_DEVINFO_IFACE_NAME_SIZE] = {};
	char val_copy[DOCA_DEVINFO_IFACE_NAME_SIZE] = {};
	int res;
	size_t i;

	/* Set default return value */
	*retval = NULL;

	/* Setup */
	if (val_size > DOCA_DEVINFO_IFACE_NAME_SIZE) {
		DOCA_LOG_ERR("Value size too large. Failed to locate device");
		return DOCA_ERROR_INVALID_VALUE;
	}
	memcpy(val_copy, value, val_size);

	res = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list: %s", doca_error_get_descr(res));
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		res = doca_devinfo_get_iface_name(dev_list[i], buf, DOCA_DEVINFO_IFACE_NAME_SIZE);
		if (res == DOCA_SUCCESS && strncmp(buf, val_copy, val_size) == 0) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS) {
				doca_devinfo_destroy_list(dev_list);
				return res;
			}
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_destroy_list(dev_list);
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
	uint32_t pf_idx,
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
			DOCA_LOG_INFO("PF%d: %s entry[%d]: %ld hits",
				pf_idx, entry_list_name, entry_idx, hits);

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
		.core_mask = 0x3,
		.sample_mask = UINT32_MAX, // disabled, by default
		.next_session_id = 4000,
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
	doca_argp_init("doca-geneve-demo", &config);
	geneve_demo_register_argp_params();
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to parse args\n");
	}

	result = load_vnet_config(config.vnet_config_file, &vnet_config);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to load config file\n");
	}

	const char *pf_netdev_names[max_num_pf] = {};
	config.num_pfs = find_my_vnet_pfs(&vnet_config, pf_netdev_names);
	if (!config.num_pfs) {
		rte_exit(0, "Failed to configure vnets");
	}

	char coremask_arg[64];
	snprintf(coremask_arg, sizeof(coremask_arg), "-c0x%x", config.core_mask);
	
	enum { num_eal_args = 3 };
	char *dpdk_argv[num_eal_args] = {
		argv[0],
		"-a00:00.0",
		coremask_arg
	};
	result = rte_eal_init(num_eal_args, dpdk_argv);
	if (result < 0) {
		rte_exit(1, "Failed to rte_eal_init");
	}
	rte_flow_dynf_metadata_register();

	for (uint16_t pf_idx = 0; pf_idx < config.num_pfs; pf_idx++) {
		uint16_t port_id = rte_eth_dev_count_avail();
		result = open_doca_device_with_iface_name(pf_netdev_names[pf_idx], strlen(pf_netdev_names[pf_idx]), NULL, &config.pf_dev[port_id]);
		if (result != DOCA_SUCCESS) {
			rte_exit(EXIT_FAILURE, "Failed to open doca device: %s", pf_netdev_names[pf_idx]);
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

	for (uint32_t i=0; i<config.num_pfs; i++) {
		config.mirror_id_ingress_to_rss[i] = i + 1;
		config.mirror_id_egress_to_rss[i] = config.num_pfs + i + 1;
	}

	flow_init(&config);

	for (uint16_t port_id = 0, pf_idx = 0; port_id < config.dpdk_config.port_config.nb_ports; port_id++) {
		if (config.port_is_pf[port_id]) {
			struct flows_and_stats *flows = &config.flows[pf_idx];
			*flows = default_flows_and_stats;
			flows->uplink_port_id = port_id;
			flows->vf_port_id = port_id + 1;
			flows->pf_port = config.ports[flows->uplink_port_id];
			++pf_idx;
		} // else, pf_idx not incremented
	}

	for (uint16_t pf_idx = 0; pf_idx < config.num_pfs; pf_idx++) {
		struct flows_and_stats *flows = &config.flows[pf_idx];
		DOCA_LOG_INFO("Creating flows for port_id %d", flows->uplink_port_id);

		flows->rss_pipe = create_rss_pipe(config.dpdk_config.port_config.nb_queues, flows->pf_port);
		flows->fwd_to_uplink_pipe = create_fwd_to_port_pipe(flows->pf_port, flows->uplink_port_id, &flows->sampling_entry_list[0]);

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
			flows->uplink_port_id,
			flows->vf_port_id,
			flows->ingr_sampl_pipe,
			flows->encap_pipe,
			flows->rss_pipe,
			&config);

		flows->arp_response_entry_list[0] = create_arp_response_pipe(
			flows->pf_port,
			flows->vf_port_id,
			config.arp_response_meta_flag);

		if (!flows->rss_pipe ||
			!flows->decap_pipe ||
			!flows->encap_pipe ||
			!flows->ingr_sampl_pipe ||
			!flows->egr_sampl_pipe ||
			!flows->root_pipe_entry_list[0] ||
			!flows->arp_response_entry_list[0]) {
			rte_exit(EXIT_FAILURE, "Failed to init doca flow for port_id %d\n", flows->uplink_port_id);
		}

		load_vnet_conf_sessions(
			&config,
			flows->uplink_port_id,
			flows->vf_port_id,
			session_ht,
			flows->encap_pipe,
			flows->decap_pipe);
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
			if (show_entry_list_counters(pf_idx, NULL, flows->root_pipe_entry_list, &config, false) != flows->prev_root_pipe_total_count) {
				flows->prev_root_pipe_total_count = show_entry_list_counters(pf_idx, "Root pipe", flows->root_pipe_entry_list, &config, true);
			}

			if (show_entry_list_counters(pf_idx, NULL, flows->arp_response_entry_list, &config, false) != flows->prev_arp_resp_pipe_total_count) {
				flows->prev_arp_resp_pipe_total_count = show_entry_list_counters(pf_idx, "ARP Resp pipe", flows->arp_response_entry_list, &config, true);
			}

			if (show_entry_list_counters(pf_idx, NULL, flows->sampling_entry_list, &config, false) != flows->prev_sampling_total_count) {
				flows->prev_sampling_total_count = show_entry_list_counters(pf_idx, "Sampling pipe", flows->sampling_entry_list, &config, true);
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
