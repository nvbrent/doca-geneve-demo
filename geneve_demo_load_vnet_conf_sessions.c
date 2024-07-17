#include <rte_ethdev.h>
#include <rte_ether.h>
#include <doca_log.h>

#include <geneve_demo.h>
#include <geneve_demo_session_hashtable.h>
#include <geneve_demo_vnet_conf.h>
#include <geneve_demo_flows.h>

DOCA_LOG_REGISTER(geneve_demo_vnet_conf_loader);

struct vnet_flow_builder_config
{
	uint16_t uplink_port_id;
	uint16_t vf_port_id;
	const struct vnet_host_t *self;
	struct geneve_demo_config *demo_config;
	struct rte_hash *session_ht;
	struct doca_flow_pipe *encap_pipe; 
	struct doca_flow_pipe *decap_pipe;
};

static const struct vnet_host_t *
find_phys_host_by_name(
    const char *hostname, 
    const struct vnet_config_t *config)
{
    for (uint16_t ihost = 0; ihost<config->num_hosts; ihost++) {
        const struct vnet_host_t *host = &config->hosts[ihost];
        if (!strcmp(hostname, host->name)) {
            return host;
        }
    }
    return NULL;
}

static const struct nic_t *
find_pf(const struct vnet_host_t *host, const struct rte_ether_addr *pf_mac_addr)
{
    for (uint16_t pf_num = 0; pf_num < host->num_nics; pf_num++) {
        const struct nic_t *pf = &host->nics[pf_num];
        if (!memcmp(pf_mac_addr->addr_bytes, pf->mac_addr.addr_bytes, 6)) {
            return pf;
        }
    }
    return NULL;
}

static const struct vnet_host_t *
find_self(uint16_t pf_port_id, const struct vnet_config_t *config)
{
    // load my own PF mac addr to auto-detect identity in config file
    struct rte_ether_addr pf_mac_addr = {};
	if (rte_eth_macaddr_get(pf_port_id, &pf_mac_addr) != 0)
		rte_exit(EXIT_FAILURE, "Failed to obtain mac addrs for port %d\n", pf_port_id);
    
    for (uint16_t ihost = 0; ihost<config->num_hosts; ihost++) {
        const struct vnet_host_t *host = &config->hosts[ihost];
        const struct nic_t *pf = find_pf(host, &pf_mac_addr);
        if (pf != NULL) {
            DOCA_LOG_INFO("Found my PF mac addr; hostname is %s", host->name);
            return host;
        }
    }

    char pf_macaddr_str[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(pf_macaddr_str, RTE_ETHER_ADDR_FMT_SIZE, &pf_mac_addr);
    rte_exit(EXIT_FAILURE, "Failed to find my mac address (%s) in vnet config\n",
        pf_macaddr_str);
    return NULL; // cannot get here
}

static bool
find_nic_and_vnic(
    const struct vnet_host_t *host, 
    const char *vnic_name, 
    const struct nic_t **nic, 
    const struct vnic_t **vnic)
{
    for (uint16_t i_pf=0; i_pf < host->num_nics; i_pf++) {
        const struct nic_t *pf = &host->nics[i_pf];
        for (uint16_t i_vf=0; i_vf < pf->num_vnics; i_vf++) {
            const struct vnic_t *vf = &pf->vnics[i_vf];
            if (strcmp(vf->name, vnic_name) != 0)
                continue;
            *nic = pf;
            *vnic = vf;
            return true;
        }
    }
    return false;
}

static const struct rte_ether_addr*
get_session_dmac(
    const struct nic_t *local_nic,
    const struct nic_t *remote_nic)
{
    if (local_nic->has_gateway && 
        local_nic->subnet_mask_len)
    {
        // TODO: support outer IPv4
        // TODO: support subnet mask not a multiple of 8
        for (int i=0; i<local_nic->subnet_mask_len / 8; i++) {
            if (local_nic->ip.ipv6[i] != remote_nic->ip.ipv6[i]) {
                // different subnets; send to gateway
                return &local_nic->gw_mac_addr;
            }
        }
    }
    return &remote_nic->mac_addr;
}

static bool build_session(
    struct vnet_flow_builder_config *builder_config,
    const char *remote_host_name,
    const char *local_vnic_name,
    const char *remote_vnic_name)
{
    const struct vnet_host_t *local_host = builder_config->self;
    const struct vnet_host_t *remote_host = find_phys_host_by_name(remote_host_name, builder_config->demo_config->vnet_config);
    if (!remote_host) {
        DOCA_LOG_ERR("Host %s: remote host not found", remote_host_name);
        return false;
    }

    DOCA_LOG_INFO("Building session: local-host: %s, remote-host: %s, local-vnic: %s, remote-vnis: %s",
        local_host->name, remote_host->name, local_vnic_name, remote_vnic_name);

    const struct nic_t *local_nic = NULL;
    const struct vnic_t *local_vnic = NULL;
    const struct nic_t *remote_nic = NULL;
    const struct vnic_t *remote_vnic = NULL;
    if (!find_nic_and_vnic(local_host, local_vnic_name, &local_nic, &local_vnic)) {
        DOCA_LOG_ERR("Host %s: Unkonwn NIC name: %s", local_host->name, local_vnic_name);
        return false;
    }
    if (!find_nic_and_vnic(remote_host, remote_vnic_name, &remote_nic, &remote_vnic)) {
        DOCA_LOG_ERR("Host %s: Unkonwn NIC name: %s", remote_host_name, remote_vnic_name);
        return false;
    }
    
    struct session_def *session = calloc(1, sizeof(struct session_def));

    session->session_id = ++builder_config->demo_config->next_session_id;
    session->pf_port_id = builder_config->uplink_port_id;
    session->vf_port_id = builder_config->vf_port_id;

    session->vnet_id_ingress = remote_vnic->vnet_id_out;
    session->vnet_id_egress = local_vnic->vnet_id_out;

    session->outer_smac = local_nic->mac_addr;
    session->outer_dmac = *get_session_dmac(local_nic, remote_nic);
    
    if (builder_config->demo_config->vnet_config->outer_addr_fam == AF_INET) {
        session->outer_local_ip.ipv4 = local_nic->ip.ipv4;
        session->outer_remote_ip.ipv4 = remote_nic->ip.ipv4;
    } else {
        memcpy(session->outer_local_ip.ipv6, local_nic->ip.ipv6, sizeof(ipv6_addr_t));
        memcpy(session->outer_remote_ip.ipv6, remote_nic->ip.ipv6, sizeof(ipv6_addr_t));
    }

    session->decap_dmac = local_vnic->mac_addr;

    if (builder_config->demo_config->vnet_config->inner_addr_fam == AF_INET) {
        session->virt_local_ip.ipv4 = local_vnic->ip.ipv4;
        session->virt_remote_ip.ipv4 = remote_vnic->ip.ipv4;
    } else {
        memcpy(session->virt_local_ip.ipv6, local_vnic->ip.ipv6, sizeof(ipv6_addr_t));
        memcpy(session->virt_remote_ip.ipv6, remote_vnic->ip.ipv6, sizeof(ipv6_addr_t));
    }

    uint32_t pipe_queue = 0;
    session->encap_entry = create_encap_entry(
        builder_config->encap_pipe, session, pipe_queue, builder_config->demo_config);
    session->decap_entry = create_decap_entry(
        builder_config->decap_pipe, session, pipe_queue, builder_config->demo_config);
    
    if (!session->encap_entry || !session->decap_entry) {
        DOCA_LOG_ERR("Failed to create session");
        free(session);
        return false;
    }
    
    add_session(builder_config->session_ht, session);

    return true;
}

int load_vnet_conf_sessions(
	struct geneve_demo_config *demo_config,
	uint32_t uplink_port_id,
	uint32_t vf_port_id,
	struct rte_hash *session_ht,
	struct doca_flow_pipe *encap_pipe, 
	struct doca_flow_pipe *decap_pipe)
{
    demo_config->self[uplink_port_id] = find_self(uplink_port_id, demo_config->vnet_config);
    
    struct vnet_flow_builder_config builder_config = {
        .uplink_port_id = uplink_port_id,
        .vf_port_id = vf_port_id,
        .self = demo_config->self[uplink_port_id],
        .demo_config = demo_config,
        .session_ht = session_ht,
        .encap_pipe = encap_pipe,
        .decap_pipe = decap_pipe,
    };

    uint32_t total_sessions = 0;
    for (uint16_t i=0; i<demo_config->vnet_config->num_routes; i++) {
        struct route_t *route = &demo_config->vnet_config->routes[i];
        // check each end of the route
        for (int idx_local=0; idx_local<2; idx_local++) {
            const char *local_hostname = route->hostname[idx_local];
            if (strcmp(local_hostname, builder_config.self->name) != 0)
                continue;

            int idx_remote = idx_local ^ 1;
            build_session(&builder_config, 
                route->hostname[idx_remote],
                route->vnic_name[idx_local],
                route->vnic_name[idx_remote]);
            ++total_sessions;
        }
        // else, this host isn't involved
    }
    DOCA_LOG_INFO("Configured %d total session(s)", total_sessions);

    return 0;
}
