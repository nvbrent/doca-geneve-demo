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
    struct geneve_demo_config *demo_config;
    const struct vnet_config_t *vnet_config;
    struct rte_hash *session_ht;
	struct doca_flow_pipe *encap_pipe; 
	struct doca_flow_pipe *decap_pipe;
    const struct vnet_host_t *self;
    session_id_t next_session_id;
};

static const struct vnet_host_t *
find_phys_host_by_name(
    const char *hostname, 
    const struct vnet_config_t *config)
{
    for (uint16_t ihost = 0; ihost<config->physical_hosts.num_hosts; ihost++) {
        const struct vnet_host_t *host = &config->physical_hosts.hosts[ihost];
        if (!strcmp(hostname, host->name)) {
            return host;
        }
    }
    return NULL;
}

static const struct vnet_host_inventory_t *
find_host_inv_by_name(
    const char *hostname, 
    const struct vnet_t *vnet)
{
    for (uint16_t i = 0; i < vnet->num_hosts; i++) {
        const struct vnet_host_inventory_t *host = &vnet->hosts[i];
        if (!strcmp(hostname, host->host_name)) {
            return host;
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
    
    for (uint16_t ihost = 0; ihost<config->physical_hosts.num_hosts; ihost++) {
        const struct vnet_host_t *host = &config->physical_hosts.hosts[ihost];
        if (!memcmp(pf_mac_addr.addr_bytes, host->mac_addr.addr_bytes, 6)) {
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

static void build_session(
    struct vnet_flow_builder_config *builder_config,
    const struct vnet_host_t *remote_host,
    const struct vnet_host_inventory_t *local_vm,
    const struct vnet_host_inventory_t *remote_vm)
{
    if (local_vm->num_virt_hosts < 1 || remote_vm->num_virt_hosts < 1)
        return; // nothing to do

    if (local_vm->num_virt_hosts > 1 || remote_vm->num_virt_hosts > 1)
        rte_exit(EXIT_FAILURE, "TODO: support >1 num_virt_hosts");
    
    const struct vnet_host_t *local_host = builder_config->self;

    struct session_def *session = calloc(1, sizeof(struct session_def));

    session->session_id = ++builder_config->next_session_id;
    session->vf_port_id = local_vm->virt_hosts[0].vf_index + 1; // skip the PF index
    session->vnet_id = local_vm->vnet_id;

    session->outer_smac = local_host->mac_addr;
    session->outer_dmac = remote_host->mac_addr;
    
    memcpy(session->outer_local_ip, local_host->ip, sizeof(ipv6_addr_t));
    memcpy(session->outer_remote_ip, remote_host->ip, sizeof(ipv6_addr_t));

    uint16_t remote_vf_index = remote_vm->virt_hosts[0].vf_index; // TODO: bounds check
    session->decap_dmac = remote_host->vfs[remote_vf_index].mac_addr;

    memcpy(session->virt_local_ip, local_vm->virt_hosts[0].ip, sizeof(ipv6_addr_t));
    memcpy(session->virt_remote_ip, remote_vm->virt_hosts[0].ip, sizeof(ipv6_addr_t));

    uint32_t pipe_queue = 0;
    session->encap_entry = create_encap_entry(
        builder_config->encap_pipe, session, pipe_queue, builder_config->demo_config);
    session->decap_entry = create_decap_entry(
        builder_config->decap_pipe, session, pipe_queue, builder_config->demo_config);
    
    if (!session->encap_entry || !session->decap_entry) {
        DOCA_LOG_ERR("Failed to create session");
        free(session);
        return;
    }
    
    add_session(builder_config->session_ht, session);
}

static uint32_t load_vnet_sessions(
    struct vnet_flow_builder_config *builder_config,
    const struct vnet_t *vnet)
{
    uint32_t total_sessions = 0;
    const struct vnet_host_inventory_t *my_host_inv = find_host_inv_by_name(
        builder_config->self->name, vnet);
    if (!my_host_inv) {
        return total_sessions; // I have no VMs on this vnet
    }

    // Iterate through every combination of hosts on a given subnet.
    // If either host is 'self', determine which host is local and
    // which is remote, and build a corresponding session object.
    for (uint16_t i = 0; i < vnet->num_hosts; i++) {
        const struct vnet_host_inventory_t *i_host = &vnet->hosts[i];
        bool i_is_self = i_host == my_host_inv;

        for (uint16_t j = i+1; j < vnet->num_hosts; j++) {
            const struct vnet_host_inventory_t *j_host = &vnet->hosts[j];
            bool j_is_self = j_host == my_host_inv;

            if (!i_is_self && !j_is_self) {
                continue; // I am neither local nor remote
            }
            
            if (i_is_self && j_is_self) {
                rte_exit(EXIT_FAILURE, "Host %s is listed twice for vnet %d", 
                    builder_config->self->name, vnet->vnet_id);
            }

            const struct vnet_host_inventory_t *remote_host_inv = i_is_self ? j_host : i_host;
            const struct vnet_host_t *remote_host = find_phys_host_by_name(
                remote_host_inv->host_name, builder_config->vnet_config);
            if (!remote_host) {
                rte_exit(EXIT_FAILURE, "Remote host %s not found", remote_host_inv->host_name);
            }
            build_session(
                builder_config, remote_host, 
                my_host_inv, remote_host_inv);
            ++total_sessions;
        }
    }
    return total_sessions;
}

int load_vnet_conf_sessions(
    struct geneve_demo_config *demo_config,
    const struct vnet_config_t *vnet_config,
    struct rte_hash *session_ht,
	struct doca_flow_pipe *encap_pipe, 
	struct doca_flow_pipe *decap_pipe)
{
    struct vnet_flow_builder_config builder_config = {
        .demo_config = demo_config,
        .vnet_config = vnet_config,
        .session_ht = session_ht,
        .encap_pipe = encap_pipe,
        .decap_pipe = decap_pipe,
        .next_session_id = 4000,
    };
    builder_config.self = find_self(demo_config->uplink_port_id, vnet_config);

    uint32_t total_sessions = 0;
    for (uint16_t ivnet=0; ivnet<vnet_config->num_vnets; ivnet++) {
        uint32_t vlan_sessions = load_vnet_sessions(&builder_config, &vnet_config->vnets[ivnet]);
        total_sessions += vlan_sessions;
        DOCA_LOG_INFO("Configured %d session(s) for VLAN %d",
            vlan_sessions, vnet_config->vnets[ivnet].vnet_id);
    }
    DOCA_LOG_INFO("Configured %d total session(s) across %d vlans",
        total_sessions, vnet_config->num_vnets);

    return 0;
}
