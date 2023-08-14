#include <geneve_demo_vnet_conf.h>
#include <doca_log.h>

DOCA_LOG_REGISTER(vnet_conf);

#define CALLOC_ARRAY(array_var, array_length) \
    array_var = calloc(array_length, sizeof(array_var[0]))

int load_vnet_config(const char *config_json_path, struct vnet_config_t *config)
{
    // TODO: read this from json
    
    if (!config_json_path) {
        DOCA_LOG_ERR("%s: config_json_path cannot be NULL", __FUNCTION__);
        return -1;
    }
    if (!config) {
        DOCA_LOG_ERR("%s: config cannot be NULL", __FUNCTION__);
        return -1;
    }

    struct vnet_host_t *host = NULL;
    struct nic_t *pf = NULL;
    struct vnic_t *vf = NULL;
    struct route_t *route = NULL;

    config->num_hosts = 2;
    CALLOC_ARRAY(config->hosts, config->num_hosts);
    
    host = &config->hosts[0];
    host->name = "doca-vr-007";

    host->num_nics = 1;
    CALLOC_ARRAY(host->nics, host->num_nics);
    pf = &host->nics[0];

    pf->name = "enp23s0f0np0";
    rte_ether_unformat_addr("b8:3f:d2:ba:65:9a", &pf->mac_addr);
    inet_pton(AF_INET6, "99::11", &pf->ip);
    pf->num_vnics = 1;
    CALLOC_ARRAY(pf->vnics, pf->num_vnics);
    vf = &pf->vnics[0];

    vf->vf_index = 0;
    vf->name = "enp23s0f0v0";
    rte_ether_unformat_addr("22:d6:04:82:05:ac", &vf->mac_addr);
    inet_pton(AF_INET6, "11::cafe", &vf->ip);
    vf->vnet_id_out = 101;

    host = &config->hosts[1];
    host->name = "doca-vr-008";

    host->num_nics = 1;
    CALLOC_ARRAY(host->nics, host->num_nics);
    pf = &host->nics[0];

    pf->name = "enp23s0f0np0";
    rte_ether_unformat_addr("b8:3f:d2:ba:65:ee", &pf->mac_addr);
    inet_pton(AF_INET6, "99::22", &pf->ip);
    pf->num_vnics = 1;
    CALLOC_ARRAY(pf->vnics, pf->num_vnics);
    vf = &pf->vnics[0];

    vf->vf_index = 0;
    vf->name = "enp23s0f0v0";
    rte_ether_unformat_addr("c2:b8:0c:93:83:86", &vf->mac_addr);
    inet_pton(AF_INET6, "11::beef", &vf->ip);
    vf->vnet_id_out = 102;

    config->num_routes = 1;
    CALLOC_ARRAY(config->routes, config->num_routes);
    route = &config->routes[0];

    route->hostname[0] = "doca-vr-007";
    route->vnic_name[0] = "enp23s0f0v0";
    route->hostname[1] = "doca-vr-008";
    route->vnic_name[1] = "enp23s0f0v0";

    return 0;
}