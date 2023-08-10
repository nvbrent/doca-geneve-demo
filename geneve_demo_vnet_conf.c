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
    struct vnet_t *vnet = NULL;
    struct vnet_host_inventory_t *host_inv = NULL;

    config->physical_hosts.num_hosts = 2;
    CALLOC_ARRAY(config->physical_hosts.hosts, config->physical_hosts.num_hosts);
    
    host = &config->physical_hosts.hosts[0];
    host->name = "host1";
    inet_pton(AF_INET6, "99::11", &host->ip);
    rte_ether_unformat_addr("b8:3f:d2:ba:65:9a", &host->mac_addr);
    host->num_vfs = 2;
    CALLOC_ARRAY(host->vfs, host->num_vfs);
    host->vfs[0].vf_index = 0;
    rte_ether_unformat_addr("22:d6:04:82:05:ac", &host->vfs[0].mac_addr);
    rte_ether_unformat_addr("b2:82:94:b5:d6:3c", &host->vfs[1].mac_addr);

    host = &config->physical_hosts.hosts[1];
    host->name = "host2";
    inet_pton(AF_INET6, "99::22", &host->ip);
    rte_ether_unformat_addr("b8:3f:d2:ba:65:ee", &host->mac_addr);
    host->num_vfs = 2;
    CALLOC_ARRAY(host->vfs, host->num_vfs);
    host->vfs[0].vf_index = 0;
    rte_ether_unformat_addr("c2:b8:0c:93:83:86", &host->vfs[0].mac_addr);
    rte_ether_unformat_addr("8a:e9:39:09:d1:cd", &host->vfs[1].mac_addr);

    config->num_vnets = 2;
    CALLOC_ARRAY(config->vnets, config->num_vnets);
    
    vnet = &config->vnets[0];
    vnet->vnet_id = 101;
    vnet->num_hosts = 2;
    CALLOC_ARRAY(vnet->hosts, vnet->num_hosts);
    host_inv = &vnet->hosts[0];
    host_inv->host_name = config->physical_hosts.hosts[0].name;
    host_inv->vnet_id = vnet->vnet_id;
    host_inv->num_virt_hosts = 1;
    CALLOC_ARRAY(host_inv->virt_hosts, host_inv->num_virt_hosts);
    host_inv->virt_hosts[0].vf_index = 0;
    inet_pton(AF_INET6, "11::cafe", host_inv->virt_hosts[0].ip);
    host_inv = &vnet->hosts[1];
    host_inv->host_name = config->physical_hosts.hosts[1].name;
    host_inv->vnet_id = vnet->vnet_id;
    host_inv->num_virt_hosts = 1;
    CALLOC_ARRAY(host_inv->virt_hosts, host_inv->num_virt_hosts);
    host_inv->virt_hosts[0].vf_index = 0;
    inet_pton(AF_INET6, "11::beef", host_inv->virt_hosts[0].ip);

    vnet = &config->vnets[1];
    vnet->vnet_id = 201;
    vnet->num_hosts = 2;
    CALLOC_ARRAY(vnet->hosts, vnet->num_hosts);
    host_inv = &vnet->hosts[0];
    host_inv->host_name = config->physical_hosts.hosts[0].name;
    host_inv->vnet_id = vnet->vnet_id;
    host_inv->num_virt_hosts = 1;
    CALLOC_ARRAY(host_inv->virt_hosts, host_inv->num_virt_hosts);
    host_inv->virt_hosts[0].vf_index = 1;
    inet_pton(AF_INET6, "22::cafe", host_inv->virt_hosts[0].ip);
    host_inv = &vnet->hosts[1];
    host_inv->host_name = config->physical_hosts.hosts[1].name;
    host_inv->vnet_id = vnet->vnet_id;
    host_inv->num_virt_hosts = 1;
    CALLOC_ARRAY(host_inv->virt_hosts, host_inv->num_virt_hosts);
    host_inv->virt_hosts[0].vf_index = 1;
    inet_pton(AF_INET6, "22::beef", host_inv->virt_hosts[0].ip);

    return 0;
}