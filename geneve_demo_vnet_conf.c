#include <json-c/json.h>
#include <unistd.h>

#include <geneve_demo_vnet_conf.h>
#include <doca_log.h>

DOCA_LOG_REGISTER(vnet_conf);

#define CALLOC_ARRAY(array_var, array_length) \
    array_var = calloc(array_length, sizeof(array_var[0]))

static doca_error_t parse_vnic(struct json_object *vnic_obj, struct vnic_t *vnic, int addr_fam)
{
    // parse name, mac, ip, pci, vnet_id
    struct json_object *mac_obj, *ip_obj, *vni_obj;
    if (!json_object_object_get_ex(vnic_obj, "mac", &mac_obj)) {
        DOCA_LOG_ERR("NIC \"mac\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *mac_str = json_object_get_string(mac_obj);
    if (rte_ether_unformat_addr(mac_str, &vnic->mac_addr) != 0) { // 0 if successful
        DOCA_LOG_ERR("NIC: bad mac addr: %s", mac_str);
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(vnic_obj, "ip", &ip_obj)) {
        DOCA_LOG_ERR("NIC \"ip\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *ip_str = json_object_get_string(ip_obj);
    if (inet_pton(addr_fam, ip_str, &vnic->ip.ipv6_addr) != 1) { // 1 if successful
        DOCA_LOG_ERR("NIC: bad IPv6 addr: %s", ip_str);
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(vnic_obj, "vnid-out", &vni_obj) ||
            !json_object_is_type(vni_obj, json_type_int)) {
        DOCA_LOG_ERR("NIC numeric \"vnid-out\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    vnic->vnet_id_out = json_object_get_int(vni_obj);

    return DOCA_SUCCESS;
}

static doca_error_t parse_nic(struct json_object *nic_obj, struct nic_t *nic, int addr_fam_outer, int addr_fam_inner)
{
    // parse NIC attributes
    struct json_object *name_obj, *mac_obj, *ip_obj, *gw_mac_obj, *vnics_obj;
    if (!json_object_object_get_ex(nic_obj, "name", &name_obj)) {
        DOCA_LOG_ERR("NIC \"name\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(nic_obj, "mac", &mac_obj)) {
        DOCA_LOG_ERR("NIC \"mac\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *mac_str = json_object_get_string(mac_obj);
    if (rte_ether_unformat_addr(mac_str, &nic->mac_addr) != 0) { // 0 if successful
        DOCA_LOG_ERR("NIC: bad mac addr: %s", mac_str);
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(nic_obj, "ip", &ip_obj)) {
        DOCA_LOG_ERR("NIC \"ip\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    char *ip_str = strdup(json_object_get_string(ip_obj));
    char *ip_str_term = strchr(ip_str, '/');
    if (ip_str_term) {
        *ip_str_term = '\0';
        nic->subnet_mask_len = atoi(ip_str_term+1);
        if (nic->subnet_mask_len < 1 || nic->subnet_mask_len > 128 ||
            (nic->subnet_mask_len % 8) != 0)
        {
            DOCA_LOG_ERR("NIC: Subnet mask length must be 1..128 and a multiple of 8");
            return DOCA_ERROR_INVALID_VALUE;
        }
    }
    if (inet_pton(addr_fam_outer, ip_str, &nic->ip.ipv6_addr) != 1) { // 1 if successful
        DOCA_LOG_ERR("NIC: bad IPv6 addr: %s", ip_str);
        return DOCA_ERROR_INVALID_VALUE;
    }
    free(ip_str);

    if (json_object_object_get_ex(nic_obj, "gw_mac", &gw_mac_obj)) {
        const char *gw_mac_str = json_object_get_string(gw_mac_obj);
        if (rte_ether_unformat_addr(gw_mac_str, &nic->gw_mac_addr) != 0) { // 0 if successful
            DOCA_LOG_ERR("NIC: bad gw_mac addr: %s", gw_mac_str);
            return DOCA_ERROR_INVALID_VALUE;
        }
        nic->has_gateway = true;
    }

    // parse vnics
    if (!json_object_object_get_ex(nic_obj, "vnics", &vnics_obj)) {
        DOCA_LOG_ERR("NIC \"vnics\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    nic->num_vnics = json_object_array_length(vnics_obj);
    if (nic->num_vnics < 1) {
        DOCA_LOG_ERR("Zero \"vnics\" configured");
        return DOCA_ERROR_INVALID_VALUE;
    }

    nic->name = strdup(json_object_get_string(name_obj));
    CALLOC_ARRAY(nic->vnics, nic->num_vnics);
    for (size_t i=0; i<nic->num_vnics; i++) {
        json_object *vnic_obj = json_object_array_get_idx(vnics_obj, i);
        doca_error_t result = parse_vnic(vnic_obj, &nic->vnics[i], addr_fam_inner);
        if (result != DOCA_SUCCESS) {
            return result;
        }
    }
    return DOCA_SUCCESS;
}

static doca_error_t parse_host(struct json_object *host_obj, struct vnet_host_t *host, int addr_fam_outer, int addr_fam_inner)
{   
    struct json_object *hostname_obj;
    if (!json_object_object_get_ex(host_obj, "name", &hostname_obj)) {
        DOCA_LOG_ERR("Host \"name\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }

    struct json_object *nics_obj = NULL;
    if (!json_object_object_get_ex(host_obj, "nics", &nics_obj)) {
        DOCA_LOG_ERR("Host \"nics\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    host->num_nics = json_object_array_length(nics_obj);
    if (host->num_nics == 0) {
        DOCA_LOG_ERR("Host \"nics\" cannot be empty");
        return DOCA_ERROR_INVALID_VALUE;
    }

    host->name = strdup(json_object_get_string(hostname_obj));
    DOCA_LOG_DBG("Host %s: configuring %d nics", host->name, host->num_nics);

    CALLOC_ARRAY(host->nics, host->num_nics);

    for (size_t i=0; i<host->num_nics; i++) {
        struct json_object *nic_obj = json_object_array_get_idx(nics_obj, i);
        doca_error_t result = parse_nic(nic_obj, &host->nics[i], addr_fam_outer, addr_fam_inner);
        if (result != DOCA_SUCCESS) {
            return result;
        }
    }
    return DOCA_SUCCESS;
}

static doca_error_t parse_route(struct json_object *route_obj, struct route_t *route)
{
    size_t num_endpoints = json_object_array_length(route_obj);
    if (num_endpoints != 2) {
        DOCA_LOG_ERR("Route must have exactly two host/vnic endpoints");
        return DOCA_ERROR_INVALID_VALUE;
    }
    for (size_t i=0; i<num_endpoints; i++) {
        struct json_object *endpt, *endpt_host, *endpt_vnic;
        endpt = json_object_array_get_idx(route_obj, i);
        if (!json_object_object_get_ex(endpt, "host", &endpt_host)) {
            DOCA_LOG_ERR("Route endpoint requires \"host\"");
            return DOCA_ERROR_INVALID_VALUE;
        }
        if (!json_object_object_get_ex(endpt, "vnic", &endpt_vnic)) {
            DOCA_LOG_ERR("Route endpoint requires \"vnic\"");
            return DOCA_ERROR_INVALID_VALUE;
        }
        route->hostname[i] = strdup(json_object_get_string(endpt_host));
        // TODO: route->vip[i] = parse IP addr based on inner_addr_fam
    }

    return DOCA_SUCCESS;
}

static int json_obj_to_addr_fam(struct json_object *ipver_obj)
{
    if (json_object_is_type(ipver_obj, json_type_int)) {
        return json_object_get_int(ipver_obj) == 4 ? AF_INET : AF_INET6;
    } else {
        return strchr(json_object_get_string(ipver_obj), '4') != NULL ? AF_INET : AF_INET6;
    }
}

static uint16_t count_vnics(const struct vnet_host_t *host)
{
    uint16_t vnics = 0;
    for (int i=0; i < host->num_nics; i++) {
        vnics += host->nics[i].num_vnics;
    }
    return vnics;
}

static uint16_t count_all_to_all_routes(const struct vnet_config_t *config)
{
    uint16_t routes = 0;
    for (int host1=0; host1<config->num_hosts; host1++) {
        struct vnet_host_t *p_host1 = &config->hosts[host1];

        for (int host2=host1 + 1; host2<config->num_hosts; host2++) {
            struct vnet_host_t *p_host2 = &config->hosts[host2];
            routes += count_vnics(p_host1) * count_vnics(p_host2);
        }
    }
    return routes;
}

static doca_error_t configure_all_to_all_routes(struct vnet_config_t *config)
{
    config->num_routes = count_all_to_all_routes(config);
    CALLOC_ARRAY(config->routes, config->num_routes);

    uint16_t idx_route = 0;

    // For every combindation of hosts:
    for (int host1=0; host1<config->num_hosts; host1++) {
        struct vnet_host_t *p_host1 = &config->hosts[host1];

        for (int host2=host1 + 1; host2<config->num_hosts; host2++) {
            struct vnet_host_t *p_host2 = &config->hosts[host2];

            // For each nic/vnic on host1:
            for (int nic1=0; nic1<p_host1->num_nics; nic1++) {
                struct nic_t *p_nic1 = &p_host1->nics[nic1];
                for (int vnic1=0; vnic1<p_nic1->num_vnics; vnic1++) {
                    // For each nic/vnic on host2:
                    for (int nic2=0; nic2<p_host2->num_nics; nic2++) {
                        struct nic_t *p_nic2 = &p_host2->nics[nic2];
                        for (int vnic2=0; vnic2<p_nic2->num_vnics; vnic2++) {
                            // Configure the route between host1.nic.vnic <-> host2.nic.vnic
                            struct route_t *p_route = &config->routes[idx_route++];
                            p_route->hostname[0] = p_host1->name;
                            p_route->hostname[1] = p_host2->name;
                            p_route->vip[0] = p_nic1->vnics[vnic1].ip;
                            p_route->vip[1] = p_nic2->vnics[vnic2].ip;
                        }
                    }
                }
            }
        }
    }
    if (idx_route != config->num_routes) {
        DOCA_LOG_ERR("Expected to configured %d routes; found %d", config->num_routes, idx_route);
        return DOCA_ERROR_UNKNOWN;
    }

    return DOCA_SUCCESS;
}

static doca_error_t configure_routes(struct vnet_config_t *config, struct json_object *json_obj)
{
    struct json_object *routes_obj = NULL;
    if (!json_object_object_get_ex(json_obj, "routes", &routes_obj)) {
        DOCA_LOG_ERR("Missing \"routes\" parameter");
        return DOCA_ERROR_INVALID_VALUE;
    }

    config->num_routes = json_object_array_length(routes_obj);
    DOCA_LOG_DBG("Config: configuring %d routes", config->num_routes);
    if (config->num_routes == 0) {
        DOCA_LOG_ERR("Zero \"routes\" configured");
        return DOCA_ERROR_INVALID_VALUE;
    }

    CALLOC_ARRAY(config->routes, config->num_routes);

    for (size_t i=0; i<config->num_routes; i++) {
        struct json_object *route_obj = json_object_array_get_idx(routes_obj, i);
        doca_error_t result = parse_route(route_obj, &config->routes[i]);
        if (result != DOCA_SUCCESS) {
            return result;
        }
    }

    return DOCA_SUCCESS;
}

doca_error_t load_vnet_config(const char *config_json_path, struct vnet_config_t *config)
{
    doca_error_t result = DOCA_ERROR_INVALID_VALUE;

    if (!config_json_path) {
        DOCA_LOG_ERR("%s: config_json_path cannot be NULL", __FUNCTION__);
        return result;
    }
    if (!config) {
        DOCA_LOG_ERR("%s: config cannot be NULL", __FUNCTION__);
        return result;
    }

	struct json_object *json_obj = json_object_from_file(config_json_path);
    if (!json_obj) {
        DOCA_LOG_ERR("Unable to parse contents of %s: %s\n", config_json_path,
            json_util_get_last_err());
        return result;
    }

    do // once
    {
        struct json_object *ipver_obj = NULL;
        if (!json_object_object_get_ex(json_obj, "outer-ip-ver", &ipver_obj)) {
            DOCA_LOG_ERR("Missing \"outer_ip_ver\" parameter");
            break;
        }
        config->outer_addr_fam = json_obj_to_addr_fam(ipver_obj);

        if (!json_object_object_get_ex(json_obj, "inner-ip-ver", &ipver_obj)) {
            DOCA_LOG_ERR("Missing \"inner_ip_ver\" parameter");
            break;
        }
        config->inner_addr_fam = json_obj_to_addr_fam(ipver_obj);

        DOCA_LOG_INFO("Configured outer IPv%d / inner IPv%d", 
            config->outer_addr_fam==AF_INET ? 4 : 6, 
            config->inner_addr_fam==AF_INET ? 4 : 6);

        struct json_object *hosts_obj = NULL;
        if (!json_object_object_get_ex(json_obj, "hosts", &hosts_obj)) {
            DOCA_LOG_ERR("Missing \"hosts\" parameter");
            break;
        }

        config->num_hosts = json_object_array_length(hosts_obj);
        DOCA_LOG_DBG("Config: configuring %d hosts", config->num_hosts);
        if (config->num_hosts == 0) {
            DOCA_LOG_ERR("Zero \"hosts\" configured");
            break;
        }

        CALLOC_ARRAY(config->hosts, config->num_hosts);

        for (size_t i=0; i<config->num_hosts; i++) {
            struct json_object *host_obj = json_object_array_get_idx(hosts_obj, i);
            result = parse_host(host_obj, &config->hosts[i], config->outer_addr_fam, config->inner_addr_fam);
            if (result != DOCA_SUCCESS) {
                break;
            }
        }
        if (result != DOCA_SUCCESS) {
            break;
        }

        struct json_object *route_a2a = NULL;
        if (json_object_object_get_ex(json_obj, "route-all-to-all", &route_a2a)) {
            config->route_all_to_all = json_object_get_boolean(route_a2a);
        }

        if (config->route_all_to_all) {
            result = configure_all_to_all_routes(config);
        } else {
            result = configure_routes(config, json_obj);
        } // if not all-to-all

        if (result != DOCA_SUCCESS) {
            break;
        }

        result = DOCA_SUCCESS;
    } while (false);

	free(json_obj);
    
    return result;
}

uint32_t find_my_vnet_pfs(const struct vnet_config_t *config, const char **pf_netdev_names)
{
    char hostname[1024];
    int status = gethostname(hostname, sizeof(hostname));
    if (status) {
        perror("gethostname");
        return 0;
    }

    const struct vnet_host_t *self = find_phys_host_by_name(hostname, config);
    if (!self) {
        DOCA_LOG_ERR("Failed to find my hostname %s in config file", hostname);
        return 0;
    }
    
    DOCA_LOG_ERR("Found my hostname %s in config file with %d PFs", hostname, self->num_nics);

    for (uint32_t i=0; i<self->num_nics; i++) {
        pf_netdev_names[i] = self->nics[i].name;
    }

    return self->num_nics;
}
