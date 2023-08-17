#include <json-c/json.h>

#include <geneve_demo_vnet_conf.h>
#include <doca_log.h>

DOCA_LOG_REGISTER(vnet_conf);

#define CALLOC_ARRAY(array_var, array_length) \
    array_var = calloc(array_length, sizeof(array_var[0]))

static void load_hard_coded_config_values(struct vnet_config_t *config)
{
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
}

static doca_error_t parse_vnic(struct json_object *vnic_obj, struct vnic_t *vnic)
{
    // parse index, name, mac, ip, pci, vnet_id
    struct json_object *index_obj, *name_obj, *mac_obj, *pci_obj, *ip_obj, *vni_obj;
    if (!json_object_object_get_ex(vnic_obj, "index", &index_obj) ||
            !json_object_is_type(index_obj, json_type_int)) {
        DOCA_LOG_ERR("NIC numeric \"index\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    vnic->vf_index = json_object_get_int(index_obj);

    if (!json_object_object_get_ex(vnic_obj, "name", &name_obj)) {
        DOCA_LOG_ERR("NIC \"name\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    if (!json_object_object_get_ex(vnic_obj, "mac", &mac_obj)) {
        DOCA_LOG_ERR("NIC \"mac\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *mac_str = json_object_get_string(mac_obj);
    if (rte_ether_unformat_addr(mac_str, &vnic->mac_addr) != 0) { // 0 if successful
        DOCA_LOG_ERR("NIC: bad mac addr: %s", mac_str);
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(vnic_obj, "pci", &pci_obj)) {
        DOCA_LOG_ERR("NIC \"pci\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    // TODO: parse PCI addr

    if (!json_object_object_get_ex(vnic_obj, "ip", &ip_obj)) {
        DOCA_LOG_ERR("NIC \"ip\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *ip_str = json_object_get_string(ip_obj);
    if (inet_pton(AF_INET6, ip_str, &vnic->ip) != 1) { // 1 if successful
        DOCA_LOG_ERR("NIC: bad IPv6 addr: %s", ip_str);
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!json_object_object_get_ex(vnic_obj, "vnid-out", &vni_obj) ||
            !json_object_is_type(vni_obj, json_type_int)) {
        DOCA_LOG_ERR("NIC numeric \"vnid-out\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    vnic->vnet_id_out = json_object_get_int(vni_obj);

    vnic->name = strdup(json_object_get_string(name_obj));
    
    return DOCA_SUCCESS;
}

static doca_error_t parse_nic(struct json_object *nic_obj, struct nic_t *nic)
{
    // parse name, mac, ip, pci
    struct json_object *name_obj, *mac_obj, *pci_obj, *ip_obj, *vnics_obj;
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

    if (!json_object_object_get_ex(nic_obj, "pci", &pci_obj)) {
        DOCA_LOG_ERR("NIC \"pci\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    // TODO: parse PCI addr

    if (!json_object_object_get_ex(nic_obj, "ip", &ip_obj)) {
        DOCA_LOG_ERR("NIC \"ip\" required");
        return DOCA_ERROR_INVALID_VALUE;
    }
    const char *ip_str = json_object_get_string(ip_obj);
    if (inet_pton(AF_INET6, ip_str, &nic->ip) != 1) { // 1 if successful
        DOCA_LOG_ERR("NIC: bad IPv6 addr: %s", ip_str);
        return DOCA_ERROR_INVALID_VALUE;
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
        doca_error_t result = parse_vnic(vnic_obj, &nic->vnics[i]);
        if (result != DOCA_SUCCESS) {
            return result;
        }
    }
    return DOCA_SUCCESS;
}

static doca_error_t parse_host(struct json_object *host_obj, struct vnet_host_t *host)
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
        doca_error_t result = parse_nic(nic_obj, &host->nics[i]);
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
        route->vnic_name[i] = strdup(json_object_get_string(endpt_vnic));
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

        struct json_object *routes_obj = NULL;
        if (!json_object_object_get_ex(json_obj, "routes", &routes_obj)) {
            DOCA_LOG_ERR("Missing \"routes\" parameter");
            break;
        }

        config->num_routes = json_object_array_length(routes_obj);
        DOCA_LOG_DBG("Config: configuring %d routes", config->num_routes);
        if (config->num_routes == 0) {
            DOCA_LOG_ERR("Zero \"routes\" configured");
            break;
        }

        CALLOC_ARRAY(config->hosts, config->num_hosts);
        CALLOC_ARRAY(config->routes, config->num_routes);

        for (size_t i=0; i<config->num_hosts; i++) {
            struct json_object *host_obj = json_object_array_get_idx(hosts_obj, i);
            result = parse_host(host_obj, &config->hosts[i]);
            if (result != DOCA_SUCCESS) {
                break;
            }
        }
        if (result != DOCA_SUCCESS) {
            break;
        }

        for (size_t i=0; i<config->num_routes; i++) {
            struct json_object *route_obj = json_object_array_get_idx(routes_obj, i);
            result = parse_route(route_obj, &config->routes[i]);
            if (result != DOCA_SUCCESS) {
                break;
            }
        }
        if (result != DOCA_SUCCESS) {
            break;
        }

        result = DOCA_SUCCESS;
    } while (false);

	free(json_obj);
    
    //load_hard_coded_config_values(config);

    return result;
}