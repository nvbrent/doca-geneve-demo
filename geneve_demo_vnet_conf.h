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
#pragma once

#include <geneve_demo.h>

// Describes a VF, including its index relateive to the parent PF,
// and its MAC address.
// Not to be confused with the corresponding port representor.
struct vnic_t
{
    struct rte_ether_addr mac_addr;
    union ip_addr ip;
    // The same VNET ID is applied to all outgoing flows on this interface
    uint32_t vnet_id_out;
};

// Describes a PF, including VFs owned by it.
// All flows are created on this device.
struct nic_t
{
    const char *name;
    struct rte_ether_addr mac_addr;
    union ip_addr ip;
    uint16_t num_vnics;
    struct vnic_t *vnics;

    uint16_t subnet_mask_len;
    bool has_gateway;
    struct rte_ether_addr gw_mac_addr;
};

// Describes a collection of physical and virtual NICs.
struct vnet_host_t
{
    const char *name;
    uint16_t num_nics;
    struct nic_t *nics;
};

struct route_t
{
    const char *hostname[2];
    union ip_addr vip[2];
};

// A configuration which describes all the physical hosts on
// a physical network, and all the virtual networks which
// span the physical hosts.
struct vnet_config_t
{
    int outer_addr_fam; // AF_INET or AF_INET6
    int inner_addr_fam;
    uint16_t num_hosts;
    struct vnet_host_t *hosts;
    bool route_all_to_all;
    uint16_t num_routes;
    struct route_t *routes;
};

doca_error_t load_vnet_config(const char *config_json_path, struct vnet_config_t *config);

uint32_t find_my_vnet_pfs(const struct vnet_config_t *config, const char **pf_netdev_names);

const struct vnet_host_t *
find_phys_host_by_name(const char *hostname, const struct vnet_config_t *config);