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
struct virtual_function_t
{
    uint16_t vf_index;
    struct rte_ether_addr mac_addr;
};

// Describes the PF and VFs owned by a physical host
struct vnet_host_t
{
    const char *name;
    ipv6_addr_t ip;
    struct rte_ether_addr mac_addr;
    uint16_t num_vfs;
    struct virtual_function_t *vfs;
};

// A list of physical hosts
struct vnet_host_list_t
{
    uint16_t num_hosts;
    struct vnet_host_t *hosts;
};

// Describes the network interface of a virtual host in terms of
// the physical host which owns it.
struct vnet_virt_host_t
{
    uint16_t vf_index;
    ipv6_addr_t ip;
};

// A list of virtual hosts, hosted on the given physical host,
// which participate on the given virtual network.
// (Typically only one VM exists for a given vnet.)
struct vnet_host_inventory_t
{
    const char *host_name;
    uint32_t vnet_id;
    uint16_t num_virt_hosts;
    struct vnet_virt_host_t *virt_hosts;
};

// A list of physical hosts which participate on a given
// virtual network.
struct vnet_t
{
    uint32_t vnet_id;
    uint16_t  num_hosts;
    struct vnet_host_inventory_t *hosts;
};

// A configuration which describes all the physical hosts on
// a physical network, and all the virtual networks which
// span the physical hosts, as well as the virtual machines
// present on the virtual network.
struct vnet_config_t
{
    struct vnet_host_list_t physical_hosts;
    uint16_t num_vnets;
    struct vnet_t *vnets;
};

int load_vnet_config(const char *config_json_path, struct vnet_config_t *config);

