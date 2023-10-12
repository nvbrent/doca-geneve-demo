#!/bin/sh
/opt/mellanox/dpdk/bin/dpdk-hugepages.py -r8G
echo legacy > /sys/class/net/enp23s0f0np0/compat/devlink/mode
echo none > /sys/class/net/enp23s0f0np0/compat/devlink/encap 
echo switchdev > /sys/class/net/enp23s0f0np0/compat/devlink/mode
echo 2 > /sys/class/net/enp23s0f0np0/device/sriov_numvfs
