from collections import defaultdict

import paramiko
import re
import json 

L1 = ["dgx-google-01","dgx-google-02","dgx-google-03","dgx-google-04"]
L2 = ["dgx-google-05","dgx-google-06","dgx-google-07","dgx-google-08"]
devices_e_w = ["mlx5_0", "mlx5_3", "mlx5_4", "mlx5_5", "mlx5_6", "mlx5_9", "mlx5_10", "mlx5_11"]
pci_addresses = ["18:00.0","40:00.0","4f:00.0","5e:00.0","9a:00.0","c0:00.0","ce:00.0","dc:00.0"]
pf_interfaces_e_w = ["enp24s0np0", "enp64s0np0", "enp79s0np0", "enp94s0np0", "enp154s0np0", "enp192s0np0", "enp206s0np0", "enp220s0np0"]
rep_interfaces_e_w = ["enp24s0npf0vf0", "enp64s0npf0vf0", "enp79s0npf0vf0", "enp94s0npf0vf0", "enp154s0npf0vf0", "enp192s0npf0vf0", "enp206s0npf0vf0", "enp220s0npf0vf0"]
vf_interfaces_e_w = ["enp24s0v0", "enp64s0v0", "enp79s0v0", "enp94s0v0", "enp154s0v0", "enp192s0v0", "enp206s0v0", "enp220s0v0"]

host_username = 'root'

def run_command_on_host(host, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.load_system_host_keys()
    try:
        ssh.connect(host, username=host_username)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip().replace('\t', '   ')
        error = stderr.read().decode().strip()
        return_code = stdout.channel.recv_exit_status()
        #print(f"## Output for command '{command}' on host '{host}':")
        #print(output)
    finally:
        ssh.close()
    return [output, error, return_code]

next_vnet_id = 400

config = {
    'outer-ip-ver': 6,
    'inner-ip-ver': 4,
    'hosts': [],
    "route-all-to-all": True
}

for hostname in L1+L2:
    host_cfg = { 'name': hostname, 'nics': [] }
    config['hosts'].append(host_cfg)
    host_pfs = host_cfg['nics']

    print(f"Creating config for {hostname}...")
    for pf in pf_interfaces_e_w:
        pf_cfg = { 'name': pf, 'vnics': [] }
        host_pfs.append(pf_cfg)

        [output, error, return_code] = run_command_on_host(hostname, f"ip -br link show dev {pf}")
        if return_code != 0:
            print(f"Failed to get mac addr for {hostname} / {pf}")
            continue

        macaddr = output.split()[2]
        pf_cfg['mac'] = macaddr

        [output, error, return_code] = run_command_on_host(hostname, f"ip -br -6 addr show dev {pf}")
        if return_code != 0:
            print(f"Failed to get IPv6 addr for {hostname} / {pf}")
            continue
        
        if not output:
            print(f"Failed to find IP addr for {hostname} / {pf}; making one up")
            output = f"{pf} UP fe80::5aa2:e1ff:dead:beef/64"
        ipaddr = output.split()[-1]
        ipaddr = re.sub('/\d+$', '', ipaddr)
        pf_cfg['ip'] = ipaddr

        vf = re.sub('np0', 'v0', pf)
        vf_cfg = { 'name': vf }
        pf_cfg['vnics'].append(vf_cfg)

        [output, error, return_code] = run_command_on_host(hostname, f"ip -br link show dev {vf}")
        if return_code != 0:
            print(f"Failed to get mac addr for {hostname} / {vf}")
            continue
            
        macaddr = output.split()[2]
        vf_cfg['mac'] = macaddr

        [output, error, return_code] = run_command_on_host(hostname, f"ip -br -4 addr show dev {vf}")
        if return_code != 0:
            print(f"Failed to get IPv6 addr for {hostname} / {vf}")
            continue

        ipaddr = output.split()[-1]
        ipaddr = re.sub('/\d+$', '', ipaddr)
        vf_cfg['ip'] = ipaddr

        vf_cfg['vnid-out'] = next_vnet_id
        next_vnet_id += 1

with open("testbed_new.jsonc", "w") as outfile:
    json.dump(config, outfile, indent=4, sort_keys=True)
