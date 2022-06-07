import sys
import socket
import struct
import netifaces as ni
# ether_addrs = ["00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4"]
ether_addrs = []
def construct_ip(small_ip, large_ip, ip_prefix = "10,10,1"):
    num_dst = large_ip - small_ip + 1
    dst_ips = ""
    for i in range(num_dst):
        dst_ips += "\tp->dst_ips[{}] = IPv4({}, {});".format(i, ip_prefix, small_ip + i)
        dst_ips += "\n"
    return num_dst, dst_ips

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def read_arp_and_ip(file = "/proc/net/arp"):
    f = open(file, "r")
    lines = f.readlines()[1:]
    dict_ip = {}
    for line in lines:
        e = line.split()
        ip = e[0]
        eth = e[3]
        if "10.10" in ip:
            dict_ip[ip2int(ip)] = eth

    # read ip 
    ip = ni.ifaddresses('eno1d1')[ni.AF_INET][0]['addr']
    ether = ni.ifaddresses('eno1d1')[ni.AF_LINK][0]['addr']
    dict_ip[ip2int(ip)] = ether

    for key in sorted(dict_ip.keys()):
        ether_addrs.append(dict_ip[key])
    print ether_addrs
    return ip

def construct_ethers():
    i = 0
    output = ""
    for addr in ether_addrs:
        parts = addr.split(":")
        j = 0
        for p in parts:
            output += "\tp->dst_ethers[{}].addr_bytes[{}] = {};\n".format(i, j, "0x" + p.upper())
            j += 1
        i += 1
    return output

def main():
    small_ip = sys.argv[1]
    large_ip = sys.argv[2]
    num_dst, dst_ips = construct_ip(int(small_ip), int(large_ip))
    # config_string.format(ip_str)
    ip = read_arp_and_ip()
    index = int(ip.split(".")[3])
    ip_str =  "IPv4(" + ip.replace(".", ",") + ")"
    config_string = """
#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>
struct Params params = {{
    .index = {0},
    .BDP = 20,
    .small_flow_thre = 20,
    .mss = 1460,
    .priority_limit = 6,
    .bandwidth = 10000000000,
    .ip = {1},
    .pim_beta = 5,
    .pim_alpha = 1.1,
    .pim_iter_limit = 3,
    .propagation_delay = 0.0000002,
    .clock_bias = 0.0000005,
    .send_port = 0,
    .pim_select_min_iters = 1,
    .batch_tokens = 5,
    .load = 0.5,
    .token_window = 20,
    .token_window_timeout = 1.1,
    .num_hosts = {2}
}};
""".format(int(index) - int(small_ip), ip_str, int(large_ip) - int(small_ip) + 1)
    statement = dst_ips
    statement += construct_ethers()
    statement += "\tparams.token_window_timeout_cycle = (uint64_t) (params.token_window_timeout * params.BDP * 1500 * 8 \n \t / params.bandwidth * rte_get_timer_hz());\n"
    init_string= """
void init_config(struct Params* p) {{
{0}
}}
""".format(statement)

    f = open("src/config2.c", "w+")
    f.write(config_string)
    f.write(init_string)
    f.close()
main()
