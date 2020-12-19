import sys
ether_addrs = ["00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4", "00:01:e8:8b:2e:e4"]

def construct_ip(ip, small_ip, large_ip, ip_prefix = "0, 0, 10"):
    ip = "IPv4({}, {})".format(ip, ip_prefix)
    num_dst = large_ip - small_ip + 1
    dst_ips = ""
    for i in range(num_dst):
        dst_ips += "\tp->dst_ips[{}] = IPv4({}, {});".format(i,small_ip + i, ip_prefix)
        dst_ips += "\n"
    return ip, num_dst, dst_ips

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
    ip = sys.argv[1]
    small_ip = sys.argv[2]
    large_ip = sys.argv[3]
    ip_str, num_dst, dst_ips = construct_ip(ip, int(small_ip), int(large_ip))
    # config_string.format(ip_str)
    config_string = """
#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>
struct Params params = {{
    .index = {0},
    .BDP = 7,
    .small_flow_thre = 7,
    .mss = 1460,
    .priority_limit = 6,
    .bandwidth = 10000000000,
    .ip = {1},
    .pim_beta = 5,
    .pim_alpha = 0.3,
    .pim_iter_limit = 5,
    .propagation_delay = 0.0000002,
    .clock_bias = 0.0000005,
    .send_port = 0,
    .pim_select_min_iters = 1,
    .batch_tokens = 1,
    .load = 0.5,
    .token_window = 7,
    .token_window_timeout = 1.1,
    .num_hosts = {2}
}};
""".format(int(ip) - int(small_ip), ip_str, int(large_ip) - int(small_ip) + 1)
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
