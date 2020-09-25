
#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>
struct Params params = {
    .BDP = 7,
    .small_flow_thre = 7,
    .mss = 1460,
    .priority_limit = 6,
    .bandwidth = 10000000000,
    .ip = IPv4(192, 168, 6, 27),
    .pim_beta = 5,
    .pim_alpha = 1.6,
    .pim_iter_limit = 5,
    .propagation_delay = 0.0000002,
    .clock_bias = 0.0000005,
    .send_port = 0,
    .pim_select_min_iters = 1,
    .batch_tokens = 7,
    .load = 0.6,
    .num_hosts = 2
};

void init_config(struct Params* p) {
	p->dst_ips[0] = IPv4(192, 168, 6, 27);
	p->dst_ips[1] = IPv4(192, 168, 6, 28);
	p->dst_ethers[0].addr_bytes[0] = 0x7C;
	p->dst_ethers[0].addr_bytes[1] = 0xFE;
	p->dst_ethers[0].addr_bytes[2] = 0x90;
	p->dst_ethers[0].addr_bytes[3] = 0x32;
	p->dst_ethers[0].addr_bytes[4] = 0x7A;
	p->dst_ethers[0].addr_bytes[5] = 0xFB;
	p->dst_ethers[1].addr_bytes[0] = 0x7C;
	p->dst_ethers[1].addr_bytes[1] = 0xFE;
	p->dst_ethers[1].addr_bytes[2] = 0x90;
	p->dst_ethers[1].addr_bytes[3] = 0x32;
	p->dst_ethers[1].addr_bytes[4] = 0x79;
	p->dst_ethers[1].addr_bytes[5] = 0x7B;

}
