
#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>
struct Params params = {
    .index = 2,
    .BDP = 7,
    .small_flow_thre = 7,
    .mss = 1460,
    .priority_limit = 6,
    .bandwidth = 10000000000,
    .ip = IPv4(7, 0, 0, 10),
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
    .num_hosts = 8
};

void init_config(struct Params* p) {
	p->dst_ips[0] = IPv4(5, 0, 0, 10);
	p->dst_ips[1] = IPv4(6, 0, 0, 10);
	p->dst_ips[2] = IPv4(7, 0, 0, 10);
	p->dst_ips[3] = IPv4(8, 0, 0, 10);
	p->dst_ips[4] = IPv4(9, 0, 0, 10);
	p->dst_ips[5] = IPv4(10, 0, 0, 10);
	p->dst_ips[6] = IPv4(11, 0, 0, 10);
	p->dst_ips[7] = IPv4(12, 0, 0, 10);
	p->dst_ethers[0].addr_bytes[0] = 0x00;
	p->dst_ethers[0].addr_bytes[1] = 0x01;
	p->dst_ethers[0].addr_bytes[2] = 0xE8;
	p->dst_ethers[0].addr_bytes[3] = 0x8B;
	p->dst_ethers[0].addr_bytes[4] = 0x2E;
	p->dst_ethers[0].addr_bytes[5] = 0xE4;
	p->dst_ethers[1].addr_bytes[0] = 0x00;
	p->dst_ethers[1].addr_bytes[1] = 0x01;
	p->dst_ethers[1].addr_bytes[2] = 0xE8;
	p->dst_ethers[1].addr_bytes[3] = 0x8B;
	p->dst_ethers[1].addr_bytes[4] = 0x2E;
	p->dst_ethers[1].addr_bytes[5] = 0xE4;
	p->dst_ethers[2].addr_bytes[0] = 0x00;
	p->dst_ethers[2].addr_bytes[1] = 0x01;
	p->dst_ethers[2].addr_bytes[2] = 0xE8;
	p->dst_ethers[2].addr_bytes[3] = 0x8B;
	p->dst_ethers[2].addr_bytes[4] = 0x2E;
	p->dst_ethers[2].addr_bytes[5] = 0xE4;
	p->dst_ethers[3].addr_bytes[0] = 0x00;
	p->dst_ethers[3].addr_bytes[1] = 0x01;
	p->dst_ethers[3].addr_bytes[2] = 0xE8;
	p->dst_ethers[3].addr_bytes[3] = 0x8B;
	p->dst_ethers[3].addr_bytes[4] = 0x2E;
	p->dst_ethers[3].addr_bytes[5] = 0xE4;
	p->dst_ethers[4].addr_bytes[0] = 0x00;
	p->dst_ethers[4].addr_bytes[1] = 0x01;
	p->dst_ethers[4].addr_bytes[2] = 0xE8;
	p->dst_ethers[4].addr_bytes[3] = 0x8B;
	p->dst_ethers[4].addr_bytes[4] = 0x2E;
	p->dst_ethers[4].addr_bytes[5] = 0xE4;
	p->dst_ethers[5].addr_bytes[0] = 0x00;
	p->dst_ethers[5].addr_bytes[1] = 0x01;
	p->dst_ethers[5].addr_bytes[2] = 0xE8;
	p->dst_ethers[5].addr_bytes[3] = 0x8B;
	p->dst_ethers[5].addr_bytes[4] = 0x2E;
	p->dst_ethers[5].addr_bytes[5] = 0xE4;
	p->dst_ethers[6].addr_bytes[0] = 0x00;
	p->dst_ethers[6].addr_bytes[1] = 0x01;
	p->dst_ethers[6].addr_bytes[2] = 0xE8;
	p->dst_ethers[6].addr_bytes[3] = 0x8B;
	p->dst_ethers[6].addr_bytes[4] = 0x2E;
	p->dst_ethers[6].addr_bytes[5] = 0xE4;
	p->dst_ethers[7].addr_bytes[0] = 0x00;
	p->dst_ethers[7].addr_bytes[1] = 0x01;
	p->dst_ethers[7].addr_bytes[2] = 0xE8;
	p->dst_ethers[7].addr_bytes[3] = 0x8B;
	p->dst_ethers[7].addr_bytes[4] = 0x2E;
	p->dst_ethers[7].addr_bytes[5] = 0xE4;
	params.token_window_timeout_cycle = (uint64_t) (params.token_window_timeout * params.BDP * 1500 * 8 
 	 / params.bandwidth * rte_get_timer_hz());

}
