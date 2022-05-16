#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>

// uint32_t id_to_ip[] = {20, 22, 24, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

// struct Params params = {
// 	.BDP = 7,
// 	.small_flow_thre = 7,
// 	.mss = 1460,
// 	.priority_limit = 6,
// 	.bandwidth = 10000000000,
// 	.ip = IPv4(192, 168, 6, 27),
// 	.dst_ip = IPv4(192, 168, 6, 28),
// 	.pim_beta = 5,
// 	.pim_alpha = 1.6,
// 	.pim_iter_limit = 5,
// 	.propagation_delay = 0.0000002,
// 	.clock_bias = 0.0000005,
// 	.send_port = 0,
// 	.pim_select_min_iters = 1,
// 	.batch_tokens = 7,
// 	.load = 0.6
// };

double get_transmission_delay(double bytes) {
	return bytes * 8 / params.bandwidth;
}

double get_rtt(double propagation_delay, int layer, double bytes) {
	double rtt = 0;
	rtt += propagation_delay * layer * 2;
	rtt += get_transmission_delay(bytes) * layer * 2;
	return rtt;
}
// uint32_t ip_to_id(uint32_t ip) {
// 	uint32_t i = 0;
// 	for(; i < 16; i++) {
// 		if(id_to_ip[i] == ip) {
// 			return i;
// 		}
// 	}
// 	return 0;
// }
uint32_t get_port_by_ip(uint32_t ip) {
	return 1;
	if(params.ip == 20) {
		if(ip == 22) {
			return 1;
		} else if(ip == 24) {
			return 0;
		}
	} else if(params.ip == 22) {
		if(ip == 20) {
			return 0;
		} else if(ip == 24) {
			return 1;
		}
	} else if(params.ip == 24) {
		if(ip == 20) {
			return 1;
		} else if(ip == 22) {
			return 0;
		}
	}
	rte_exit(EXIT_FAILURE, "none exists port");
	return 5;
}
