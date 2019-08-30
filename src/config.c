#include "config.h"
#include <rte_ip.h>
#include <rte_common.h>

uint32_t id_to_ip[] = {20, 22, 24, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
int node_flow_types[] = {0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0};
char flow_path0[] = {24,0};
char flow_path1[] = {22,0};
char flow_path2[] = {24,22,0};
char flow_path3[] = {22,24,0};
char flow_path4[] = {20,0};
char flow_path5[] = {24,0};
char flow_path6[] = {20,24,0};
char flow_path7[] = {24,20,0};
char flow_path8[] = {22,0};
char flow_path9[] = {20,0};
char flow_path10[] = {22,20,0};
char flow_path11[] = {20,22,0};
char *flow_paths[] = {flow_path0, flow_path1, flow_path2, flow_path3, flow_path4, flow_path5, flow_path6, flow_path7, flow_path8, flow_path9, flow_path10, flow_path11};

char link_correspondence0[] = {1,0,1,0,0,0,1,0,0,0,0,0};
char link_correspondence1[] = {0,1,0,1,0,0,0,0,0,0,0,1};
char link_correspondence2[] = {0,0,0,0,1,0,1,0,0,0,1,0};
char link_correspondence3[] = {0,0,0,1,0,1,0,1,0,0,0,0};
char link_correspondence4[] = {0,0,1,0,0,0,0,0,1,0,1,0};
char link_correspondence5[] = {0,0,0,0,0,0,0,1,0,1,0,1};
char *link_correspondence[] = {link_correspondence0, link_correspondence1, link_correspondence2, link_correspondence3, link_correspondence4, link_correspondence5};

struct Params params = {
	.BDP = 7,
	.small_flow_thre = 7,
	.mss = 1460,
	.priority_limit = 6,
	.bandwidth = 10000000000,
	.ip = IPv4(192, 168, 6, 27),
	.dst_ip = IPv4(192, 168, 6, 28),
	.pim_beta = 5,
	.pim_alpha = 1.6,
	.pim_iter_limit = 5,
	.propagation_delay = 0.0000002,
	.clock_bias = 0.0000005,
	.send_port = 0,
	.pim_select_min_iters = 1,
	.batch_tokens = 7,
	.load = 0.6
};

double get_transmission_delay(double bytes) {
	return bytes * 8 / params.bandwidth;
}

double get_rtt(double propagation_delay, int layer, double bytes) {
	double rtt = 0;
	rtt += propagation_delay * layer * 2;
	rtt += get_transmission_delay(bytes) * layer * 2;
	return rtt;
}

uint32_t ip_to_id(uint32_t ip) {
	uint32_t i = 0;
	for(; i < 16; i++) {
		if(id_to_ip[i] == ip) {
			return i;
		}
	}
	return 0;
}
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
