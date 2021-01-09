#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include <rte_cycles.h>

#define MY_ID 22
#define PORT_0 20
#define PORT_1 24

#define RRCC_MTU 1500
#define TARGET_RATE_bps 5000000000

#define NUM_FLOW_TYPES 12
#define NUM_LINKS 6
#define IP_DN_FRAGMENT_FLAG 0x0040

// highest to lowest: 7 - 1
// #define TCI_7 0xE000
// #define TCI_6 0xC000
// #define TCI_5 0xA000
// #define TCI_4 0x8000
// #define TCI_3 0x6000
// #define TCI_2 0x4000
// #define TCI_1 0x2000
// #define TCI_0 0x0000

#define TOS_7 0xE0
#define TOS_6 0xC0
#define TOS_5 0xA0
#define TOS_4 0x80
#define TOS_3 0x60
#define TOS_2 0x40
#define TOS_1 0x20
#define TOS_0 0x00

struct Params {
	double load;
	double BDP;
	double small_flow_thre;
	uint32_t mss;
	uint32_t priority_limit;
	uint64_t bandwidth;
	uint32_t ip;
	uint32_t pim_select_min_iters;
	double pim_alpha;
	double pim_beta;
	uint32_t pim_iter_limit;
	double pim_iter_epoch;
	double pim_epoch;
	double pipe_epoch;
	uint32_t token_window;
	double token_window_timeout;
	uint64_t token_window_timeout_cycle;
	// debug purpose
	uint32_t index;
	uint32_t num_hosts;
	uint32_t dst_ips[40];
	struct ether_addr dst_ethers[40];
	struct ether_addr ether_addr;
	uint32_t batch_tokens;
	double propagation_delay;
	uint32_t send_port;
	double clock_bias;
};

extern struct Params params;

double get_transmission_delay(double bytes);
double get_rtt(double propagation_delay, int layer, double bytes);
uint32_t get_port_by_ip(uint32_t ip);
uint32_t ip_to_id(uint32_t ip);
void init_config(struct Params* p);
#endif
