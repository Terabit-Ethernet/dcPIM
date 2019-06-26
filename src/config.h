#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define MY_ID 22
#define PORT_0 20
#define PORT_1 24

#define RRCC_MTU 1500
#define TARGET_RATE_bps 5000000000

#define NUM_FLOW_TYPES 12
#define NUM_LINKS 6

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

extern uint32_t id_to_ip[];
extern int node_flow_types[];
extern char flow_path0[];
extern char flow_path1[]; 
extern char flow_path2[]; 
extern char flow_path3[]; 
extern char flow_path4[];
extern char flow_path5[];
extern char flow_path6[];
extern char flow_path7[];
extern char flow_path8[]; 
extern char flow_path9[];
extern char flow_path10[];
extern char flow_path11[];
extern char *flow_paths[];

extern char link_correspondence0[];
extern char link_correspondence1[];
extern char link_correspondence2[];
extern char link_correspondence3[];
extern char link_correspondence4[];
extern char link_correspondence5[];
extern char *link_correspondence[];


struct Params {
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
	// debug purpose
	uint32_t dst_ip;
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
#endif