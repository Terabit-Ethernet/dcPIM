#ifndef PIM_HOST_H
#define PIM_HOST_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_rwlock.h>
#include <rte_timer.h>

#include "debug.h"
#include "header.h"
#include "zedro_pacer.h"
#include "zedro_flow.h"
#include "pq.h"

struct zedro_flow;

extern bool start_signal;

// virtual link for receiver
struct zedro_virtual_link {
	int link_id;
	struct zedro_flow* flow;
	bool used;
};

struct zedro_send_data_evt_param {
	int link_id;
	struct zedro_host* host;
	// struct zedro_epoch* zedro_epoch;
	struct zedro_pacer* pacer;
	struct zedro_flow* flow;
	int receiver_link_id;
	uint32_t num_pkts;
	bool used;
};


// struct event_params {
// 	void (*func)(void*);
// 	void* params;
// };

struct zedro_host{
	// uint32_t cur_epoch;

	// sender
	// struct rte_timer zedro_send_token_timer;
	// uint32_t cur_match_dst_addr;
	int sender_k;
	struct rte_mempool *tx_flow_pool;
	// struct rte_hash *dst_minflow_table;
	// struct rte_hash *src_minflow_table;

	// struct rte_ring * control_message_q;
	struct rte_hash * tx_flow_table;
	uint32_t finished_flow;
	uint64_t sent_bytes;
	// hard code for now
	struct rte_timer sender_link_timers[16];
	struct zedro_send_data_evt_param sender_link_params[16];
	uint64_t num_cts_received;
	uint64_t num_nts_sent;

	// receiver
	Pq inactive_flows;
	int receiver_k;
	// hard code for now
	struct zedro_virtual_link  zedro_receiver_links[16];
	// uint32_t cur_match_src_addr;
	struct rte_mempool *rx_flow_pool;
	struct rte_hash *rx_flow_table;
	uint64_t num_cts_sent;
	uint64_t num_nts_received;
	// uint32_t num_token_sent;
	// min large flow
	// struct rte_ring *temp_pkt_buffer;
	// struct rte_ring * control_message_q;
	// struct rte_ring *short_flow_token_q;
	// struct rte_ring *long_flow_token_q;
	// struct rte_ring *send_token_q;
	// struct rte_ring *event_q;
	uint32_t received_bytes;
	uint64_t start_cycle;
	uint64_t end_cycle;
};
bool zedro_zflow_compare(const void *a, const void* b);

void zedro_new_flow_comes(struct zedro_host * host, struct zedro_pacer* pacer, 
	uint32_t flow_id, uint32_t dst_addr, struct ether_addr* dst_ether, uint32_t flow_size);


// void zedro_host_dump(struct zedro_host* host, struct zedro_pacer* pacer);



// host logic 
void zedro_init_host(struct zedro_host *host, uint32_t socket_id);
void zedro_host_dump(struct zedro_host* host);

void zedro_increase_sender_k(struct zedro_host* host);
void zedro_decrease_sender_k(struct zedro_host* host);
void zedro_send_rts(struct zedro_pacer* pacer, struct zedro_flow* flow);
void zedro_receive_cts(struct zedro_host* host, struct zedro_pacer* pacer, 
	struct zedro_hdr* zedro_hdr, struct zedro_cts_hdr* zedro_cts_hdr);

void zedro_rx_packets(struct zedro_host* host, struct zedro_pacer* pacer,
struct rte_mbuf* p);
void zedro_receive_rts(struct zedro_host* host, struct zedro_pacer* pacer, struct ether_hdr* ether_hdr,
	struct ipv4_hdr* ipv4_hdr, struct zedro_hdr* zedro_hdr, struct zedro_rts_hdr* zedro_rts_hdr);
void zedro_receive_accept_cts(struct zedro_flow *flow, struct zedro_accept_cts_hdr* zedro_accept_cts_hdr);
void zedro_receive_data(struct zedro_host *host, struct zedro_pacer* pacer, struct zedro_hdr* zedro_hdr,
 struct zedro_data_hdr * zedro_data_hdr, struct rte_mbuf *p);
void zedro_receive_nts(struct zedro_host* host, struct zedro_pacer* pacer, struct zedro_nts_hdr* zedro_nts_hdr);
void zedro_receive_start(void);
void zedro_try_send_cts_pkt(struct zedro_host* host, struct zedro_pacer* pacer);

void zedro_increase_receiver_k(struct zedro_host* host);
void zedro_decrease_receiver_k(struct zedro_host* host);

int zedro_find_available_receiver_link(struct zedro_host* host);
void zedro_set_receiver_link(struct zedro_host* host, int link_id, struct zedro_flow* flow);

struct zedro_flow* get_smallest_unfinished_flow(Pq* pq);
void zedro_send_data_evt_handler(__rte_unused struct rte_timer *timer, void* arg);

#endif