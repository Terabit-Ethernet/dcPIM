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
#include "pim_pacer.h"
#include "pim_flow.h"
#include "pq.h"

struct pim_flow;

struct pim_rts {
    uint8_t iter;
    uint32_t src_addr;
    int remaining_sz;
};
struct pim_grant {
    bool prompt;
    uint32_t dst_addr;
    int remaining_sz;
};

struct pim_epoch {
	rte_rwlock_t rw_lock;
	uint32_t epoch;
	uint32_t iter;
	bool prompt;
	uint32_t match_src_addr;
	uint32_t match_dst_addr;
	struct pim_grants grants_q[16];
	struct pim_rts rts_q[16];
	uint32_t grant_size;
	uint32_t rts_size;
	struct pim_rts* min_rts;
	struct pim_grant* min_grant;
	struct rte_timer epoch_timer;
	struct rte_timer sender_iter_timer;
	struct rte_timer receiver_iter_timer;
};

struct event_params {
	void (*func)(void*);
	void* params;
};

struct pim_host{
	uint32_t cur_epoch;
	// sender

	uint32_t cur_match_dst_addr;
	struct rte_mempool *tx_flow_pool;
	struct rte_hash *dst_minflow_table;
	// struct rte_ring * control_message_q;
	struct rte_hash * tx_flow_table;
	uint32_t finished_flow;
	uint32_t sent_bytes;
	Pq active_short_flows;
	// receiver
	uint32_t cur_match_src_addr;
	struct rte_mempool *rx_flow_pool;
	struct rte_hash *rx_flow_table;
	// min large flow
	struct rte_ring *temp_pkt_buffer;
	// struct rte_ring * control_message_q;

	struct rte_ring *event_q;
	uint32_t received_bytes;
	uint64_t start_cycle;
	uint64_t end_cycle;
};
bool pim_pflow_compare(const void *a, const void* b);

void pim_new_flow_comes(struct pim_sender * sender, struct pim_pacer* pacer, 
	uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size);

// set epoch function 
void pim_init_epoch(struct pim_epoch *pim_epoch);
void pim_start_new_epoch(struct pim_epoch *pim_epoch, double time, int epoch);
void pim_advance_iter(struct pim_epoch *pim_epoch);

void pim_host_dump(struct pim_host* host, struct pim_pacer* pacer);

// PIM matching logic
void pim_get_grantr_pkt(struct pim_host* pim_host, struct ipv4_hdr ipv4_hdr, int iter, int epoch);
void pim_get_grant_pkt(struct pim_rts* pim_rts, struct pim_host* pim_host, struct ipv4_hdr ipv4_hdr, int iter, int epoch, bool prompt);
void pim_get_accept_pkt(struct pim_grant* pim_grant, struct pim_host* pim_host, int iter, int epoch);
void pim_get_rts_pkt(struct pim_flow* flow, int iter, int epoch);

void pim_send_all_rts(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer);
void pim_handle_all_grant(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer);
void pim_handle_all_rts(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer);
void pim_receive_rts(struct pim_epoch* epoch, 
	struct ipv4_hdr* ipv4_hdr, struct pim_rts_hdr* pim_rts_hdr);
void pim_receive_accept(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer,
 struct ipv4_hdr* ipv4_hdr, struct pim_accept_hdr* pim_accept_hdr);
void pim_receive_data(struct pim_host *host, struct pim_pacer* pacer,
 struct pim_data_hdr * pim_data_hdr, struct rte_mbuf *p);
void pim_receive_grant(struct pim_epoch* pim_epoch, struct ipv4_hdr* ipv4_hdr, struct pim_grant_hdr* pim_grant_hdr);
void pim_receive_grantr(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_grantr_hdr* pim_grantr_hdr);
// host logic 
void pim_init_host(struct pim_host *host, uint32_t socket_id);
void pim_rx_packets(struct pim_host* host, struct pim_pacer* pacer,
 struct rte_mbuf* p);
void pim_flow_finish_at_receiver(struct pim_receiver *receiver, struct pim_flow * f);

// sender logic
void pim_receive_ack(struct pim_sender *sender, struct pim_ack_hdr * pim_ack_hdr);
// void enqueue();
// void dequeue();

void pim_new_flow(struct pim_pacer* pacer,
 uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size);
struct pim_flow* get_smallest_unfinished_flow(Pq* pq);


#endif