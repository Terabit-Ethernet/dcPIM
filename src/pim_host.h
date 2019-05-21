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
#include <rte_timer.h>

#include "debug.h"
#include "header.h"
#include "pim_pacer.h"
#include "pim_flow.h"
#include "pq.h"

struct pim_flow;

struct gosrc_info {
	uint32_t src_addr;
	struct pim_flow* current_flow;
    int max_tokens;
    int remain_tokens;
    int round;
    bool has_gosrc;
    bool send_nrts;   
};

struct idle_timeout_params {
	struct pim_pacer* pacer;
	struct pim_receiver* receiver;
};

struct send_token_evt_params {
	struct pim_pacer* pacer;
	struct pim_receiver* receiver;
};

struct send_listsrc_params {
	struct pim_pacer *pacer;
	struct pim_receiver *receiver;
	int nrts_src_addr; 
};

struct event_params {
	void (*func)(void*);
	void* params;
};

struct src_dst_pair {
	uint32_t src;
	uint32_t dst;
	uint32_t flow_size;
};

struct pim_sender{
	
	struct rte_mempool *tx_flow_pool;
	struct rte_ring *short_flow_token_q;
	struct rte_ring *long_flow_token_q;
	// struct rte_ring * control_message_q;
	struct rte_hash * tx_flow_table;
	uint32_t finished_flow;
	uint32_t sent_bytes;

};

struct pim_receiver{
	struct rte_mempool *rx_flow_pool;
	struct rte_hash *rx_flow_table;
	// min large flow
	struct rte_hash *src_minflow_table;
	struct rte_ring *long_flow_token_q;
	struct rte_ring *short_flow_token_q;
	struct rte_ring *temp_pkt_buffer;
	// struct rte_ring * control_message_q;
	struct rte_timer idle_timeout;
	struct idle_timeout_params* idle_timeout_params;
	struct gosrc_info gosrc_info;
	struct rte_timer send_token_evt_timer;
	struct send_token_evt_params* send_token_evt_params;

	struct rte_ring *event_q;
    // struct rte_timer send_listsrc_timer;
    // struct send_listsrc_params* send_listsrc_params;
	uint32_t received_bytes;
	uint64_t start_cycle;
	uint64_t end_cycle;
	uint32_t num_token_sent;
	uint32_t idle_timeout_times;
	uint32_t invoke_sent_nrts_num;
	uint32_t sent_nrts_num;
};

struct pim_controller{
	// struct rte_mempool* node_pool;
	// struct rte_mempool* element_pool;
	struct rte_hash* sender_state;
	struct rte_hash* receiver_state;
	struct rte_timer handle_rq_timer;
	Pq pq;
	// Node* head;
};

void pim_new_flow_comes(struct pim_sender * sender, struct pim_pacer* pacer, 
	uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size);
// set gosrc
void init_gosrc(struct gosrc_info *gosrc);
void reset_gosrc(struct gosrc_info *gosrc);
// receiver logic
void idle_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void send_token_evt_handler(__rte_unused struct rte_timer *timer, void* arg);

void reset_idle_timeout(struct pim_receiver *receiver, struct pim_pacer *pacer);
void reset_send_tokens_evt(struct pim_receiver *receiver, struct pim_pacer* pacer, int sent_token);

void pim_rx_packets(struct pim_receiver* receiver, struct pim_sender* sender, struct pim_pacer* pacer,
 struct rte_mbuf* p);
void pim_receive_rts(struct pim_receiver* receiver, struct pim_pacer *pacer, 
	struct ipv4_hdr* ipv4_hdr, struct pim_rts_hdr* pim_rts_hdr);
void pim_receive_gosrc(struct pim_receiver *receiver, struct pim_pacer *pacer,
 struct pim_gosrc_hdr *pim_gosrc_hdr);
void pim_receive_data(struct pim_receiver *receiver, struct pim_pacer* pacer,
 struct pim_data_hdr * pim_data_hdr, struct rte_mbuf *p);

void host_dump(struct pim_sender* sender, struct pim_receiver *receiver, struct pim_pacer* pacer);

void send_listsrc(void* arg);
void invoke_send_listsrc(struct pim_receiver* receiver, struct pim_pacer *pacer, int nrts_src_addr);

void pim_flow_finish_at_receiver(struct pim_receiver *receiver, struct pim_flow * f);
// sender logic
void pim_receive_token(struct pim_sender *sender, struct pim_token_hdr *pim_token_hdr, struct rte_mbuf* p);
void pim_receive_ack(struct pim_sender *sender, struct pim_ack_hdr * pim_ack_hdr);
// void enqueue();
// void dequeue();

void pim_new_flow(
 struct pim_pacer* pacer, uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size);

// controller logic 

void pim_receive_listsrc(struct pim_controller *controller, struct rte_mbuf *p);
void handle_requests(__rte_unused struct rte_timer *timer, void* arg);

void init_sender(struct pim_sender *pim_sender, uint32_t socket_id);
void init_receiver(struct pim_receiver *pim_receiver, uint32_t socket_id);
void init_controller(struct pim_controller* controller, uint32_t socket_id);

bool src_dst_compare(const void* a, const void* b);
// helper function
void send_rts(struct pim_sender* sender, struct pim_pacer* pacer, struct pim_flow* flow);
void iterate_temp_pkt_buf(struct pim_receiver* receiver, struct pim_pacer* pacer, uint32_t flow_id);
void get_gosrc_pkt(struct rte_mbuf* p, uint32_t src_addr,
 uint32_t dst_addr, uint32_t token_num);
#endif