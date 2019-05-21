#ifndef RUF_PACER_H
#define RUF_PACER_H

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_timer.h>

#include "debug.h"
#include "ruf_host.h"
extern struct rte_mempool* pktmbuf_pool;


struct send_data_timeout_params {
	struct ruf_pacer *pacer;
	struct ruf_sender *sender;
};
struct send_token_timeout_params {
	struct ruf_pacer *pacer;
	struct ruf_receiver *receiver;
};

struct ruf_pacer {
	// except token
	struct rte_ring* ctrl_q;
	// struct rte_ring* data_q;
	uint64_t remaining_bytes;
	uint64_t last_update_time;
	struct rte_timer token_timer;
	struct rte_timer data_timer;
	struct send_data_timeout_params* send_data_timeout_params;
	struct send_token_timeout_params* send_token_timeout_params;
};

void init_pacer(struct ruf_pacer* pacer, struct ruf_receiver * receiver, struct ruf_sender *ruf_sender, uint32_t socket_id);
void ruf_pacer_send_data_pkt_handler(__rte_unused struct rte_timer *timer, void* arg);
void ruf_pacer_send_token_handler(__rte_unused struct rte_timer *timer, void* arg);
void ruf_pacer_send_pkts(struct ruf_pacer* pacer);
void update_time_byte(struct ruf_pacer* pacer);
#endif