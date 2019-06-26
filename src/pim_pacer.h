#ifndef PIM_PACER_H
#define PIM_PACER_H

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_timer.h>

#include "debug.h"
#include "pim_host.h"
extern struct rte_mempool* pktmbuf_pool;


struct send_data_timeout_params {
	struct pim_pacer *pacer;
	struct pim_host *host;
};
struct send_token_timeout_params {
	struct pim_pacer *pacer;
	struct pim_host *host;
};
struct pim_pacer {
	// except token
	struct rte_ring* ctrl_q;
	struct rte_ring* data_q;
	// struct rte_ring* data_q;
	uint64_t remaining_bytes;
	uint64_t last_update_time;
	struct rte_timer data_timer;
	struct rte_timer token_timer;

	struct send_data_timeout_params* send_data_timeout_params;
	struct send_token_timeout_params* send_token_timeout_params;

};

void pim_init_pacer(struct pim_pacer* pacer, struct pim_host * host, uint32_t socket_id);
void pim_pacer_send_data_pkt_handler(__rte_unused struct rte_timer *timer, void* arg);
void pim_pacer_send_token_handler(__rte_unused struct rte_timer *timer, void* arg);
void pim_pacer_send_pkts(struct pim_pacer* pacer);
void update_time_byte(struct pim_pacer* pacer);
#endif