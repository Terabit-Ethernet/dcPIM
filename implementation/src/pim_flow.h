#ifndef PIM_FLOW_H
#define PIM_FLOW_H

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_cycles.h>
#include <rte_hash.h>

#include "debug.h"
#include "flow.h"
#include "pq.h"
#include "pim_host.h"
#include "pim_pacer.h"

struct pim_pacer;

enum pflow_state {SYNC_SENT, SYNC_ACK,  // sender state
	SYNC_RECEIVE, FINISH_WAIT, // receiver state
	FINISH}; // finish state 


struct rd_ctrl_timeout_params {
    struct pim_host* host;
    struct pim_flow* flow;
};

struct finish_timeout_params {
    struct pim_host* host;
    uint32_t flow_id;
};

struct flow_sync_resent_timeout_params {
   struct pim_host *host;
   struct pim_flow *flow;
   struct pim_pacer *pacer;
   double time;
};

struct flow_fin_resent_timeout_params {
   struct pim_host *host;
   struct pim_flow *flow;
   struct pim_pacer *pacer;
   double time;
};

struct pim_flow {
    struct flow _f;
    struct rte_mbuf* buf;
    enum pflow_state state;
    bool flow_sync_received;
    bool finished_at_receiver;
    int last_token_data_seq_num_sent;
    int received_until;
    int token_count;
    int token_packet_sent_count;
    int token_waste_count;
    int token_goal;
    int remaining_pkts_at_sender;
    int largest_token_seq_received;
    int largest_token_data_seq_received;
    uint64_t latest_token_sent_time;
    double latest_data_pkt_sent_time;
    
    struct rte_timer rd_ctrl_timeout;
    int rd_ctrl_timeout_times;
    struct rd_ctrl_timeout_params* rd_ctrl_timeout_params;
    
    struct rte_timer rtx_flow_sync_timeout;
    struct flow_sync_resent_timeout_params flow_sync_resent_timeout_params;

    struct rte_timer rtx_fin_timeout;
    struct flow_fin_resent_timeout_params flow_fin_resent_timeout_params;
    // need to wait some time before cleaning states
    struct rte_timer finish_timeout;
    struct finish_timeout_params* finish_timeout_params;

};

void pflow_dump(struct pim_flow* f);
struct pim_flow* pflow_new(struct rte_mempool* pool);
void pflow_init(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, 
    struct ether_addr* ether_addr, double start_time, int receiver_side);

// void pim_flow_free(struct rte_mempool* pool);
bool pflow_is_small_flow(struct pim_flow* pim_flow);
int pflow_init_token_size(struct pim_flow* pim_flow);
int pflow_token_gap(const struct pim_flow* f);
int pflow_get_next_token_seq_num(struct pim_flow* f);
void pflow_relax_token_gap(struct pim_flow* f);
// pim_flow* pim_flow_free(pim_flow* pim_f);
bool pflow_is_rd_ctrl_timeout_params_null(struct pim_flow* flow);
void pflow_set_rd_ctrl_timeout_params_null(struct pim_flow* flow);
void pflow_rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void pflow_finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void pflow_set_finish_timeout(struct pim_host* host, struct pim_flow* flow);
void pflow_reset_rd_ctrl_timeout(struct pim_host* host, struct pim_flow* flow, double time);
void pflow_set_finish_at_receiver(struct pim_flow* flow);
bool pflow_get_finish(struct pim_flow* flow);
bool pflow_get_finish_at_receiver(struct pim_flow* flow);
void pflow_set_finish(struct pim_flow* flow);
void pflow_rtx_flow_sync_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void pflow_rtx_fin_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
// // receiver side
int pflow_remaining_pkts(const struct pim_flow* pim_f);
// void pim_relax_token_gap(pim_flow* pim_f);
struct rte_mbuf* pflow_get_fin_pkt(struct pim_flow* flow);
struct rte_mbuf* pflow_get_token_pkt(struct pim_flow* flow, uint32_t data_seq, bool free_token);
// struct rte_mbuf* pflow_send_data_pkt(struct pim_flow* flow);
// void pim_receive_short_flow(pim_flow* pim_f);
void pflow_receive_fin(struct pim_host* host, struct pim_flow* flow, struct pim_fin_hdr* p);
void pflow_receive_data(struct pim_host* host,  struct pim_pacer* pacer, struct pim_flow* f, struct pim_data_hdr* pim_data_hdr);

#endif
