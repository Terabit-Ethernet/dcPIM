#ifndef PIM_FLOW_H
#define PIM_FLOW_H

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_hash.h>

#include "debug.h"
#include "flow.h"
#include "pq.h"
#include "pim_host.h"
typedef struct //for extendability
{
    double timeout;
    int seq_num;
    int data_seq_num;
    int round;
} pim_token;

struct pim_flow{
	struct flow _f;
    struct rte_mbuf* buf;
    bool flow_sync_received;
    bool finished_at_receiver;
    int largest_seq_ack;
    int last_data_seq_num_sent;
    int next_seq_no;
    int remaining_pkts_at_sender;
    double redundancy_ctrl_timeout;
    double latest_data_pkt_send_time;
    bool first_loop;
    int ack_until;
    int ack_count;
    struct rte_timer rd_ctrl_timeout;
    int rd_ctrl_timeout_times;
    struct rd_ctrl_timeout_params* rd_ctrl_timeout_params;
    // need to wait some time before cleaning states
    struct rte_timer finish_timeout;
    struct finish_timeout_params* finish_timeout_params;
};

struct rd_ctrl_timeout_params {
    struct pim_host* host;
    struct pim_flow* flow;
};

struct finish_timeout_params {
    struct pim_host* host;
    uint32_t flow_id;
};

void pflow_dump(struct pim_flow* f);
struct pim_flow* pim_flow_new(struct rte_mempool* pool);
void pflow_init(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, double start_time, int receiver_side);

// void pim_flow_free(struct rte_mempool* pool);
bool pflow_is_small_flow(struct pim_flow* pim_flow);
// pim_flow* pim_flow_free(pim_flow* pim_f);
bool pflow_is_rd_ctrl_timeout_params_null(struct pim_flow* flow);
void pflow_set_rd_ctrl_timeout_params_null(struct pim_flow* flow);
void pflow_rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void pflow_finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);

void pflow_reset_rd_ctrl_timeout(struct pim_host* host, struct pim_flow* flow, double time);

// // receiver side
int pflow_remaining_pkts(struct pim_flow* pim_f);
// void pim_relax_token_gap(pim_flow* pim_f);
void pflow_get_ack_pkt(struct rte_mbuf* p, struct pim_flow* flow);
// void pim_receive_short_flow(pim_flow* pim_f);



#endif