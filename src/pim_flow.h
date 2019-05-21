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
    bool rts_received;
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
    double latest_token_sent_time;
    double latest_data_pkt_sent_time;
    
    struct rte_timer rd_ctrl_timeout;
    int rd_ctrl_timeout_times;
    struct rd_ctrl_timeout_params* rd_ctrl_timeout_params;
    // need to wait some time before cleaning states
    struct rte_timer finish_timeout;
    struct finish_timeout_params* finish_timeout_params;
};

struct rd_ctrl_timeout_params {
    struct pim_receiver* receiver;
    struct pim_flow* flow;
};

struct finish_timeout_params {
    struct pim_receiver* receiver;
    uint32_t flow_id;
};

void pim_flow_dump(struct pim_flow* f);
struct pim_flow* pim_flow_new(struct rte_mempool* pool);
void init_pim_flow(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, double start_time, int receiver_side);

// void pim_flow_free(struct rte_mempool* pool);

bool pim_flow_compare(const void *a, const void* b);
// pim_flow* pim_flow_free(pim_flow* pim_f);
int pim_init_token_size(struct pim_flow* pim_f);

void rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);

void reset_rd_ctrl_timeout(struct pim_receiver* receiver, struct pim_flow* flow, double time);

// double pim_calc_oct_time_ratio();
// // send control signals
// void pim_sending_rts(pim_flow* pim_f);
// void pim_sending_nrts(pim_flow* pim_f, int round);
// void pim_sending_nrts_to_arbiter(pim_flow* pim_f, uint32_t src_id, uint32_t dst_id);
// void pim_sending_gosrc(pim_flow* pim_f, uint32_t src_id);
// void pim_sending_ack(pim_flow* pim_f, int round);
// // sender side
// void pim_clear_token(pim_flow* pim_f);
// pim_token* pim_use_token(pim_flow* pim_f);
// bool pim_has_token(pim_flow* pim_f);
// struct rte_mbuf* pim_send(pim_flow* pim_f, uint32_t seq, int token_seq, int data_seq, int priority, int ranking_round);
// void pim_assign_init_token(pim_flow* pim_f);
// // receiver side
int pim_remaining_pkts(struct pim_flow* pim_f);
int pim_token_gap(struct pim_flow* pim_f);
// void pim_relax_token_gap(pim_flow* pim_f);
int pim_get_next_token_seq_num(struct pim_flow* pim_f);
void pim_get_token_pkt(struct pim_flow* pim_f, struct rte_mbuf* p, uint32_t round, int data_seq);
void pim_get_ack_pkt(struct rte_mbuf* p, struct pim_flow* flow);
// void pim_receive_short_flow(pim_flow* pim_f);
struct pim_flow* get_src_smallest_unfinished_flow(Pq* pq);



#endif