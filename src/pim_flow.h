#ifndef RUF_FLOW_H
#define RUF_FLOW_H

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_hash.h>

#include "debug.h"
#include "flow.h"
#include "pq.h"
#include "ruf_host.h"
typedef struct //for extendability
{
    double timeout;
    int seq_num;
    int data_seq_num;
    int round;
} ruf_token;

struct ruf_flow{
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
    struct ruf_receiver* receiver;
    struct ruf_flow* flow;
};

struct finish_timeout_params {
    struct ruf_receiver* receiver;
    uint32_t flow_id;
};

void ruf_flow_dump(struct ruf_flow* f);
struct ruf_flow* ruf_flow_new(struct rte_mempool* pool);
void init_ruf_flow(struct ruf_flow* ruf_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, double start_time, int receiver_side);

// void ruf_flow_free(struct rte_mempool* pool);

bool ruf_flow_compare(const void *a, const void* b);
// ruf_flow* ruf_flow_free(ruf_flow* ruf_f);
int ruf_init_token_size(struct ruf_flow* ruf_f);

void rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);
void finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg);

void reset_rd_ctrl_timeout(struct ruf_receiver* receiver, struct ruf_flow* flow, double time);

// double ruf_calc_oct_time_ratio();
// // send control signals
// void ruf_sending_rts(ruf_flow* ruf_f);
// void ruf_sending_nrts(ruf_flow* ruf_f, int round);
// void ruf_sending_nrts_to_arbiter(ruf_flow* ruf_f, uint32_t src_id, uint32_t dst_id);
// void ruf_sending_gosrc(ruf_flow* ruf_f, uint32_t src_id);
// void ruf_sending_ack(ruf_flow* ruf_f, int round);
// // sender side
// void ruf_clear_token(ruf_flow* ruf_f);
// ruf_token* ruf_use_token(ruf_flow* ruf_f);
// bool ruf_has_token(ruf_flow* ruf_f);
// struct rte_mbuf* ruf_send(ruf_flow* ruf_f, uint32_t seq, int token_seq, int data_seq, int priority, int ranking_round);
// void ruf_assign_init_token(ruf_flow* ruf_f);
// // receiver side
int ruf_remaining_pkts(struct ruf_flow* ruf_f);
int ruf_token_gap(struct ruf_flow* ruf_f);
// void ruf_relax_token_gap(ruf_flow* ruf_f);
int ruf_get_next_token_seq_num(struct ruf_flow* ruf_f);
void ruf_get_token_pkt(struct ruf_flow* ruf_f, struct rte_mbuf* p, uint32_t round, int data_seq);
void ruf_get_ack_pkt(struct rte_mbuf* p, struct ruf_flow* flow);
// void ruf_receive_short_flow(ruf_flow* ruf_f);
struct ruf_flow* get_src_smallest_unfinished_flow(Pq* pq);



#endif