#ifndef FLOW_H
#define FLOW_H

#include <rte_bitmap.h>
#include <stdbool.h>
#include <rte_ether.h>
#include "debug.h"

// #include <set>
// #include "node.h"

// class Packet;
// class Ack;
// class Probe;
// class RetxTimeoutEvent;
// class FlowProcessingEvent;

struct flow{
    // // Only sets the timeout if needed; i.e., flow hasn't finished
    // virtual void set_timeout(double time);
    // virtual void handle_timeout();
    // virtual void cancel_retx_event();

    // virtual uint32_t get_priority(uint32_t seq);
    // virtual void increase_cwnd();
    // virtual double get_avg_queuing_delay_in_us();

    uint32_t id;
    uint64_t start_time;
    uint64_t finish_time;
    uint32_t size;
    uint32_t src_addr;
    uint32_t dst_addr;
    struct ether_addr src_ether_addr;
    struct ether_addr dst_ether_addr;

    uint32_t received_bytes;
    uint32_t received_count;
    uint32_t sent_bytes;
    uint32_t recv_till;
    uint32_t max_seq_no_recv;

    uint32_t total_pkt_sent;
    uint32_t size_in_pkt;
    // int pkt_drop;
    // int data_pkt_drop;
    // int ack_pkt_drop;
    // int first_hop_departure;
    // int last_hop_departure;
    // Sack
    // uint32_t scoreboard_sack_bytes;
    // finished variables
    bool finished;
    // double flow_completion_time;
    // double total_queuing_time;
    uint64_t first_byte_send_time;
    double first_byte_receive_time;

    uint8_t priority;
    struct rte_bitmap* bmp;
    // double deadline;
};
void init_flow(struct flow* f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, 
    struct ether_addr* ether, uint64_t start_time, int receiver_side);
uint8_t get_flow_priority(struct flow* f, uint32_t base, uint32_t limit);
// uint16_t get_tci(uint8_t priority);
uint8_t get_tos(uint8_t priority);
void flow_dump(struct flow* f);
double flow_oracle_fct(struct flow* f);
// void set_flow_id(flow* f, uint32_t id);
// void set_flow_addr(flow* f, uint32_t src_addr, uint32_t dst_addr);
// void set_flow_size(flow* f, uint32_t size);
// void set_flow_start_time(flow* f, double start_time);
// void set_flow_finish_time(flow* f, double finish_time);
// flow* flow_free(flow* f);
// flow* flow_new(void);

#endif