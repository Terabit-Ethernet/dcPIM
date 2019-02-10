#ifndef RUF_FLOW_H
#define RUF_FLOW_H

#include <unordered_map>
#include <list>
#include <set>
#include "fountainflow.h"
#include "../coresim/flow.h"

class RufEpochSchedule;

class Token //for extendability
{
public:
    double timeout;
    int seq_num;
    int data_seq_num;
    int create_time;
    int ruf_round;
};

class RufFlow : public FountainFlow {
public:
    RufFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d);
    virtual void start_flow();
    virtual void receive(Packet *p);
    virtual void send_pending_data();

    int init_token_size();
    double calc_oct_time_ratio();
    // send control signals
    void sending_rts();
    void sending_nrts(int round);
    void sending_nrts_to_arbiter(uint32_t src_id, uint32_t dst_id);
    void sending_gosrc(uint32_t src_id);
    void sending_ack(int round);
    // sender side
    void clear_token();
    Token* use_token();
    bool has_token();
    Packet* send(uint32_t seq, int token_seq, int data_seq, int priority, int ruf_round);
    void assign_init_token();
    std::list<Token*> tokens;
   
    // receiver side
    int remaining_pkts();
    int token_gap();
    void relax_token_gap();
    int get_next_token_seq_num();
    void send_token_pkt();
    void receive_short_flow();
    std::set<int> packets_received;

    int last_token_data_seq_num_sent;
    int received_until;
    bool finished_at_receiver;
    int token_count;
    int token_packet_sent_count;
    int token_waste_count;
    double redundancy_ctrl_timeout;
    int token_goal;
    int remaining_pkts_at_sender;
    int largest_token_seq_received;
    int largest_token_data_seq_received;
    double latest_token_sent_time;
    bool rts_received;
    double latest_data_pkt_sent_time;
    // int notified_num_flow_at_sender;
    bool first_loop;
};

// #define RUF_FLOW_PROCESSING 18
// class RufFlowProcessingEvent : public Event {
//     public:
//         RufFlowProcessingEvent(double time, RufFlow *flow);
//         ~RufFlowProcessingEvent();
//         void process_event();
//         RufFlow* flow;
// };

// #define RUF_TIMEOUT 19
// class RufTimeoutEvent : public Event {
//     public:
//         RufTimeoutEvent(double time, RufFlow *flow);
//         ~RufTimeoutEvent();
//         void process_event();
//         RufFlow* flow;
// };

#endif
