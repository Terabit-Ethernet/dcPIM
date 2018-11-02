#ifndef RANKING_FLOW_H
#define RANKING_FLOW_H

#include <unordered_map>
#include <list>
#include <set>
#include "fountainflow.h"
#include "../coresim/flow.h"

class RankingEpochSchedule;

struct Token //for extendability
{
    double timeout;
    int seq_num;
    int data_seq_num;
    int create_time;
};

struct ListRTS //for extendability
{
    Host* dst;
    std::list<Flow*> listFlows;
};

struct GoSRC {
    Flow* f;
};
class RankingFlow : public FountainFlow {
public:
    RankingFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d);
    virtual void start_flow();
    virtual void receive(Packet *p);
    virtual void send_pending_data();

    void update_remaining_size();
    void send_ack_pkt(uint32_t);
    void schedule_send_pkt(double time);

    // send control signals
    void sending_rts();
    void sending_nrts();
    void sending_nrts_to_arbiter();
    void sending_gosrc();
    // sender side
    Token* use_token();
    bool has_token();
    Packet* send(uint32_t seq, int token_seq, int data_seq, int priority);

    // receiver side
    int remaining_pkts();
    int token_gap();
    void relax_token_gap();
    int get_next_token_seq_num();
    void send_token_pkt();
    std::set<int> packets_received;
    std::list<Token*> tokens;

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
    double latest_token_sent_time;
    bool rts_received;
    double latest_data_pkt_sent_time;
    // int notified_num_flow_at_sender;
};

// #define RANKING_FLOW_PROCESSING 18
// class RankingFlowProcessingEvent : public Event {
//     public:
//         RankingFlowProcessingEvent(double time, RankingFlow *flow);
//         ~RankingFlowProcessingEvent();
//         void process_event();
//         RankingFlow* flow;
// };

// #define RANKING_TIMEOUT 19
// class RankingTimeoutEvent : public Event {
//     public:
//         RankingTimeoutEvent(double time, RankingFlow *flow);
//         ~RankingTimeoutEvent();
//         void process_event();
//         RankingFlow* flow;
// };

#endif
