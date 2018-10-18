#ifndef RANKING_FLOW_H
#define RANKING_FLOW_H

#include <unordered_map>
#include <set>

#include "../coresim/flow.h"

class RankingEpochSchedule;

class RankingFlow : public Flow {
public:
    RankingFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d);
    void start_flow();
    void update_remaining_size();
    void send_ack_pkt(uint32_t);
    void send_schedule_pkt(RankingEpochSchedule* schd);
    void send_data_pkt();
    void receive(Packet *p);
    void schedule_send_pkt(double time);
    int next_pkt_to_send();
    void ranking_timeout();

    int sender_remaining_num_pkts;
    std::set<int> sender_acked;
    std::set<int> receiver_received;
    int sender_acked_count;
    int sender_acked_until;
    int sender_last_pkt_sent;
    bool sender_finished;
    int arbiter_remaining_num_pkts;
    bool arbiter_received_rts;
    bool arbiter_finished;
};

#define RANKING_FLOW_PROCESSING 18
class RankingFlowProcessingEvent : public Event {
    public:
        RankingFlowProcessingEvent(double time, RankingFlow *flow);
        ~RankingFlowProcessingEvent();
        void process_event();
        RankingFlow* flow;
};

#define RANKING_TIMEOUT 19
class RankingTimeoutEvent : public Event {
    public:
        RankingTimeoutEvent(double time, RankingFlow *flow);
        ~RankingTimeoutEvent();
        void process_event();
        RankingFlow* flow;
};

#endif
