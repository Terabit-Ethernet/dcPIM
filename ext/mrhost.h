#ifndef MR_HOST_H
#define MR_HOST_H

#include <set>
#include <queue>

#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"
#include "../coresim/topology.h"

#include "schedulinghost.h"
#include "custompriorityqueue.h"
#include "mrflow.h"
class ProcessReceiverIterEvent;
class ProcessSenderIterEvent;
class NewRoundEvent;
class MrHost;

struct MR_RTS {
    int iter;
    MrFlow *f;
};
struct MR_CTS {
    bool prompt;
    int iter;
    MrFlow *f;
};

class MrEpoch {
public:
    int round;
    int iter;
    MrHost* host;
    MrHost* match_receiver;
    MrHost* match_sender;
    ProcessSenderIterEvent* proc_sender_iter_evt;
    ProcessReceiverIterEvent* proc_receiver_iter_evt;
    std::vector<MR_CTS> cts_q;
    std::vector<MR_RTS> rts_q;
    std::vector<bool> receiver_state;
    MrEpoch();
    ~MrEpoch();
    void advance_iter();
    void receive_cts(MRCTS *p);
    void receive_offer_packet(OfferPkt *p); 
    void receive_decision_pkt(DecisionPkt *p);
    void receive_ctsr(CTSR* p);
    void receive_rts(MRRTS *p); 
    void send_all_rts();
    void handle_all_cts();
    void handle_all_rts();
    void schedule_receiver_iter_evt();
    void schedule_sender_iter_evt();
};
class MrFlowComparator {
    public:
        bool operator() (MrFlow* a, MrFlow* b);
};

// class CapabilityFlowComparator {
//     public:
//         bool operator() (CapabilityFlow* a, CapabilityFlow* b);
// };

// class CapabilityFlowComparatorAtReceiver {
//     public:
//         bool operator() (CapabilityFlow* a, CapabilityFlow* b);
// };

class MrHost : public SchedulingHost {
    public:
        MrHost(uint32_t id, double rate, uint32_t queue_type);
        // void schedule_host_proc_evt();
        void start_flow(MrFlow* f);
        void start_host();
        //void send();
        void send();

        void start_new_epoch(double time, int round);
        void advance_iter();
        void schedule_host_proc_evt();
        MrFlow* get_top_unfinish_flow(uint32_t dst_id);
        bool flow_compare(MrFlow* long_flow, MrFlow* short_flow);
        NewRoundEvent* new_round_evt;
        // std::vector<bool> receiver_state;
        std::unordered_map<uint32_t, CustomPriorityQueue<MrFlow*, std::vector<MrFlow*>, MrFlowComparator>> dst_to_flows;
        CustomPriorityQueue<MrFlow*, std::vector<MrFlow*>, MrFlowComparator> active_short_flows;
        std::unordered_map<int, MrEpoch> epochs;
        // std::vector<MR_CTS> cts_q;
        // std::vector<MR_RTS> rts_q;
        // who send data to the host
        // MrHost* match_sender;
        MrHost* sender;
        // send data to whom
        // MrHost* match_receiver;
        MrHost* receiver;
        // uint32_t round;
        // uint32_t iter;
        double iter_epoch;
        int cur_round;
        //std::priority_queue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparator> active_sending_flows;
        // CustomPriorityQueue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparator> active_sending_flows;
        // int round;
        // bool sender_match;
        // bool receiver_match;
        // void send_capability();
        // void schedule_capa_proc_evt(double time, bool is_timeout);
        // void schedule_sender_notify_evt();
        // bool check_better_schedule(CapabilityFlow* f);
        // bool is_sender_idle();
        // void notify_flow_status();
        // //std::priority_queue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparatorAtReceiver> active_receiving_flows;
        // CustomPriorityQueue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparatorAtReceiver> active_receiving_flows;
        // CapabilityProcessingEvent *capa_proc_evt;
        // SenderNotifyEvent* sender_notify_evt;
        // int hold_on;
        // int total_capa_schd_evt_count;
        // int could_better_schd_count;
};

#define PROCESS_RECEIVER_ITER_REQUEST 20
class ProcessReceiverIterEvent : public Event {
    public:
        ProcessReceiverIterEvent(double time, MrEpoch *epoch);
        ~ProcessReceiverIterEvent();
        void process_event();
        MrEpoch *epoch;
};

#define PROCESS_SENDER_ITER_REQUEST 21
class ProcessSenderIterEvent : public Event {
    public:
        ProcessSenderIterEvent(double time, MrEpoch *epoch);
        ~ProcessSenderIterEvent();
        void process_event();
        MrEpoch *epoch;
};

#define NEW_ROUND_PROCESSING 22
class NewRoundEvent : public Event {
    public:
        NewRoundEvent(double time, int round, MrHost *host);
        ~NewRoundEvent();
        void process_event();
        MrHost *host;
        int round;
};

#endif
