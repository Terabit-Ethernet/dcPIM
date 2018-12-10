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
class UpdateRoundEvent;

struct MR_RTS {
    int iter;
    MrFlow *f;
};
struct MR_CTS {
    int iter;
    MrFlow *f;
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
        void schedule_update_round_evt();
        void advance_iter();
        void schedule_host_proc_evt();
        MrFlow* get_top_unfinish_flow(uint32_t dst_id);
        bool flow_compare(MrFlow* long_flow, MrFlow* short_flow);
        UpdateRoundEvent* update_round_evt;
        ProcessSenderIterEvent* proc_sender_iter_evt;
        ProcessReceiverIterEvent* proc_receiver_iter_evt;
        std::vector<bool> receiver_state;
        std::unordered_map<uint32_t, CustomPriorityQueue<MrFlow*, std::vector<MrFlow*>, MrFlowComparator>> dst_to_flows;
        CustomPriorityQueue<MrFlow*, std::vector<MrFlow*>, MrFlowComparator> active_short_flows;

        std::vector<MR_CTS> cts_q;
        std::vector<MR_RTS> rts_q;
        // who send data to the host
        MrHost* match_sender;
        MrHost* sender;
        // send data to whom
        MrHost* match_receiver;
        MrHost* receiver;
        uint32_t round;
        uint32_t iter;
        double iter_epoch;
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
        ProcessReceiverIterEvent(double time, MrHost *host);
        ~ProcessReceiverIterEvent();
        void process_event();
        MrHost *host;
};

#define PROCESS_SENDER_ITER_REQUEST 21
class ProcessSenderIterEvent : public Event {
    public:
        ProcessSenderIterEvent(double time, MrHost *host);
        ~ProcessSenderIterEvent();
        void process_event();
        MrHost *host;
};

#define UPDATE_ROUND_PROCESSING 22
class UpdateRoundEvent : public Event {
    public:
        UpdateRoundEvent(double time, MrHost *host);
        ~UpdateRoundEvent();
        void process_event();
        MrHost *host;
};

#endif
