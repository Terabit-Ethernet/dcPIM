#ifndef PIM_HOST_H
#define PIM_HOST_H

#include <set>
#include <queue>
#include <unordered_map>
#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"
#include "../coresim/topology.h"

#include "schedulinghost.h"
#include <climits>

#include "custompriorityqueue.h"
#include "pimflow.h"

class ProcessReceiverIterEvent;
class ProcessSenderIterEvent;
class NewEpochEvent;
class PimHost;

struct PIM_RTS {
    int iter;
    PimFlow *f;
    int remaining_sz;

    PIM_RTS() {
        iter = 0;
        f = NULL;
        remaining_sz = INT_MAX;
    }
};
struct PIM_Grants {
    bool prompt;
    int iter;
    PimFlow *f;
};

class PimEpoch {
public:
    int epoch;
    int iter;
    PimHost* host;
    PimHost* match_receiver;
    PimHost* match_sender;
    ProcessSenderIterEvent* proc_sender_iter_evt;
    ProcessReceiverIterEvent* proc_receiver_iter_evt;
    std::vector<PIM_Grants> grants_q;
    std::vector<PIM_RTS> rts_q;
    PIM_RTS min_rts;

    // std::vector<bool> receiver_state;
    PimEpoch();
    ~PimEpoch();
    void advance_iter();
    void receive_grants(PIMGrants *p);
    // void receive_offer_packet(OfferPkt *p); 
    void receive_accept_pkt(AcceptPkt *p);
    void receive_grantsr(GrantsR* p);
    void receive_rts(PIMRTS *p); 
    void send_all_rts();
    void handle_all_grants();
    void handle_all_rts();
    void schedule_receiver_iter_evt();
    void schedule_sender_iter_evt();
};
class PimFlowComparator {
    public:
        bool operator() (PimFlow* a, PimFlow* b);
};

// class CapabilityFlowComparator {
//     public:
//         bool operator() (CapabilityFlow* a, CapabilityFlow* b);
// };

// class CapabilityFlowComparatorAtReceiver {
//     public:
//         bool operator() (CapabilityFlow* a, CapabilityFlow* b);
// };

class PimHost : public SchedulingHost {
    public:
        PimHost(uint32_t id, double rate, uint32_t queue_type);
        // void schedule_host_proc_evt();
        void start_flow(PimFlow* f);
        void start_host();
        //void send();
        void send();

        void start_new_epoch(double time, int epoch);
        void advance_iter();
        void schedule_host_proc_evt();
        PimFlow* get_top_unfinish_flow(uint32_t dst_id);
        bool flow_compare(PimFlow* long_flow, PimFlow* short_flow);
        NewEpochEvent* new_epoch_evt;
        // std::vector<bool> receiver_state;
        std::unordered_map<uint32_t, CustomPriorityQueue<PimFlow*, std::vector<PimFlow*>, PimFlowComparator>> dst_to_flows;
        CustomPriorityQueue<PimFlow*, std::vector<PimFlow*>, PimFlowComparator> active_short_flows;
        std::unordered_map<int, PimEpoch> epochs;
        // std::vector<PIM_Grants> grants_q;
        // std::vector<PIM_RTS> rts_q;
        // who send data to the host
        // PimHost* match_sender;
        PimHost* sender;
        // send data to whom
        // PimHost* match_receiver;
        PimHost* receiver;
        // uint32_t epoch;
        // uint32_t iter;
        double iter_epoch;
        int cur_epoch;
        //std::priority_queue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparator> active_sending_flows;
        // CustomPriorityQueue<CapabilityFlow*, std::vector<CapabilityFlow*>, CapabilityFlowComparator> active_sending_flows;
        // int epoch;
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
        ProcessReceiverIterEvent(double time, PimEpoch *epoch);
        ~ProcessReceiverIterEvent();
        void process_event();
        PimEpoch *epoch;
};

#define PROCESS_SENDER_ITER_REQUEST 21
class ProcessSenderIterEvent : public Event {
    public:
        ProcessSenderIterEvent(double time, PimEpoch *epoch);
        ~ProcessSenderIterEvent();
        void process_event();
        PimEpoch *epoch;
};

#define NEW_EPOCH_PROCESSING 22
class NewEpochEvent : public Event {
    public:
        NewEpochEvent(double time, int epoch, PimHost *host);
        ~NewEpochEvent();
        void process_event();
        PimHost *host;
        int epoch;
};

#endif
