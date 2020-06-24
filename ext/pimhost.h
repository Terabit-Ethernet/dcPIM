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
class PimTokenProcessingEvent;

struct PIM_Vlink {
    int id;
    int total_links;
    int prompt_links;
    // bool prompt;
    PimHost* host;
    PimHost* target;
    PimTokenProcessingEvent *token_send_evt;

    void schedule_token_proc_evt(double time, bool is_timeout);
    void send_token();
    PIM_Vlink() {
        host = NULL;
        target = NULL;
        token_send_evt = NULL;
        id = 0;
        // prompt = 0;
        total_links = 0;
        prompt_links = 0;
    }

};
struct PIM_REQ {
    int iter;
    int remaining_sz;
    int total_links;
    int prompt_links;
    PimFlow *f;
    PIM_REQ() {
        iter = 0;
        f = NULL;
        remaining_sz = INT_MAX;
        total_links = 0;
        prompt_links = 0;
    }
    bool operator < (const PIM_REQ& req) const
    {
        return (remaining_sz < req.remaining_sz);
    }
};
struct PIM_Grants {
    bool prompt;
    int iter;
    PimFlow *f;
    int remaining_sz;
    int total_links;
    int prompt_links;
    PIM_Grants() {
        prompt = false;
        iter = 0;
        f = NULL;
        remaining_sz = INT_MAX;    
        total_links = 0;
        prompt_links = 0;
    }
    bool operator < (const PIM_Grants& grant) const
    {
        return (remaining_sz < grant.remaining_sz);
    }
};

class PimEpoch {
public:
    int epoch;
    int iter;
    // int occupied_link;
    // bool prompt;
    PimHost* host;
    std::vector<PIM_Vlink> match_receiver_links;
    std::vector<PIM_Vlink> match_sender_links;
    unsigned num_tx_link;
    unsigned num_tx_prompt_link;
    unsigned num_rx_link;
    unsigned num_rx_prompt_link;
    // PimHost* match_receiver;
    // PimHost* match_sender;
    ProcessSenderIterEvent* proc_sender_iter_evt;
    ProcessReceiverIterEvent* proc_receiver_iter_evt;
    std::vector<PIM_Grants> grants_q;
    std::vector<PIM_REQ> req_q;
    // PIM_REQ min_req;
    // PIM_Grants min_grant;
    // std::vector<bool> receiver_state;
    PimEpoch();
    ~PimEpoch();
    void advance_iter();
    void receive_grants(PIMGrants *p);
    // void receive_offer_packet(OfferPkt *p); 
    void receive_accept_pkt(AcceptPkt *p);
    void receive_grantsr(GrantsR* p);
    void receive_req(PIMREQ *p); 
    void send_all_req();
    void handle_all_grants();
    void handle_all_req();
    void schedule_receiver_iter_evt();
    void schedule_sender_iter_evt();
};
class PimFlowComparator {
    public:
        bool operator() (PimFlow* a, PimFlow* b);
};

class PimFlowComparatorAtReceiver {
    public:
        bool operator() (PimFlow* a, PimFlow* b);
};

class PimTokenComparator {
    public:
         bool operator() (Pim_Token* a, Pim_Token* b);
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
        // void send_token();
        void receive_rts(FlowRTS* pkt);
        void start_new_epoch(double time, int epoch);
        void advance_iter();
        void schedule_host_proc_evt();
        // void schedule_token_proc_evt(double time, bool is_timeout);
        void receive_token(PIMToken* pkt);
        void flow_finish_at_receiver(Packet* pkt);
        PimFlow* get_top_unfinish_flow(uint32_t src_id);
        bool flow_compare(PimFlow* long_flow, PimFlow* short_flow);

        NewEpochEvent* new_epoch_evt;
        // PimTokenProcessingEvent *token_send_evt;

        // std::vector<bool> receiver_state;
        std::unordered_map<uint32_t, CustomPriorityQueue<PimFlow*, std::vector<PimFlow*>, PimFlowComparatorAtReceiver>> src_to_flows;
        CustomPriorityQueue<PimFlow*, std::vector<PimFlow*>, PimFlowComparator> active_sending_flows;
        CustomPriorityQueue<Pim_Token*, std::vector<Pim_Token*>, PimTokenComparator> token_q;

        // std::unordered_map<uint32_t, CustomPriorityQueue<PimFlow*, std::vector<PimFlow*>, PimFlowComparator>> dst_to_flows;

        std::unordered_map<int, PimEpoch> epochs;
        // std::vector<PIM_Grants> grants_q;
        // std::vector<PIM_RTS> rts_q;
        // who send data to the host
        // PimHost* match_sender;
        // PimHost* sender;
        // send data to whom
        // PimHost* match_receiver;
        // PimHost* receiver;
        std::vector<PIM_Vlink> match_receiver_links;
        std::vector<PIM_Vlink> match_sender_links;
        // uint32_t epoch;
        // uint32_t iter;
        double iter_epoch;
        int cur_epoch;
        int hold_on;
        int total_token_schd_evt_count;

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

#define PROCESS_RECEIVER_ITER_REQUEST 21
class ProcessReceiverIterEvent : public Event {
    public:
        ProcessReceiverIterEvent(double time, PimEpoch *epoch);
        ~ProcessReceiverIterEvent();
        void process_event();
        PimEpoch *epoch;
};

#define PROCESS_SENDER_ITER_REQUEST 22
class ProcessSenderIterEvent : public Event {
    public:
        ProcessSenderIterEvent(double time, PimEpoch *epoch);
        ~ProcessSenderIterEvent();
        void process_event();
        PimEpoch *epoch;
};

#define NEW_EPOCH_PROCESSING 23
class NewEpochEvent : public Event {
    public:
        NewEpochEvent(double time, int epoch, PimHost *host);
        ~NewEpochEvent();
        void process_event();
        PimHost *host;
        int epoch;
};

#define PIM_TOKEN_PROCESSING 24
class PimTokenProcessingEvent : public Event {
    public:
        PimTokenProcessingEvent(double time, PIM_Vlink *l, bool is_timeout);
        ~PimTokenProcessingEvent();
        void process_event();
        PIM_Vlink *link;
        bool is_timeout_evt;
};
#endif
