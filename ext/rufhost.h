#ifndef RUF_HOST_H
#define RUF_HOST_H

#include <map>
#include <queue>
#include <unordered_map>
#include <set>

#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"

#include "custompriorityqueue.h"
#include "schedulinghost.h"

#include "../run/params.h"
#include "rufflow.h"

class RufHostWakeupProcessingEvent;
class TokenProcessingEvent;
class RufArbiterProcessingEvent;
class RufGoSrcQueuingEvent;
class RufFlow;
class RufHost;

class GoSRC {
public:
    int max_tokens;
    int remain_tokens;
    int round;
    RufHost* src; 
    bool send_nrts;   
    GoSRC() {
        max_tokens = -1;
        remain_tokens = -1;
        round = -1;
        src = NULL;
        send_nrts = false;
    };
    void reset() {
        max_tokens = -1;
        remain_tokens = -1;
        round = -1;
        src = NULL;
    };
    ~GoSRC() = default;
};

class PqElement {
public:
    Host* dst;
    uint32_t src_id;
    int flow_size;
};

// used for host when forming new listSrc
class ListSrcsComparator {
public:
    bool operator()(const std::pair<int,int> &left, const std::pair<int,int> &right) {
        return left.first < right.first;
    }
};

// used for the arbiter
class HostState {
public:
    bool state;
    double timeout;
    int round; 
    HostState() {
        state = true;
        timeout = -1;
        round = -1;
    }
    void reset_state() {
        state = true;
    }
    void reset_timeout() {
        timeout = -1;
    }
    void reset_round() {
        round = -1;
    }
    void reset() {
        this->reset_state();
        this->reset_timeout();
        this->reset_round(); 
    }
};

class PqElementComparator {
public:
    bool local;
    PqElementComparator(const bool & localize = false) {
        local = localize;
    }
    bool operator() (PqElement* a, PqElement* b);
};

class RufFlowComparator {
    public:
        bool operator() (RufFlow* a, RufFlow* b);
};

class RufFlowComparatorAtReceiver {
    public:
        bool operator() (RufFlow* a, RufFlow* b);
};

class RufShortFlowComparatorAtReceiver {
public:
    bool operator() (RufFlow* a, RufFlow* b);
};
// class RufFlowComparatorAtReceiverForP1 {
//     public:
//         bool operator() (RufFlow* a, RufFlow* b);
// };

class RufHost : public SchedulingHost {
    public:
        RufHost(uint32_t id, double rate, uint32_t queue_type);
        void schedule_host_proc_evt();
        // debug for max-min fairness
        void print_max_min_fairness();
        // receiver side
        void receive_rts(RufRTS* pkt);
        void flow_finish_at_receiver(Packet* pkt);
        bool flow_compare(RufFlow* long_flow, RufFlow* short_flow);
        //void receive_nrts(RufNRTS* pkt);
        void receive_gosrc(RufGoSrc* pkt);
        void send_listSrcs(int src_id = -1, int round = -1);
        void send_token();
        void schedule_wakeup_event();
        void schedule_token_proc_evt(double time, bool is_timeout);
        void wakeup();

        int debug_send_flow_finish;
        int debug_send_go_src;
        int debug_send_wake_up;
        int debug_new_flow;
        int debug_use_all_tokens;
        RufFlow* get_top_unfinish_flow(uint32_t src_id);
        // CustomPriorityQueue<RufFlow*, std::vector<RufFlow*>, RufShortFlowComparatorAtReceiver> active_short_flows;
        std::unordered_map<uint32_t, CustomPriorityQueue<RufFlow*, std::vector<RufFlow*>, RufFlowComparatorAtReceiver>> src_to_flows;

        GoSRC gosrc_info;
        double idle_count;
        double last_send_list_src_time;
        // only used for fairness testing
        std::unordered_map<int, int> src_to_pkts;
        // std::list <RufFlow*> pending_flows;
        RufHostWakeupProcessingEvent *wakeup_evt;
        TokenProcessingEvent *token_send_evt;
        int total_token_schd_evt_count;
        int hold_on;
        // fake flow used to communicate with the arbiter
        RufFlow * fake_flow;
        // sender side
        void send();
        void receive_token(RufToken* pkt);
        void start_ruf_flow(RufFlow* f);
        CustomPriorityQueue<RufFlow*, std::vector<RufFlow*>, RufFlowComparator> active_sending_flows;
        //std::priority_queue<Token*, std::vector<Token*>, TokenComparator> token_q;

};

class RufArbiter : public Host {
    public:
        RufArbiter(uint32_t id, double rate, uint32_t queue_type);
        void start_arbiter();
        void schedule_proc_evt(double time);
        void schedule_epoch();
        void receive_listsrcs(RufListSrcs* pkt);
        // void receive_nrts(RufNRTS* pkt);
        void reset_ruf();
        void ruf_schedule();
        void send_gosrc();
        
        int round;
        std::queue<std::pair<RufHost*, uint32_t>> gosrc_queue;
        std::vector<HostState> src_state;
        std::vector<HostState> dst_state;
        RufArbiterProcessingEvent* arbiter_proc_evt;
        RufGoSrcQueuingEvent* gosrc_queue_evt;
        std::vector<int> inbound_cons;
        std::vector<int> outbound_cons;

        // double last_reset_ruf_time;
        CustomPriorityQueue<PqElement*, std::vector<PqElement*>, PqElementComparator> ruf_q;
};

#define RUF_ARBITER_PROCESSING 17
class RufArbiterProcessingEvent : public Event {
    public:
        RufArbiterProcessingEvent(double time, RufArbiter *host);
        ~RufArbiterProcessingEvent();
        void process_event();
        RufArbiter* arbiter;
};


#define TOKEN_PROCESSING 18
class TokenProcessingEvent : public Event {
    public:
        TokenProcessingEvent(double time, RufHost *host, bool is_timeout);
        ~TokenProcessingEvent();
        void process_event();
        RufHost *host;
        bool is_timeout_evt;
};

#define RUFHOST_WAKEUP_PROCESSING 19
class RufHostWakeupProcessingEvent : public Event {
    public:
        RufHostWakeupProcessingEvent(double time, RufHost *host);
        ~RufHostWakeupProcessingEvent();
        void process_event();
        RufHost *host;
};

#define RUF_GOSRC_QUEUING 20
class RufGoSrcQueuingEvent : public Event {
    public:
        RufGoSrcQueuingEvent(double time, RufArbiter *host);
        ~RufGoSrcQueuingEvent();
        void process_event();
        RufArbiter *arbiter;
};
#endif
