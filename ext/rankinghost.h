#ifndef RANKING_HOST_H
#define RANKING_HOST_H

#include <map>
#include <unordered_map>
#include <set>

#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"

#include "custompriorityqueue.h"
#include "schedulinghost.h"

#include "../run/params.h"
#include "rankingflow.h"

class RankingHostWakeupProcessingEvent;
class TokenProcessingEvent;
class RankingArbiterProcessingEvent;
class RankingFlow;

class ListSrcsComparator {
    public:
        ListSrcsComparator();
        std::vector<double> ranking;
        bool operator() (ListSrcs* a, ListSrcs* b);
        void reset_ranking();
};

class RankingFlowComparator {
    public:
        bool operator() (RankingFlow* a, RankingFlow* b);
};

class RankingFlowComparatorAtReceiver {
    public:
        bool operator() (RankingFlow* a, RankingFlow* b);
};

class RankingHost : public SchedulingHost {
    public:
        RankingHost(uint32_t id, double rate, uint32_t queue_type);
        void schedule_host_proc_evt();
        // receiver side
        void receive_rts(RankingRTS* pkt);
        void receive_nrts(RankingNRTS* pkt);
        void receive_gosrc(RankingGoSrc* pkt);
        void send_listSrcs();
        void send_token();
        void schedule_wakeup_event();
        void schedule_token_proc_evt(double time, bool is_timeout);
        void wakeup();
        CustomPriorityQueue<RankingFlow*, std::vector<RankingFlow*>, RankingFlowComparatorAtReceiver> active_receiving_flows;
        std::unordered_map<uint32_t, CustomPriorityQueue<RankingFlow*, std::vector<RankingFlow*>, RankingFlowComparatorAtReceiver>> src_to_flows;
        RankingHost* active_src_from_arbiter;
        // std::list <RankingFlow*> pending_flows;
        RankingHostWakeupProcessingEvent *wakeup_evt;
        TokenProcessingEvent *token_send_evt;
        int total_token_schd_evt_count;
        int hold_on;
        // fake flow used to communicate with the arbiter
        RankingFlow * fake_flow;
        // sender side
        void send();
        void receive_token(RankingToken* pkt);
        void start_ranking_flow(RankingFlow* f);
        CustomPriorityQueue<RankingFlow*, std::vector<RankingFlow*>, RankingFlowComparator> active_sending_flows;
        //std::priority_queue<Token*, std::vector<Token*>, TokenComparator> token_q;

};

class RankingArbiter : public Host {
    public:
        RankingArbiter(uint32_t id, double rate, uint32_t queue_type);
        void start_arbiter();
        void schedule_proc_evt(double time);
        void schedule_epoch();
        void receive_listsrcs(RankingListSrcs* pkt);
        void receive_nrts(RankingNRTS* pkt);
        void reset_ranking();
        std::vector<bool> src_state;
        std::vector<bool> dst_state;
        RankingArbiterProcessingEvent* arbiter_proc_evt;
        double last_reset_ranking_time;
        CustomPriorityQueue<ListSrcs*, std::vector<ListSrcs*>, ListSrcsComparator> pending_q;
};

#define RANKING_ARBITER_PROCESSING 17
class RankingArbiterProcessingEvent : public Event {
    public:
        RankingArbiterProcessingEvent(double time, RankingArbiter *host);
        ~RankingArbiterProcessingEvent();
        void process_event();
        RankingArbiter* arbiter;
};


#define TOKEN_PROCESSING 18
class TokenProcessingEvent : public Event {
    public:
        TokenProcessingEvent(double time, RankingHost *host, bool is_timeout);
        ~TokenProcessingEvent();
        void process_event();
        RankingHost *host;
        bool is_timeout_evt;
};

#define RANKINGHOST_WAKEUP_PROCESSING 19
class RankingHostWakeupProcessingEvent : public Event {
    public:
        RankingHostWakeupProcessingEvent(double time, RankingHost *host);
        ~RankingHostWakeupProcessingEvent();
        void process_event();
        RankingHost *host;
};
#endif
