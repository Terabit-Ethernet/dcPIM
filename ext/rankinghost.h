#ifndef RANKING_HOST_H
#define RANKING_HOST_H

#include <map>
#include <set>

#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"

#include "schedulinghost.h"
#include "../run/params.h"
#include "rankingflow.h"

class RankingHostWakeupProcessingEvent;
class TokenProcessingEvent;
class RankingArbiterProcessingEvent;
class RankingFlow;

class ListRTSComparator {
    public:
        ListRTSComparator();
        std::vector<int> ranking;
        bool operator() (ListRTS* a, ListRTS* b);
};

// class RankingEpochSchedule {
//     public:
//         RankingEpochSchedule(double s);
//         RankingFlow* get_sender();
//         double start_time;
//         std::map<int, RankingFlow*> schedule;
// };

class RankingHost : public SchedulingHost {
    public:
        RankingHost(uint32_t id, double rate, uint32_t queue_type);
        void schedule_host_proc_evt();
        // receiver side
        void receive_rts(RankingRTS* pkt);
        void receive_nrts(RankingNRTS* pkt);
        void receive_gosrc(RankingGoSrc* pkt);
        void send_listRTS();
        void send_token();
        void schedule_wakeup_event();
        void schedule_token_proc_evt(double time, bool is_timeout);
        void wakeup();
        RankingFlow* active_receiving_flow;
        std::list <Flow*> pending_flows;
        RankingHostWakeupProcessingEvent *wakeup_evt;
        TokenProcessingEvent *token_send_evt;
        int total_token_schd_evt_count;
        // sender side
        void send();
        void receive_token(RankingToken* pkt);
        RankingFlow* active_sending_flow;
        //std::priority_queue<Token*, std::vector<Token*>, TokenComparator> token_q;

};

class RankingArbiter : public Host {
    public:
        RankingArbiter(uint32_t id, double rate, uint32_t queue_type);
        void start_arbiter();
        void schedule_proc_evt(double time);
        void schedule_epoch();
        void receive_listrts(RankingListRTS* pkt);
        void receive_nrts(RankingNRTS* pkt);

        std::vector<bool> src_state;
        std::vector<bool> dst_state;
        RankingArbiterProcessingEvent* arbiter_proc_evt;
        RankingFlow * fake_flow;
        std::priority_queue<ListRTS*, std::vector<ListRTS*>, ListRTSComparator> pending_q;
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
