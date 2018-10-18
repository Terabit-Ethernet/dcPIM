#ifndef RANKING_HOST_H
#define RANKING_HOST_H

#include <map>
#include <set>

#include "../coresim/node.h"
#include "../coresim/packet.h"
#include "../coresim/event.h"

#include "../run/params.h"

class RankingArbiterProcessingEvent;
class RankingFlow;

class RankingFlowComparator {
    public:
        bool operator() (RankingFlow* a, RankingFlow* b);
};

class RankingEpochSchedule {
    public:
        RankingEpochSchedule(double s);
        RankingFlow* get_sender();
        double start_time;
        std::map<int, RankingFlow*> schedule;
};

class RankingHost : public Host {
    public:
        RankingHost(uint32_t id, double rate, uint32_t queue_type);
        void receive_schedule_pkt(RankingSchedulePkt* pkt);
};

class RankingArbiter : public Host {
    public:
        RankingArbiter(uint32_t id, double rate, uint32_t queue_type);
        void start_arbiter();
        void schedule_proc_evt(double time);
        std::map<int, RankingFlow*> schedule_timeslot();
        void schedule_epoch();
        void receive_rts(RankingRTS* rts);

        ArbiterProcessingEvent* arbiter_proc_evt;
        std::priority_queue<RankingFlow*, std::vector<RankingFlow*>, RankingFlowComparator> sending_flows;
};

#define RANKING_ARBITER_PROCESSING 17
class RankingArbiterProcessingEvent : public Event {
    public:
        RankingArbiterProcessingEvent(double time, RankingArbiter *host);
        ~RankingArbiterProcessingEvent();
        void process_event();
        RankingArbiter* arbiter;
};

#endif
