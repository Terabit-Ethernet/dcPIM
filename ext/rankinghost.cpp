#include "assert.h"

#include "../coresim/event.h"
#include "../coresim/topology.h"
#include "../coresim/debug.h"

#include "factory.h"
#include "rankingflow.h"
#include "rankinghost.h"
#include "rankingTopology.h"

#include "../run/params.h"

extern uint32_t total_finished_flows;
extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern Topology *topology;

bool RankingFlowComparator::operator() (RankingFlow* a, RankingFlow* b) {
    return a->arbiter_remaining_num_pkts > b->arbiter_remaining_num_pkts;
}


RankingEpochSchedule::RankingEpochSchedule(double s) {
    this->start_time = s;
    for(int i = 0; i < RANKING_EPOCH_PKTS; i++)
    {
        schedule[i] = NULL;
    }
}

RankingFlow* RankingEpochSchedule::get_sender() {
    for (int i = 0; i < RANKING_EPOCH_PKTS; i++) {
        if (schedule[i]) return schedule[i];
    }
    return NULL;
}

RankingHost::RankingHost(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, RANKING_HOST) {
}

void RankingHost::receive_schedule_pkt(RankingSchedulePkt* pkt) {
    // assert(pkt->schedule->start_time >= get_current_time());
    if (pkt->schedule->start_time >= get_current_time()) {
        pkt->schedule->start_time = get_current_time();
    }

    for(int i = 0; i < RANKING_EPOCH_PKTS; i++)
    {
        if(pkt->schedule->schedule[i])
            pkt->schedule->schedule[i]->schedule_send_pkt(pkt->schedule->start_time + i * params.ranking_epoch_time / RANKING_EPOCH_PKTS);
    }

    delete pkt->schedule;
}


RankingArbiter::RankingArbiter(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, RANKING_ARBITER) {}

void RankingArbiter::start_arbiter() {
    this->schedule_proc_evt(1.0);
}

std::map<int, RankingFlow*> RankingArbiter::schedule_timeslot()
{
    std::map<int, RankingFlow*> schedule;
    std::set<int> sender_used;
    std::set<int> receiver_used;


    std::queue<RankingFlow*> flows_tried;
    while(!sending_flows.empty())
    {
        RankingFlow* f = sending_flows.top();
        sending_flows.pop();
        if(f->arbiter_finished){
            continue;
        }
        bool sender_free = sender_used.count(f->src->id) == 0;
        bool receiver_free = receiver_used.count(f->dst->id) == 0;
        if(debug_flow(f->id) && get_current_time() >= 1.03000023262123){
            std::cout << get_current_time() << " attempting schedule flow " << f->id << " " << f->src->id << "->" << f->dst->id << " for epoch " <<
                get_current_time() + params.ranking_epoch_time << " s_free" << sender_free << " r_free" << receiver_free << " arb_remaining " << f->arbiter_remaining_num_pkts <<
                " sender_last_pkt_sent " << f->sender_last_pkt_sent << "/" << f->size_in_pkt << "\n";
            if(!sender_free)
                std::cout << "sender used by " << schedule[f->src->id]->id << " " << schedule[f->src->id]->src->id << "->" << schedule[f->src->id]->dst->id << "\n";
        }

        if(f->arbiter_remaining_num_pkts > 0 && sender_free && receiver_free){
            f->arbiter_remaining_num_pkts--;
            sender_used.insert(f->src->id);
            receiver_used.insert(f->dst->id);
            schedule[f->src->id] = f;
            if(debug_flow(f->id))
                std::cout << get_current_time() << " scheduled flow " << f->id << " for epoch " << get_current_time() + params.ranking_epoch_time <<
                    " remaining pkts " << f->arbiter_remaining_num_pkts << "\n";
        }
        flows_tried.push(f);
    }

    while(!flows_tried.empty())
    {
        sending_flows.push(flows_tried.front());
        flows_tried.pop();
    }


    return schedule;
}


void RankingArbiter::schedule_proc_evt(double time) {
    if (this->arbiter_proc_evt != NULL) {
        this->arbiter_proc_evt->cancelled = true;
        this->arbiter_proc_evt = NULL;
    }
    this->arbiter_proc_evt = new RankingArbiterProcessingEvent(time, this);
    add_to_event_queue(this->arbiter_proc_evt);
}

void RankingArbiter::schedule_epoch() {
    if (total_finished_flows >= params.num_flows_to_run)
        return;

    std::vector<RankingEpochSchedule*> schedules;
    for (uint i = 0; i < params.num_hosts; i++){
        schedules.push_back(new RankingEpochSchedule(get_current_time() + params.ranking_epoch_time));
    }



    for(int i = 0; i < RANKING_EPOCH_PKTS; i++){
        if(this->sending_flows.size() > 0){
            std::map<int, RankingFlow*> one_time_slot = schedule_timeslot();

            for(auto iter = one_time_slot.begin(); iter != one_time_slot.end(); ++iter)
            {
                int sender = iter->first;
                RankingFlow* f = iter->second;
                schedules[sender]->schedule[i] = f;
            }
        }
    }

    assert(this->queue->limit_bytes - this->queue->bytes_in_queue >= 144 * 40);

    for(int i = 0; i < params.num_hosts; i++)
    {
        RankingFlow* f = schedules[i]->get_sender();
        if(f)
            f->send_schedule_pkt(schedules[i]);
        else
            delete schedules[i];
    }

    //schedule next arbiter proc evt
    this->schedule_proc_evt(get_current_time() + params.ranking_epoch_time);
}

void RankingArbiter::receive_rts(RankingRTS* rts)
{
    if(!((RankingFlow*)rts->flow)->arbiter_received_rts)
    {
        ((RankingFlow*) rts->flow)->arbiter_received_rts = true;
        dynamic_cast<RankingTopology*>(topology)->arbiter->sending_flows.push((RankingFlow*)rts->flow);
    }

    if(rts->remaining_num_pkts < 0){
        ((RankingFlow*)rts->flow)->arbiter_remaining_num_pkts = 0;
        ((RankingFlow*)rts->flow)->arbiter_finished = true;
    }
    else
        ((RankingFlow*)rts->flow)->arbiter_remaining_num_pkts = rts->remaining_num_pkts;
}


RankingFlowProcessingEvent::RankingFlowProcessingEvent(double time, RankingFlow* f)
    : Event(RANKING_FLOW_PROCESSING, time) {
    this->flow = f;
}

RankingFlowProcessingEvent::~RankingFlowProcessingEvent() {
}

void RankingFlowProcessingEvent::process_event() {
    this->flow->send_data_pkt();
}


RankingTimeoutEvent::RankingTimeoutEvent(double time, RankingFlow* f) : Event(RANKING_TIMEOUT, time) {
    this->flow = f;
}

RankingTimeoutEvent::~RankingTimeoutEvent() {
}

void RankingTimeoutEvent::process_event() {
    this->flow->ranking_timeout();
}

