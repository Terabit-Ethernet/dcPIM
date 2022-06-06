#include "assert.h"

#include "../coresim/event.h"
#include "../coresim/topology.h"
#include "../coresim/debug.h"

#include "factory.h"
#include "fastpassflow.h"
#include "fastpasshost.h"
#include "fastpassTopology.h"

#include "../run/params.h"

extern uint32_t total_finished_flows;
extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern Topology *topology;

bool FastpassFlowComparator::operator() (FastpassFlow* a, FastpassFlow* b) {
    if(params.fastpass_localize) {
        bool a_same_rack = topology->is_same_rack(a->src->id, a->dst->id);
        bool b_same_rack = topology->is_same_rack(b->src->id, b->dst->id);
        if(a_same_rack && b_same_rack) {
            return a->arbiter_remaining_num_pkts > b->arbiter_remaining_num_pkts;
        } else if (a_same_rack) {
            return false; 
        } else if (b_same_rack) {
            return true;
        } else {
            return a->arbiter_remaining_num_pkts > b->arbiter_remaining_num_pkts;
        }
    }
    return a->arbiter_remaining_num_pkts > b->arbiter_remaining_num_pkts;
}


FastpassEpochSchedule::FastpassEpochSchedule(double s) {
    this->start_time = s;
    for(int i = 0; i < params.fastpass_epoch_pkts; i++)
    {
        schedule[i] = NULL;
    }
}

FastpassFlow* FastpassEpochSchedule::get_sender() {
    for (int i = 0; i < params.fastpass_epoch_pkts; i++) {
        if (schedule[i]) return schedule[i];
    }
    return NULL;
}

FastpassHost::FastpassHost(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, FASTPASS_HOST) {
}

void FastpassHost::receive_schedule_pkt(FastpassSchedulePkt* pkt) {
    // assert(pkt->schedule->start_time >= get_current_time());
    if (pkt->schedule->start_time >= get_current_time()) {
        pkt->schedule->start_time = get_current_time();
    }

    for(int i = 0; i < params.fastpass_epoch_pkts; i++)
    {
        if(pkt->schedule->schedule[i])
            pkt->schedule->schedule[i]->schedule_send_pkt(pkt->schedule->start_time + i * params.fastpass_epoch_time / params.fastpass_epoch_pkts);
    }

    delete pkt->schedule;
}


FastpassArbiter::FastpassArbiter(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, FASTPASS_ARBITER) {}

void FastpassArbiter::start_arbiter() {
    this->schedule_proc_evt(1.0);
}

std::map<int, FastpassFlow*> FastpassArbiter::schedule_timeslot()
{
    std::map<int, FastpassFlow*> schedule;
    std::set<int> sender_used;
    std::set<int> receiver_used;

    std::map <int, int> send_tor_cons;
    std::map <int, int> recv_tor_cons;

    std::queue<FastpassFlow*> flows_tried;
    int con_limit = topology->num_hosts_per_tor() * params.os_ratio;
    while(!sending_flows.empty())
    {
        FastpassFlow* f = sending_flows.top();
        sending_flows.pop();
        if(f->arbiter_finished){
            continue;
        }

        int sender_tor = f->src->id / topology->num_hosts_per_tor();
        int receiver_tor = f->dst->id / topology->num_hosts_per_tor();
        bool sender_free = sender_used.count(f->src->id) == 0;
        bool receiver_free = receiver_used.count(f->dst->id) == 0;
        if (send_tor_cons.count(sender_tor) == 0)
            send_tor_cons[sender_tor] = 0;
        if (recv_tor_cons.count(receiver_tor) == 0)
            recv_tor_cons[receiver_tor] = 0;
        bool send_tor_avil = send_tor_cons[sender_tor] < con_limit;
        bool recv_tor_avil = recv_tor_cons[receiver_tor] < con_limit;

        if(debug_flow(f->id) && get_current_time() >= 1.03000023262123){
            std::cout << get_current_time() << " attempting schedule flow " << f->id << " " << f->src->id << "->" << f->dst->id << " for epoch " <<
                get_current_time() + params.fastpass_epoch_time << " s_free" << sender_free << " r_free" << receiver_free << " arb_remaining " << f->arbiter_remaining_num_pkts <<
                " sender_last_pkt_sent " << f->sender_last_pkt_sent << "/" << f->size_in_pkt << "\n";
            if(!sender_free)
                std::cout << "sender used by " << schedule[f->src->id]->id << " " << schedule[f->src->id]->src->id << "->" << schedule[f->src->id]->dst->id << "\n";
        }

        if(f->arbiter_remaining_num_pkts > 0 && sender_free && receiver_free){
            if(params.fastpass_limit_conns) {
                if (sender_tor == receiver_tor || (send_tor_avil && recv_tor_avil)) {
                    if (sender_tor != receiver_tor) {
                        send_tor_cons[sender_tor] += 1;
                        recv_tor_cons[receiver_tor] += 1;
                    }
                    f->arbiter_remaining_num_pkts--;
                    sender_used.insert(f->src->id);
                    receiver_used.insert(f->dst->id);
                    schedule[f->src->id] = f;
                    if(debug_flow(f->id)) {
                        std::cout << get_current_time() << " scheduled flow " << f->id << " for epoch " << get_current_time() + params.fastpass_epoch_time <<
                            " remaining pkts " << f->arbiter_remaining_num_pkts << "\n";
                    }
                }
            } else {
                f->arbiter_remaining_num_pkts--;
                sender_used.insert(f->src->id);
                receiver_used.insert(f->dst->id);
                schedule[f->src->id] = f;
                if(debug_flow(f->id)) {
                    std::cout << get_current_time() << " scheduled flow " << f->id << " for epoch " << get_current_time() + params.fastpass_epoch_time <<
                        " remaining pkts " << f->arbiter_remaining_num_pkts << "\n";
                }
            }
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


void FastpassArbiter::schedule_proc_evt(double time) {
    if (this->arbiter_proc_evt != NULL) {
        this->arbiter_proc_evt->cancelled = true;
        this->arbiter_proc_evt = NULL;
    }
    this->arbiter_proc_evt = new ArbiterProcessingEvent(time, this);
    add_to_event_queue(this->arbiter_proc_evt);
}

void FastpassArbiter::schedule_epoch() {
    if (total_finished_flows >= params.num_flows_to_run)
        return;

    std::vector<FastpassEpochSchedule*> schedules;
    for (uint i = 0; i < params.num_hosts; i++){
        schedules.push_back(new FastpassEpochSchedule(get_current_time() + params.fastpass_epoch_time));
    }



    for(int i = 0; i < params.fastpass_epoch_pkts; i++){
        if(this->sending_flows.size() > 0){
            std::map<int, FastpassFlow*> one_time_slot = schedule_timeslot();

            for(auto iter = one_time_slot.begin(); iter != one_time_slot.end(); ++iter)
            {
                int sender = iter->first;
                FastpassFlow* f = iter->second;
                schedules[sender]->schedule[i] = f;
            }
        }
    }

    assert(this->queue->limit_bytes - this->queue->bytes_in_queue >= 144 * 40);

    for(int i = 0; i < params.num_hosts; i++)
    {
        FastpassFlow* f = schedules[i]->get_sender();
        if(f)
            f->send_schedule_pkt(schedules[i]);
        else
            delete schedules[i];
    }

    //schedule next arbiter proc evt
    this->schedule_proc_evt(get_current_time() + params.fastpass_epoch_time);
}

void FastpassArbiter::receive_rts(FastpassRTS* rts)
{
    if(!((FastpassFlow*)rts->flow)->arbiter_received_rts)
    {
        ((FastpassFlow*) rts->flow)->arbiter_received_rts = true;
        dynamic_cast<FastpassArbiter*>(topology->arbiter)->sending_flows.push((FastpassFlow*)rts->flow);
    }

    if(rts->remaining_num_pkts < 0){
        ((FastpassFlow*)rts->flow)->arbiter_remaining_num_pkts = 0;
        ((FastpassFlow*)rts->flow)->arbiter_finished = true;
    }
    else
        ((FastpassFlow*)rts->flow)->arbiter_remaining_num_pkts = rts->remaining_num_pkts;
}


FastpassFlowProcessingEvent::FastpassFlowProcessingEvent(double time, FastpassFlow* f)
    : Event(FASTPASS_FLOW_PROCESSING, time) {
    this->flow = f;
}

FastpassFlowProcessingEvent::~FastpassFlowProcessingEvent() {
}

void FastpassFlowProcessingEvent::process_event() {
    this->flow->send_data_pkt();
}


FastpassTimeoutEvent::FastpassTimeoutEvent(double time, FastpassFlow* f) : Event(FASTPASS_TIMEOUT, time) {
    this->flow = f;
}

FastpassTimeoutEvent::~FastpassTimeoutEvent() {
}

void FastpassTimeoutEvent::process_event() {
    this->flow->fastpass_timeout();
}

