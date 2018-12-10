#include <assert.h>
#include <stdlib.h>

#include "../coresim/event.h"
#include "../coresim/flow.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"`

#include "mrflow.h"
#include "mrhost.h"
#include "factory.h"

#include "../run/params.h"

extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern uint32_t total_finished_flows;

bool MrFlowComparator::operator() (MrFlow* a, MrFlow* b){
    if (a->remaining_pkts_at_sender > b->remaining_pkts_at_sender)
        return true;
    else if (a->remaining_pkts_at_sender == b->remaining_pkts_at_sender)
        return a->start_time > b->start_time;
    else
        return false;
}

UpdateRoundEvent::UpdateRoundEvent(double time, MrHost *h)
    : Event(UPDATE_ROUND_PROCESSING, time) {
        this->host = h;
    }

UpdateRoundEvent::~UpdateRoundEvent() {
    if (host->update_round_evt == this) {
        host->update_round_evt = NULL;
    }
}

void UpdateRoundEvent::process_event() {
    this->host->update_round_evt = NULL;
    this->host->schedule_update_round_evt();
}

ProcessReceiverIterEvent::ProcessReceiverIterEvent(double time, MrHost *h)
    : Event(PROCESS_RECEIVER_ITER_REQUEST, time) {
        this->host = h;
    }

ProcessReceiverIterEvent::~ProcessReceiverIterEvent() {
    if (host->proc_receiver_iter_evt == this) {
        host->proc_receiver_iter_evt = NULL;
    }
}

void ProcessReceiverIterEvent::process_event() {
    this->host->proc_receiver_iter_evt = NULL;
    this->host->schedule_receiver_iter_evt();
}

ProcessSenderIterEvent::ProcessSenderIterEvent(double time, MrHost *h)
    : Event(PROCESS_SENDER_ITER_REQUEST, time) {
        this->host = h;
    }

ProcessSenderIterEvent::~ProcessSenderIterEvent() {
    if (host->proc_sender_iter_evt == this) {
        host->proc_sender_iter_evt = NULL;
    }
}

void ProcessSenderIterEvent::process_event() {
    this->host->proc_sender_iter_evt = NULL;
    this->host->schedule_sender_iter_evt();
}

MrHost::MrHost(uint32_t id, double rate, uint32_t queue_type) : SchedulingHost(id, rate, queue_type) {
    // this->capa_proc_evt = NULL;
    // this->hold_on = 0;
    // this->total_capa_schd_evt_count = 0;
    // this->could_better_schd_count = 0;
    // this->sender_notify_evt = NULL;
    this->host_type = MR_HOST;
    this->round = 0;
    this->iter = 0;
    this->match_sender = NULL;
    this->match_receiver = NULL;
    this->sender = NULL;
    this->receiver = NULL;
    this->update_round_evt = NULL;
    this->iter_epoch = 2 * (params.ctrl_pkt_rtt / 2 + 0.5 /1000000); // assuming 500ns queuing delay; can do better;
    for(uint32_t i = 0; i < params.num_hosts; i++) {
        this->receiver_state.push_back(true);
    }
    this->proc_receiver_iter_evt = 0;
    this->proc_sender_iter_evt = 0;
    this->update_round_evt = 0;

}

void MrHost::start_host() {
    this->proc_receiver_iter_evt = new ProcessReceiverIterEvent(1.0 + this->iter_epoch / 2, this);
    this->proc_sender_iter_evt = new ProcessSenderIterEvent(1.0, this);
    this->update_round_evt = new UpdateRoundEvent(1.0 + params.mr_epoch - this->iter_epoch * params.mr_iter_limit, this);
    add_to_event_queue(this->proc_receiver_iter_evt);
    add_to_event_queue(this->proc_sender_iter_evt);
    add_to_event_queue(this->update_round_evt);
}
bool MrHost::flow_compare(MrFlow* long_flow, MrFlow* short_flow) {
    if(long_flow == NULL)
        return true;
    if(short_flow == NULL)
        return false;
    if(params.deadline && params.schedule_by_deadline) {
        return long_flow->deadline > short_flow->deadline;
    }
    if(long_flow->remaining_pkts_at_sender > short_flow->remaining_pkts_at_sender)
        return true;
    else if (long_flow->remaining_pkts_at_sender == short_flow->remaining_pkts_at_sender)
        return long_flow->start_time > short_flow->start_time; //TODO: this is cheating. but not a big problem
    else
        return false;
}

MrFlow* MrHost::get_top_unfinish_flow(uint32_t dst_id) {
    MrFlow* best_large_flow = NULL;
    std::queue<MrFlow*> flows_tried;
    if(this->dst_to_flows.find(dst_id) == this->dst_to_flows.end())
        return best_large_flow;
    while (!this->dst_to_flows[dst_id].empty()) {
        best_large_flow = this->dst_to_flows[dst_id].top();
        if(best_large_flow->finished) {
            best_large_flow = NULL;
            this->dst_to_flows[dst_id].pop();
        } else if (best_large_flow->redundancy_ctrl_timeout > get_current_time()) {
            flows_tried.push(best_large_flow);
            this->dst_to_flows[dst_id].pop();
        } else {
            break;
        }
    }
    while(!flows_tried.empty()) {
        this->dst_to_flows[dst_id].push(flows_tried.front());
        flows_tried.pop();
    }
    if(this->dst_to_flows[dst_id].empty()){
        this->dst_to_flows.erase(dst_id);
    }
    return best_large_flow;
}

// sender logic
void MrHost::receive_cts(MRCTS *p) {
    assert(p->round == this->round);
    if(p->iter < this->iter)
        return;
    MR_CTS cts;
    cts.iter = p->iter;
    cts.f = (MrFlow*)p->flow;
    // may need to check round number
    // TO DO: trigger random dicision process
    if(debug_flow(p->flow->id)) {
        std::cout << get_current_time() << " round " << this->round << "iter " << this->iter << " receive cts for flow " << p->flow->id << "host: " << id << std::endl; 
    }
    assert(this->iter == p->iter);
    this->cts_q.push_back(cts);
    // if(this->proc_cts_evt == NULL) {
    //     this->proc_cts_evt = new ProcessCTSEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}
void MrHost::advance_iter() {
    this->iter++;
    this->rts_q.clear();
    this->cts_q.clear();
}
void MrHost::receive_offer_packet(OfferPkt *p) {
    // assert(p->iter == this->iter);
    assert(p->round == this->round);
    if(p->iter < this->iter)
        return;
    assert(p->iter == this->iter);
    this->receiver_state[p->flow->dst->id] = p->is_free;
}


void MrHost::receive_ctsr(CTSR *p) {
    // assert(this->iter == p->iter + 1);
    assert(p->round == this->round);
    if(debug_host(id)) {
        std::cout << get_current_time() << " round " << this->round << " iter " << this->iter << " receive ctsr packet from dst " << p->flow->dst->id << " src:" << id  << " q delay:" << p->total_queuing_delay << std::endl; 
    }
    assert(this->match_receiver == p->flow->dst);
    this->match_receiver = NULL;
    // if(this->proc_decision_evt == NULL) {
    //     this->proc_decision_evt = new ProcssDecisionEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}

// receiver logic
void MrHost::receive_decision_pkt(DecisionPkt *p) {
    // if(this->iter != p->iter + 1) {
    //     std::cout << get_current_time() << " " << this->iter << " " << p->iter + 1 << " flow id" << p->flow->id << " receiver:" << this->id << " q delay:" << p->total_queuing_delay << std::endl;
    // }
    // assert(this->iter == p->iter + 1);
    assert(p->round == this->round);
    if(p->accept) {
        if(this->match_sender != NULL){
            ((MrFlow*)p->flow)->send_ctsr(this->iter, this->round);
            return;
        }
        if(debug_host(id)) {
            std::cout << get_current_time() << " round " << this->round << " iter " << this->iter << " match src " << p->flow->src->id << "dst:" << id  << " q delay:" << p->total_queuing_delay << std::endl; 
        }
        assert(this->match_sender == NULL);
        this->match_sender = (MrHost*)p->flow->src;
        if(this->iter > params.mr_iter_limit) {
            // corner case
            this->sender = this->match_sender;
        }
    }
    // if(this->proc_decision_evt == NULL) {
    //     this->proc_decision_evt = new ProcssDecisionEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}

void MrHost::receive_rts(MRRTS *p) {
    if(p->iter < this->iter)
        return;
    assert(p->round == this->round);
    assert(p->iter == this->iter);
    if(debug_host(id)) {
        std::cout << get_current_time() << " round " << this->round << " iter " << this->iter << " receive rts for src " << p->flow->src->id << " dst:" << id << std::endl; 
    }
    if(this->match_sender != NULL) {
        ((MrFlow*)(p->flow))->send_offer_pkt(this->iter, this->round, false);
    }
    MR_RTS rts;
    rts.iter = p->iter;
    rts.f = (MrFlow*)p->flow;
    this->rts_q.push_back(rts);
    // schduling handle all rtses
}
void MrHost::start_flow(MrFlow* f) {
    if(debug_flow(f->id) || debug_host(this->id)) {
        std::cout 
            << get_current_time() 
            << " flow " << f->id 
            << " src " << this->id
             <<"\n";
    }
    if(f->is_small_flow()) {
        this->active_short_flows.push(f);
    } else {
        this->dst_to_flows[f->dst->id].push(f);
    }
}

void MrHost::send_all_rts() {
    if(this->match_receiver != NULL)
        return;
    for(auto i = this->dst_to_flows.begin(); i != this->dst_to_flows.end();) {
        if(this->receiver_state[i->first] == false) {  
            i++;
            continue;
        }
        while(!i->second.empty()) {
            if(i->second.top()->finished == true) {
                i->second.pop();
            } else {
                if(debug_flow(i->second.top()->id)) {
                    std::cout << "flow " << i->second.top()->id << " src " << id << " send_rts" << std::endl;
                }
                i->second.top()->send_rts(this->iter, this->round);
                break;
            }
        }
        if(i->second.empty()) {
            i = this->dst_to_flows.erase(i);
        } else {
            i++;
        }
    }
}

void MrHost::handle_all_rts() {
    if(this->match_sender != NULL)
        return;
    assert(this->match_sender == NULL);
    uint32_t index = 0;
    if(debug_host(id)) {
        std::cout << get_current_time() << " round " << this->round << " iter " << this->iter << " handle of all rts dst:" << id << std::endl; 
    }
    while(!this->rts_q.empty()) {
        index = rand() % this->rts_q.size();
        if(this->rts_q[index].iter != this->iter) {
            assert(this->rts_q[index].iter < this->iter);
            this->rts_q.erase(this->rts_q.begin() + index);
        } else {
            break;
        }
    }
    for(uint32_t i = 0; i < this->rts_q.size(); i++) {
        if (i == index && this->match_sender == NULL) {
            // send CTS
            this->rts_q[i].f->send_cts(this->iter, this->round);
        } else {
            // send offerPkt
            this->rts_q[i].f->send_offer_pkt(this->iter, this->round, this->match_sender == NULL);
        }
    }
}

void MrHost::handle_all_cts() {
    if(this->match_receiver != NULL)
        return;
    assert(this->match_receiver == NULL);
    assert(this->proc_sender_iter_evt == NULL);
    if(this->cts_q.empty())
        return;
    uint32_t index = 0;
    while(!this->cts_q.empty()) {
        index = rand() % this->cts_q.size();
        if(this->cts_q[index].iter != this->iter) {
            assert(this->cts_q[index].iter < this->iter);
            this->cts_q.erase(this->cts_q.begin() + index);
        } else {
            break;
        }
    }
    for(uint32_t i = 0; i < this->cts_q.size(); i++) {
        if (i == index && this->match_receiver == NULL) {
            // send decision_pkt true
            this->cts_q[i].f->send_decision_pkt(this->
                iter, this->round, true);
            if(debug_host(this->cts_q[i].f->dst->id)) {
                std::cout << get_current_time() << " round " << this->round << " iter " << this->iter << " src " << id << " accept " << this->cts_q[i].f->dst->id << std::endl;
            }
            this->match_receiver = (MrHost*)(this->cts_q[i].f->dst);
            this->receiver_state[this->cts_q[i].f->dst->id] = false;

        } else {
            // send decision_pkt false
            this->cts_q[i].f->send_decision_pkt(this->iter, this->round, false);
        }
    }
}

void MrHost::schedule_sender_iter_evt() {
    assert(this->proc_sender_iter_evt == NULL);
    this->handle_all_cts();
    this->advance_iter();
    if(debug_host(id)) {
        std::cout << get_current_time() << "new iter " << this->iter << std::endl;
    }
    if(this->iter > params.mr_iter_limit) {
        if(debug_host(id)) {
            std::cout << get_current_time() << " pass the limit " << std::endl;
        }
        this->receiver = this->match_receiver;
        if(this->host_proc_event != NULL && host_proc_event->is_timeout) {
            this->host_proc_event->cancelled = true;
            this->host_proc_event = NULL;
        }
        if(this->host_proc_event == NULL) {
            this->schedule_host_proc_evt();
        }
        return;
    }
    this->send_all_rts();
    this->proc_sender_iter_evt = new ProcessSenderIterEvent(get_current_time() + this->iter_epoch, this);
    add_to_event_queue(this->proc_sender_iter_evt);

}

void MrHost::schedule_receiver_iter_evt() {
    assert(this->proc_receiver_iter_evt == NULL);
    if(this->iter > params.mr_iter_limit) {
        this->sender = this->match_sender;
        return;
    }
    this->handle_all_rts();
    this->proc_receiver_iter_evt = new ProcessReceiverIterEvent(get_current_time() + this->iter_epoch, this);
    add_to_event_queue(this->proc_receiver_iter_evt);

}

void MrHost::schedule_update_round_evt() {
    if (total_finished_flows >= params.num_flows_to_run)
        return;
    this->round++;
    this->iter = 0;
    assert(this->update_round_evt == NULL);
    assert(this->proc_receiver_iter_evt == NULL);
    assert(this->proc_sender_iter_evt == NULL);
    for(uint32_t i = 0; i < this->receiver_state.size(); i++) {
        this->receiver_state[i] = true;
    }
    this->match_sender = NULL;
    this->match_receiver = NULL;
    this->rts_q.clear();
    this->cts_q.clear();
    this->proc_receiver_iter_evt = new ProcessReceiverIterEvent(get_current_time() + this->iter_epoch / 2, this);;
    this->proc_sender_iter_evt = new ProcessSenderIterEvent(get_current_time(), this);
    this->update_round_evt = new UpdateRoundEvent(get_current_time() + params.mr_epoch - this->iter_epoch * params.mr_iter_limit, this);
    add_to_event_queue(this->proc_receiver_iter_evt);
    add_to_event_queue(this->proc_sender_iter_evt);
    add_to_event_queue(this->update_round_evt);
}
void MrHost::schedule_host_proc_evt() {
    assert(this->host_proc_event == NULL);

    double qpe_time = 0;
    double td_time = 0;
    if(this->queue->busy){
        qpe_time = this->queue->queue_proc_event->time;
    }
    else{
        qpe_time = get_current_time();
    }

    uint32_t queue_size = this->queue->bytes_in_queue;
    td_time = this->queue->get_transmission_delay(queue_size);

    this->host_proc_event = new HostProcessingEvent(qpe_time + td_time + INFINITESIMAL_TIME, this);
    add_to_event_queue(this->host_proc_event);
}

//should only be called in HostProcessingEvent::process()
void MrHost::send(){
    assert(this->host_proc_event == NULL);
    double closet_timeout = 999999;
    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        bool pkt_sent = false;
        std::queue<MrFlow*> flows_tried;
        MrFlow* best_short_flow = NULL;
        MrFlow* best_large_flow = NULL;
        if(this->receiver!= NULL) {
            best_large_flow = this->get_top_unfinish_flow(this->receiver->id);
        }
        while(!pkt_sent) {
            if (this->active_short_flows.empty() && best_large_flow == NULL) {
                break;
            }
            MrFlow* f;
            if(!this->active_short_flows.empty()) {
                best_short_flow = this->active_short_flows.top();
            }
            if(flow_compare(best_large_flow, best_short_flow)) {
                f = this->active_short_flows.top();
                this->active_short_flows.pop();
                best_short_flow = NULL;
            } else {
                f = best_large_flow;
                best_large_flow = NULL;
            }
            if(f->finished) {
                continue;
            }
            // can do better to find the best case
            if(f->is_small_flow()) {
                flows_tried.push(f);
            }
            if(f->redundancy_ctrl_timeout > get_current_time()) {
                if(debug_flow(f->id)) {
                    std::cout << get_current_time() << " redundancy_ctrl_timeout has not met " << f->id  << "\n";
                }
                if(f->redundancy_ctrl_timeout < closet_timeout)
                {
                    closet_timeout = f->redundancy_ctrl_timeout;
                }
            }
            else {
                //just timeout, reset timeout state
                if(f->redundancy_ctrl_timeout > 0)
                {
                    f->redundancy_ctrl_timeout = -1;
                    // f->token_goal += f->remaining_pkts();
                    if(debug_flow(f->id)) {
                        std::cout << get_current_time() << " redundancy_ctrl_timeout met" << f->id  << "\n";
                    }
                }
                if(f->gap() > params.mr_window_size) {
                    if(get_current_time() >= f->latest_data_pkt_send_time + params.mr_window_timeout) {
                        f->relax_gap();
                        if(debug_host(this->id)) {
                            std::cout << get_current_time() << " host " << this->id << " relax token gap for flow " << f->id << std::endl;
                        }
                    }
                    else{
                        if(f->latest_data_pkt_send_time + params.mr_window_timeout < closet_timeout)
                        {
                            closet_timeout = f->latest_data_pkt_send_time + params.mr_window_timeout;
                            if(debug_host(this->id)) {
                                std::cout << get_current_time() << " host " << this->id << " token_window full wait for timeout for flow " << f->id << std::endl;
                            }
                        }
                    }

                }
                if(f->gap() <= params.mr_window_size) {
                    auto next_data_seq = f->get_next_data_seq_num();
                    f->send_pending_data();
                    if(debug_host(id)) {
                            std::cout << get_current_time() << " sending data for flow " << f->id << std::endl;   
                    }
                    pkt_sent = true;
                    // this->token_hist.push_back(this->recv_flow->id);
                    if(next_data_seq >= f->get_next_data_seq_num()) {
                        // if(!f->first_loop) {
                        //     f->first_loop = true;
                        // } else {
                            f->redundancy_ctrl_timeout = get_current_time() + params.mr_resend_timeout;
                            if(debug_flow(f->id)) {
                                std::cout << get_current_time() << " redundancy_ctrl_timeout set up " << f->id << " timeout value: " << f->redundancy_ctrl_timeout << "\n";
                            }
                        // }
                    }
                }
            }
        }

        while(!flows_tried.empty()) {
            MrFlow* f = flows_tried.front();
            flows_tried.pop();
            this->active_short_flows.push(f);
        }
        if(closet_timeout < 999999 && !pkt_sent) {
            assert(closet_timeout > get_current_time());
            assert(((SchedulingHost*) this)->host_proc_event == NULL);
            if(debug_host(id)) {
                std::cout << get_current_time() << " set up timeout event " << std::endl;   
            }
            ((SchedulingHost*) this)->host_proc_event = new HostProcessingEvent(closet_timeout, (SchedulingHost*) this);
            ((SchedulingHost*) this)->host_proc_event->is_timeout = true;
            add_to_event_queue(((SchedulingHost*) this)->host_proc_event);
        }
    }
}