#include <assert.h>
#include <stdlib.h>
#include <climits>
#include "../coresim/event.h"
#include "../coresim/flow.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"`

#include "pimflow.h"
#include "pimhost.h"
#include "factory.h"

#include "../run/params.h"

extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern uint32_t total_finished_flows;
extern Topology *topology;

bool PimFlowComparator::operator() (PimFlow* a, PimFlow* b){
    if (a->remaining_pkts_at_sender > b->remaining_pkts_at_sender)
        return true;
    else if (a->remaining_pkts_at_sender == b->remaining_pkts_at_sender)
        return a->start_time > b->start_time;
    else
        return false;
}

NewEpochEvent::NewEpochEvent(double time, int epoch, PimHost *h)
    : Event(NEW_EPOCH_PROCESSING, time) {
        this->time = time;
        this->epoch = epoch;
        this->host = h;
    }

NewEpochEvent::~NewEpochEvent() {
    if (host->new_epoch_evt == this) {
        host->new_epoch_evt = NULL;
    }
}

void NewEpochEvent::process_event() {
    this->host->new_epoch_evt = NULL;
    this->host->start_new_epoch(this->time, this->epoch);
}


ProcessReceiverIterEvent::ProcessReceiverIterEvent(double time, PimEpoch *epoch)
    : Event(PROCESS_RECEIVER_ITER_REQUEST, time) {
        this->epoch = epoch;
    }

ProcessReceiverIterEvent::~ProcessReceiverIterEvent() {
    if (this->epoch->proc_receiver_iter_evt == this) {
        this->epoch->proc_receiver_iter_evt = NULL;
    }
}

void ProcessReceiverIterEvent::process_event() {
    this->epoch->proc_receiver_iter_evt = NULL;
    this->epoch->schedule_receiver_iter_evt();
}

ProcessSenderIterEvent::ProcessSenderIterEvent(double time, PimEpoch *epoch)
    : Event(PROCESS_SENDER_ITER_REQUEST, time) {
        this->epoch = epoch;
    }

ProcessSenderIterEvent::~ProcessSenderIterEvent() {
    if (this->epoch->proc_sender_iter_evt == this) {
        this->epoch->proc_sender_iter_evt = NULL;
    }
}

void ProcessSenderIterEvent::process_event() {
    this->epoch->proc_sender_iter_evt = NULL;
    this->epoch->schedule_sender_iter_evt();
}


PimEpoch::PimEpoch(){
    this->epoch = -1;
    this->iter = 0;
    this->match_receiver = NULL;
    this->match_sender = NULL;
    this->proc_sender_iter_evt = NULL;
    this->proc_receiver_iter_evt = NULL;
    this->host = NULL;
    this->min_rts = PIM_RTS();
    // for(uint32_t i = 0; i < params.num_hosts; i++) {
    //     this->receiver_state.push_back(true);
    // }
}
PimEpoch::~PimEpoch() {
    grants_q.clear();
    rts_q.clear();
    // receiver_state.clear();
}

// sender logic
void PimEpoch::receive_grants(PIMGrants *p) {
    assert(p->epoch == this->epoch);
    if(p->iter < this->iter)
        return;
    PIM_Grants grants;
    grants.iter = p->iter;
    grants.f = (PimFlow*)p->flow;
    grants.prompt = p->prompt;
    // may need to check epoch number
    // TO DO: trigger random dicision process
    if(debug_flow(p->flow->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << "iter " << this->iter << " receive grants for flow " << p->flow->id << "host: " << this->host->id << std::endl; 
    }
    assert(this->iter == p->iter);
    this->grants_q.push_back(grants);
    // if(this->proc_grants_evt == NULL) {
    //     this->proc_grants_evt = new ProcessGrantsEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}
void PimEpoch::advance_iter() {
    this->iter++;
    this->rts_q.clear();
    this->grants_q.clear();
    this->min_rts = PIM_RTS();
}
// void PimEpoch::receive_offer_packet(OfferPkt *p) {
//     // assert(p->iter == this->iter);
//     assert(p->epoch == this->epoch);
//     if(p->iter < this->iter)
//         return;
//     assert(p->iter == this->iter);
//     this->receiver_state[p->flow->dst->id] = p->is_free;
// }
void PimEpoch::receive_grantsr(GrantsR *p) {
    // assert(this->iter == p->iter + 1);
    assert(p->epoch == this->epoch);
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " receive grantsr packet from dst " << p->flow->dst->id << " src:" << this->host->id  << " q delay:" << p->total_queuing_delay << std::endl; 
    }
    assert(this->match_receiver == p->flow->dst);
    this->match_receiver = NULL;
    this->host->receiver = this->match_receiver;
    // if(this->proc_accept_evt == NULL) {
    //     this->proc_accept_evt = new ProcssAcceptEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}
// receiver logic
void PimEpoch::receive_accept_pkt(AcceptPkt *p) {
    // if(this->iter != p->iter + 1) {
    //     std::cout << get_current_time() << " " << this->iter << " " << p->iter + 1 << " flow id" << p->flow->id << " receiver:" << this->id << " q delay:" << p->total_queuing_delay << std::endl;
    // }
    // assert(this->iter == p->iter + 1);
    assert(p->epoch == this->epoch);
    if(p->accept) {
        if(this->match_sender != NULL){
            ((PimFlow*)p->flow)->send_grantsr(this->iter, this->epoch);
            return;
        }
        if(debug_host(this->host->id)) {
            std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " match src " << p->flow->src->id << "dst:" << this->host->id  << " q delay:" << p->total_queuing_delay << std::endl; 
        }
        assert(this->match_sender == NULL);
        // for non-pipeline
        this->match_sender = (PimHost*)p->flow->src;
        // this->host->sender = this->match_sender;

        // for pipeline
        if(this->iter > params.pim_iter_limit && this->host->cur_epoch == this->epoch) {
            // corner case
            this->host->sender = this->match_sender;
        }
    }
    // if(this->proc_accept_evt == NULL) {
    //     this->proc_accept_evt = new ProcssAcceptEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}
void PimEpoch::receive_rts(PIMRTS *p) {
    if(p->iter < this->iter)
        return;
    assert(p->epoch == this->epoch);
    assert(p->iter == this->iter);
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " receive rts for src " << p->flow->src->id << " dst:" << this->host->id << std::endl; 
        std::cout << "queue delay:" << p->total_queuing_delay << std::endl;

    }
    // if(this->match_sender != NULL) {
    //     ((PimFlow*)(p->flow))->send_offer_pkt(this->iter, this->epoch, false);
    // }
    PIM_RTS rts;
    rts.iter = p->iter;
    rts.f = (PimFlow*)p->flow;
    rts.remaining_sz = p->remaining_sz;
    this->rts_q.push_back(rts);
    if(this->min_rts.f == NULL || this->min_rts.remaining_sz > rts.remaining_sz) {
        this->min_rts.f = rts.f;
        this->min_rts.remaining_sz = rts.remaining_sz;
        this->min_rts.iter = rts.iter;
    }
    // schduling handle all rtses
}
void PimEpoch::send_all_rts() {
    if(this->match_receiver != NULL)
        return;
    for(auto i = this->host->dst_to_flows.begin(); i != this->host->dst_to_flows.end();) {
        // if(this->receiver_state[i->first] == false) {  
        //     i++;
        //     continue;
        // }
        while(!i->second.empty()) {
            if(i->second.top()->finished == true) {
                i->second.pop();
            } else {
                if(debug_flow(i->second.top()->id) || debug_host(this->host->id)) {
                    std::cout << "flow " << i->second.top()->id << " src " << this->host->id << " send_rts" << std::endl;
                }
                i->second.top()->send_rts(this->iter, this->epoch);
                break;
            }
        }
        if(i->second.empty()) {
            i = this->host->dst_to_flows.erase(i);
        } else {
            i++;
        }
    }
}
void PimEpoch::handle_all_rts() {
    if(this->match_sender != NULL)
        return;
    assert(this->match_sender == NULL);
    uint32_t index = 0;
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " handle of all rts dst:" << this->host->id << std::endl; 
    }
    if(params.pim_select_min_iters > 0 && this->iter <= params.pim_select_min_iters) {
        if(this->min_rts.f != NULL) {
            assert(min_rts.f != NULL);
            min_rts.f->send_grants(this->iter, this->epoch, this->epoch - 1 == this->host->cur_epoch && this->host->sender == NULL);
        }
    }
    else {
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
                // send Grants
                // this->rts_q[i].f->send_grants(this->iter, this->epoch, false);
                this->rts_q[i].f->send_grants(this->iter, this->epoch, this->epoch - 1 == this->host->cur_epoch && this->host->sender == NULL);
            } else {
                // send offerPkt
                // this->rts_q[i].f->send_offer_pkt(this->iter, this->epoch, this->match_sender == NULL);
            }
        }
    }
}
void PimEpoch::handle_all_grants() {
    if(this->match_receiver != NULL)
        return;
    assert(this->match_receiver == NULL);
    assert(this->proc_sender_iter_evt == NULL);
    if(this->grants_q.empty())
        return;
    int min_size = INT_MAX;
    uint32_t index = 0;
    if(params.pim_select_min_iters > 0 && this->iter <= params.pim_select_min_iters) {
        for(uint32_t i = 0; i < this->grants_q.size(); i++) { 
            if(min_size > this->grants_q[i].f->remaining_pkts_at_sender && this->iter == this->grants_q[index].iter) {
                min_size = this->grants_q[i].f->remaining_pkts_at_sender;
                index = i;
            }
        }
    } else {
        while(!this->grants_q.empty()) {
            index = rand() % this->grants_q.size();
            if(this->grants_q[index].iter != this->iter) {
                assert(this->grants_q[index].iter < this->iter);
                this->grants_q.erase(this->grants_q.begin() + index);
            } else {
                break;
            }
        }
    }
    for(uint32_t i = 0; i < this->grants_q.size(); i++) {
        if (i == index && this->match_receiver == NULL) {
            // send accept_pkt true
            this->grants_q[i].f->send_accept_pkt(this->
                iter, this->epoch, true);
            if(debug_host(this->grants_q[i].f->dst->id)) {
                std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " src " << this->host->id << " accept " << this->grants_q[i].f->dst->id << std::endl;
            }
            this->match_receiver = (PimHost*)(this->grants_q[i].f->dst);

            // non-pipeline
            // this->host->receiver = this->match_receiver;
            // if(this->host->host_proc_event != NULL && this->host->host_proc_event->is_timeout) {
            //     this->host->host_proc_event->cancelled = true;
            //     this->host->host_proc_event = NULL;
            // }
            // if(this->host->host_proc_event == NULL) {
            //     this->host->schedule_host_proc_evt();
            // }


            // Optimization
            // this->receiver_state[this->grants_q[i].f->dst->id] = false;
            if(this->grants_q[i].prompt && this->host->receiver == NULL) {
                assert(this->host->cur_epoch == this->epoch - 1);
                this->host->receiver = this->match_receiver;
                if(this->host->host_proc_event != NULL && this->host->host_proc_event->is_timeout) {
                    this->host->host_proc_event->cancelled = true;
                    this->host->host_proc_event = NULL;
                }
                if(this->host->host_proc_event == NULL) {
                    this->host->schedule_host_proc_evt();
                }
            }

        } else {
            // send accept_pkt false
            // this->grants_q[i].f->send_accept_pkt(this->iter, this->epoch, false);
        }
    }
}
void PimEpoch::schedule_sender_iter_evt() {
    assert(this->proc_sender_iter_evt == NULL);
    this->handle_all_grants();
    this->advance_iter();
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << "new iter " << this->iter << std::endl;
    }
    if(this->iter > params.pim_iter_limit) {
        if(debug_host(this->host->id)) {
            std::cout << get_current_time() << " new epoch start sending packets: " << this->epoch  << std::endl;
        }

        // pipeline code
        this->host->receiver = this->match_receiver;
        this->host->sender = this->match_sender;
        //senders starts to send packets at this epoch
        this->host->cur_epoch = this->epoch;
        if(this->host->epochs.count(this->epoch - 1) > 0){
            this->host->epochs.erase(this->epoch - 1);
        }
        if(this->host->host_proc_event != NULL && this->host->host_proc_event->is_timeout) {
            this->host->host_proc_event->cancelled = true;
            this->host->host_proc_event = NULL;
        }
        if(this->host->host_proc_event == NULL) {
            this->host->schedule_host_proc_evt();
        }
        return;
    }
    this->send_all_rts();
    this->proc_sender_iter_evt = new ProcessSenderIterEvent(get_current_time() + params.pim_iter_epoch, this);
    add_to_event_queue(this->proc_sender_iter_evt);
}

void PimEpoch::schedule_receiver_iter_evt() {
    assert(this->proc_receiver_iter_evt == NULL);
    if(this->iter > params.pim_iter_limit) {
        // this->host->sender = this->match_sender;
        return;
    }
    this->handle_all_rts();
    this->proc_receiver_iter_evt = new ProcessReceiverIterEvent(get_current_time() + params.pim_iter_epoch, this);
    add_to_event_queue(this->proc_receiver_iter_evt);

}

PimHost::PimHost(uint32_t id, double rate, uint32_t queue_type) : SchedulingHost(id, rate, queue_type) {
    // this->capa_proc_evt = NULL;
    // this->hold_on = 0;
    // this->total_capa_schd_evt_count = 0;
    // this->could_better_schd_count = 0;
    // this->sender_notify_evt = NULL;
    this->host_type = PIM_HOST;
    // this->epoch = 0;
    // this->iter = 0;
    // this->match_sender = NULL;
    // this->match_receiver = NULL;
    this->sender = NULL;
    this->receiver = NULL;
    this->new_epoch_evt = NULL;
    // for(uint32_t i = 0; i < params.num_hosts; i++) {
    //     this->receiver_state.push_back(true);
    // }
    this->cur_epoch = -1;

}

void PimHost::start_new_epoch(double time, int epoch) {
    assert(this->epochs.count(epoch) == 0);
    // this->iter_epoch = 2 * (topology->get_control_pkt_rtt(143) / 2 + 1.5 /1000000); // assuming 500ns queuing delay; can do better;
    if (total_finished_flows >= params.num_flows_to_run)
        return;
    // this->receiver = NULL;
    // this->sender = NULL;
    // this->cur_epoch = epoch;
    this->epochs[epoch].epoch = epoch;
    this->epochs[epoch].iter = 0;
    this->epochs[epoch].host = this;
    this->epochs[epoch].proc_receiver_iter_evt = new ProcessReceiverIterEvent(time + params.pim_iter_epoch / 2, &this->epochs[epoch]);
    this->epochs[epoch].proc_sender_iter_evt = new ProcessSenderIterEvent(time, &this->epochs[epoch]);
    // pipeline
    this->new_epoch_evt = new NewEpochEvent(time + params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit, epoch + 1 , this);
    // non-pipeline
    // this->new_epoch_evt = new NewEpochEvent(time + params.pim_epoch, epoch + 1 , this);
    add_to_event_queue(this->epochs[epoch].proc_receiver_iter_evt);
    add_to_event_queue(this->epochs[epoch].proc_sender_iter_evt);
    add_to_event_queue(this->new_epoch_evt);
    if(debug_host(this->id)){
        std::cout << time << "new epoch start " << epoch << std::endl;
    }
    // if(this->epochs.count(this->cur_epoch - 1) > 0){
    //     this->epochs.erase(this->cur_epoch - 1);
    // }
}
bool PimHost::flow_compare(PimFlow* long_flow, PimFlow* short_flow) {
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

PimFlow* PimHost::get_top_unfinish_flow(uint32_t dst_id) {
    PimFlow* best_large_flow = NULL;
    std::queue<PimFlow*> flows_tried;
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

void PimHost::start_flow(PimFlow* f) {
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
    if(this->host_proc_event != NULL && this->host_proc_event->is_timeout) {
        this->host_proc_event->cancelled = true;
        this->host_proc_event = NULL;
    }
    if(this->host_proc_event == NULL) {
        this->schedule_host_proc_evt();
    }
}

// void PimHost::schedule_update_epoch_evt() {
//     if (total_finished_flows >= params.num_flows_to_run)
//         return;
//     this->epoch++;
//     this->iter = 0;
//     assert(this->update_epoch_evt == NULL);
//     assert(this->proc_receiver_iter_evt == NULL);
//     assert(this->proc_sender_iter_evt == NULL);
//     for(uint32_t i = 0; i < this->receiver_state.size(); i++) {
//         this->receiver_state[i] = true;
//     }
//     this->match_sender = NULL;
//     this->match_receiver = NULL;
//     this->rts_q.clear();
//     this->grants_q.clear();
//     this->proc_receiver_iter_evt = new ProcessReceiverIterEvent(get_current_time() + this->iter_epoch / 2, this);;
//     this->proc_sender_iter_evt = new ProcessSenderIterEvent(get_current_time(), this);
//     this->update_epoch_evt = new UpdateEpochEvent(get_current_time() + params.pim_epoch - this->iter_epoch * params.pim_iter_limit, this);
//     add_to_event_queue(this->proc_receiver_iter_evt);
//     add_to_event_queue(this->proc_sender_iter_evt);
//     add_to_event_queue(this->update_epoch_evt);
// }

void PimHost::schedule_host_proc_evt() {
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
void PimHost::send(){
    assert(this->host_proc_event == NULL);
    double closet_timeout = 999999;
    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        bool pkt_sent = false;
        std::queue<PimFlow*> flows_tried;
        PimFlow* best_short_flow = NULL;
        PimFlow* best_large_flow = NULL;
        if(this->receiver!= NULL) {
            best_large_flow = this->get_top_unfinish_flow(this->receiver->id);
        }
        while(!pkt_sent) {
            if (this->active_short_flows.empty() && best_large_flow == NULL) {
                break;
            }
            PimFlow* f;
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
                if(f->gap() > params.pim_window_size) {
                    if(get_current_time() >= f->latest_data_pkt_send_time + params.pim_window_timeout) {
                        f->relax_gap();
                        if(debug_host(this->id)) {
                            std::cout << get_current_time() << " host " << this->id << " relax token gap for flow " << f->id << std::endl;
                        }
                    }
                    else{
                        if(f->latest_data_pkt_send_time + params.pim_window_timeout < closet_timeout)
                        {
                            closet_timeout = f->latest_data_pkt_send_time + params.pim_window_timeout;
                            if(debug_host(this->id)) {
                                std::cout << get_current_time() << " host " << this->id << " token_window full wait for timeout for flow " << f->id << std::endl;
                            }
                        }
                    }

                }
                if(f->gap() <= params.pim_window_size) {
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
                            f->redundancy_ctrl_timeout = get_current_time() + params.pim_resend_timeout;
                            if(debug_flow(f->id)) {
                                std::cout << get_current_time() << " redundancy_ctrl_timeout set up " << f->id << " timeout value: " << f->redundancy_ctrl_timeout << "\n";
                            }
                        // }
                    }
                }
            }
        }
        // if(!pkt_sent && params.pim_low_priority) {
        //     int min = INT_MAX;
        //     PimFlow* f_low = NULL;
        //     for(auto i = this->dst_to_flows.begin(); i != this->dst_to_flows.end(); i++) {
        //         std::queue<PimFlow*> flows_low_tried;
        //         if(this->receiver != NULL && i->first == this->receiver->id) {
        //             continue;
        //         }
        //         while(1) {
        //             if(i->second.empty()) {
        //                 break;
        //             }
        //             if(i->second.top()->redundancy_ctrl_timeout > get_current_time()) {
        //                 flows_low_tried.push(i->second.top());
        //                 i->second.pop();
        //                 continue;
        //             } else if(i->second.top()->gap() > params.pim_window_size 
        //                 && get_current_time() < i->second.top()->latest_data_pkt_send_time + params.pim_window_timeout) {
        //                 flows_low_tried.push(i->second.top());
        //                 i->second.pop();
        //                 continue;                
        //             }
        //             if(min > i->second.top()->size_in_pkt) {
        //                 min = i->second.top()->size_in_pkt;
        //                 f_low = i->second.top();
        //             }
        //             break;
        //         }
        //         while(!flows_low_tried.empty()) {
        //             i->second.push(flows_low_tried.front());
        //             flows_low_tried.pop();
        //         }
        //     }
        //     if(f_low != NULL) {
        //         f_low->send_pending_data_low_priority();
        //         pkt_sent = true;
        //     }
        // }

        while(!flows_tried.empty()) {
            PimFlow* f = flows_tried.front();
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
