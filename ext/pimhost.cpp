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

PimTokenProcessingEvent::PimTokenProcessingEvent(double time, PimHost *h, bool is_timeout)
    : Event(PIM_TOKEN_PROCESSING, time) {
        this->host = h;
        this->is_timeout_evt = is_timeout;
    }

PimTokenProcessingEvent::~PimTokenProcessingEvent() {
    if (host->token_send_evt == this) {
        host->token_send_evt = NULL;
    }
}

void PimTokenProcessingEvent::process_event() {
    this->host->token_send_evt = NULL;
    this->host->send_token();
}

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
    this->prompt = false;
    this->match_receiver = NULL;
    this->match_sender = NULL;
    this->proc_sender_iter_evt = NULL;
    this->proc_receiver_iter_evt = NULL;
    this->host = NULL;
    this->min_req = PIM_REQ();
    this->min_grant = PIM_Grants();
    // for(uint32_t i = 0; i < params.num_hosts; i++) {
    //     this->receiver_state.push_back(true);
    // }
}
PimEpoch::~PimEpoch() {
    grants_q.clear();
    req_q.clear();
    // receiver_state.clear();
}

// sender logic
void PimEpoch::advance_iter() {
    this->iter++;
    this->req_q.clear();
    this->grants_q.clear();
    this->min_req = PIM_REQ();
    this->min_grant = PIM_Grants();
}
// void PimEpoch::receive_offer_packet(OfferPkt *p) {
//     // assert(p->iter == this->iter);
//     assert(p->epoch == this->epoch);
//     if(p->iter < this->iter)
//         return;
//     assert(p->iter == this->iter);
//     this->receiver_state[p->flow->dst->id] = p->is_free;
// }
void PimEpoch::receive_req(PIMREQ *p) {
    if(p->iter < this->iter)
        return;
    assert(p->epoch == this->epoch);
    assert(p->iter == this->iter);
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " receive req for dst " << p->flow->dst->id << " src:" << this->host->id << std::endl; 
        std::cout << "queue delay:" << p->total_queuing_delay << std::endl;

    }
    // if(this->match_sender != NULL) {
    //     ((PimFlow*)(p->flow))->send_offer_pkt(this->iter, this->epoch, false);
    // }
    PIM_REQ req;
    uint32_t src_addr = ((PimFlow*)p->flow)->src->id;
    req.f = (PimFlow*)p->flow;
    if(req.f == NULL) {
        return;
    }
    req.iter = p->iter;
    req.remaining_sz = p->remaining_sz;
    this->req_q.push_back(req);
    if(this->min_req.f == NULL || this->min_req.remaining_sz > req.remaining_sz) {
        this->min_req.f = req.f;
        this->min_req.remaining_sz = req.remaining_sz;
        this->min_req.iter = req.iter;
    }
    // schduling handle all rtses
}

void PimEpoch::receive_grantsr(GrantsR *p) {
    // assert(this->iter == p->iter + 1);
    assert(p->epoch == this->epoch);
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " receive grantsr packet from src " << p->flow->src->id << " dst:" << this->host->id  << " q delay:" << p->total_queuing_delay << std::endl; 
    }
    assert(this->match_sender == p->flow->src);
    this->match_sender = NULL;
    if(this->host->cur_epoch == this->epoch || this->prompt) {
    	this->host->sender = this->match_sender;
	    this->prompt = false;
    }
    // this->host->receiver = this->match_receiver;
    // if(this->proc_accept_evt == NULL) {
    //     this->proc_accept_evt = new ProcssAcceptEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}
// receiver logic

void PimEpoch::receive_grants(PIMGrants *p) {
    assert(p->epoch == this->epoch);
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << std::endl;
        std::cout << "           "<< " receive grants for flow " << p->flow->id << "host: " << this->host->id << " p iter:" << p->iter  << " total queue delay:" << p->total_queuing_delay << std::endl; 
    }
    if(p->iter < this->iter)
        return;
    PIM_Grants grant;
    grant.iter = p->iter;
    grant.f = (PimFlow*)p->flow;
    grant.remaining_sz = p->remaining_sz;
    grant.prompt = p->prompt;
    // may need to check epoch number
    // TO DO: trigger random dicision process

    assert(this->iter == p->iter);
    this->grants_q.push_back(grant);
    if(this->min_grant.f == NULL || this->min_grant.remaining_sz > grant.remaining_sz) {
        this->min_grant.f = grant.f;
        this->min_grant.remaining_sz = grant.remaining_sz;
        this->min_grant.iter = grant.iter;
        this->min_grant.prompt = grant.prompt;
    }
    // if(this->proc_grants_evt == NULL) {
    //     this->proc_grants_evt = new ProcessGrantsEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}

void PimEpoch::receive_accept_pkt(AcceptPkt *p) {
    // if(this->iter != p->iter + 1) {
    //     std::cout << get_current_time() << " " << this->iter << " " << p->iter + 1 << " flow id" << p->flow->id << " receiver:" << this->id << " q delay:" << p->total_queuing_delay << std::endl;
    // }
    // assert(this->iter == p->iter + 1);
    assert(p->epoch == this->epoch);
    // if(p->accept) {
    if(this->match_receiver != NULL){
        ((PimFlow*)p->flow)->send_grantsr(this->iter, this->epoch);
        return;
    }
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " match src " << p->flow->src->id << " to dst:" << p->flow->dst->id  << " q delay:" << p->total_queuing_delay << std::endl; 
    }
    assert(this->match_receiver == NULL);
    // for non-pipeline
    this->match_receiver = (PimHost*)p->flow->dst;
    // this->host->sender = this->match_sender;
    // }
    // if(this->proc_accept_evt == NULL) {
    //     this->proc_accept_evt = new ProcssAcceptEvent(get_current_time() + params.ctrl_pkt_rtt / 4, this->host);
    // }
}

void PimEpoch::send_all_req() {
    if(this->match_sender!= NULL)
        return;
    for(auto i = this->host->src_to_flows.begin(); i != this->host->src_to_flows.end();) {
        // if(this->receiver_state[i->first] == false) {  
        //     i++;
        //     continue;
        // }
        PimFlow* best_flow = NULL;
        std::queue<PimFlow*> flows_tried;
        while(!i->second.empty()) {
            best_flow = i->second.top();
            if(best_flow->finished_at_receiver) {
                best_flow = NULL;
                i->second.pop();
            } else if (best_flow->redundancy_ctrl_timeout > get_current_time()) {
                flows_tried.push(best_flow);
                i->second.pop();
                best_flow = NULL;
            } else {
                break;
            }
        }
        if(best_flow != NULL) {
            if(debug_flow(best_flow->id) || debug_host(this->host->id)) {
                std::cout << "flow " << best_flow->id << " dst " << this->host->id << " send_req to src " << best_flow->src->id << std::endl;
            }
            best_flow->send_req(this->iter, this->epoch);
        }
        while(!flows_tried.empty()) {
            i->second.push(flows_tried.front());
            flows_tried.pop();
        }
        if(i->second.empty()) {
            i = this->host->src_to_flows.erase(i);
        } else {
            i++;
        }
    }
}
void PimEpoch::handle_all_req() {
    if(this->match_receiver != NULL)
        return;
    assert(this->match_receiver == NULL);
    uint32_t index = 0;
    if(debug_host(this->host->id)) {
        std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " handle of all rts dst:" << this->host->id << std::endl; 
    }
    if(params.pim_select_min_iters > 0 && this->iter <= params.pim_select_min_iters) {
        if(this->min_req.f != NULL) {
            assert(min_req.f != NULL);
            min_req.f->send_grants(this->iter, this->epoch, min_req.remaining_sz, this->host->receiver == NULL);
        }
    }
    else {
        while(!this->req_q.empty()) {
            index = rand() % this->req_q.size();
            if(this->req_q[index].iter != this->iter) {
                assert(this->req_q[index].iter < this->iter);
                this->req_q.erase(this->req_q.begin() + index);
            } else {
                break;
            }
        }
        for(uint32_t i = 0; i < this->req_q.size(); i++) {
            if (i == index && this->match_receiver == NULL) {
                // send Grants
                // this->rts_q[i].f->send_grants(this->iter, this->epoch, false);
                this->req_q[i].f->send_grants(this->iter, this->epoch, this->req_q[index].remaining_sz, this->host->receiver == NULL);
            } else {
                // send offerPkt
                // this->rts_q[i].f->send_offer_pkt(this->iter, this->epoch, this->match_sender == NULL);
            }
        }
    }
}
void PimEpoch::handle_all_grants() {
    if(this->match_sender != NULL)
        return;
    assert(this->match_sender == NULL);
    assert(this->proc_receiver_iter_evt == NULL);
    if(this->grants_q.empty())
        return;
    int min_size = INT_MAX;
    PimFlow *f = NULL;
    PIM_Grants *grant = NULL;
    if(params.pim_select_min_iters > 0 && this->iter <= params.pim_select_min_iters) {
        if(this->min_grant.f != NULL) {
            f = this->min_grant.f;
            grant = &(this->min_grant);
        }
    } else {
        while(!this->grants_q.empty()) {
            int index = rand() % this->grants_q.size();
            if(this->grants_q[index].iter != this->iter) {
                assert(this->grants_q[index].iter < this->iter);
                this->grants_q.erase(this->grants_q.begin() + index);
            } else {
                f = this->grants_q[index].f;
                grant = &this->grants_q[index];
                break;
            }
        }
    }
    if(f != NULL) {
        f->send_accept_pkt(this->iter, this->epoch);
        if(debug_host(f->dst->id)) {
            std::cout << get_current_time() << " epoch " << this->epoch << " iter " << this->iter << " dst " << this->host->id << " accept " << f->src->id << std::endl;
        }
        this->match_sender = (PimHost*)(f->src);
        if(grant->prompt && this->host->sender == NULL && this->host->cur_epoch == this->epoch - 1) {
            this->host->sender = this->match_sender;
            this->prompt = true;
            if(this->host->token_send_evt != NULL && this->host->token_send_evt->is_timeout_evt) {
                this->host->token_send_evt->cancelled = true;
                this->host->token_send_evt = NULL;
            }
            if(this->host->token_send_evt == NULL) {
                this->host->schedule_token_proc_evt(0, false);
            }
        }
    }

    // for pipeline
    // if(this->iter > params.pim_iter_limit && this->host->cur_epoch == this->epoch) {
    //     // corner case
    //     this->host->sender = this->match_sender;
    //     if(this->host->token_send_evt != NULL && this->host->token_send_evt->is_timeout_evt) {
    //         this->host->token_send_evt->cancelled = true;
    //         this->host->token_send_evt = NULL;
    //     }
    //     if(this->host->token_send_evt == NULL) {
    //         this->host->schedule_token_proc_evt(0, false);
    //     }
    // }
            // non-pipeline
            // this->host->receiver = this->match_receiver;
            // if(this->host->host_proc_event != NULL && this->host->host_proc_event->is_timeout) {
            //     this->host->host_proc_event->cancelled = true;
            //     this->host->host_proc_event = NULL;
            // }
            // if(this->host->host_proc_event == NULL) {
            //     this->host->schedule_host_proc_evt();
            // }

}
void PimEpoch::schedule_sender_iter_evt() {
    assert(this->proc_sender_iter_evt == NULL);
    if(this->iter > params.pim_iter_limit) {
        // this->host->sender = this->match_sender;
        return;
    }
    this->handle_all_req();
    this->proc_sender_iter_evt = new ProcessSenderIterEvent(get_current_time() + params.pim_iter_epoch, this);
    add_to_event_queue(this->proc_sender_iter_evt);
}



void PimEpoch::schedule_receiver_iter_evt() {
    assert(this->proc_receiver_iter_evt == NULL);

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
        if(this->host->token_send_evt != NULL && this->host->token_send_evt->is_timeout_evt) {
            this->host->token_send_evt->cancelled = true;
            this->host->token_send_evt = NULL;
        }
        if(this->host->sender != NULL && this->host->token_send_evt == NULL) {
            this->host->schedule_token_proc_evt(0, false);
        }
        return;
    }
    this->send_all_req();
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
    this->token_send_evt = NULL;
    // for(uint32_t i = 0; i < params.num_hosts; i++) {
    //     this->receiver_state.push_back(true);
    // }
    this->cur_epoch = -1;
    this->hold_on = 0;
    this->token_send_evt = NULL;
    total_token_schd_evt_count = 0;

}
void PimHost::schedule_token_proc_evt(double time, bool is_timeout)
{
    assert(this->token_send_evt == NULL);
    this->token_send_evt = new PimTokenProcessingEvent(get_current_time() + time + INFINITESIMAL_TIME, this, is_timeout);
    add_to_event_queue(this->token_send_evt);
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
    this->epochs[epoch].proc_receiver_iter_evt = new ProcessReceiverIterEvent(time, &this->epochs[epoch]);
    this->epochs[epoch].proc_sender_iter_evt = new ProcessSenderIterEvent(time + params.pim_iter_epoch / 2, &this->epochs[epoch]);
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

PimFlow* PimHost::get_top_unfinish_flow(uint32_t src_id) {
    PimFlow* best_flow = NULL;
    std::queue<PimFlow*> flows_tried;
    if(this->src_to_flows.find(src_id) == this->src_to_flows.end())
        return best_flow;
    while (!this->src_to_flows[src_id].empty()) {
        best_flow =  this->src_to_flows[src_id].top();
        if(best_flow->finished_at_receiver) {
            best_flow = NULL;
            this->src_to_flows[src_id].pop();
        } else if (best_flow->redundancy_ctrl_timeout > get_current_time()) {
            flows_tried.push(best_flow);
            this->src_to_flows[src_id].pop();
            best_flow = NULL;
        } else {
            break;
        }
    }
    while(!flows_tried.empty()) {
        this->src_to_flows[src_id].push(flows_tried.front());
        flows_tried.pop();
    }
    if(this->src_to_flows[src_id].empty()){
        this->src_to_flows.erase(src_id);
    }
    return best_flow;
}

void PimHost::start_flow(PimFlow* f) {
    if(debug_flow(f->id) || debug_host(this->id)) {
        std::cout 
            << get_current_time() 
            << " flow " << f->id 
            << " src " << this->id
             <<"\n";
    }
    f->assign_init_token();
    this->active_sending_flows.push(f);
    if(!f->tokens.empty()) {
        if (((SchedulingHost*) this)->host_proc_event == NULL) {
            this->schedule_host_proc_evt();
        }
    }
    f->sending_rts();
    if(!f->tokens.empty()) {
        if(this->host_proc_event != NULL && this->host_proc_event->is_timeout) {
            this->host_proc_event->cancelled = true;
            this->host_proc_event = NULL;
        }
        if(this->host_proc_event == NULL) {
            this->schedule_host_proc_evt();
        }
    }
    // this->dst_to_flows[f->dst->id].push(f);
}

void PimHost::receive_rts(FlowRTS* pkt) {
    if(debug_flow(pkt->flow->id))
            std::cout << get_current_time() << " flow " << pkt->flow->id << " "<< pkt->size_in_pkt <<  " received rts\n";
    ((PimFlow*)pkt->flow)->rts_received = true;
    this->src_to_flows[pkt->flow->src->id].push((PimFlow*)pkt->flow);
    if(pkt->size_in_pkt > params.token_initial) {
        // if(debug_host(id)) {
        //     std::cout << "push flow " << pkt->flow->id << std::endl;
        // }
        if(this->sender != NULL && 
            this->sender->id == pkt->flow->src->id && 
            this->src_to_flows[pkt->flow->src->id].top()->id == pkt->flow->id) {
            if (this->token_send_evt != NULL && this->token_send_evt->is_timeout_evt) {
                this->token_send_evt->cancelled = true;
                this->token_send_evt = NULL;
            }
            if(this->token_send_evt == NULL){
                this->schedule_token_proc_evt(0, false);
            }
        }
    } else {
        ((PimFlow*)pkt->flow)->receive_short_flow();
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
void PimHost::receive_token(PIMToken* pkt) {
    // To Do: need a queue to maintain current active sending flows;
    if(debug_flow(pkt->flow->id)) {
        std::cout << get_current_time() << " receive token " << pkt->data_seq_num << " timeout: " << get_current_time() + pkt->ttl  << " queue delay:" << pkt->total_queuing_delay<< std::endl;
    }
    auto f = (PimFlow*)pkt->flow;
    Pim_Token* t = new Pim_Token();
    // if(!f->tokens.empty()) {
    //     t->timeout = fto->back().timeout + get_full_pkt_tran_delay(1500) - pkt->ttl;
    // }
    // token is never expired
    t->timeout = get_current_time() + pkt->ttl;
    t->seq_num = pkt->token_seq_num;
    t->data_seq_num = pkt->data_seq_num;
    f->tokens.push_back(t);
    f->remaining_pkts_at_sender = pkt->remaining_sz;
    if(this->host_proc_event == NULL) {
        this->schedule_host_proc_evt();
    }
}

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
    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        std::queue<PimFlow*> flows_tried;
        while(!this->active_sending_flows.empty()) {
            auto flow = this->active_sending_flows.top();
            this->active_sending_flows.pop();
            if(flow->finished) {
                continue;
            }
            flows_tried.push(flow);
            if(debug_flow(flow->id)) {
                std::cout << get_current_time() << " try to send data "<< std::endl;
            }
            if(flow->has_token()) {
                flow->send_pending_data();
                break;
            }
        }
        while(!flows_tried.empty()) {
            this->active_sending_flows.push(flows_tried.front());
            flows_tried.pop();
        }
    }
}

void PimHost::send_token() {
    assert(this->token_send_evt == NULL);
    bool token_sent = false;
    this->total_token_schd_evt_count++;
    double closet_timeout = 999999;
    std::queue<PimFlow*> flows_tried;
    if(TOKEN_HOLD && this->hold_on > 0){
        hold_on--;
        token_sent = true;
    }
    PimFlow* f = NULL;
    if(this->sender!= NULL && !token_sent) {
        f = this->get_top_unfinish_flow(this->sender->id);
    }
    if(f != NULL) {
        // PimFlow* best_short_flow = NULL;
        // if(!this->active_short_flows.empty()) {
        //     best_short_flow = this->active_short_flows.top();
        // }
        // if(flow_compare(best_large_flow, best_short_flow)) {
        //     f = this->active_short_flows.top();
        //     this->active_short_flows.pop();
        //     // if(debug_flow(f->id)) {
        //     //     std::cout << get_current_time() << " pop flow " << f->id  << "\n";
        //     // }
        // } else {
        //     f = best_large_flow;
        //     best_large_flow = NULL;
        // }
        // if(debug_host(this->id)) {
        //     std::cout << "try to send token" << std::endl;
        // }
        // probably can do better here
        // if(f->finished_at_receiver) {
        //     continue;
        // }
        // if(f->is_small_flow()) {
        //     flows_tried.push(f);
        // }
        //not yet timed out, shouldn't send
        // if(f->redundancy_ctrl_timeout > get_current_time()){
        //     if(debug_flow(f->id)) {
        //         std::cout << get_current_time() << " redundancy_ctrl_timeout has not met " << f->id  << "\n";
        //     }
        //     if(f->redundancy_ctrl_timeout < closet_timeout)
        //     {
        //         closet_timeout = f->redundancy_ctrl_timeout;
        //     }
        // }
        //ok to send
        // else
        // {
            //just timeout, reset timeout state
            if(f->redundancy_ctrl_timeout > 0)
            {
                if(debug_flow(f->id)) {
                    std::cout << get_current_time() << " redundancy_ctrl_timeout met" << f->id  << "\n";
                }
                f->redundancy_ctrl_timeout = -1;
                f->token_goal += f->remaining_pkts();
            }

            if(f->token_gap() > params.token_window)
            {
                if(get_current_time() >= f->latest_token_sent_time + params.token_window_timeout) {
                    if(debug_host(this->id)) {
                        std::cout << get_current_time() << " host " << this->id << " relax token gap for flow " << f->id << std::endl;
                    }
                    f->relax_token_gap();
                }
                else{
                    if(f->latest_token_sent_time + params.token_window_timeout < closet_timeout)
                    {
                        if(debug_host(this->id)) {
                            std::cout << get_current_time() << " host " << this->id << " token_window full wait for timeout for flow " << f->id << std::endl;
                        }
                        closet_timeout = f->latest_token_sent_time + params.token_window_timeout;
                    }
                }

            }
            if(f->token_gap() <= params.token_window)
            {
                if(debug_host(id)) {
                        std::cout << get_current_time() << " sending tokens for flow " << f->id << std::endl;   
                }
                auto next_data_seq = f->get_next_token_seq_num();
                f->send_token_pkt();
                token_sent = true;
                // this->token_hist.push_back(this->recv_flow->id);
                if(next_data_seq >= f->get_next_token_seq_num()) {
                    // if(!f->first_loop) {
                    //     f->first_loop = true;
                    // } else {
                        if(debug_flow(f->id)) {
                            std::cout << get_current_time() << " redundancy_ctrl_timeout set up " << f->id << " timeout value: " << f->redundancy_ctrl_timeout << "\n";
                        }
                        f->redundancy_ctrl_timeout = get_current_time() + params.token_resend_timeout;
                    // }
                }
            }
    }
    // }

    // while(!flows_tried.empty()) {
    //     this->active_short_flows.push(flows_tried.front());
    //     flows_tried.pop();
    // }

    if(token_sent)// pkt sent
    {
        this->schedule_token_proc_evt(params.get_full_pkt_tran_delay(1500/* + 40*/), false);
    }
    else if(closet_timeout < 999999) //has unsend flow, but its within timeout
    {
        assert(closet_timeout > get_current_time());
        this->schedule_token_proc_evt(closet_timeout - get_current_time(), true);
    }

}

void PimHost::flow_finish_at_receiver(Packet* pkt) {
    if(debug_host(this->id)) {
        std::cout << get_current_time () << " flow finish at receiver " <<  pkt->flow->id << std::endl;
    }
    if (((PimFlow*)pkt->flow)->finished_at_receiver)
        return;
    ((PimFlow*)pkt->flow)->finished_at_receiver = true;
}