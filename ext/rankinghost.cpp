#include "assert.h"

#include "../coresim/event.h"
#include "../coresim/topology.h"
#include "../coresim/debug.h"

#include "factory.h"
#include "rankingflow.h"
#include "rankinghost.h"
#include "rankingTopology.h"

#include "../run/params.h"
#include "custompriorityqueue.h"

#include <set>
extern uint32_t total_finished_flows;
extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern Topology *topology;


TokenProcessingEvent::TokenProcessingEvent(double time, RankingHost *h, bool is_timeout)
    : Event(TOKEN_PROCESSING, time) {
        this->host = h;
        this->is_timeout_evt = is_timeout;
    }

TokenProcessingEvent::~TokenProcessingEvent() {
    if (host->token_send_evt == this) {
        host->token_send_evt = NULL;
    }
}

void TokenProcessingEvent::process_event() {
    this->host->token_send_evt = NULL;
    this->host->send_token();
}


RankingHostWakeupProcessingEvent::RankingHostWakeupProcessingEvent(double time, RankingHost *h)
    : Event(RANKINGHOST_WAKEUP_PROCESSING, time) {
        this->host = h;
    }

RankingHostWakeupProcessingEvent::~RankingHostWakeupProcessingEvent() {
    if (host->wakeup_evt == this) {
        host->wakeup_evt = NULL;
    }
}

void RankingHostWakeupProcessingEvent::process_event() {
    this->host->wakeup_evt = NULL;
    this->host->wakeup();
}


// Comparator
ListSrcsComparator::ListSrcsComparator() {
    for (uint i = 0; i < params.num_hosts; i++){
        this->ranking.push_back(double(rand()) / RAND_MAX);
    }
}

void ListSrcsComparator::reset_ranking() {
    this->ranking.clear();
    for (uint i = 0; i < params.num_hosts; i++) {
        this->ranking.push_back(double(rand()) / RAND_MAX);
    }
}
bool ListSrcsComparator::operator() (ListSrcs* a, ListSrcs* b) {
    return this->ranking[a->dst->id] > this->ranking[b->dst->id];
}

bool RankingFlowComparator::operator() (RankingFlow* a, RankingFlow* b){
    if (a->remaining_pkts_at_sender > b->remaining_pkts_at_sender)
        return true;
    else if (a->remaining_pkts_at_sender == b->remaining_pkts_at_sender)
        return a->start_time > b->start_time;
    else
        return false;
}
bool RankingFlowComparatorAtReceiver::operator() (RankingFlow* a, RankingFlow* b){
    if(a->remaining_pkts() - a->token_gap() > b->remaining_pkts() - b->token_gap())
        return true;
    else if (a->remaining_pkts() - a->token_gap() == b->remaining_pkts() - b->token_gap())
        return a->start_time > b->start_time; //TODO: this is cheating. but not a big problem
    else
        return false;
}

RankingHost::RankingHost(uint32_t id, double rate, uint32_t queue_type) : SchedulingHost(id, rate, queue_type) {

    this->host_proc_event = NULL;
    this->token_send_evt = NULL;
    this->wakeup_evt = NULL;
    this->host_type = RANKING_HOST;
    this->total_token_schd_evt_count = 0;
    this->hold_on = 0;
    this->active_src_from_arbiter = NULL;
    this->fake_flow = NULL;
}

// ---- Sender -------
void RankingHost::start_ranking_flow(RankingFlow* f) {
    f->assign_init_token();
    this->active_sending_flows.push(f);
    if(!f->tokens.empty()) {
        if (((SchedulingHost*) this)->host_proc_event == NULL) {
            this->schedule_host_proc_evt();
        }
    }
    f->sending_rts();
}
void RankingHost::receive_token(RankingToken* pkt) {
    // To Do: need a queue to maintain current active sending flows;
    auto f = (RankingFlow*)pkt->flow;
    Token* t = new Token();
    t->timeout = get_current_time() + pkt->ttl;
    t->seq_num = pkt->token_seq_num;
    t->data_seq_num = pkt->data_seq_num;
    f->tokens.push_back(t);
    f->remaining_pkts_at_sender = pkt->remaining_sz;
    if(this->host_proc_event == NULL) {
        this->schedule_host_proc_evt();
    }
}

void RankingHost::schedule_host_proc_evt(){
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

void RankingHost::send(){
    // To Do: need a queue to maintain current active sending flows;

    assert(this->host_proc_event == NULL);
    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        std::queue<RankingFlow*> flows_tried;
        while(!this->active_sending_flows.empty()) {
            auto flow = this->active_sending_flows.top();
            this->active_sending_flows.pop();
            if(flow->finished) {
                continue;
            }
            flows_tried.push(flow);
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

// ---- Receiver -----
void RankingHost::schedule_token_proc_evt(double time, bool is_timeout)
{
    assert(this->token_send_evt == NULL);
    this->token_send_evt = new TokenProcessingEvent(get_current_time() + time + INFINITESIMAL_TIME, this, is_timeout);
    add_to_event_queue(this->token_send_evt);
}

void RankingHost::receive_rts(RankingRTS* pkt) {
    if(debug_flow(pkt->flow->id))
            std::cout << get_current_time() << " flow " << pkt->flow->id << " "<< pkt->size_in_pkt <<  " received rts\n";
    ((RankingFlow*)pkt->flow)->rts_received = true;
    if(pkt->size_in_pkt > params.token_initial) {
        this->src_to_flows[pkt->flow->src->id].push((RankingFlow*)pkt->flow);
        if(this->active_src_from_arbiter != NULL && 
            this->active_src_from_arbiter->id == pkt->flow->src->id && 
            this->src_to_flows[pkt->flow->src->id].top()->id == pkt->flow->id) {
            if (this->token_send_evt != NULL && this->token_send_evt->is_timeout_evt) {
                this->token_send_evt->cancelled = true;
                this->token_send_evt = NULL;
            }
            if(this->token_send_evt == NULL){
                this->schedule_token_proc_evt(0, false);
            }
        }
        if(this->active_src_from_arbiter == NULL) {
            // send list Srcs
            send_listSrcs();
            if(this->wakeup_evt != NULL) {
                this->wakeup_evt->cancelled = true;
            }
            this->wakeup_evt = NULL;
            schedule_wakeup_event();
            if(debug_flow(pkt->flow->id))
                std::cout << get_current_time() << " flow " << this->id << " schedule wake up" << std::endl;
        }
    } else {
        ((RankingFlow*)pkt->flow)->receive_short_flow();
    }
}

void RankingHost::receive_nrts(RankingNRTS* pkt) {
    // std::cout << pkt->flow->id << std::endl;
    // std::cout << this->id << std::endl;
    if((RankingHost*)(pkt->flow->src) != this->active_src_from_arbiter) {
        return;
    }
    if(pkt->flow->size_in_pkt <= params.token_initial) {
        return;
    }
    assert(pkt->flow->src->id == this->active_src_from_arbiter->id);
    std::queue<RankingFlow*> flows_tried;
    auto src_id = this->active_src_from_arbiter->id;
    while(1) {
        if(this->src_to_flows[src_id].top() == (RankingFlow*)pkt->flow) {
            this->src_to_flows[src_id].pop();
            break;
        }
        flows_tried.push(this->src_to_flows[src_id].top());
        this->src_to_flows[src_id].pop();
    }
    while(!flows_tried.empty()) {
        this->src_to_flows[src_id].push(flows_tried.front());
        flows_tried.pop();
    }
    if(this->src_to_flows[src_id].empty()) {
        this->src_to_flows.erase(src_id);
    }
    this->active_src_from_arbiter = NULL;
    ((RankingFlow*)pkt->flow)->sending_nrts_to_arbiter();
    if(!this->src_to_flows.empty()) {
        this->send_listSrcs();
        assert(this->wakeup_evt == NULL);
        if(this->wakeup_evt == NULL) {
            schedule_wakeup_event();
        }
    }
}
void RankingHost::send_listSrcs() {
    if(debug_host(this->id)) {
        for (auto i = this->src_to_flows.begin(); i != this->src_to_flows.end(); i++) {
            if (!i->second.empty()) {
            std::cout << get_current_time() << " src " <<  i->first << "\n";
            }
        }
    }
    std::list<uint32_t> srcs;
    for (auto i = this->src_to_flows.begin(); i != this->src_to_flows.end(); i++) {
        if(!i->second.empty()) {
            srcs.push_back(i->first);
        }
    }
    if(srcs.empty())
        return;
    RankingListSrcs* listSrcs = new RankingListSrcs(this->fake_flow,
     this, dynamic_cast<RankingTopology*>(topology)->arbiter , this, srcs);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), listSrcs, this->queue));
} 

void RankingHost::schedule_wakeup_event() {
    assert(this->wakeup_evt == NULL);
    if(debug_host(this->id)) {
        std::cout << get_current_time() << " next wake up"  << get_current_time() + params.rankinghost_idle_timeout / 1000000.0 << std::endl;
    }
    this->wakeup_evt = new RankingHostWakeupProcessingEvent(get_current_time() + params.rankinghost_idle_timeout / 1000000.0, this);
    add_to_event_queue(this->wakeup_evt);
}

void RankingHost::wakeup() {
    assert(this->wakeup_evt == NULL);
    if(!this->src_to_flows.empty()) {
        this->send_listSrcs();
        this->schedule_wakeup_event();
    }
}
void RankingHost::send_token() {
    assert(this->token_send_evt == NULL);
    bool token_sent = false;
    this->total_token_schd_evt_count++;
    double closet_timeout = 999999;
    std::queue<RankingFlow*> flows_tried;
    if(TOKEN_HOLD && this->hold_on > 0){
        hold_on--;
        token_sent = true;
    }
    RankingFlow* best_large_flow = NULL;
    if(this->active_src_from_arbiter != NULL) {
        if (!this->src_to_flows[this->active_src_from_arbiter->id].empty()) {
            best_large_flow =  this->src_to_flows[this->active_src_from_arbiter->id].top();
        }
    }
    while(!token_sent) {
        if (this->active_receiving_flows.empty() && best_large_flow == NULL) {
            break;
        }
        RankingFlow* f = NULL;
        if(best_large_flow != NULL && !this->active_receiving_flows.empty() && 
         this->active_receiving_flows.top()->remaining_pkts() > best_large_flow->remaining_pkts()) {
            f = best_large_flow;
            best_large_flow = NULL;
        } else if (this->active_receiving_flows.empty()){
            f = best_large_flow;
            best_large_flow = NULL;
        } else {
            f = this->active_receiving_flows.top();
            this->active_receiving_flows.pop();
        }
        // probably can do better here
        if(f->finished_at_receiver) {
            continue;
        }
        if(f->size_in_pkt <= params.token_initial) {
            flows_tried.push(f);
        }
        //not yet timed out, shouldn't send
        if(f->redundancy_ctrl_timeout > get_current_time()){
            if(debug_flow(f->id)) {
                std::cout << get_current_time() << " timeout not occur " << f->id  << "\n";
            }
            if(f->redundancy_ctrl_timeout < closet_timeout)
            {
                closet_timeout = f->redundancy_ctrl_timeout;
            }
        }
        //ok to send
        else
        {
            //just timeout, reset timeout state
            if(f->redundancy_ctrl_timeout > 0)
            {
                f->redundancy_ctrl_timeout = -1;
                f->token_goal += f->remaining_pkts();
                if(debug_flow(f->id)) {
                    std::cout << get_current_time() << " redundancy_ctrl_timeout" << f->id  << "\n";
                }
            }

            if(f->token_gap() > params.token_window)
            {
                if(get_current_time() >= f->latest_token_sent_time + params.token_window_timeout * params.get_full_pkt_tran_delay()) {
                    f->relax_token_gap();
                    if(debug_host(this->id)) {
                        std::cout << get_current_time() << " host " << this->id << " relax token gap for flow " << f->id << std::endl;
                    }
                }
                else{
                    if(f->latest_token_sent_time + params.token_window_timeout * params.get_full_pkt_tran_delay() < closet_timeout)
                    {
                        closet_timeout = f->latest_token_sent_time + params.token_window_timeout * params.get_full_pkt_tran_delay();
                        if(debug_host(this->id)) {
                            std::cout << get_current_time() << " host " << this->id << " token_window full wait for timeout for flow " << f->id << std::endl;
                        }
                    }
                }

            }
            if(f->token_gap() <= params.token_window)
            {
                f->send_token_pkt();
                token_sent = true;
                // this->token_hist.push_back(this->recv_flow->id);
                if(f->token_count == f->token_goal){
                    f->redundancy_ctrl_timeout = get_current_time() + params.token_resend_timeout * params.get_full_pkt_tran_delay();
                    if(debug_flow(f->id)) {
                        std::cout << get_current_time() << " redundancy_ctrl_timeout set up" << f->id << "timeout value: " << f->redundancy_ctrl_timeout << "\n";
                    }
                }
            }
        }
    }
    while(!flows_tried.empty()) {
        this->active_receiving_flows.push(flows_tried.front());
        flows_tried.pop();
    }

    if(token_sent)// pkt sent
    {
        this->schedule_token_proc_evt(params.get_full_pkt_tran_delay(1500/* + 40*/), false);
    }
    else if(closet_timeout < 999999) //has unsend flow, but its within timeout
    {
        assert(closet_timeout > get_current_time());
        this->schedule_token_proc_evt(closet_timeout - get_current_time(), true);
    }
    else{
        //do nothing, no unfinished flow
    }


}

void RankingHost::receive_gosrc(RankingGoSrc* pkt) {
    if(debug_host(this->id)) {
        std::cout << get_current_time() << " receive GoSRC for dst " << this->id << std::endl; 
    }
    // find the minimum size of the flow for a source;
    this->active_src_from_arbiter = (RankingHost*)this->src_to_flows[pkt->src_id].top()->src;
    //cancel wake up event
    if(this->wakeup_evt != NULL) {
        this->wakeup_evt->cancelled = true;
        this->wakeup_evt = NULL;
    }
    // schedule sending token event;
    if (this->token_send_evt != NULL && this->token_send_evt->is_timeout_evt) {
        this->token_send_evt->cancelled = true;
        this->token_send_evt = NULL;
    }
    if(this->token_send_evt == NULL){
        this->schedule_token_proc_evt(0, false);
    }
}

// ---- Ranking Arbiter

RankingArbiter::RankingArbiter(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, RANKING_ARBITER) {
    this->src_state = std::vector<bool>(params.num_hosts, true);
    this->dst_state = std::vector<bool>(params.num_hosts, true);
    this->arbiter_proc_evt = NULL;
    this->last_reset_ranking_time = 0;
}

void RankingArbiter::start_arbiter() {
    this->schedule_proc_evt(1.0);
}


void RankingArbiter::schedule_proc_evt(double time) {
    assert(this->arbiter_proc_evt == NULL);
    this->arbiter_proc_evt = new RankingArbiterProcessingEvent(time, this);
    add_to_event_queue(this->arbiter_proc_evt);
}

void RankingArbiter::schedule_epoch() {
    if (total_finished_flows >= params.num_flows_to_run)
        return;
    // std::cout << get_current_time() <<  " empty the pending queue " << std::endl;
    while(!this->pending_q.empty()) {
        auto request = this->pending_q.top();
        this->pending_q.pop();
        if(this->dst_state[request->dst->id] == false) {
            delete request;
            continue;
        }
        if(debug_host(request->dst->id)) {
            for(auto i = request->listSrcs.begin(); i != request->listSrcs.end(); i++) {
                std::cout << "src " << (*i) << "state " << this->src_state[(*i)] << std::endl;
            }
        }
        for(auto i = request->listSrcs.begin(); i != request->listSrcs.end(); i++) {
            // if(debug_host(request->dst->id)) {
            //     std::cout << "src " << (*i) << "state " << this->src_state[(*i)] << std::endl;
            // }
            if(this->src_state[(*i)]) {
                this->src_state[(*i)] = false;
                this->dst_state[request->dst->id] = false;
                // send GoSRC packet
                ((RankingHost*)(request->dst))->fake_flow->sending_gosrc(*i);
                break;
            }
        }
        delete request;
    }
    if(get_current_time() > this->last_reset_ranking_time + params.ranking_reset_epoch) {
        this->pending_q.comp.reset_ranking();
        this->last_reset_ranking_time = get_current_time();
    }
    //schedule next arbiter proc evt
    this->schedule_proc_evt(get_current_time() + params.ranking_epoch_time);
}

void RankingArbiter::receive_listsrcs(RankingListSrcs* pkt) {
    if(debug_host(pkt->rts_dst->id))
        std::cout << get_current_time() << " Arbiter: receive listsrcs " << pkt->rts_dst->id << std::endl;
    auto listSrcs = new ListSrcs();
    listSrcs->dst = pkt->rts_dst;
    listSrcs->listSrcs = pkt->listSrcs;
    this->pending_q.push(listSrcs);
}

void RankingArbiter::receive_nrts(RankingNRTS* pkt) {
    assert(this->src_state[pkt->flow->src->id] == false);
    assert(this->dst_state[pkt->flow->dst->id] == false);

    this->src_state[pkt->flow->src->id] = true;
    this->dst_state[pkt->flow->dst->id] = true;
    if(debug_flow(pkt->flow->id)) {
        std::cout << get_current_time () << " arbiter receive nrts of flow " << pkt->flow->id;
        std::cout << " src " << pkt->flow->src->id << " state " <<  this->src_state[pkt->flow->src->id] << std::endl;
    }
}