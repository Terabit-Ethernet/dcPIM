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

#include <algorithm>    // std::sort
#include <set>
#include <climits>

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
    if(params.deadline && params.schedule_by_deadline) {
        return a->deadline > b->deadline;
    }
    if(a->remaining_pkts() - a->token_gap() > b->remaining_pkts() - b->token_gap())
        return true;
    else if (a->remaining_pkts() - a->token_gap() == b->remaining_pkts() - b->token_gap())
        return a->start_time > b->start_time; //TODO: this is cheating. but not a big problem
    else
        return false;
}
bool RankingShortFlowComparatorAtReceiver::operator() (RankingFlow* a, RankingFlow* b){
    if(params.deadline && params.schedule_by_deadline) {
        return a->deadline > b->deadline;
    }
    if(a->remaining_pkts() > b->remaining_pkts())
        return true;
    else if (a->remaining_pkts() == b->remaining_pkts())
        return a->start_time > b->start_time; //TODO: this is cheating. but not a big problem
    else
        return false;
}
// bool RankingFlowComparatorAtReceiverForP1::operator() (RankingFlow* a, RankingFlow* b){
//     if(a->token_count > 0)
//         return false;
//     if(b->token_count > 0)
//         return true;
//     if(a->remaining_pkts() - a->token_gap() > b->remaining_pkts() - b->token_gap())
//         return true;
//     else if (a->remaining_pkts() - a->token_gap() == b->remaining_pkts() - b->token_gap())
//         return a->start_time > b->start_time; //TODO: this is cheating. but not a big problem
//     else
//         return false;
// }

bool RankingHost::flow_compare(RankingFlow* long_flow, RankingFlow* short_flow) {
    if(long_flow == NULL)
        return true;
    if(short_flow == NULL)
        return false;
    if(params.deadline && params.schedule_by_deadline) {
        return long_flow->deadline > short_flow->deadline;
    }
    if(long_flow->remaining_pkts() > short_flow->remaining_pkts())
        return true;
    else if (long_flow->remaining_pkts() == short_flow->remaining_pkts())
        return long_flow->start_time > short_flow->start_time; //TODO: this is cheating. but not a big problem
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
    this->fake_flow = NULL;
}

// Statistics 

void RankingHost::print_max_min_fairness() {
    int max = 0;
    int min = INT_MAX;
    for (auto i = this->src_to_pkts.begin(); i != this->src_to_pkts.end(); i++) {
        if(i->second > max) {
            max = i->second;
        }
        if(i->second < min) {
            min = i->second;
        }
    }
    if(min == 0) {
        std::cout << this->id << " " << this->src_to_pkts.size() << " " << 0 << std::endl;
    }
    else {
        std::cout << this->id << " "  << this->src_to_pkts.size() << " " << (double)max / min << std::endl;
    }
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
    t->ranking_round = pkt->ranking_round;
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
RankingFlow* RankingHost::get_top_unfinish_flow(uint32_t src_id) {
    RankingFlow* best_large_flow = NULL;
    if(this->src_to_flows.find(src_id) == this->src_to_flows.end())
        return best_large_flow;
    while (!this->src_to_flows[src_id].empty()) {
        best_large_flow =  this->src_to_flows[src_id].top();
        if(best_large_flow->finished_at_receiver) {
            best_large_flow = NULL;
            this->src_to_flows[src_id].pop();
        } else {
            break;
        }
    }
    if(best_large_flow == NULL){
        assert(this->src_to_flows[src_id].empty());
        this->src_to_flows.erase(src_id);
    }
    return best_large_flow;
}
void RankingHost::receive_rts(RankingRTS* pkt) {
    if(debug_flow(pkt->flow->id))
            std::cout << get_current_time() << " flow " << pkt->flow->id << " "<< pkt->size_in_pkt <<  " received rts\n";
    ((RankingFlow*)pkt->flow)->rts_received = true;
    if(pkt->size_in_pkt > params.token_initial) {
        if(debug_host(id)) {
            std::cout << "push flow " << pkt->flow->id << std::endl;
        }
        this->src_to_flows[pkt->flow->src->id].push((RankingFlow*)pkt->flow);
        if(this->gosrc_info.src != NULL && 
            this->gosrc_info.src->id == pkt->flow->src->id && 
            this->src_to_flows[pkt->flow->src->id].top()->id == pkt->flow->id) {
            if (this->token_send_evt != NULL && this->token_send_evt->is_timeout_evt) {
                this->token_send_evt->cancelled = true;
                this->token_send_evt = NULL;
            }
            if(this->token_send_evt == NULL){
                this->schedule_token_proc_evt(0, false);
            }
        }
        if(this->gosrc_info.src == NULL) {
            // send list Srcs
            if(debug_host(id)) {
                std::cout << get_current_time() << "sending listSRC for new flow " <<pkt->flow->id << std::endl;
            }
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

void RankingHost::flow_finish_at_receiver(Packet* pkt) {
    if(debug_flow(pkt->flow->id)) {
        std::cout << get_current_time () << " flow finish at receiver " <<  pkt->flow->id << std::endl;
    }
    if(pkt->flow->size_in_pkt <= params.token_initial) {
        return;
    }
    if(this->gosrc_info.round == pkt->ranking_round) {
        assert(this->wakeup_evt != NULL);
        this->gosrc_info.reset();
    } else if (this->gosrc_info.src == (RankingHost*)pkt->flow->src) {
        auto best_large_flow = this->get_top_unfinish_flow(pkt->flow->src->id);
        if(best_large_flow == NULL) {
            if(this->gosrc_info.send_nrts == false) {
                (this->fake_flow)->sending_nrts_to_arbiter(pkt->flow->src->id, pkt->flow->dst->id);
                assert(this->wakeup_evt == NULL);
                this->wakeup();
            }
            this->gosrc_info.reset();
        }
    }
}
void RankingHost::send_listSrcs() {
    std::vector<std::pair<int, int>> vect;
    std::list<uint32_t> srcs;
    for (auto i = this->src_to_flows.begin(); i != this->src_to_flows.end();) {
        while(!i->second.empty()) {
            if(i->second.top()->finished_at_receiver) {
                i->second.pop();
            } else {
                break;
            }
        }
        if(!i->second.empty()) {
            vect.push_back(std::make_pair(i->second.top()->remaining_pkts() - i->second.top()->token_gap(),
             i->first));
            i++;
        } else {
            i = this->src_to_flows.erase(i);
        }
    }
    sort(vect.begin(), vect.end());
    for(auto i = vect.begin(); i != vect.end(); i++) {
        srcs.push_back(i->second);
        // if(debug_host(this->id)) {
        //     std::cout << get_current_time() << " " << i->first << " " << i->second << std::endl;
        // }
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
        std::cout << get_current_time() << " next wake up"  << get_current_time() + params.rankinghost_idle_timeout << std::endl;
    }
    this->wakeup_evt = new RankingHostWakeupProcessingEvent(get_current_time() + params.rankinghost_idle_timeout, this);
    add_to_event_queue(this->wakeup_evt);
}

void RankingHost::wakeup() {
    assert(this->wakeup_evt == NULL);
    // if(!this->src_to_flows.empty()) {
        if(debug_host(id)) {
            std::cout << "wake up for sending listSRC" << std::endl;
        }
        this->send_listSrcs();
        if(!this->src_to_flows.empty()) {
            this->schedule_wakeup_event();
        }
    //}
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
    if(this->gosrc_info.src!= NULL) {
        best_large_flow = this->get_top_unfinish_flow(this->gosrc_info.src->id);
        // if(best_large_flow == NULL) {
        //     std::cout << "i am here" << std::endl;
        //     this->fake_flow->sending_nrts_to_arbiter(this->gosrc_info.src->id, id);
        //     this->gosrc_info.reset();
        //     assert(this->wakeup_evt == NULL);
        //     this->wakeup();
        // }
    }
    while(!token_sent) {
        if (this->active_short_flows.empty() && best_large_flow == NULL) {
            break;
        }
        RankingFlow* f = NULL;
        RankingFlow* best_short_flow = NULL;
        if(!this->active_short_flows.empty()) {
            best_short_flow = this->active_short_flows.top();
        }
        if(flow_compare(best_large_flow, best_short_flow)) {
            f = this->active_short_flows.top();
            this->active_short_flows.pop();
            if(debug_flow(f->id)) {
                std::cout << get_current_time() << " pop flow " << f->id  << "\n";
            }
        } else {
            f = best_large_flow;
            best_large_flow = NULL;
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

                if(get_current_time() >= f->latest_token_sent_time + params.token_window_timeout) {
                    f->relax_token_gap();
                    if(debug_host(this->id)) {
                        std::cout << get_current_time() << " host " << this->id << " relax token gap for flow " << f->id << std::endl;
                    }
                }
                else{
                    if(f->latest_token_sent_time + params.token_window_timeout < closet_timeout)
                    {
                        closet_timeout = f->latest_token_sent_time + params.token_window_timeout;
                        if(debug_host(this->id)) {
                            std::cout << get_current_time() << " host " << this->id << " token_window full wait for timeout for flow " << f->id << std::endl;
                        }
                    }
                }

            }
            if(f->token_gap() <= params.token_window)
            {
                f->send_token_pkt();
                if(debug_host(id)) {
                        std::cout << get_current_time() << " sending tokens for flow" << f->id << std::endl;   
                }
                token_sent = true;
                // this->token_hist.push_back(this->recv_flow->id);
                if(f->token_count == f->token_goal){
                    f->redundancy_ctrl_timeout = get_current_time() + params.token_resend_timeout;
                    if(debug_flow(f->id)) {
                        std::cout << get_current_time() << " redundancy_ctrl_timeout set up" << f->id << "timeout value: " << f->redundancy_ctrl_timeout << "\n";
                    }
                }
                // for P4 ranking algorithm
                if(f->size_in_pkt > params.token_initial) {
                    assert( this->gosrc_info.remain_tokens > 0);
                    if(debug_host(id)) {
                        std::cout << get_current_time() << " remain_tokens: " << this->gosrc_info.remain_tokens << std::endl;   
                    }
                    this->gosrc_info.remain_tokens--;
                    if(this->gosrc_info.remain_tokens == 0) {
                        this->gosrc_info.reset();
                    }
                }
            }
        }
        if(f->size_in_pkt > params.token_initial) {
            auto gap = 0;
            if(this->gosrc_info.remain_tokens > f->remaining_pkts() - f->token_gap()) {
                gap = f->remaining_pkts() - f->token_gap();
            } else {
                gap = this->gosrc_info.remain_tokens;
            }
            if (gap <= params.BDP && this->gosrc_info.send_nrts == false) {
                this->fake_flow->sending_nrts_to_arbiter(f->src->id, f->dst->id);
                this->gosrc_info.send_nrts = true;
                this->wakeup();
            }
        }
    }
    while(!flows_tried.empty()) {
        this->active_short_flows.push(flows_tried.front());
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
        std::cout << get_current_time() << " receive GoSRC for dst " << this->id << "src id is " << pkt->src_id << std::endl; 
    }
    // find the minimum size of the flow for a source;
    RankingFlow* best_large_flow = this->get_top_unfinish_flow(pkt->src_id);
    if(best_large_flow == NULL) {
        this->gosrc_info.reset();
        this->fake_flow->sending_nrts_to_arbiter(pkt->src_id, this->id);
        return;
    }
    this->gosrc_info.src = (RankingHost*)this->src_to_flows[pkt->src_id].top()->src;
    this->gosrc_info.max_tokens = pkt->max_tokens;
    this->gosrc_info.remain_tokens = pkt->max_tokens;
    this->gosrc_info.round += 1;
    this->gosrc_info.send_nrts = false;
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
    if(this->token_send_evt == NULL) {
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
    //std::cout << get_current_time() <<  "pending queue size of arbirter " << this->pending_q.size() << std::endl;
    while(!this->pending_q.empty()) {
        auto request = this->pending_q.top();
        this->pending_q.pop();
        if(this->dst_state[request->dst->id] == false) {
            delete request;
            continue;
        }
        if(debug_host(request->dst->id)) {
            for(auto i = request->listSrcs.begin(); i != request->listSrcs.end(); i++) {
                std::cout << get_current_time() << " src " << (*i) << "state " << this->src_state[(*i)] << std::endl;
            }
        }
        for(auto i = request->listSrcs.begin(); i != request->listSrcs.end(); i++) {
            if(this->src_state[(*i)]) {
                this->src_state[(*i)] = false;
                this->dst_state[request->dst->id] = false;
                // send GoSRC packet
                // if(*i == 121) {
                //     std::cout << get_current_time() << " src " << (*i) << " assign to dst " << request->dst->id << std::endl;
                // }
                ((RankingHost*)(request->dst))->fake_flow->sending_gosrc(*i);
                break;
            }
        }
        delete request;
    }
    if(get_current_time() > this->last_reset_ranking_time + params.ranking_reset_epoch) {
        this->pending_q.comp.reset_ranking();
        this->last_reset_ranking_time = get_current_time();
        // std::cout << get_current_time() << " reset ranking " << std::endl;
    }
    //schedule next arbiter proc evt
    this->schedule_proc_evt(get_current_time() + params.ranking_controller_epoch);
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
    assert(this->src_state[pkt->src_id] == false);
    assert(this->dst_state[pkt->dst_id] == false);
    this->src_state[pkt->src_id] = true;
    this->dst_state[pkt->dst_id] = true;
}