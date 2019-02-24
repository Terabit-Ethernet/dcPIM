#include "assert.h"
#include "../coresim/event.h"
#include "../coresim/topology.h"
#include "../coresim/debug.h"

#include "factory.h"
#include "rufflow.h"
#include "rufhost.h"
#include "rufTopology.h"

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


TokenProcessingEvent::TokenProcessingEvent(double time, RufHost *h, bool is_timeout)
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


RufHostWakeupProcessingEvent::RufHostWakeupProcessingEvent(double time, RufHost *h)
    : Event(RUFHOST_WAKEUP_PROCESSING, time) {
        this->host = h;
    }

RufHostWakeupProcessingEvent::~RufHostWakeupProcessingEvent() {
    if (host->wakeup_evt == this) {
        host->wakeup_evt = NULL;
    }
}

void RufHostWakeupProcessingEvent::process_event() {
    this->host->wakeup_evt = NULL;
    this->host->wakeup();
}

RufGoSrcQueuingEvent::RufGoSrcQueuingEvent(double time, RufArbiter *h)
    : Event(RUF_GOSRC_QUEUING, time) {
        this->arbiter = h;
    }

RufGoSrcQueuingEvent::~RufGoSrcQueuingEvent() {
    if (arbiter->gosrc_queue_evt == this) {
        arbiter->gosrc_queue_evt = NULL;
    }
}

void RufGoSrcQueuingEvent::process_event() {
    this->arbiter->gosrc_queue_evt = NULL;
    this->arbiter->send_gosrc();
}



// Comparator

bool RufFlowComparator::operator() (RufFlow* a, RufFlow* b){
    if (a->remaining_pkts_at_sender > b->remaining_pkts_at_sender)
        return true;
    else if (a->remaining_pkts_at_sender == b->remaining_pkts_at_sender)
        return a->start_time > b->start_time;
    else
        return false;
}
bool RufFlowComparatorAtReceiver::operator() (RufFlow* a, RufFlow* b){
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
bool RufShortFlowComparatorAtReceiver::operator() (RufFlow* a, RufFlow* b){
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

bool RufHost::flow_compare(RufFlow* long_flow, RufFlow* short_flow) {
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
RufHost::RufHost(uint32_t id, double rate, uint32_t queue_type) : SchedulingHost(id, rate, queue_type) {

    this->host_proc_event = NULL;
    this->token_send_evt = NULL;
    this->wakeup_evt = NULL;
    this->host_type = RUF_HOST;
    this->total_token_schd_evt_count = 0;
    this->hold_on = 0;
    this->idle_count = 0;
    this->fake_flow = NULL;

    this->debug_new_flow = 0;
    this->debug_send_flow_finish = 0;
    this->debug_send_go_src = 0;
    this->debug_send_wake_up = 0;
    this->debug_use_all_tokens = 0;
    this->last_send_list_src_time = 1.0;
}

// Statistics 

void RufHost::print_max_min_fairness() {
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
void RufHost::start_ruf_flow(RufFlow* f) {
    f->assign_init_token();
    this->active_sending_flows.push(f);
    if(!f->tokens.empty()) {
        if (((SchedulingHost*) this)->host_proc_event == NULL) {
            this->schedule_host_proc_evt();
        }
    }
    f->sending_rts();
}
void RufHost::receive_token(RufToken* pkt) {
    // To Do: need a queue to maintain current active sending flows;
    if(debug_flow(pkt->flow->id)) {
        std::cout << get_current_time() << " receive token " << pkt->data_seq_num << " timeout: " << get_current_time() + pkt->ttl  << " queue delay:" << pkt->total_queuing_delay<< std::endl;
    }
    auto f = (RufFlow*)pkt->flow;
    Token* t = new Token();
    // if(!f->tokens.empty()) {
    //     t->timeout = fto->back().timeout + get_full_pkt_tran_delay(1500) - pkt->ttl;
    // }
    t->timeout = get_current_time() + pkt->ttl;
    t->seq_num = pkt->token_seq_num;
    t->data_seq_num = pkt->data_seq_num;
    t->ruf_round = pkt->ruf_round;
    f->tokens.push_back(t);
    f->remaining_pkts_at_sender = pkt->remaining_sz;
    if(this->host_proc_event == NULL) {
        this->schedule_host_proc_evt();
    }
}

void RufHost::schedule_host_proc_evt(){
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

void RufHost::send(){
    // To Do: need a queue to maintain current active sending flows;

    assert(this->host_proc_event == NULL);
    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        std::queue<RufFlow*> flows_tried;
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
void RufHost::schedule_token_proc_evt(double time, bool is_timeout)
{
    assert(this->token_send_evt == NULL);
    this->token_send_evt = new TokenProcessingEvent(get_current_time() + time + INFINITESIMAL_TIME, this, is_timeout);
    add_to_event_queue(this->token_send_evt);
}

RufFlow* RufHost::get_top_unfinish_flow(uint32_t src_id) {
    RufFlow* best_large_flow = NULL;
    std::queue<RufFlow*> flows_tried;
    if(this->src_to_flows.find(src_id) == this->src_to_flows.end())
        return best_large_flow;
    while (!this->src_to_flows[src_id].empty()) {
        best_large_flow =  this->src_to_flows[src_id].top();
        if(best_large_flow->finished_at_receiver) {
            best_large_flow = NULL;
            this->src_to_flows[src_id].pop();
        } else if (best_large_flow->redundancy_ctrl_timeout > get_current_time()) {
            flows_tried.push(best_large_flow);
            this->src_to_flows[src_id].pop();
            best_large_flow = NULL;
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
    return best_large_flow;
}

void RufHost::receive_rts(RufRTS* pkt) {
    if(debug_flow(pkt->flow->id))
            std::cout << get_current_time() << " flow " << pkt->flow->id << " "<< pkt->size_in_pkt <<  " received rts\n";
    ((RufFlow*)pkt->flow)->rts_received = true;
    if(pkt->size_in_pkt > params.token_initial) {
        // if(debug_host(id)) {
        //     std::cout << "push flow " << pkt->flow->id << std::endl;
        // }
        this->src_to_flows[pkt->flow->src->id].push((RufFlow*)pkt->flow);
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
            this->debug_new_flow++;
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
        ((RufFlow*)pkt->flow)->receive_short_flow();
    }
}

void RufHost::flow_finish_at_receiver(Packet* pkt) {
    if(debug_host(this->id)) {
        std::cout << get_current_time () << " flow finish at receiver " <<  pkt->flow->id << std::endl;
    }

    if (((RufFlow*)pkt->flow)->finished_at_receiver)
        return;
    
    ((RufFlow*)pkt->flow)->finished_at_receiver = true;

    if(pkt->flow->size_in_pkt <= params.token_initial) {
        return;
    }
    if(this->gosrc_info.round == pkt->ruf_round) {
        // assert(this->wakeup_evt != NULL);
        // assert(this->gosrc_info.src != NULL);
        // if(!this->src_to_flows.empty()) {
        //     assert(this->wakeup_evt != NULL);
        // }
        // this->gosrc_info.reset();
    } else if (this->gosrc_info.src == (RufHost*)pkt->flow->src) {
        auto best_large_flow = this->get_top_unfinish_flow(pkt->flow->src->id);
        if(best_large_flow == NULL) {
            // if(this->gosrc_info.send_nrts == false) {
            //     // (this->fake_flow)->sending_nrts_to_arbiter(pkt->flow->src->id, pkt->flow->dst->id);
            //     assert(this->wakeup_evt == NULL);
            //     //std::cout << pkt->flow->id << " "  << pkt->flow->src->id << " " << pkt->flow->dst->id << std::endl;
            //     //assert(false);
            //     this->debug_send_flow_finish++;
            //     this->send_listSrcs(pkt->flow->src->id, this->gosrc_info.control_round);
            //     this->schedule_wakeup_event();
            // }

            // this->gosrc_info.reset();
        }
    }
}
void RufHost::send_listSrcs(int nrts_src_id, int control_round) {
    std::vector<std::pair<int, int>> vect1;
    std::vector<std::pair<int, int>> vect2;

    std::list<uint32_t> srcs;
    std::list<uint32_t> flow_sizes;
    int remain_tokens = 0;
    if(this->gosrc_info.src != NULL && this->gosrc_info.src->id == nrts_src_id){
        remain_tokens = this->gosrc_info.remain_tokens;
    }
    if(debug_host(id)) {
        std::cout << get_current_time() << "send list_src time diff:" <<  get_current_time() - this->last_send_list_src_time << std::endl;
        this->last_send_list_src_time = get_current_time();
    }
    // if(debug_host(this->id)) {
    //     std::cout << get_current_time() << " debug_new_flow: " << this->debug_new_flow
    //     << " debug_send_flow_finish " << this->debug_send_flow_finish 
    //     << " debug_send_go_src " << this->debug_send_go_src
    //     << " debug_send_wake_up" << this->debug_send_wake_up
    //     << " debug_use_all_tokens" << this->debug_use_all_tokens << std::endl;
    // }
    auto max_flow_limit = INT_MAX;
    for (auto i = this->src_to_flows.begin(); i != this->src_to_flows.end();) {
        std::queue<RufFlow*> flows_tried;
        RufFlow* best_flow = NULL;
        while(!i->second.empty()) {
            if(i->second.top()->finished_at_receiver) {
                i->second.pop();
            } else if(i->second.top()->redundancy_ctrl_timeout > get_current_time()) {
                flows_tried.push(i->second.top());
                i->second.pop();
            } 
            else {
                if(i->first == nrts_src_id) {
                    if(remain_tokens > 0){
                        remain_tokens -= (i->second.top()->remaining_pkts() - i->second.top()->token_gap());
                    }
                    if(remain_tokens < 0){
                        best_flow = i->second.top();
                        break;
                    } else {
                        flows_tried.push(i->second.top());
                        i->second.pop();               
                    }
                } else {
                    best_flow = i->second.top();
                    break;
                }
            }
        }
        while(!flows_tried.empty()) {
            i->second.push(flows_tried.front());
            flows_tried.pop();
        }
        if(best_flow != NULL) {
            vect1.push_back(std::make_pair(std::min(best_flow->remaining_pkts() - best_flow->token_gap(), 65535),
             i->first));
            if(i->first == nrts_src_id) {
                max_flow_limit = best_flow->remaining_pkts() - best_flow->token_gap();
            }
            i++;
        } else if(i->second.empty()){
            i = this->src_to_flows.erase(i);
        } else {
            i++;
        }
    }
    std::random_shuffle(vect1.begin(), vect1.end());
    std::sort(vect1.begin(), vect1.end(), ListSrcsComparator());
    for(auto i = vect1.begin(); i != vect1.end(); i++) {
        flow_sizes.push_back(i->first);
        srcs.push_back(i->second);
    }
    if(srcs.empty() && (nrts_src_id == -1))
        return;

    RufListSrcs* listSrcs = new RufListSrcs(this->fake_flow,
     this, topology->arbiter , this, srcs);
    listSrcs->flowSizes = flow_sizes;
    listSrcs->size += 2 * flow_sizes.size();
    if(nrts_src_id != -1) {
        listSrcs->has_nrts = true;
        listSrcs->nrts_src_id = nrts_src_id;
        listSrcs->nrts_dst_id = this->id;
        listSrcs->round = control_round;
        // listSrcs->pf_priority = 0;
        this->gosrc_info.send_nrts = true;
    }
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), listSrcs, this->queue));
} 

void RufHost::schedule_wakeup_event() {
    assert(this->wakeup_evt == NULL);
    double idle_time = params.rufhost_idle_timeout;
    this->wakeup_evt = new RufHostWakeupProcessingEvent(get_current_time() + idle_time, this);
    add_to_event_queue(this->wakeup_evt);
}

void RufHost::wakeup() {
    assert(this->wakeup_evt == NULL);
    this->idle_count++;
    if(debug_host(id)) {
        std::cout <<get_current_time() <<  " wake up for sending listSRC" << std::endl;
    }
    this->debug_send_wake_up++;

    this->send_listSrcs();
    if(!this->src_to_flows.empty()) {
        this->schedule_wakeup_event();
    }
}
void RufHost::send_token() {
    assert(this->token_send_evt == NULL);
    bool token_sent = false;
    this->total_token_schd_evt_count++;
    double closet_timeout = 999999;
    std::queue<RufFlow*> flows_tried;
    if(TOKEN_HOLD && this->hold_on > 0){
        hold_on--;
        token_sent = true;
    }
    RufFlow* best_large_flow = NULL;
    if(this->gosrc_info.src!= NULL) {
        best_large_flow = this->get_top_unfinish_flow(this->gosrc_info.src->id);
    }
    while(!token_sent) {
        if (this->active_short_flows.empty() && best_large_flow == NULL) {
            break;
        }
        RufFlow* f = NULL;
        RufFlow* best_short_flow = NULL;
        if(!this->active_short_flows.empty()) {
            best_short_flow = this->active_short_flows.top();
        }
        if(flow_compare(best_large_flow, best_short_flow)) {
            f = this->active_short_flows.top();
            this->active_short_flows.pop();
            // if(debug_flow(f->id)) {
            //     std::cout << get_current_time() << " pop flow " << f->id  << "\n";
            // }
        } else {
            f = best_large_flow;
            best_large_flow = NULL;
        }
        // if(debug_host(this->id)) {
        //     std::cout << "try to send token" << std::endl;
        // }
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
                std::cout << get_current_time() << " redundancy_ctrl_timeout has not met " << f->id  << "\n";
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
                // for P4 ruf algorithm
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
            auto ctrl_pkt_rtt = topology->get_control_pkt_rtt(this->id);
            if(this->gosrc_info.remain_tokens > f->remaining_pkts() - f->token_gap()) {
                gap = f->remaining_pkts() - f->token_gap();
            } else {
                gap = this->gosrc_info.remain_tokens;
            }
            if(debug_host(id)) {
                std::cout << get_current_time() << " gap " << gap << " large or not " <<  (gap * params.get_full_pkt_tran_delay() <= ctrl_pkt_rtt + params.ruf_controller_epoch) << std::endl;
            }
            if ((f->redundancy_ctrl_timeout > get_current_time() || 
                gap * params.get_full_pkt_tran_delay() <= ctrl_pkt_rtt + params.ruf_controller_epoch)
             && this->gosrc_info.send_nrts == false) {
                // this->fake_flow->sending_nrts_to_arbiter(f->src->id, f->dst->id);
                // this->gosrc_info.send_nrts = true;
                assert(this->wakeup_evt == NULL);
                this->debug_use_all_tokens++;
                this->send_listSrcs(f->src->id, this->gosrc_info.control_round);
                this->schedule_wakeup_event();
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
        if(this->gosrc_info.src != NULL) {
            if(!this->gosrc_info.send_nrts){
                this->send_listSrcs(this->gosrc_info.src->id, this->gosrc_info.control_round);
                assert(this->wakeup_evt == NULL);
                this->schedule_wakeup_event();
            }
            this->gosrc_info.reset();
            // assert(false);
        }
    }


}

void RufHost::receive_gosrc(RufGoSrc* pkt) {
    if(debug_host(this->id)) {
        std::cout << get_current_time() << " receive GoSRC for dst " << this->id << "src id is " << pkt->src_id << " queue delay:" << pkt->total_queuing_delay << std::endl; 
    }
    // find the minimum size of the flow for a source;
    RufFlow* best_large_flow = this->get_top_unfinish_flow(pkt->src_id);
    if(best_large_flow == NULL) {
        // this->fake_flow->sending_nrts_to_arbiter(pkt->src_id, this->id);
        this->debug_send_go_src++;
        this->send_listSrcs(pkt->src_id, pkt->round);
        // if(!this->src_to_flows.empty()) {
        //     assert(this->wakeup_evt != NULL);
        // }
        if(this->wakeup_evt != NULL) {
            this->wakeup_evt->cancelled = true;
            this->wakeup_evt = NULL;
        }
        this->schedule_wakeup_event();
        this->gosrc_info.reset();
        return;
    }
    this->idle_count = 0;

    this->gosrc_info.src = (RufHost*)this->src_to_flows[pkt->src_id].top()->src;
    this->gosrc_info.max_tokens = pkt->max_tokens;
    this->gosrc_info.remain_tokens = pkt->max_tokens;
    this->gosrc_info.round += 1;
    this->gosrc_info.control_round = pkt->round;
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

// ---- Ruf Arbiter

RufArbiter::RufArbiter(uint32_t id, double rate, uint32_t queue_type) : Host(id, rate, queue_type, RUF_ARBITER) {
    this->src_state = std::vector<HostState>(params.num_hosts, HostState());
    this->dst_state = std::vector<HostState>(params.num_hosts, HostState());
    this->arbiter_proc_evt = NULL;
    this->gosrc_queue_evt = NULL;
    this->round = 0;
    // this->last_reset_ruf_time = 0;
}

void RufArbiter::start_arbiter() {
    this->schedule_proc_evt(1.0);
}


void RufArbiter::schedule_proc_evt(double time) {
    assert(this->arbiter_proc_evt == NULL);
    this->arbiter_proc_evt = new RufArbiterProcessingEvent(time, this);
    add_to_event_queue(this->arbiter_proc_evt);
}

void RufArbiter::send_gosrc() {
    assert(this->gosrc_queue_evt == NULL);
    // gosrc pkt size is 40 bytes;
    uint32_t gosrc_size = 40;
    uint32_t max_go_src = (this->queue->limit_bytes - this->queue->bytes_in_queue) / gosrc_size;
    while(this->gosrc_queue.size() > 0) {
        auto request = this->gosrc_queue.front();
        request.first->fake_flow->sending_gosrc(request.second, this->src_state[request.second].round);
        max_go_src--;
        if(max_go_src == 0)
            break;
        this->gosrc_queue.pop();
    }
    if(!this->gosrc_queue.empty()) {
        this->gosrc_queue_evt = new RufGoSrcQueuingEvent(this->queue->get_transmission_delay(this->queue->limit_bytes) + INFINITESIMAL_TIME + get_current_time(), this);
        add_to_event_queue(this->gosrc_queue_evt);
        assert(false);
    }

}
void RufArbiter::ruf_schedule() {
    assert(gosrc_queue.empty());
    // gosrc pkt size is 40 bytes;
    uint32_t gosrc_size = 40;
    uint32_t max_go_src = (this->queue->limit_bytes - this->queue->bytes_in_queue) / gosrc_size;
    while(!this->ruf_q.empty()) {
        auto request = this->ruf_q.top();
        this->ruf_q.pop();
        if(debug_host(request->dst->id)) {
            std::cout << get_current_time() << " schedule epoch for dst " << request->dst->id << std::endl;
            std::cout << get_current_time() << " src " << (request->src_id) << "state " << this->src_state[request->src_id].state << " flow size:" << request->flow_size << std::endl;
        }
        bool dst_state = true;
        bool src_state = true;
        // reset the dst state if the timeout happens;
        if(this->dst_state[request->dst->id].state == false) {
            if(this->dst_state[request->dst->id].timeout >= get_current_time()) {
                dst_state = false;
            } else {
                this->dst_state[request->dst->id].reset();
                assert(false);
            }
        } 
        // reset the src state if timeout happens;
        if(this->src_state[request->src_id].state == false) {
            if(this->src_state[request->src_id].timeout >= get_current_time()) {
                src_state = false;
            } else {
                this->src_state[request->src_id].reset();
                assert(false);
            }

        }

        if(!src_state || !dst_state) {
            delete request;
            continue;
        }
        this->src_state[request->src_id].state = false;
        // set the timeout of the src state
        this->src_state[request->src_id].timeout = get_current_time() +
             topology->get_control_pkt_rtt(request->src_id) + 5 * params.ruf_max_tokens * params.get_full_pkt_tran_delay();
        this->src_state[request->src_id].round = this->round;
        
        this->dst_state[request->dst->id].state = false;
        // set the timeout of the dst state
        this->dst_state[request->dst->id].timeout = get_current_time() + 
             topology->get_control_pkt_rtt(request->dst->id) + 5 * params.ruf_max_tokens * params.get_full_pkt_tran_delay();
        this->dst_state[request->dst->id].round = this->round;
        if(max_go_src > 0){
            ((RufHost*)(request->dst))->fake_flow->sending_gosrc(request->src_id, this->round);
            max_go_src--;
        } else {
            this->gosrc_queue.push(std::make_pair((RufHost*)request->dst, request->src_id));
        }
        delete request;
    }
    if(!this->gosrc_queue.empty() && this->gosrc_queue_evt == NULL) {
        this->gosrc_queue_evt = new RufGoSrcQueuingEvent(this->queue->get_transmission_delay(this->queue->limit_bytes) + INFINITESIMAL_TIME + get_current_time(), this);
        add_to_event_queue(this->gosrc_queue_evt);
    }
}
void RufArbiter::schedule_epoch() {
    if (total_finished_flows >= params.num_flows_to_run)
        return;
    this->ruf_schedule();
    //schedule next arbiter proc evt
    this->round = (this->round + 1) % 65536;
    this->schedule_proc_evt(get_current_time() + params.ruf_controller_epoch);
}

void RufArbiter::receive_listsrcs(RufListSrcs* pkt) {
    if(debug_host(pkt->rts_dst->id))
        std::cout << get_current_time() << " Arbiter: receive listsrcs " << pkt->rts_dst->id << " queue delay:" << pkt->total_queuing_delay << std::endl;
    if(pkt->has_nrts) {
        // To DO: check the round number;
        if(pkt->round == this->src_state[pkt->nrts_src_id].round) {
            this->src_state[pkt->nrts_src_id].reset();
        } else {
            // std::cout << get_current_time() << " src id: " << pkt->nrts_src_id << std::endl;
            // std::cout << get_current_time() << " pkt round: " << pkt->round << 
            //     " current src round: " <<  this->src_state[pkt->nrts_src_id].round << std::endl;
            // std::cout << get_current_time() << "pkt total queue delay: " << pkt->total_queuing_delay << std::endl;
            // assert(false);
        }
        if(pkt->round == this->dst_state[pkt->nrts_dst_id].round) {
            this->dst_state[pkt->nrts_dst_id].reset();
        } else {
            // std::cout << get_current_time() << " dst id: " << pkt->nrts_dst_id << std::endl;
            // std::cout << get_current_time() << " pkt round: " << pkt->round << 
            //     " current dst round: " <<  this->dst_state[pkt->nrts_dst_id].round << std::endl;
            // std::cout << get_current_time() << "pkt total queue delay: " << pkt->total_queuing_delay << std::endl;
            // assert(false);
        }
    }
    if(this->dst_state[pkt->rts_dst->id].state){
        auto i = pkt->listSrcs.begin();
        auto j = pkt->flowSizes.begin();
        while(i != pkt->listSrcs.end()) {
            auto element = new PqElement();
            element->dst = pkt->rts_dst;
            element->src_id = *i;
            element->flow_size = *j;
            i++;
            j++;
            this->ruf_q.push(element);
        }
    }
}

// void RufArbiter::receive_nrts(RufNRTS* pkt) {
//     assert(this->src_state[pkt->src_id].state == false);
//     assert(this->dst_state[pkt->dst_id].state == false);
//     if(debug_host(pkt->dst_id)) {
//         std::cout << get_current_time() << "controller receivers nrts from dst " << pkt->dst_id << " src " << pkt->src_id << " pkt address:" << pkt << " queue delay" << pkt->total_queuing_delay << std::endl;
//     }
//     this->src_state[pkt->src_id].state = true;
//     this->dst_state[pkt->dst_id].state = true;
// }