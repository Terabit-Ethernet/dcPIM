#include <assert.h>
#include <stdlib.h>

#include "../coresim/event.h"
#include "../coresim/flow.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"

#include "capabilityflow.h"
#include "capabilityhost.h"
#include "factory.h"

#include "../run/params.h"

extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;

CapabilityProcessingEvent::CapabilityProcessingEvent(double time, CapabilityHost *h, bool is_timeout)
    : Event(CAPABILITY_PROCESSING, time) {
        this->host = h;
        this->is_timeout_evt = is_timeout;
    }

CapabilityProcessingEvent::~CapabilityProcessingEvent() {
    if (host->capa_proc_evt == this) {
        host->capa_proc_evt = NULL;
    }
}

void CapabilityProcessingEvent::process_event() {
    this->host->capa_proc_evt = NULL;
    this->host->send_capability();
}

SenderNotifyEvent::SenderNotifyEvent(double time, CapabilityHost* h) : Event(SENDER_NOTIFY, time) {
    this->host = h;
}

SenderNotifyEvent::~SenderNotifyEvent() {
}

void SenderNotifyEvent::process_event() {
    this->host->sender_notify_evt = NULL;
    this->host->notify_flow_status();
}

bool CapabilityFlowComparator::operator() (CapabilityFlow* a, CapabilityFlow* b){
    //return a->remaining_pkts_at_sender > b->remaining_pkts_at_sender;
    if(params.deadline && params.schedule_by_deadline) {
        return a->deadline > b->deadline;
    }
    else {
        if (a->remaining_pkts_at_sender > b->remaining_pkts_at_sender)
            return true;
        else if (a->remaining_pkts_at_sender == b->remaining_pkts_at_sender)
            return a->start_time > b->start_time;
        else
            return false;
        //return a->latest_data_pkt_send_time > b->latest_data_pkt_send_time;
        //return a->start_time > b->start_time;
    }
}

bool CapabilityFlowComparatorAtReceiver::operator() (CapabilityFlow* a, CapabilityFlow* b){
    //return a->size_in_pkt > b->size_in_pkt;
    if(params.deadline && params.schedule_by_deadline) {
        return a->deadline > b->deadline;
    }
    else {
        if (a->notified_num_flow_at_sender > b->notified_num_flow_at_sender)
            return true;
        else if(a->notified_num_flow_at_sender == b->notified_num_flow_at_sender) {
            if(a->remaining_pkts() > b->remaining_pkts())
                return true;
            else if (a->remaining_pkts() == b->remaining_pkts())
                return a->start_time > b->start_time; //TODO: this is cheating. but not a big problem
            else
                return false;
        }
        else
            return false;
        //return a->latest_cap_sent_time > b->latest_cap_sent_time;
        //return a->start_time > b->start_time;
    }
}

CapabilityHost::CapabilityHost(uint32_t id, double rate, uint32_t queue_type) : SchedulingHost(id, rate, queue_type) {
    this->capa_proc_evt = NULL;
    this->hold_on = 0;
    this->total_capa_schd_evt_count = 0;
    this->could_better_schd_count = 0;
    this->sender_notify_evt = NULL;
    if (params.host_type == CAPABILITY_HOST) {
        this->host_type = CAPABILITY_HOST;
    } else if (params.host_type == RANDOM_HOST) {
        this->host_type = RANDOM_HOST;
        this->send_flow = NULL;
        this->recv_flow = NULL;
    }
}

void CapabilityHost::start_capability_flow(CapabilityFlow* f) {
    if(debug_flow(f->id) || debug_host(this->id)) {
        if (this->host_type == RANDOM_HOST) {
            std::cout 
                << get_current_time() 
                << " flow " << f->id 
                << " src " << this->id
                << " curr q size " << this->queue->bytes_in_queue 
                << " num flows " << this->active_recv_flows_array.size() <<"\n";
        } else if (this->host_type == CAPABILITY_HOST) {
            std::cout 
                << get_current_time() 
                << " flow " << f->id 
                << " src " << this->id
                << " curr q size " << this->queue->bytes_in_queue 
                << " num flows " << this->active_receiving_flows.size() <<"\n";
        }
    }
    if (this->host_type == CAPABILITY_HOST) {
        this->active_sending_flows.push(f);
    } else if (this->host_type == RANDOM_HOST) {
        this->active_send_flows_array.push_back(f);
    }
    f->send_rts_pkt();
    if(f->has_capability() && ((CapabilityHost*)(f->src))->host_proc_event == NULL) {
        ((CapabilityHost*)(f->src))->schedule_host_proc_evt();
    }
    if(CAPABILITY_NOTIFY_BLOCKING && this->sender_notify_evt == NULL)
        this->notify_flow_status();
}

void CapabilityHost::schedule_host_proc_evt(){
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

void CapabilityHost::schedule_capa_proc_evt(double time, bool is_timeout)
{
    assert(this->capa_proc_evt == NULL);
    this->capa_proc_evt = new CapabilityProcessingEvent(get_current_time() + time + INFINITESIMAL_TIME, this, is_timeout);
    add_to_event_queue(this->capa_proc_evt);
}

void CapabilityHost::schedule_sender_notify_evt()
{
    assert(this->sender_notify_evt == NULL);
    this->sender_notify_evt = new SenderNotifyEvent(get_current_time() + (params.get_full_pkt_tran_delay() * 20) + INFINITESIMAL_TIME, this);
    add_to_event_queue(this->sender_notify_evt);
}

CapabilityFlow* CapabilityHost::choose_send_flow() {
    CapabilityFlow* f = NULL;
    if(this->host_type == RANDOM_HOST) {
        if (this->send_flow != NULL ) {
            f = this->send_flow;
            this->send_flow = NULL;
            for(auto i = this->active_send_flows_array.begin(); i != this->active_send_flows_array.end(); i++) {
                if (f == *i) {
                    this->active_send_flows_array.erase(i);
                    break;
                }
            }
            return f;
        }

        if (!this->active_send_flows_array.empty()) {
            int index = rand() % this->active_send_flows_array.size();
            f = this->active_send_flows_array[index];
            if(this->active_send_flows_array.size() == 1) {
                this->active_send_flows_array.pop_back();
            } else {
                auto temp = this->active_send_flows_array[index];
                this->active_send_flows_array[index] = this->active_send_flows_array[this->active_send_flows_array.size() - 1];
                this->active_send_flows_array.pop_back();
            }        
        }
    } else if(this->host_type == CAPABILITY_HOST) {
        if (!this->active_sending_flows.empty()) {
            f = this->active_sending_flows.top();

            this->active_sending_flows.pop();
        }
    }
    return f;

}
//should only be called in HostProcessingEvent::process()
void CapabilityHost::send(){
    assert(this->host_proc_event == NULL);


    if(this->queue->busy)
    {
        schedule_host_proc_evt();
    }
    else
    {
        bool pkt_sent = false;
        std::queue<CapabilityFlow*> flows_tried;
        while(1){
            CapabilityFlow* top_flow = this->choose_send_flow();
           
            if (top_flow == NULL) {
                break;
            }

            if(top_flow->finished){
                continue;
            }
            flows_tried.push(top_flow);
            if(top_flow->has_capability()) {
                this->send_flow = top_flow;
                // this->send_hist.push_back(top_flow->id);
                top_flow->send_pending_data();
                pkt_sent = true;
                break;
            }
        }
        //code for 4th priority level
        if(params.capability_fourth_level && !pkt_sent && flows_tried.size() > 0){
            std::vector<CapabilityFlow*> candidate;
            for(int i = 0; i < flows_tried.size(); i++){
                if(flows_tried.front()->size_in_pkt > params.capability_initial)
                    candidate.push_back(flows_tried.front());
            }

            if(candidate.size()){
                int f_index = rand()%candidate.size();
                candidate[f_index]->send_pending_data_low_prio();
            }

        }

        while(!flows_tried.empty())
        {
            CapabilityFlow* f = flows_tried.front();
            flows_tried.pop();
            if (this->host_type == RANDOM_HOST) {
                this->active_send_flows_array.push_back(f);
            } else if (this->host_type == CAPABILITY_HOST) {
                this->active_sending_flows.push(f);
            }
        }
    }
}

void CapabilityHost::notify_flow_status()
{
    std::queue<CapabilityFlow*> flows_tried;
    int num_large_flow = 0;

    while(!this->active_sending_flows.empty())
    {
        CapabilityFlow* f = this->active_sending_flows.top();

        this->active_sending_flows.pop();
        if(!f->finished){
            flows_tried.push(f);
            if(f->size_in_pkt > params.capability_initial)
                num_large_flow++;
        }
    }

    while(!flows_tried.empty()){
        this->active_sending_flows.push(flows_tried.front());
        if(flows_tried.front()->size_in_pkt > params.capability_initial)
            flows_tried.front()->send_notify_pkt(num_large_flow>2?2:1);
        flows_tried.pop();
    }

    if(!this->active_sending_flows.empty())
        this->schedule_sender_notify_evt();
}

bool CapabilityHost::check_better_schedule(CapabilityFlow* f)
{
    return ((CapabilityHost*)f->src)->active_sending_flows.top() == f;
}

bool CapabilityHost::is_sender_idle(){
    bool idle = true;
    std::queue<CapabilityFlow*> flows_tried;
    while(!this->active_sending_flows.empty())
    {
        CapabilityFlow* f = this->active_sending_flows.top();
        this->active_sending_flows.pop();
        flows_tried.push(f);
        if(f->has_capability()){
            idle = false;
            break;
        }
    }
    while(!flows_tried.empty())
    {
        this->active_sending_flows.push(flows_tried.front());
        flows_tried.pop();
    }

    return idle;
}

// choose sender flow without replacemnt
CapabilityFlow* CapabilityHost::choose_recv_flow() {
    CapabilityFlow* f = NULL;
    if(this->host_type == RANDOM_HOST) {
        if(this->recv_flow != NULL) {
            f = this->recv_flow;
            this->recv_flow = NULL;
            for(auto i = this->active_recv_flows_array.begin(); i != this->active_recv_flows_array.end(); i++) {
                if (f == *i) {
                    this->active_recv_flows_array.erase(i);
                    break;
                }
            }
            return f;
        }
        if (!this->active_recv_flows_array.empty()) {
            int index = rand() % this->active_recv_flows_array.size();
            f = this->active_recv_flows_array[index];
            if(this->active_recv_flows_array.size() == 1) {
                this->active_recv_flows_array.pop_back();
            } else {
                auto temp = this->active_recv_flows_array[index];
                this->active_recv_flows_array[index] = this->active_recv_flows_array[this->active_recv_flows_array.size() - 1];
                this->active_recv_flows_array.pop_back();
            }
        }
    } else if(this->host_type == CAPABILITY_HOST) {
        if(!this->active_receiving_flows.empty()) {
            f = this->active_receiving_flows.top();
            this->active_receiving_flows.pop();
        }
    }
    return f;
}
void CapabilityHost::send_capability(){
    //if(debug_host(this->id))
    //    std::cout << get_current_time() << " CapabilityHost::send_capability() at host " << this->id << "\n";
    assert(capa_proc_evt == NULL);

    bool capability_sent = false;
    bool could_schd_better = false;
    this->total_capa_schd_evt_count++;
    std::queue<CapabilityFlow*> flows_tried;
    double closet_timeout = 999999;

    if(CAPABILITY_HOLD && this->hold_on > 0){
        hold_on--;
        capability_sent = true;
    }

    while(!capability_sent)
    {
        CapabilityFlow* f = this->choose_recv_flow();
        if (f == NULL) {
            break;
        }
        if(debug_flow(f->id))
           std::cout << get_current_time() << " pop out flow " << f->id << "\n";


        if(f->finished_at_receiver)
        {
            continue;
        }
        flows_tried.push(f);

        //not yet timed out, shouldn't send
        if(f->redundancy_ctrl_timeout > get_current_time()){
            if(this->host_type == CAPABILITY_HOST && check_better_schedule(f))
                could_schd_better = true;
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
                f->capability_goal += f->remaining_pkts();
                if(debug_flow(f->id))
                    std::cout << get_current_time() << " redundancy_ctrl_timeout " << f->id << "\n";
            }

            if(f->capability_gap() > params.capability_window)
            {
                if(debug_flow(f->id))
                    std::cout << get_current_time() << " capability_gap > capability_window " << f->id << "\n";
                if(get_current_time() >= f->latest_cap_sent_time + params.capability_window_timeout * params.get_full_pkt_tran_delay())
                    f->relax_capability_gap();
                else{
                    if(f->latest_cap_sent_time + params.capability_window_timeout * params.get_full_pkt_tran_delay() < closet_timeout)
                    {
                        closet_timeout = f->latest_cap_sent_time + params.capability_window_timeout* params.get_full_pkt_tran_delay();
                    }
                    if(debug_flow(f->id))
                        std::cout << get_current_time() << " closed timeout " << f->id << "\n";
                }

            }


            if(f->capability_gap() <= params.capability_window)
            {
                f->send_capability_pkt();
                this->recv_flow = f;
                capability_sent = true;
                // this->token_hist.push_back(this->recv_flow->id);
                if(f->capability_count == f->capability_goal){
                    f->redundancy_ctrl_timeout = get_current_time() + params.capability_resend_timeout * params.get_full_pkt_tran_delay();
                }

                break;
            }
        }
    }

    while(!flows_tried.empty()){
        CapabilityFlow* tf = flows_tried.front();
        flows_tried.pop();
        if (this->host_type == RANDOM_HOST) {
            this->active_recv_flows_array.push_back(tf);
        } else if (this->host_type == CAPABILITY_HOST) {
            this->active_receiving_flows.push(tf);
        }
    }

    if(capability_sent)// pkt sent
    {
        this->schedule_capa_proc_evt(params.get_full_pkt_tran_delay(1500/* + 40*/), false);
    }
    else if(closet_timeout < 999999) //has unsend flow, but its within timeout
    {
        assert(closet_timeout > get_current_time());
        this->schedule_capa_proc_evt(closet_timeout - get_current_time(), true);
    }
    else{
        //do nothing, no unfinished flow
    }
    if(could_schd_better)
        this->could_better_schd_count++;
}

