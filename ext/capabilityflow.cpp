#include "math.h"

#include "../coresim/event.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"

#include "capabilityhost.h"
#include "capabilityflow.h"
#include "factory.h"

#include "../run/params.h"
extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern long long num_outstanding_packets;

bool CapabilityComparator::operator() (Capability* a, Capability* b)
{
    return a->timeout > b->timeout;
}


CapabilityFlow::CapabilityFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d)
    : FountainFlow(id, start_time, size, s, d) {
    this->finished_at_receiver = false;
    this->capability_count = 0;
    this->redundancy_ctrl_timeout = -1;
    this->capability_goal = (int)(std::ceil(this->size_in_pkt * 1.00));
    this->remaining_pkts_at_sender = this->size_in_pkt;
    this->largest_cap_seq_received = -1;
    this->total_queuing_time = 0;
    this->rts_received = false;
    this->latest_cap_sent_time = start_time;
    this->latest_data_pkt_send_time = start_time;
    this->capability_packet_sent_count = 0;
    this->capability_waste_count = 0;
    this->notified_num_flow_at_sender = 1;
    this->last_capa_data_seq_num_sent = -1;
    this->received_until = 0;
    this->received_count = 0;
}


void CapabilityFlow::start_flow()
{
    assign_init_capability();
    ((CapabilityHost*) this->src)->start_capability_flow(this);
}


void CapabilityFlow::send_pending_data()
{
    int capa_data_seq = this->capabilities.top()->data_seq_num;
    int capa_seq = this->use_capability();

	Packet *p;
	if (next_seq_no + mss <= this->size) {
		p = this->send(next_seq_no, capa_seq, capa_data_seq, params.capability_third_level && this->size_in_pkt > params.capability_prio_thresh?2:1);
		next_seq_no += mss;
	} else {
		p = this->send(next_seq_no, capa_seq, capa_data_seq, params.capability_third_level && this->size_in_pkt > params.capability_prio_thresh?2:1);
		next_seq_no = this->size;
	}

    if(debug_host(this->src->id))
        std::cout << get_current_time() << " sender " << this->src->id << " flow " << this->id << " send pkt " << this->total_pkt_sent << " " << "capacity data sequence: " << capa_data_seq  << " " << p->size << "\n";

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}


void CapabilityFlow::send_pending_data_low_prio()
{
    assert(false);
    Packet *p = this->send(this->next_seq_no, -1, -1, 9);
    next_seq_no += mss;
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send pkt " << this->total_pkt_sent << "\n";

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}

void CapabilityFlow::receive_rts(Packet* p) {
    if(debug_flow(p->flow->id))
        std::cout << get_current_time() << " received RTS for flow " << p->flow->id << "\n";

    this->rts_received = true;
    set_capability_count();
    ((CapabilityHost*)(this->dst))->hold_on = this->init_capa_size();
    if (params.host_type == CAPABILITY_HOST) {
        ((CapabilityHost*)(this->dst))->active_receiving_flows.push(this);
    } else if (params.host_type == RANDOM_HOST) {
        ((CapabilityHost*)(this->dst))->active_recv_flows_array.push_back(this);
    }

    if( ((CapabilityHost*)(this->dst))->capa_proc_evt &&
            ((CapabilityHost*)(this->dst))->capa_proc_evt->is_timeout_evt
      )
    {
        ((CapabilityHost*)(this->dst))->capa_proc_evt->cancelled = true;
        ((CapabilityHost*)(this->dst))->capa_proc_evt = NULL;
    }

    if(((CapabilityHost*)(this->dst))->capa_proc_evt == NULL){
        ((CapabilityHost*)(this->dst))->schedule_capa_proc_evt(0, false);
    }
}

void CapabilityFlow::receive(Packet *p)
{
    if(this->finished) {
        delete p;
        return;
    }

    if(p->type == NORMAL_PACKET)
    {
        if (this->first_byte_receive_time == -1) {
            this->first_byte_receive_time = get_current_time();
        }
        
        if (!rts_received) {
            receive_rts(p);
        }
        if(debug_flow(this->id)){
            std::cout << get_current_time() << " flow " << this->id << "receive data seq " << p->capa_data_seq << " seq number:" << p->capability_seq_num_in_data  << " total q delay: " << p->total_queuing_delay << std::endl;
        }
        if(packets_received.count(p->capa_data_seq) == 0){
            log_utilization(p->size);
            packets_received.insert(p->capa_data_seq);
            received_count++;
            while(received_until < size_in_pkt && packets_received.count(received_until) > 0)
            {
                received_until++;
            }
            if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
                num_outstanding_packets -= ((p->size - hdr_size) / (mss));
            else
                num_outstanding_packets = 0;
        }

        received_bytes += (p->size - hdr_size);
        total_queuing_time += p->total_queuing_delay;
        if(p->capability_seq_num_in_data > largest_cap_seq_received)
            largest_cap_seq_received = p->capability_seq_num_in_data;
//        if(debug_flow(this->id))
//            std::cout << get_current_time() << " flow " << this->id << " received pkt " << received_count << "\n";
        if (received_count >= goal) {
            // if(this->finished_at_receiver) 
            //     assert(false);
            this->finished_at_receiver = true;
            send_ack();
            if(debug_flow(this->id))
                std::cout << get_current_time() << " flow " << this->id << " send ACK \n";
        }
    }
    else if(p->type == ACK_PACKET)
    {
        if(debug_flow(this->id))
            std::cout << get_current_time() << " flow " << this->id << " received ack\n";
        // ((CapabilityHost*)(this->src))->send_flow = NULL;
        this->packets_received.clear();
        add_to_event_queue(new FlowFinishedEvent(get_current_time(), this));
    }
    else if(p->type == CAPABILITY_PACKET)
    {
        Capability* c = new Capability();
        if(CAPABILITY_MEASURE_WASTE)
        {
            if(this->has_sibling_idle_source())
                c->has_idle_sibling_sender = true;
            else
                c->has_idle_sibling_sender = false;
        }
        c->timeout = get_current_time() + ((CapabilityPkt*)p)->ttl;
        c->seq_num = ((CapabilityPkt*)p)->cap_seq_num;
        c->data_seq_num = ((CapabilityPkt*)p)->data_seq_num;
        this->capabilities.push(c);
        if(debug_flow(this->id)) {
            std::cout << get_current_time() << " receive capa: " << c->seq_num << " data seq: " << c->data_seq_num << std::endl;
        }
        this->remaining_pkts_at_sender = ((CapabilityPkt*)p)->remaining_sz;

        if(((CapabilityHost*)(this->src))->host_proc_event == NULL)
        {
            ((CapabilityHost*)(this->src))->schedule_host_proc_evt();
        }
    }
    else if(p->type == RTS_PACKET)
    {
        if (!rts_received) {
            this->receive_rts(p);
        }
    }
    else if(p->type == STATUS_PACKET)
    {
        if(CAPABILITY_NOTIFY_BLOCKING){
            StatusPkt* s = (StatusPkt*) p;
            this->notified_num_flow_at_sender = s->num_flows_at_sender;
        }

    }
    delete p;
}

bool CapabilityFlow::has_sibling_idle_source()
{
    bool has_idle = false;
    CapabilityHost* dst = (CapabilityHost*)this->dst;
    std::queue<CapabilityFlow*> flows_tried;
    while(!dst->active_receiving_flows.empty())
    {
        CapabilityFlow* f = dst->active_receiving_flows.top();
        dst->active_receiving_flows.pop();
        flows_tried.push(f);
        if(f != this && f->redundancy_ctrl_timeout <= get_current_time()
                && ((CapabilityHost*)(f->src))->is_sender_idle())
        {
            has_idle = true;
            break;
        }

    }

    while(!flows_tried.empty())
    {
        dst->active_receiving_flows.push(flows_tried.front());
        flows_tried.pop();
    }

    return has_idle;
}

Packet* CapabilityFlow::send(uint32_t seq, int capa_seq, int data_seq, int priority)
{
    this->latest_data_pkt_send_time = get_current_time();
	
	uint32_t pkt_size = 1500;
	// if (seq + mss > this->size) {
	// 	pkt_size = hdr_size + (this->size - seq);
	// } else {
	// 	pkt_size = hdr_size + mss;
	// }

    Packet *p = new Packet(get_current_time(), this, seq, priority, pkt_size, src, dst);
    p->capability_seq_num_in_data = capa_seq;
    p->capa_data_seq = data_seq;
    total_pkt_sent++;
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), p, src->queue));
    return p;
}


void CapabilityFlow::assign_init_capability(){
    //sender side
    int init_capa = this->init_capa_size();
    for(int i = 0; i < init_capa; i++){
        Capability* c = new Capability();
        c->timeout = get_current_time() + init_capa * params.get_full_pkt_tran_delay() + params.capability_timeout * params.get_full_pkt_tran_delay();
        c->seq_num = i;
        c->data_seq_num = i;
        this->capabilities.push(c);
    }
}


void CapabilityFlow::set_capability_count(){
    int init_capa = this->init_capa_size();
    this->capability_count = init_capa;
    this->last_capa_data_seq_num_sent = init_capa - 1;
    if(this->capability_count == this->capability_goal){
        this->redundancy_ctrl_timeout = get_current_time() + init_capa * params.get_full_pkt_tran_delay() * 2;
    }
}


int CapabilityFlow::get_next_capa_seq_num()
{
    int count = 0;
    int data_seq = (last_capa_data_seq_num_sent + 1)%this->size_in_pkt;
    while(count < this->size_in_pkt)
    {
        if(packets_received.count(data_seq) == 0)
        {
            assert(data_seq >= 0 && data_seq < size_in_pkt);
            return data_seq;
        }
        else
        {
            data_seq++;
            if(data_seq >= size_in_pkt)
            {
                data_seq = received_until;
            }

        }
        count++;
    }
    assert(false);
}

void CapabilityFlow::send_capability_pkt(){
    int data_seq_num = this->get_next_capa_seq_num();
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send capa " << this->capability_count << " capacity data sequence " << data_seq_num << "\n";
    last_capa_data_seq_num_sent = data_seq_num;
    CapabilityPkt* cp = new CapabilityPkt(this, this->dst, this->src, params.capability_timeout * params.get_full_pkt_tran_delay(), this->remaining_pkts(), this->capability_count, data_seq_num);
    this->capability_count++;
    this->capability_packet_sent_count++;
    this->latest_cap_sent_time = get_current_time();
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), cp, dst->queue));
}

void CapabilityFlow::send_notify_pkt(int num_flows_at_sender){
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send notify " << num_flows_at_sender << "\n";
    StatusPkt* cp = new StatusPkt(this, this->src, this->dst, num_flows_at_sender);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), cp, src->queue));
}

void CapabilityFlow::send_rts_pkt(){
    RTS* rts = new RTS(this, this->src, this->dst, 0, 0);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), rts, src->queue));
}

bool CapabilityFlow::has_capability(){
    while(!this->capabilities.empty()){
        //expired capability
        if(this->capabilities.top()->timeout < get_current_time())
        {
            if(CAPABILITY_MEASURE_WASTE){
                this->capability_waste_count += this->capabilities.top()->has_idle_sibling_sender?1:0;
            }
            if(debug_host(this->src->id)) {
                std::cout << get_current_time() <<  "capacity timeout" << std::endl;
            }
            delete this->capabilities.top();
            this->capabilities.pop();
        }
        //not expired
        else
        {
            return true;
        }
    }
    return false;
}

int CapabilityFlow::use_capability(){
    assert(!this->capabilities.empty() && this->capabilities.top()->timeout >= get_current_time());
    int seq_num = this->capabilities.top()->seq_num;
    delete this->capabilities.top();
    this->capabilities.pop();
    return seq_num;
}

Capability* CapabilityFlow::top_capability()
{
    assert(!this->capabilities.empty());
    return this->capabilities.top();
}

double CapabilityFlow::top_capability_timeout(){
    if(this->has_capability())
        return this->top_capability()->timeout;
    else
        return 999999;
}

int CapabilityFlow::remaining_pkts(){
    return std::max((int)0, (int)(this->size_in_pkt - this->received_count));
}

int CapabilityFlow::capability_gap(){
    assert(this->capability_count - this->largest_cap_seq_received >= 0);
    return this->capability_count - this->largest_cap_seq_received;
}

void CapabilityFlow::relax_capability_gap()
{
    assert(this->capability_count - this->largest_cap_seq_received >= 0);
    this->largest_cap_seq_received = this->capability_count - params.capability_window;
}

int CapabilityFlow::init_capa_size(){
    return this->size_in_pkt <= params.capability_initial?this->size_in_pkt:0;
}


