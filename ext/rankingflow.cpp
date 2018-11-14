#include "rankinghost.h"
#include "rankingflow.h"

#include "../coresim/packet.h"
#include "../coresim/topology.h"
#include "../coresim/event.h"
#include "../coresim/debug.h"

#include "rankingTopology.h"

extern Topology *topology;
extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern uint32_t num_outstanding_packets;

RankingFlow::RankingFlow(
        uint32_t id, 
        double start_time, 
        uint32_t size,
        Host *s, 
        Host *d
        ) : FountainFlow(id, start_time, size, s, d) {
    this->finished_at_receiver = false;
    this->token_count = 0;
    this->redundancy_ctrl_timeout = -1;
    this->token_goal = (int)(std::ceil(this->size_in_pkt * 1.00));
    this->remaining_pkts_at_sender = this->size_in_pkt;
    this->largest_token_seq_received = -1;
    this->total_queuing_time = 0;
    this->rts_received = false;
    this->latest_token_sent_time = -1;
    this->latest_data_pkt_sent_time = -1;
    this->token_packet_sent_count = 0;
    this->token_waste_count = 0;
    this->last_token_data_seq_num_sent = -1;
    this->received_until = 0;
    this->received_count = 0;
}

void RankingFlow::start_flow() {
    ((RankingHost*) this->src)->start_ranking_flow(this);
    // To Do: adding short flow logic: 1. assign free tokens. 2. schedule host processing event.
}

void RankingFlow::sending_rts() {
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << "sending rts flow " << this->id << " src " << this->src->id << "size : " << size_in_pkt <<std::endl;
    }
    RankingRTS* rts = new RankingRTS(this, this->src, this->dst, this->size_in_pkt);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), rts, src->queue));
}

void RankingFlow::sending_nrts() {
    RankingNRTS* nrts = new RankingNRTS(this, this->src, this->dst);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), nrts, src->queue));
}

void RankingFlow::sending_nrts_to_arbiter() {
    RankingNRTS* nrts = new RankingNRTS(this, this->dst, dynamic_cast<RankingTopology*>(topology)->arbiter);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), nrts, dst->queue));
}

void RankingFlow::sending_gosrc(uint32_t src_id) {
    if(debug_host(this->src->id)) {
        std::cout << get_current_time () << " sending gosrc to host " << this->src->id << std::endl;
    }
    RankingGoSrc* gosrc = new RankingGoSrc(this, dynamic_cast<RankingTopology*>(topology)->arbiter, this->src, src_id);

    add_to_event_queue(new PacketQueuingEvent(get_current_time(), gosrc, dynamic_cast<RankingTopology*>(topology)->arbiter->queue));
}

// sender side
void RankingFlow::assign_init_token(){
    //sender side
    int init_token = this->init_token_size();
    if(debug_flow(this->id)) {
        std::cout << "initial token for flow " << this->id << " token size:" << init_token << std::endl;
    }
    for(int i = 0; i < init_token; i++){
        Token* c = new Token();
        c->timeout = get_current_time() + init_token * params.get_full_pkt_tran_delay() + params.token_timeout * params.get_full_pkt_tran_delay();
        c->seq_num = i;
        c->data_seq_num = i;
        this->tokens.push_back(c);
    }
}

bool RankingFlow::has_token(){
    while(!this->tokens.empty()){
        //expired token
        if(this->tokens.front()->timeout < get_current_time())
        {
            if(debug_flow(this->id)) {
                std::cout << get_current_time() << "token timeout " << this->tokens.front()->timeout << std::endl;
            }
            delete this->tokens.front();
            this->tokens.pop_front();
        }
        //not expired
        else
        {
            return true;
        }
    }
    return false;
}
void RankingFlow::clear_token(){
    for(auto i = this->tokens.begin(); i != this->tokens.end(); i++) {
        delete (*i);
        *i = NULL;
    }
    this->tokens.clear();
}
Token* RankingFlow::use_token(){
    assert(!this->tokens.empty() && this->tokens.front()->timeout >= get_current_time());
    auto token = this->tokens.front();
    this->tokens.pop_front();
    return token;
}
void RankingFlow::send_pending_data()
{
    auto token = this->use_token();
    int token_data_seq = token->data_seq_num;
    int token_seq = token->seq_num;

    delete token;

    Packet *p;
    if (next_seq_no + mss <= this->size) {
        p = this->send(next_seq_no, token_seq, token_data_seq, params.token_third_level && this->size_in_pkt > params.token_initial?2:1);
        next_seq_no += mss;
    } else {
        p = this->send(next_seq_no, token_seq, token_data_seq, params.token_third_level && this->size_in_pkt > params.token_initial?2:1);
        next_seq_no = this->size;
    }

    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " flow " << this->id << " send pkt " << token_seq << " " << p->size << " data seq num " << token_data_seq <<  "\n";
    }

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}

Packet* RankingFlow::send(uint32_t seq, int token_seq, int data_seq, int priority)
{
    this->latest_data_pkt_sent_time = get_current_time();
    
    uint32_t pkt_size;
    if (seq + mss > this->size) {
        pkt_size = hdr_size + (this->size - seq);
    } else {
        pkt_size = hdr_size + mss;
    }

    Packet *p = new Packet(get_current_time(), this, seq, priority, pkt_size, src, dst);
    p->capability_seq_num_in_data = token_seq;
    p->capa_data_seq = data_seq;
    total_pkt_sent++;
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), p, src->queue));
    return p;
}

void RankingFlow::receive(Packet *p) {
    if (p->type == RANKING_NRTS) {
        if(p->dst->id == params.num_hosts) {
            dynamic_cast<RankingTopology*>(topology)->arbiter->receive_nrts((RankingNRTS*) p);
        } else {
            ((RankingHost*) this->dst)->receive_nrts((RankingNRTS*) p);
        }
    } 
    if(this->finished) {
        delete p;
        return;
    }
    if (p->type == RANKING_RTS) {
        if(this->rts_received == false) {
            ((RankingHost*) this->dst)->receive_rts((RankingRTS*) p);
        }
    } else if(p->type == RANKING_LISTSRCS) {
        dynamic_cast<RankingTopology*>(topology)->arbiter->receive_listsrcs((RankingListSrcs*) p);
       //((RankingListRTS*) p)->listRTS->listFlows.clear();
    } else if (p->type == RANKING_GOSRC) {
        ((RankingHost*) this->src)->receive_gosrc((RankingGoSrc*) p);
    } else if (p->type == RANKING_TOKEN) {
        ((RankingHost*) this->src)->receive_token((RankingToken*) p);
    } else if (p->type == NORMAL_PACKET) {
        if (this->first_byte_receive_time == -1) {
            this->first_byte_receive_time = get_current_time();
        }
        
        if (!rts_received) {
            this->receive_short_flow();
        }
        if(debug_flow(this->id)){
            std::cout << get_current_time() << " flow " << this->id << "receive data seq " << p->capa_data_seq  << std::endl;
        }
        if(packets_received.count(p->capa_data_seq) == 0){

            packets_received.insert(p->capa_data_seq);
            received_count++;
            while(received_until < size_in_pkt && packets_received.count(received_until) > 0)
            {
                received_until++;
            }
            if(debug_flow(this->id)){
                std::cout << get_current_time() << " flow " << this->id << " receive util " << received_until << std::endl;
            }
        }

        received_bytes += (p->size - hdr_size);
        if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
            num_outstanding_packets -= ((p->size - hdr_size) / (mss));
        else
            num_outstanding_packets = 0;
        total_queuing_time += p->total_queuing_delay;
        if(p->capability_seq_num_in_data > largest_token_seq_received)
            largest_token_seq_received = p->capability_seq_num_in_data;
//        if(debug_flow(this->id))
//            std::cout << get_current_time() << " flow " << this->id << " received pkt " << received_count << "\n";
        if (received_count >= goal) {
            this->finished_at_receiver = true;
            send_ack();
            if(debug_flow(this->id))
                std::cout << get_current_time() << " flow " << this->id << " send ACK" << std::endl;
        } else {
            // check token_gap is reduced
            if (this->token_gap() <= params.token_window) {
                RankingHost * dst = (RankingHost*)this->dst;
                // sending token process should be restarted if the timeout event happens
                if(dst->active_src_from_arbiter != NULL && 
                dst->active_src_from_arbiter->id == p->flow->src->id && 
                dst->src_to_flows[p->flow->src->id].top()->id == p->flow->id) { 
                    if (dst->token_send_evt != NULL && dst->token_send_evt->is_timeout_evt) {
                        if(debug_host(dst->id)) {
                            std::cout << get_current_time() << " cancel timeout event " << this->id 
                            << " for dst " << dst->id << std::endl;
                        }
                        dst->token_send_evt->cancelled = true;
                        dst->token_send_evt = NULL;
                    }

                    if(dst->token_send_evt == NULL){
                        if(debug_host(dst->id)) {
                            std::cout << get_current_time() << " restart sending tokens for flow " << this->id 
                            << " for dst " << dst->id << std::endl;
                        }
                        dst->schedule_token_proc_evt(0, false);
                    }
                }
            }
        }

    }  else if (p->type == ACK_PACKET) {
        if(debug_flow(this->id))
            std::cout << get_current_time() << " flow " << this->id << " received ack" << std::endl;
        this->packets_received.clear();
        this->clear_token();
        // ((RankingHost*)(this->src))->active_sending_flow = NULL;
        sending_nrts();
        add_to_event_queue(new FlowFinishedEvent(get_current_time(), this));
    } else {
        assert(false);
    }
    //     else if (p->type == RANKING_SCHEDULE) {
    //     if(debug_flow(this->id))
    //         std::cout << get_current_time() << " flow " << this->id << " received schedule\n";
    //     ((RankingHost*) this->src)->receive_schedule_pkt((RankingSchedulePkt*) p);
    // }
    delete p;
}

// receiver side

void RankingFlow::receive_short_flow() {
    this->rts_received = true;
    auto init_token = this->init_token_size();
    auto dstination = (RankingHost*)(this->dst);
    if (init_token == 0) {
        assert(false);
    }
    this->token_count = init_token;
    this->last_token_data_seq_num_sent = init_token - 1;
    if(this->token_count == this->token_goal){
        this->redundancy_ctrl_timeout = get_current_time() + init_token * params.get_full_pkt_tran_delay() * 2;
    }
    dstination->hold_on += init_token;
    dstination->active_receiving_flows.push(this);
    if (dstination->token_send_evt != NULL && dstination->token_send_evt->is_timeout_evt) {
        dstination->token_send_evt->cancelled = true;
        dstination->token_send_evt = NULL;
    }
    if(dstination->token_send_evt == NULL){
        dstination->schedule_token_proc_evt(0, false);
    }
}

int RankingFlow::remaining_pkts(){
    return std::max((int)0, (int)(this->size_in_pkt - this->received_count));
}

int RankingFlow::token_gap(){
    if (this->token_count - this->largest_token_seq_received < 0) {
        std::cout << "flow " << this->id;
        std::cout << " token count " << this->token_count;
        std::cout << " largest_token_seq_received " << this->largest_token_seq_received << std::endl;
    }
    assert(this->token_count - this->largest_token_seq_received >= 0);
    return this->token_count - this->largest_token_seq_received - 1;
}

void RankingFlow::relax_token_gap()
{
    assert(this->token_count - this->largest_token_seq_received >= 0);
    this->largest_token_seq_received = this->token_count - params.token_window;
}

int RankingFlow::get_next_token_seq_num()
{
    int count = 0;
    int data_seq = (last_token_data_seq_num_sent + 1)%this->size_in_pkt;
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

void RankingFlow::send_token_pkt(){
    int data_seq_num = this->get_next_token_seq_num();
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " flow " << this->id << " send token " << this->token_count << "data seq number:" << data_seq_num << "\n";
    } 
    last_token_data_seq_num_sent = data_seq_num;
    RankingToken* cp = new RankingToken(this, this->dst, this->src, params.token_timeout * params.get_full_pkt_tran_delay(), this->remaining_pkts(), this->token_count, data_seq_num);
    this->token_count++;
    this->token_packet_sent_count++;
    this->latest_token_sent_time = get_current_time();
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), cp, dst->queue));
}
int RankingFlow::init_token_size(){
    return this->size_in_pkt <= params.token_initial?this->size_in_pkt:0;
}

RankingArbiterProcessingEvent::RankingArbiterProcessingEvent(double time, RankingArbiter* a) : Event(RANKING_ARBITER_PROCESSING, time) {
    this->arbiter = a;
}

RankingArbiterProcessingEvent::~RankingArbiterProcessingEvent() {
}

void RankingArbiterProcessingEvent::process_event() {
    this->arbiter->arbiter_proc_evt = NULL;
    this->arbiter->schedule_epoch();
}

