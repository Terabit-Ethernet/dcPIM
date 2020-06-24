#include "math.h"

#include "../coresim/event.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"

#include "pimhost.h"
#include "pimflow.h"

#include "../run/params.h"

extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern long long num_outstanding_packets;

PimFlow::PimFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d)
    : FountainFlow(id, start_time, size, s, d) {
    // this->finished_at_receiver = false;
    // this->capability_count = 0;
    this->finished_at_receiver = false;
    this->token_count = 0;
    this->redundancy_ctrl_timeout = -1;
    this->token_goal = (int)(std::ceil(this->size_in_pkt * 1.00));
    this->remaining_pkts_at_sender = this->size_in_pkt;
    this->largest_token_seq_received = -1;
    this->largest_token_data_seq_received = -1;
    this->total_queuing_time = 0;
    this->rts_received = false;
    this->latest_token_sent_time = -1;
    this->latest_data_pkt_sent_time = -1;
    this->token_packet_sent_count = 0;
    this->token_waste_count = 0;
    this->last_token_data_seq_num_sent = -1;
    this->received_until = 0;
    this->received_count = 0;
    this->first_loop = false;
}


void PimFlow::start_flow()
{
    //assign_init_capability();
    ((PimHost*) this->src)->start_flow(this);
}
bool PimFlow::is_small_flow() {
    return this->size_in_pkt <= params.pim_small_flow;
}
void PimFlow::send_grants(int iter, int epoch, int remaining_sz, int total_links, bool prompt) {

    if(debug_flow(id) || debug_host(this->dst->id)) {
        std::cout << this->dst->id << std::endl;
        std::cout << get_current_time() << " iter " << iter << "send grants for flow " 
        << id  << " to dst:" << this->dst->id << "link: " << total_links << std::endl; 
    }
    PIMGrants* grants = new PIMGrants(this, this->src, this->dst, iter, epoch, remaining_sz, total_links, prompt);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), grants, src->queue));
}

void PimFlow::send_grantsr(int iter, int epoch, int total_link) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << " iter " << iter <<  " send grantsr for flow " << id  << " to dst:" << this->dst->id << std::endl; 
    }
    GrantsR* grantsr = new GrantsR(this, this->src, this->dst, iter, epoch, total_link);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), grantsr, src->queue));
}

void PimFlow::send_req(int iter, int epoch, int total_links) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << "send req for flow " << id 
        << " to src:" << this->src->id << "link: " << total_links << std::endl; 
    }
    PIMREQ* req = new PIMREQ(this, this->dst, this->src, iter, epoch, this->remaining_pkts(), total_links);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), req, dst->queue));
}

void PimFlow::send_accept_pkt(int iter, int epoch, int total_links){
    if(debug_flow(id) || debug_host(this->dst->id)) {
        std::cout << get_current_time() << " iter " << iter  << 
        " send accept for flow " << id  << " to src:" << this->src->id << "link: " << total_links << std::endl; 
    }
    AcceptPkt* dpkt = new AcceptPkt(this, this->dst, this->src, iter, epoch, total_links);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), dpkt, dst->queue));
}
// void PimFlow::send_offer_pkt(int iter, int epoch, bool is_free) {
//     if(debug_flow(id)) {
//         std::cout << get_current_time() << "send offer packet for flow " << id  << " to src:" << this->src->id << std::endl; 
//     }
//     OfferPkt* offer_pkt = new OfferPkt(this, this->dst, this->src, is_free, iter, epoch);
//     add_to_event_queue(new PacketQueuingEvent(get_current_time(), offer_pkt, dst->queue));
// }

void PimFlow::send_pending_data(Pim_Token* token) 
{
    // auto token = this->use_token();
    int token_data_seq = token->data_seq_num;
    int token_seq = token->seq_num;
    // delete token;

    Packet *p;
    if (next_seq_no + mss <= this->size) {
        p = this->send(next_seq_no, token_seq, token_data_seq, params.packet_priority(this->size_in_pkt, params.token_initial));
        next_seq_no += mss;
    } else {
        p = this->send(next_seq_no, token_seq, token_data_seq, params.packet_priority(this->size_in_pkt, params.token_initial));
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

Packet* PimFlow::send(uint32_t seq, int token_seq, int data_seq, int priority)
{
    // fairness testing
    // if(params.print_max_min_fairness) {
    //     ((PimHost*)dst)->src_to_[src->id]++;
    // }
    this->latest_data_pkt_sent_time = get_current_time();
    
    uint32_t pkt_size = 1500;
    // if (seq + mss > this->size) {
    //     pkt_size = hdr_size + (this->size - seq);
    // } else {
    //     pkt_size = hdr_size + mss;
    // }

    Packet *p = new Packet(get_current_time(), this, seq, priority, pkt_size, src, dst);
    p->capability_seq_num_in_data = token_seq;
    p->capa_data_seq = data_seq;
    total_pkt_sent++;
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), p, src->queue));
    return p;
}
// void PimFlow::send_pending_data_low_priority() {
//     Packet *p;
//     auto data_seq = get_next_data_seq_num();
//     // if (next_seq_no + mss <= this->size) {
//     p = this->send(next_seq_no, data_seq, 7);
//     next_seq_no++;
//     // } else {
//     //     p = this->send(next_seq_no, data_seq, 7);
//     //     next_seq_no++;
//     // }
//   //  assert(false);
//     if(debug_flow(this->id))
//         std::cout << get_current_time() << " flow " << this->id << " send pkt data seq:" << data_seq << "\n";

//     double td = src->queue->get_transmission_delay(p->size);
//     assert(((SchedulingHost*) src)->host_proc_event == NULL);
//     ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
//     add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
// }
void PimFlow::send_ack(Packet* p) {
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " send ack: " << p->seq_no << " " << p->capa_data_seq << std::endl;
    }
    Packet* a = new PIMAck(this, p->seq_no, p->capa_data_seq, hdr_size, dst, src);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), a, dst->queue));
}

void PimFlow::receive(Packet *p) {

    if(this->finished) {
        delete p;
        return;
    }
    if(debug_host(p->dst->id)) {
        std::cout << get_current_time() << "receive pkt size: " << p->size << " pkt type:" << p->type << "for flow " << this->id  << std::endl;
    }
    if (p->type == FLOW_RTS) {
        if(this->rts_received == false) {
            ((PimHost*) this->dst)->receive_rts((FlowRTS*) p);
        }
    } else if(p->type == PIM_REQ_PACKET) {
        auto s = (PimHost*)src;
        int epoch = ((PIMREQ*)p)->epoch;
        if(s->epochs.count(epoch) <= 0) {
            return;
        }
        // if(d->cur_epoch == epoch) {
        assert(s->epochs.count(epoch) > 0);
        s->epochs[epoch].receive_req((PIMREQ*)p);
        // }
    } else if (p->type == PIM_GRANTS_PACKET) {
        auto d = (PimHost*)dst;
        int epoch  = ((PIMGrants*)p)->epoch;
        if(d->epochs.count(epoch) <= 0) {
            return;
        }
        // if(s->cur_epoch == epoch) {
            assert(d->epochs.count(epoch) > 0);
            d->epochs[epoch].receive_grants((PIMGrants*)p);
        // }
    } else if (p->type == ACCEPT_PACKET) {
        auto s = (PimHost*)src;
        int epoch = ((AcceptPkt*)p)->epoch;
        // if(d->cur_epoch == epoch) {
        if(s->epochs.count(epoch) <= 0) {
            return;
        }
            assert(s->epochs.count(epoch) > 0);
            s->epochs[epoch].receive_accept_pkt((AcceptPkt*)p);
        // }
    } else if(p->type == GRANTSR_PACKET) {
        auto d = (PimHost*)dst;
        int epoch = ((GrantsR*)p)->epoch;
        if(d->epochs.count(epoch) <= 0) {
            return;
        }
        // if(s->cur_epoch == epoch) {
            assert(d->epochs.count(epoch) > 0);
            d->epochs[epoch].receive_grantsr((GrantsR*)p);
        // }
    } else if (p->type == PIM_TOKEN) {
        ((PimHost*) this->src)->receive_token((PIMToken*) p);
    } else if (p->type == NORMAL_PACKET) {
        if (this->first_byte_receive_time == -1) {
            this->first_byte_receive_time = get_current_time();
        }
        
        if (!rts_received) {
            this->receive_short_flow();
        }
        if(debug_flow(this->id)){
            std::cout << get_current_time() << " flow " << this->id << "receive data seq " << p->capa_data_seq << " seq number:" << p->capability_seq_num_in_data  << " total q delay: " << p->total_queuing_delay << std::endl;
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
            if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
                num_outstanding_packets -= ((p->size - hdr_size) / (mss));
            else
                num_outstanding_packets = 0;
            if(largest_token_data_seq_received < p->capa_data_seq) {
                largest_token_data_seq_received = p->capa_data_seq;
            }
        }

        received_bytes += (p->size - hdr_size);
        total_queuing_time += p->total_queuing_delay;
        if(p->capability_seq_num_in_data > largest_token_seq_received)
            largest_token_seq_received = p->capability_seq_num_in_data;
//        if(debug_flow(this->id))
//            std::cout << get_current_time() << " flow " << this->id << " received pkt " << received_count << "\n";
        if (received_count >= goal) {
            sending_ack();
            ((PimHost*)p->dst)->flow_finish_at_receiver(p);
            if(debug_flow(this->id))
                std::cout << get_current_time() << " flow " << this->id << " send ACK" << std::endl;
        } else {
            // check token_gap is reduced
            if (this->token_gap() <= params.token_window) {
                PimHost * dst = (PimHost*)this->dst;
                // sending token process should be restarted if the timeout event happens
                 // std::cout << "flow id" << p->flow->id << "source id:" << p->src->id << " " <<  p->dst->id << std::endl;
                auto best_large_flow = dst->get_top_unfinish_flow(p->flow->src->id);
                // std::cout << p->flow->id << " " << p->flow->dst->id << std::endl;
                if(best_large_flow == (PimFlow*)p->flow) {
                    for(unsigned int i = 0; i < dst->match_sender_links.size(); i++) {
                        if(dst->match_sender_links[i].target == (PimHost*)p->flow->src) {
                            if (dst->match_sender_links[i].token_send_evt != NULL && 
                                dst->match_sender_links[i].token_send_evt->is_timeout_evt) {
                                dst->match_sender_links[i].token_send_evt->cancelled = true;
                                dst->match_sender_links[i].token_send_evt = NULL;
                            }

                            if(dst->match_sender_links[i].token_send_evt == NULL)
                                dst->match_sender_links[i].schedule_token_proc_evt(0, false);
                            
                        }
                    }
                }
            }
        }
    } else if(p->type == ACK_PACKET) {
        if(debug_flow(this->id))
            std::cout << get_current_time() << " flow " << this->id << " received ack" << std::endl;
        this->packets_received.clear();
        this->clear_token();
        // ((RufHost*)(this->src))->active_sending_flow = NULL;
        add_to_event_queue(new FlowFinishedEvent(get_current_time(), this));
    } else {
        std::cout << p->type << std::endl;
        assert(false);
    }
    delete p;
}

int PimFlow::init_token_size(){
    return this->size_in_pkt <= params.token_initial?this->size_in_pkt:0;
}

void PimFlow::receive_short_flow() {
    this->rts_received = true;
    auto init_token = this->init_token_size();
    auto dstination = (PimHost*)(this->dst);
    if (init_token == 0) {
        assert(false);
    }
    this->token_count = init_token;
    this->last_token_data_seq_num_sent = init_token - 1;
    if(this->token_count == this->token_goal){
        this->redundancy_ctrl_timeout = get_current_time() + init_token * params.get_full_pkt_tran_delay() + params.token_resend_timeout;
    }
    // if(debug_flow(this->id)) {
    //     std::cout << get_current_time() << " flow id " << this->id << " token_count: " << init_token <<" redundancy_ctrl_timeout:" << this->redundancy_ctrl_timeout << "\n";
    // }
    dstination->hold_on = init_token;
    // if (dstination->token_send_evt != NULL && dstination->token_send_evt->is_timeout_evt) {
    //     dstination->token_send_evt->cancelled = true;
    //     dstination->token_send_evt = NULL;
    // }
    // if(dstination->token_send_evt == NULL) {
    //     dstination->schedule_token_proc_evt(0, false);
    // }
}

int PimFlow::remaining_pkts(){
    return std::max((int)0, (int)(this->size_in_pkt - this->received_count));
}

int PimFlow::token_gap(){
    if (this->token_count - this->largest_token_seq_received < 0) {
        std::cout << "flow " << this->id;
        std::cout << " token count " << this->token_count;
        std::cout << " largest_token_seq_received " << this->largest_token_seq_received << std::endl;
    }
    assert(this->token_count - this->largest_token_seq_received >= 0);
    return this->token_count - this->largest_token_seq_received - 1;
}

void PimFlow::relax_token_gap()
{
    assert(this->token_count - this->largest_token_seq_received >= 0);
    this->largest_token_seq_received = this->token_count - params.token_window;
}

void PimFlow::clear_token(){
    // for(auto i = this->tokens.begin(); i != this->tokens.end(); i++) {
    //     delete (*i);
    //     *i = NULL;
    // }
    // this->tokens.clear();
}

// bool PimFlow::has_token(){
//     while(!this->tokens.empty()){
//         //expired token
//         if(this->tokens.front()->timeout < get_current_time())
//         {
//             if(debug_flow(this->id)) {
//                 std::cout << get_current_time() << " token timeout " << this->tokens.front()->timeout << " data seq num:" <<  this->tokens.front()->data_seq_num << std::endl;
//             }
//             delete this->tokens.front();
//             this->tokens.pop_front();
//         }
//         //not expired
//         else
//         {
//             return true;
//         }
//     }
//     return false;
// }

// Pim_Token* PimFlow::use_token(){
//     assert(!this->tokens.empty() && this->tokens.front()->timeout >= get_current_time());
//     auto token = this->tokens.front();
//     this->tokens.pop_front();
//     return token;
// }

// sender side
void PimFlow::assign_init_token(){
    //sender side
    int init_token = this->init_token_size();
    // if(debug_flow(this->id)) {
    //     std::cout << "initial token for flow " << this->id << " token size:" << init_token << std::endl;
    // }
    for(int i = 0; i < init_token; i++){
        Pim_Token* c = new Pim_Token();
        // free token never timeout
        c->timeout = get_current_time() + 100000000.0;
        c->seq_num = i;
        c->data_seq_num = i;
        c->flow = this;
        c->priority = 0;
        // this->tokens.push_back(c);
        ((PimHost*) this->src)->token_q.push(c);
    }
}

int PimFlow::get_next_token_seq_num()
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

void PimFlow::send_token_pkt(){
    int data_seq_num = this->get_next_token_seq_num();
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " flow " << this->id << " send token " << this->token_count << "data seq number:" << data_seq_num << "\n";
    } 
    last_token_data_seq_num_sent = data_seq_num;

    auto cp = new PIMToken(this, this->dst, this->src, params.token_timeout, this->remaining_pkts(), this->token_count, data_seq_num);
    this->token_count++;
    this->token_packet_sent_count++;
    this->latest_token_sent_time = get_current_time();
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), cp, dst->queue));
}

void PimFlow::sending_ack() {
    Packet *ack = new PlainAck(this, 0, hdr_size, dst, src);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), ack, dst->queue));
}
void PimFlow::sending_rts() {
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << "sending rts flow " << this->id << " src " << this->src->id << "size : " << size_in_pkt <<std::endl;
    }
    FlowRTS* rts = new FlowRTS(this, this->src, this->dst, this->size_in_pkt);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), rts, src->queue));
}