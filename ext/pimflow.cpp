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
    this->redundancy_ctrl_timeout = -1;
    // this->capability_goal = (int)(std::ceil(this->size_in_pkt * 1.00));
    this->remaining_pkts_at_sender = this->size_in_pkt;
    this->ack_until = 0;
    this->largest_seq_ack = -1;
    this->last_data_seq_num_sent = -1;
    this->latest_data_pkt_send_time = -1;
    this->first_loop = false;
    this->next_seq_no = 0;
    // this->received_util = 0;
    // this->largest_cap_seq_received = -1;
    // this->total_queuing_time = 0;
    // this->rts_received = false;
    // this->latest_cap_sent_time = start_time;
    // this->latest_data_pkt_send_time = start_time;
    // this->capability_packet_sent_count = 0;
    // this->capability_waste_count = 0;
    // this->notified_num_flow_at_sender = 1;
    // this->last_capa_data_seq_num_sent = -1;
    // this->received_count = 0;
}


void PimFlow::start_flow()
{
    //assign_init_capability();
    ((PimHost*) this->src)->start_flow(this);
}
bool PimFlow::is_small_flow() {
    return this->size_in_pkt <= params.pim_small_flow;
}
void PimFlow::send_grants(int iter, int epoch, bool prompt) {
    if(debug_flow(id) || debug_host(this->dst->id)) {
        std::cout << get_current_time() << " iter " << iter << "send grants for flow " << id  << " to src:" << this->src->id << std::endl; 
    }
    PIMGrants* grants = new PIMGrants(this, this->dst, this->src, iter, epoch, prompt);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), grants, dst->queue));
}

void PimFlow::send_grantsr(int iter, int epoch) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << " iter " << iter <<  " send grantsr for flow " << id  << " to src:" << this->src->id << std::endl; 
    }
    GrantsR* grantsr = new GrantsR(this, this->dst, this->src, iter, epoch);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), grantsr, dst->queue));
}

void PimFlow::send_rts(int iter, int epoch) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << "send rts for flow " << id << " to dst:" << this->dst->id << std::endl; 
    }
    PIMRTS* rts = new PIMRTS(this, this->src, this->dst, iter, epoch);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), rts, src->queue));
}

void PimFlow::send_accept_pkt(int iter, int epoch, bool accept){
    if(debug_flow(id) || debug_host(this->src->id)) {
        std::cout << get_current_time() << " iter " << iter <<  " send accept " << accept <<  " for flow " << id  << " to dst:" << this->dst->id << std::endl; 
    }
    AcceptPkt* dpkt = new AcceptPkt(this, this->src, this->dst, accept, iter, epoch);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), dpkt, src->queue));
}
// void PimFlow::send_offer_pkt(int iter, int epoch, bool is_free) {
//     if(debug_flow(id)) {
//         std::cout << get_current_time() << "send offer packet for flow " << id  << " to src:" << this->src->id << std::endl; 
//     }
//     OfferPkt* offer_pkt = new OfferPkt(this, this->dst, this->src, is_free, iter, epoch);
//     add_to_event_queue(new PacketQueuingEvent(get_current_time(), offer_pkt, dst->queue));
// }

void PimFlow::send_pending_data() {
	Packet *p;
    auto data_seq = get_next_data_seq_num();
	// if (next_seq_no + mss <= this->size) {
	p = this->send(next_seq_no, data_seq, params.packet_priority(this->size_in_pkt, params.pim_small_flow));
    next_seq_no++;
	// } else {
	// 	p = this->send(next_seq_no, data_seq, params.packet_priority(this->size_in_pkt, params.pim_small_flow));
 //        next_seq_no++;
	// }
  //  assert(false);
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send pkt data seq:" << data_seq << "\n";

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}

void PimFlow::send_pending_data_low_priority() {
    Packet *p;
    auto data_seq = get_next_data_seq_num();
    // if (next_seq_no + mss <= this->size) {
    p = this->send(next_seq_no, data_seq, 7);
    next_seq_no++;
    // } else {
    //     p = this->send(next_seq_no, data_seq, 7);
    //     next_seq_no++;
    // }
  //  assert(false);
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send pkt data seq:" << data_seq << "\n";

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}
void PimFlow::send_ack(Packet* p) {
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " send ack: " << p->seq_no << " " << p->capa_data_seq << std::endl;
    }
    Packet* a = new PIMAck(this, p->seq_no, p->capa_data_seq, hdr_size, dst, src);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), a, dst->queue));
}

void PimFlow::receive_ack(PIMAck* p) {
    // Determing which ack to send
    // auto sack_list = p->sack_list;
    // if(this->next_seq_no < p->seq_no_acked)
    //     this->next_seq_no = p->seq_no_acked;
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " receive ack : data seq" << p->data_seq_no_acked  << " seq:" << p->seq_no << "\n";

    if(ack_received.count(p->data_seq_no_acked) == 0) {
        this->ack_received.insert(p->data_seq_no_acked);
        while(ack_until < size_in_pkt && ack_received.count(ack_until) > 0) {
            ack_until++;
        }
        remaining_pkts_at_sender--;

        if(debug_flow(this->id)) {
            std::cout << get_current_time() << " flow " << this->id << " ack util " << ack_until << " remaining packets:"  << remaining_pkts_at_sender << std::endl;
        }
    }
    if(this->largest_seq_ack < int(p->seq_no)) {
        this->largest_seq_ack = p->seq_no;
    }
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " flow " << this->id << " largerst seq ack " << largest_seq_ack << std::endl;
    }
    if(remaining_pkts_at_sender == 0) {
        add_to_event_queue(new FlowFinishedEvent(get_current_time(), this));
        ack_received.clear();
        packets_received.clear();
        return;
    }
    if(((SchedulingHost*) src)->host_proc_event != NULL && 
        ((SchedulingHost*) src)->host_proc_event->is_timeout) {
        auto receiver = (PimHost*) this->dst;
        auto de_receiver = ((PimHost*) this->src)->receiver;
        if(this->redundancy_ctrl_timeout > get_current_time()) {
            return;
        }
        if(this->is_small_flow() || (receiver == de_receiver && !this->finished)) {
            if(debug_flow(this->id)) {
                std::cout << get_current_time() << " reset host processing for flow " << this->id << " src id:" << this->src->id << "receiver " << receiver->id << " receiver " << de_receiver->id << std::endl;
            }
            ((SchedulingHost*) src)->host_proc_event->cancelled = true;
            ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time(), (SchedulingHost*) this->src);
            add_to_event_queue(((SchedulingHost*) src)->host_proc_event);

        }
    }
}

void PimFlow::receive(Packet *p) {

    if(this->finished) {
        delete p;
        return;
    }
    if(p->type == PIM_RTS_PACKET) {
        auto d = (PimHost*)dst;
        int epoch = ((PIMRTS*)p)->epoch;

        // if(d->cur_epoch == epoch) {
        assert(d->epochs.count(epoch) > 0);
        d->epochs[epoch].receive_rts((PIMRTS*)p);
        // }
    } else if (p->type == OFFER_PACKET) {
        assert(false);
        // auto s = (PimHost*)src;
        // int epoch = ((OfferPkt*)p)->epoch;
        // if(s->cur_epoch < epoch) {
        //     assert(s->epochs.count(epoch) > 0);
        //     s->epochs[epoch].receive_offer_packet((OfferPkt*)p);
        // }
    } else if (p->type == PIM_GRANTS_PACKET) {
        auto s = (PimHost*)src;
        int epoch  = ((PIMGrants*)p)->epoch;
        // if(s->cur_epoch == epoch) {
            assert(s->epochs.count(epoch) > 0);
            s->epochs[epoch].receive_grants((PIMGrants*)p);
        // }
    } else if (p->type == ACCEPT_PACKET) {
        auto d = (PimHost*)dst;
        int epoch = ((AcceptPkt*)p)->epoch;
        // if(d->cur_epoch == epoch) {
            assert(d->epochs.count(epoch) > 0);
            d->epochs[epoch].receive_accept_pkt((AcceptPkt*)p);
        // }
    } else if(p->type == GRANTSR_PACKET) {
        auto s = (PimHost*)src;
        int epoch = ((GrantsR*)p)->epoch;
        // if(s->cur_epoch == epoch) {
            assert(s->epochs.count(epoch) > 0);
            s->epochs[epoch].receive_grantsr((GrantsR*)p);
        // }
    } else if (p->type == NORMAL_PACKET) {
        if (this->first_byte_receive_time == -1) {
            this->first_byte_receive_time = get_current_time();
        }
        if(packets_received.count(p->capa_data_seq) == 0){
            packets_received.insert(p->capa_data_seq);
            if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
                num_outstanding_packets -= ((p->size - hdr_size) / (mss));
            else
                num_outstanding_packets = 0;
        }
        this->send_ack(p);
    } else if(p->type == PIM_ACK) {
        this->receive_ack((PIMAck*)p);
    } else {
        assert(false);
    }
    delete p;
}

Packet* PimFlow::send(uint32_t seq, uint32_t data_seq, int priority) {
    this->latest_data_pkt_send_time = get_current_time();
	
	uint32_t pkt_size = 1500;
    last_data_seq_num_sent = data_seq;
    Packet *p = new Packet(get_current_time(), this, seq, priority, pkt_size, src, dst);
    p->capa_data_seq = data_seq;
    total_pkt_sent++;
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), p, src->queue));
    return p;
}

int PimFlow::get_next_data_seq_num() {
    int count = 0;
    int data_seq = (last_data_seq_num_sent + 1) % this->size_in_pkt;
    while(count < this->size_in_pkt)
    {
        if(ack_received.count(data_seq) == 0)
        {
            if(!(data_seq >= 0 && data_seq < size_in_pkt)) {
                std::cout << "flow id" << id << " " << data_seq << " " << size_in_pkt << std::endl;
            }
            assert(data_seq >= 0 && data_seq < size_in_pkt);
            return data_seq;
        }
        else
        {
            data_seq++;
            if(data_seq >= size_in_pkt)
            {
                data_seq = ack_until;
            }

        }
        count++;
    }
    return data_seq;
}

int PimFlow::gap() {
    if(this->next_seq_no - this->largest_seq_ack < 0) {
        std::cout << "flow id" << id << " " << this->next_seq_no << " " << this->largest_seq_ack << std::endl;
    }
    assert(this->next_seq_no - this->largest_seq_ack >= 0);
    return this->next_seq_no - this->largest_seq_ack;
}

void PimFlow::relax_gap() {
    assert(this->next_seq_no - this->largest_seq_ack >= 0);
    this->largest_seq_ack = this->next_seq_no - params.pim_window_size;
}
