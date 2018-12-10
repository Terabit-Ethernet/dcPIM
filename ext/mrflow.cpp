#include "math.h"

#include "../coresim/event.h"
#include "../coresim/packet.h"
#include "../coresim/debug.h"

#include "mrhost.h"
#include "mrflow.h"

#include "../run/params.h"

extern double get_current_time();
extern void add_to_event_queue(Event*);
extern DCExpParams params;
extern uint32_t num_outstanding_packets;

MrFlow::MrFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d)
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


void MrFlow::start_flow()
{
    //assign_init_capability();
    ((MrHost*) this->src)->start_flow(this);
}
bool MrFlow::is_small_flow() {
    return this->size_in_pkt < params.mr_small_flow;
}
void MrFlow::send_cts(int iter, int round) {
    if(debug_flow(id) || debug_host(this->dst->id)) {
        std::cout << get_current_time() << " iter " << iter << "send cts for flow " << id  << " to src:" << this->src->id << std::endl; 
    }
    MRCTS* cts = new MRCTS(this, this->dst, this->src, iter, round);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), cts, dst->queue));
}

void MrFlow::send_ctsr(int iter, int round) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << " iter " << iter <<  " send ctsr for flow " << id  << " to src:" << this->src->id << std::endl; 
    }
    CTSR* ctsr = new CTSR(this, this->dst, this->src, iter, round);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), ctsr, dst->queue));
}

void MrFlow::send_rts(int iter, int round) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << "send rts for flow " << id << " to dst:" << this->dst->id << std::endl; 
    }
    MRRTS* rts = new MRRTS(this, this->src, this->dst, iter, round);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), rts, src->queue));
}

void MrFlow::send_decision_pkt(int iter, int round, bool accept){
    if(debug_flow(id) || debug_host(this->dst->id)) {
        std::cout << get_current_time() << " iter " << iter <<  " send decision for flow " << id  << " to dst:" << this->dst->id << std::endl; 
    }
    DecisionPkt* dpkt = new DecisionPkt(this, this->src, this->dst, accept, iter, round);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), dpkt, src->queue));
}
void MrFlow::send_offer_pkt(int iter, int round, bool is_free) {
    if(debug_flow(id)) {
        std::cout << get_current_time() << "send offer packet for flow " << id  << " to src:" << this->src->id << std::endl; 
    }
    OfferPkt* offer_pkt = new OfferPkt(this, this->dst, this->src, is_free, iter, round);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), offer_pkt, dst->queue));
}

void MrFlow::send_pending_data() {
	Packet *p;
    auto data_seq = get_next_data_seq_num();
	if (next_seq_no + mss <= this->size) {
		p = this->send(next_seq_no, data_seq, this->size_in_pkt > params.capability_prio_thresh?2:1);
        next_seq_no++;
	} else {
		p = this->send(next_seq_no, data_seq, this->size_in_pkt > params.capability_prio_thresh?2:1);
        next_seq_no++;
	}
   // std::cout << params.capability_prio_thresh << std:: endl;
  //  assert(false);
    if(debug_flow(this->id))
        std::cout << get_current_time() << " flow " << this->id << " send pkt data seq:" << data_seq << "\n";

    double td = src->queue->get_transmission_delay(p->size);
    assert(((SchedulingHost*) src)->host_proc_event == NULL);
    ((SchedulingHost*) src)->host_proc_event = new HostProcessingEvent(get_current_time() + td + INFINITESIMAL_TIME, (SchedulingHost*) src);
    add_to_event_queue(((SchedulingHost*) src)->host_proc_event);
}

void MrFlow::send_ack(Packet* p) {
    if(debug_flow(this->id)) {
        std::cout << get_current_time() << " send ack: " << p->seq_no << " " << p->capa_data_seq << std::endl;
    }
    Packet* a = new MRAck(this, p->seq_no, p->capa_data_seq, hdr_size, dst, src);
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), a, dst->queue));
}

void MrFlow::receive_ack(MRAck* p) {
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
        if(debug_flow(this->id)) {
            std::cout << get_current_time() << " flow " << this->id << " ack util " << ack_until << std::endl;
        }
        remaining_pkts_at_sender--;
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
        auto receiver = (MrHost*) this->dst;
        auto de_receiver = ((MrHost*) this->src)->receiver;
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

void MrFlow::receive(Packet *p) {
    if(this->finished) {
        delete p;
        return;
    }
    if(p->type == MRRTS_PACKET) {
        ((MrHost*)dst)->receive_rts((MRRTS*)p);
    } else if (p->type == OFFER_PACKET) {
        ((MrHost*)src)->receive_offer_packet((OfferPkt*)p);
    } else if (p->type == MRCTS_PACKET) {
        ((MrHost*)src)->receive_cts((MRCTS*)p);
    } else if (p->type == DECISION_PACKET) {
        ((MrHost*)dst)->receive_decision_pkt((DecisionPkt*)p);
    } else if(p->type == CTSR_PACKET) {
       ((MrHost*)src)->receive_ctsr((CTSR*)p);
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
    } else if(p->type == MR_ACK) {
        this->receive_ack((MRAck*)p);
    } else {
        assert(false);
    }
    delete p;
}

Packet* MrFlow::send(uint32_t seq, uint32_t data_seq, int priority) {
    this->latest_data_pkt_send_time = get_current_time();
	
	uint32_t pkt_size = 1500;
    last_data_seq_num_sent = data_seq;
    Packet *p = new Packet(get_current_time(), this, seq, priority, pkt_size, src, dst);
    p->capa_data_seq = data_seq;
    total_pkt_sent++;
    add_to_event_queue(new PacketQueuingEvent(get_current_time(), p, src->queue));
    return p;
}

int MrFlow::get_next_data_seq_num() {
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

int MrFlow::gap() {
    if(this->next_seq_no - this->largest_seq_ack < 0) {
        std::cout << "flow id" << id << " " << this->next_seq_no << " " << this->largest_seq_ack << std::endl;
    }
    assert(this->next_seq_no - this->largest_seq_ack >= 0);
    return this->next_seq_no - this->largest_seq_ack;
}

void MrFlow::relax_gap() {
    assert(this->next_seq_no - this->largest_seq_ack >= 0);
    this->largest_seq_ack = this->next_seq_no - params.mr_window_size;
}
