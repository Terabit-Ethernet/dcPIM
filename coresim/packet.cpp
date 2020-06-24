#include "packet.h"
#include "../run/params.h"

extern DCExpParams params;
uint32_t Packet::instance_count = 0;

Packet::Packet(
        double sending_time, 
        Flow *flow, 
        uint32_t seq_no, 
        uint32_t pf_priority,
        uint32_t size, 
        Host *src, 
        Host *dst
    ) {
    this->sending_time = sending_time;
    this->flow = flow;
    this->seq_no = seq_no;
    this->pf_priority = pf_priority;
    this->size = size;
    this->src = src;
    this->dst = dst;
    this->hop = 0;
    this->type = NORMAL_PACKET;
    this->unique_id = Packet::instance_count++;
    this->total_queuing_delay = 0;
}

PlainAck::PlainAck(Flow *flow, uint32_t seq_no_acked, uint32_t size, Host* src, Host *dst) : Packet(0, flow, seq_no_acked, 0, size, src, dst) {
    this->type = ACK_PACKET;
}

Ack::Ack(Flow *flow, uint32_t seq_no_acked, std::vector<uint32_t> sack_list, uint32_t size, Host* src, Host *dst) : Packet(0, flow, seq_no_acked, 0, size, src, dst) {
    this->type = ACK_PACKET;
    this->sack_list = sack_list;
}

RTSCTS::RTSCTS(bool type, double sending_time, Flow *f, uint32_t size, Host *src, Host *dst) : Packet(sending_time, f, 0, 0, f->hdr_size, src, dst) {
    if (type) {
        this->type = RTS_PACKET;
    }
    else {
        this->type = CTS_PACKET;
    }
}

RTS::RTS(Flow *flow, Host *src, Host *dst, double delay, int iter) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RTS_PACKET;
    this->delay = delay;
    this->iter = iter;
}


OfferPkt::OfferPkt(Flow *flow, Host *src, Host *dst, bool is_free, int iter, int epoch) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = OFFER_PACKET;
    this->is_free = is_free;
    this->iter = iter;
    this->epoch = epoch;
}

DecisionPkt::DecisionPkt(Flow *flow, Host *src, Host *dst, bool accept, int iter, int epoch) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = DECISION_PACKET;
    this->accept = accept;
    this->iter = iter;
    this->epoch = epoch;
}

AcceptPkt::AcceptPkt(Flow *flow, Host *src, Host *dst, int iter, int epoch, int total_links) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = ACCEPT_PACKET;
    this->iter = iter;
    this->epoch = epoch;
    this->total_links = total_links;
}

CTS::CTS(Flow *flow, Host *src, Host *dst) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = CTS_PACKET;
}
// ----
FlowRTS::FlowRTS(Flow *flow, Host *src, Host *dst, int size_in_pkt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = FLOW_RTS;
    this->size_in_pkt = size_in_pkt;
}
GrantsR::GrantsR(Flow *flow, Host *src, Host *dst, int iter, int epoch, int total_links) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = GRANTSR_PACKET;
    this->iter = iter;
    this->epoch = epoch;
    this->total_links = total_links;
}
PIMGrants::PIMGrants(Flow *flow, Host *src, Host *dst, int iter, int epoch, int remaining_sz, int total_links, bool prompt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = PIM_GRANTS_PACKET;
    this->iter = iter;
    this->epoch = epoch;
    this->remaining_sz = remaining_sz;
    this->total_links = total_links;
    // this->prompt = prompt;
}

PIMREQ::PIMREQ(Flow *flow, Host *src, Host *dst, int iter, int epoch, int remaining, int total_links) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = PIM_REQ_PACKET;
    this->iter = iter;
    this->epoch = epoch;
    this->remaining_sz = remaining;
    this->total_links = total_links;
}

PIMToken::PIMToken(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int token_seq_num, int data_seq_num, int priority) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = PIM_TOKEN;
    this->ttl = ttl;
    this->remaining_sz = remaining;
    this->token_seq_num = token_seq_num;
    this->data_seq_num = data_seq_num;
    this->priority = priority;
}

PIMAck::PIMAck(Flow *flow, uint32_t seq_no_acked, uint32_t data_seq_no_acked, uint32_t size, Host* src, Host *dst) : Packet(0, flow, seq_no_acked, 0, size, src, dst) {
    this->type = PIM_ACK;
    this->data_seq_no_acked = data_seq_no_acked;
}
//-------
CapabilityPkt::CapabilityPkt(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int cap_seq_num, int data_seq_num) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = CAPABILITY_PACKET;
    this->ttl = ttl;
    this->remaining_sz = remaining;
    this->cap_seq_num = cap_seq_num;
    this->data_seq_num = data_seq_num;
}

StatusPkt::StatusPkt(Flow *flow, Host *src, Host *dst, int num_flows_at_sender) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = STATUS_PACKET;
    this->num_flows_at_sender = num_flows_at_sender;
}


FastpassRTS::FastpassRTS(Flow *flow, Host *src, Host *dst, int remaining_pkt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = FASTPASS_RTS;
    this->remaining_num_pkts = remaining_pkt;
}

FastpassSchedulePkt::FastpassSchedulePkt(Flow *flow, Host *src, Host *dst, FastpassEpochSchedule* schd) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = FASTPASS_SCHEDULE;
    this->schedule = schd;
}
// ----- for ruf algorithm

RufRTS::RufRTS(Flow *flow, Host *src, Host *dst, int size_in_pkt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RUF_RTS;
    this->size_in_pkt = size_in_pkt;
}

RufListSrcs::RufListSrcs(Flow *flow, Host *src, Host *dst, Host *rts_dst, std::list<uint32_t> listSrcs) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RUF_LISTSRCS;
    this->rts_dst = rts_dst;
    this->listSrcs = listSrcs;
    // assume src id  is 2 bytes;
    this->size += uint32_t(2 * this->listSrcs.size());
    this->has_nrts = false;
}

RufListSrcs::~RufListSrcs() {
    this->listSrcs.clear();
}
RufNRTS::RufNRTS(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t dst_id) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RUF_NRTS;
    this->src_id = src_id;
    this->dst_id = dst_id;
}

RufGoSrc::RufGoSrc(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t max_tokens, int round) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RUF_GOSRC;
    this->src_id = src_id;
    this->max_tokens = max_tokens;
    this->round = round;
}

RufToken::RufToken(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int token_seq_num, int data_seq_num) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RUF_TOKEN;
    this->ttl = ttl;
    this->remaining_sz = remaining;
    this->token_seq_num = token_seq_num;
    this->data_seq_num = data_seq_num;
}
