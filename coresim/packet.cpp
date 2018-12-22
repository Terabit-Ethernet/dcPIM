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

    this->type = NORMAL_PACKET;
    this->unique_id = Packet::instance_count++;
    this->total_queuing_delay = 0;
    this->ranking_round = -1;
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

AcceptPkt::AcceptPkt(Flow *flow, Host *src, Host *dst, bool accept, int iter, int epoch) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = ACCEPT_PACKET;
    this->accept = accept;
    this->iter = iter;
    this->epoch = epoch;
}

CTS::CTS(Flow *flow, Host *src, Host *dst) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = CTS_PACKET;
}

GrantsR::GrantsR(Flow *flow, Host *src, Host *dst, int iter, int epoch) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = GRANTSR_PACKET;
    this->iter = iter;
    this->epoch = epoch;
}
PIMGrants::PIMGrants(Flow *flow, Host *src, Host *dst, int iter, int epoch, bool prompt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = PIM_GRANTS_PACKET;
    this->iter = iter;
    this->epoch = epoch;
    this->prompt = prompt;
}

PIMRTS::PIMRTS(Flow *flow, Host *src, Host *dst, int iter, int epoch) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = PIM_RTS_PACKET;
    this->iter = iter;
    this->epoch = epoch;
}

PIMAck::PIMAck(Flow *flow, uint32_t seq_no_acked, uint32_t data_seq_no_acked, uint32_t size, Host* src, Host *dst) : Packet(0, flow, seq_no_acked, 0, size, src, dst) {
    this->type = PIM_ACK;
    this->data_seq_no_acked = data_seq_no_acked;
}

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
// ----- for ranking algorithm

RankingRTS::RankingRTS(Flow *flow, Host *src, Host *dst, int size_in_pkt) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RANKING_RTS;
    this->size_in_pkt = size_in_pkt;
}

RankingListSrcs::RankingListSrcs(Flow *flow, Host *src, Host *dst, Host *rts_dst, std::list<uint32_t> listSrcs) : Packet(0, flow, 0, 1, params.hdr_size, src, dst) {
    this->type = RANKING_LISTSRCS;
    this->rts_dst = rts_dst;
    this->listSrcs = listSrcs;
    // assume src id  is 2 bytes;
    this->size += uint32_t(2 * this->listSrcs.size());
    this->has_nrts = false;
}

RankingListSrcs::~RankingListSrcs() {
    this->listSrcs.clear();
}
RankingNRTS::RankingNRTS(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t dst_id) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RANKING_NRTS;
    this->src_id = src_id;
    this->dst_id = dst_id;
}

RankingGoSrc::RankingGoSrc(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t max_tokens) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RANKING_GOSRC;
    this->src_id = src_id;
    this->max_tokens = max_tokens;
}

RankingToken::RankingToken(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int token_seq_num, int data_seq_num) : Packet(0, flow, 0, 0, params.hdr_size, src, dst) {
    this->type = RANKING_TOKEN;
    this->ttl = ttl;
    this->remaining_sz = remaining;
    this->token_seq_num = token_seq_num;
    this->data_seq_num = data_seq_num;
}
