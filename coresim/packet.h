#ifndef PACKET_H
#define PACKET_H

#include "flow.h"
#include "node.h"
#include <vector>
#include <list>
#include <stdint.h>
// TODO: Change to Enum
#define NORMAL_PACKET 0
#define ACK_PACKET 1

#define RTS_PACKET 3
#define CTS_PACKET 4
#define OFFER_PACKET 5
#define DECISION_PACKET 6
#define CAPABILITY_PACKET 7
#define STATUS_PACKET 8
#define FASTPASS_RTS 9
#define FASTPASS_SCHEDULE 10

// RANKING
#define RANKING_RTS 11
#define RANKING_LISTSRCS 12
#define RANKING_NRTS 13
#define RANKING_GOSRC 14
#define RANKING_TOKEN 15

// MR
#define MRCTS_PACKET 16
#define MR_ACK 17
#define CTSR_PACKET 18
#define MRRTS_PACKET 19

class FastpassEpochSchedule;

class Packet {

    public:
        Packet(double sending_time, Flow *flow, uint32_t seq_no, uint32_t pf_priority,
                uint32_t size, Host *src, Host *dst);
        virtual ~Packet() = default;
        double sending_time;
        Flow *flow;
        uint32_t seq_no;
        uint32_t pf_priority;
        uint32_t size;
        Host *src;
        Host *dst;
        uint32_t unique_id;
        static uint32_t instance_count;
        int remaining_pkts_in_batch;
        int capability_seq_num_in_data;

        uint32_t type; // Normal or Ack packet
        double total_queuing_delay;
        double last_enque_time;

        int capa_data_seq;
        // round of ranking
        int ranking_round;
};

class PlainAck : public Packet {
    public:
        PlainAck(Flow *flow, uint32_t seq_no_acked, uint32_t size, Host* src, Host* dst);
};

class Ack : public Packet {
    public:
        Ack(Flow *flow, uint32_t seq_no_acked, std::vector<uint32_t> sack_list,
                uint32_t size,
                Host* src, Host *dst);
        uint32_t sack_bytes;
        std::vector<uint32_t> sack_list;
};

class RTSCTS : public Packet {
    public:
        //type: true if RTS, false if CTS
        RTSCTS(bool type, double sending_time, Flow *f, uint32_t size, Host *src, Host *dst);
};

class RTS : public Packet{
    public:
        RTS(Flow *flow, Host *src, Host *dst, double delay, int iter);
        double delay;
        int iter;
};

class OfferPkt : public Packet{
    public:
        OfferPkt(Flow *flow, Host *src, Host *dst, bool is_free, int iter, int round);
        bool is_free;
        int iter;
        int round;
};

class DecisionPkt : public Packet{
    public:
        DecisionPkt(Flow *flow, Host *src, Host *dst, bool accept, int iter, int round);
        bool accept;
        int iter;
        int round;
};

class CTS : public Packet{
    public:
        CTS(Flow *flow, Host *src, Host *dst);
};

// For Multi-Round algorithm (PIM)
class MRRTS : public Packet{
    public:
        MRRTS(Flow *flow, Host *src, Host *dst, int iter, int round);
        int iter;
        int round;
};

class CTSR : public Packet{
    public:
        CTSR(Flow *flow, Host *src, Host *dst, int iter, int round);
        int iter;
        int round;
};

class MRCTS : public Packet{
    public:
        MRCTS(Flow *flow, Host *src, Host *dst, int iter, int round);
        int iter;
        int round;
};

class MRAck : public Packet {
    public:
        MRAck(Flow *flow, uint32_t seq_no_acked, uint32_t data_seq_num, uint32_t size, Host* src, Host* dst);
        uint32_t data_seq_no_acked;
};


class CapabilityPkt : public Packet{
    public:
        CapabilityPkt(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int cap_seq_num, int data_seq_num);
        double ttl;
        int remaining_sz;
        int cap_seq_num;
        int data_seq_num;
};

class StatusPkt : public Packet{
    public:
        StatusPkt(Flow *flow, Host *src, Host *dst, int num_flows_at_sender);
        double ttl;
        bool num_flows_at_sender;
};


class FastpassRTS : public Packet
{
    public:
        FastpassRTS(Flow *flow, Host *src, Host *dst, int remaining_pkt);
        int remaining_num_pkts;
};

class FastpassSchedulePkt : public Packet
{
    public:
        FastpassSchedulePkt(Flow *flow, Host *src, Host *dst, FastpassEpochSchedule* schd);
        FastpassEpochSchedule* schedule;
};
// Ranking Algorithm
class RankingRTS : public Packet
{
    public:
        RankingRTS(Flow *flow, Host *src, Host *dst, int size_in_pkt);
        int size_in_pkt;
};

class RankingListSrcs : public Packet
{
    public:
        RankingListSrcs(Flow *flow, Host *src, Host *dst, Host* rts_dst, std::list<uint32_t> listSrcs);
        ~RankingListSrcs();
        std::list<uint32_t> listSrcs;
        Host* rts_dst;
};

class RankingNRTS : public Packet
{
    public:
        RankingNRTS(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t dst_id);
        uint32_t src_id;
        uint32_t dst_id;

};

class RankingGoSrc : public Packet
{
    public:
        RankingGoSrc(Flow *flow, Host *src, Host *dst, uint32_t src_id, uint32_t max_tokens);
        uint32_t src_id;
        uint32_t max_tokens;
};

class RankingToken : public Packet
{
    public:
        RankingToken(Flow *flow, Host *src, Host *dst, double ttl, int remaining, int token_seq_num, int data_seq_num);
        double ttl;
        int remaining_sz;
        int token_seq_num;
        int data_seq_num;
};

#endif

