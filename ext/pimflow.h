#ifndef PIM_FLOW_H
#define PIM_FLOW_H

#include <map>
#include <set>

#include "fountainflow.h"
#include "custompriorityqueue.h"

// struct Capability //for extendability
// {
//     double timeout;
//     int seq_num;
//     bool has_idle_sibling_sender;
//     int data_seq_num;
// };

// class CapabilityComparator{
// public:
//     bool operator() (Capability* a, Capability* b);
// };


class PimFlow : public FountainFlow {
public:
    PimFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d);
    virtual void start_flow();
    // virtual void send_pending_data();
    // void receive_rts(Packet *p);
    virtual void receive(Packet *p);
    // void send_pending_data_low_prio();
    // Packet* send(uint32_t seq, int capa_seq, int data_seq, int priority);
    // sender logic
    void send_rts(int iter, int epoch);
    void send_accept_pkt(int iter, int epoch, bool accept);
    void receive_ack(PIMAck* p);
    int get_next_data_seq_num();
    int gap();
    void relax_gap();
    bool is_small_flow();
    Packet* send(uint32_t, uint32_t, int);
    void send_pending_data();
    void send_pending_data_low_priority();
    int ack_until;
    std::set<uint32_t> ack_received;
    int largest_seq_ack;
    int last_data_seq_num_sent;
    int next_seq_no;
    int remaining_pkts_at_sender;
    double redundancy_ctrl_timeout;
    double latest_data_pkt_send_time;
    bool first_loop;
    // receiver logic
    void send_grants(int iter, int epoch, bool prompt);
    void send_offer_pkt(int iter, int epoch, bool is_free);
    void send_ack(Packet* p);
    void send_grantsr(int iter, int epoch);
    std::set<uint32_t> packets_received;

    // void send_capability_pkt();
    // void send_notify_pkt(int);
    // bool has_capability();
    // int use_capability();
    // Capability* top_capability();
    // double top_capability_timeout();
    // int remaining_pkts();
    // void assign_init_capability();
    // void set_capability_count();
    // int init_capa_size();
    // bool has_sibling_idle_source();

    // std::priority_queue<Capability*, std::vector<Capability*>, CapabilityComparator> capabilities;
    // int last_capa_data_seq_num_sent;
    // bool finished_at_receiver;
    // int capability_count;
    // int capability_packet_sent_count;
    // int capability_waste_count;
    // int capability_goal;
    // int remaining_pkts_at_sender;
    // int largest_cap_seq_received;
    // double latest_cap_sent_time;
    // bool rts_received;
    // double latest_data_pkt_send_time;
    // int notified_num_flow_at_sender;
};


#endif

