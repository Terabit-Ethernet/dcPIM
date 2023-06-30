#ifndef PIM_FLOW_H
#define PIM_FLOW_H

#include <unordered_map>
#include <set>

#include "fountainflow.h"
#include "custompriorityqueue.h"

class PimFlow;
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

class Pim_Token //for extendability
{
public:
    double timeout;
    int seq_num;
    int data_seq_num;
    int create_time;
    int priority;
    PimFlow* flow;
};

class PimFlow : public FountainFlow {
public:
    PimFlow(uint32_t id, double start_time, uint32_t size, Host *s, Host *d);
    virtual void start_flow();
    // virtual void send_pending_data();
    // void receive_rts(Packet *p);
    virtual void receive(Packet *p);
    // void send_pending_data_low_prio();
    Packet* send(uint32_t seq, int capa_seq, int data_seq, int priority);
    // sender logic
    bool is_small_flow();
    int init_token_size();
    void assign_init_token();
    void clear_token();
    Pim_Token* use_token();
    bool has_token();

    void send_req(int iter, int epoch, int total_links, int prompt_links);
    void send_accept_pkt(int iter, int epoch, int total_links, int prompt_links);
    void receive_ack(PIMAck* p);
    Packet* send(uint32_t, uint32_t, int);
    void send_pending_data(Pim_Token* token);
    void send_pending_data_low_priority();
    std::list<Pim_Token*> tokens;

    // receiver logic
    void send_grants(int iter, int epoch, int remaining_sz, int total_link, int prompt_links);
    void send_offer_pkt(int iter, int epoch, bool is_free);
    void send_ack(Packet* p);
    void send_grantsr(int iter, int epoch, int total_links, int prompt_links);
    int remaining_pkts();
    int token_gap();
    void relax_token_gap(int window);
    int get_next_token_seq_num();
    void send_token_pkt(int priority, int epoch);
    void receive_short_flow();
    void sending_ack();
    void sending_rts();
    std::set<int> packets_received;

    int last_token_data_seq_num_sent;
    int received_until;
    bool finished_at_receiver;
    int token_count;
    int token_packet_sent_count;
    int token_waste_count;
    double redundancy_ctrl_timeout;
    int token_goal;
    int remaining_pkts_at_sender;
    int largest_token_seq_received;
    int largest_token_data_seq_received;
    double latest_token_sent_time;
    bool rts_received;
    double latest_data_pkt_sent_time;
    // int notified_num_flow_at_sender;
    bool first_loop;
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

