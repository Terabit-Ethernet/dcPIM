#ifndef TOPOLOGY_H
#define TOPOLOGY_H

#include <cstddef>
#include <iostream>
#include <math.h>
#include <vector>

#include "node.h"
#include "assert.h"
#include "packet.h"
#include "queue.h"

#include "../ext/factory.h"

#include "../run/params.h"

class Topology {
    public:
        Topology();
        virtual Queue *get_next_hop(Packet *p, Queue *q) = 0;
        virtual double get_oracle_fct(Flow* f) = 0;
        virtual double get_control_pkt_rtt(int host_id) = 0;
        virtual bool is_same_rack(int src_id, int dst_id) = 0;
        virtual int num_hosts_per_tor() = 0;
        void print_queue_length();
        uint32_t num_hosts;
        Host* arbiter;
        std::vector<Host *> hosts;
        std::vector<Switch*> switches;
};

// class PFabricTopology : public Topology {
//     public:
//         PFabricTopology(
//                 uint32_t num_hosts, 
//                 uint32_t num_agg_switches,
//                 uint32_t num_core_switches, 
//                 double bandwidth, 
//                 uint32_t queue_type
//                 );

//         virtual Queue* get_next_hop(Packet *p, Queue *q);
//         virtual double get_oracle_fct(Flow* f);
//         virtual double get_control_pkt_rtt(int host_id);
//         void set_up_parameter();
//        	uint32_t num_agg_switches;
//         uint32_t num_core_switches;

//         std::vector<AggSwitch*> agg_switches;
//         std::vector<CoreSwitch*> core_switches;
// };


// class BigSwitchTopology : public Topology {
//     public:
//         BigSwitchTopology(uint32_t num_hosts, double bandwidth, uint32_t queue_type);
//         virtual Queue *get_next_hop(Packet *p, Queue *q);
//         virtual double get_oracle_fct(Flow* f);
//         virtual double get_control_pkt_rtt(int host_id) {
//             assert(false);
//         }
//         CoreSwitch* the_switch;
// };

#endif
