#ifndef LEAF_SPINE_TOPOLOGY_H
#define LEAF_SPINE_TOPOLOGY_H

#include <cstddef>
#include <iostream>
#include <math.h>
#include <vector>

#include "node.h"
#include "assert.h"
#include "packet.h"
#include "queue.h"
#include "topology.h"

#include "../ext/factory.h"
#include "../ext/rufhost.h"
#include "../ext/fastpasshost.h"


#include "../run/params.h"
class LeafSpineTopology : public Topology {
    public:
        LeafSpineTopology(
            uint32_t num_hosts,
            uint32_t num_agg_switches,
            uint32_t num_core_switches,
            double bandwidth,
            uint32_t queue_type
        );
		bool is_arbiter(Host* n);
		bool is_same_rack(Host* a, Host*b);
        bool is_same_rack(int a, int b);

		// uint32_t get_rack_num(Host* a);
        void set_up_parameter();

        virtual Queue* get_next_hop(Packet *p, Queue *q);
        virtual double get_control_pkt_rtt(int host_id);
        virtual double get_oracle_fct(Flow* f);

        uint32_t hosts_per_agg_switch;
        uint32_t num_agg_switches;
        uint32_t num_core_switches;
        std::vector<AggSwitch*> agg_switches;
        std::vector<CoreSwitch*> core_switches;
};


#endif
