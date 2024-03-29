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

		// uint32_t get_rack_num(Host* a);
        void set_up_parameter();

        virtual Queue* get_next_hop(Packet *p, Queue *q);
        virtual double get_control_pkt_rtt(int host_id);
        virtual double get_oracle_fct(Flow* f);

        // this is for RUF local matching; not optimized yet;
        virtual bool is_same_rack(int a, int b);
        virtual int num_hosts_per_tor();

        uint32_t hosts_per_agg_switch;
        uint32_t num_agg_switches;
        uint32_t num_core_switches;
        double access_bw;
        double core_bw;
        std::vector<AggSwitch*> agg_switches;
        std::vector<CoreSwitch*> core_switches;
};


#endif
