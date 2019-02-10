#ifndef FAT_TREE_TOPOLOGY_H
#define FAT_TREE_TOPOLOGY_H

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
class FatTreeTopology : public Topology {
    public:
        FatTreeTopology(
        		uint32_t k,
	        	double bandwidth,
        		uint32_t queue_type
                );
		bool is_arbiter(Host* n);
		bool is_same_rack(Host* a, Host*b);
		uint32_t get_rack_num(Host* a);
		bool is_same_pod(Host* a, Host*b);
		uint32_t get_pod_num(Host* a);
		Queue* get_host_next_hop(Packet *p, Queue *q);
		Queue* get_edge_next_hop(Packet *p, Queue *q);
		Queue* get_agg_next_hop(Packet *p, Queue *q);
		Queue* get_core_next_hop(Packet *p, Queue *q);
        void set_up_parameter();

        virtual Queue* get_next_hop(Packet *p, Queue *q);
        virtual double get_control_pkt_rtt(int host_id);
        virtual double get_oracle_fct(Flow* f);

        uint32_t num_edge_switches;
        uint32_t num_agg_switches;
        uint32_t num_core_switches;
        uint32_t _k;
        std::vector<FatTreeSwitch*> edge_switches;
        std::vector<FatTreeSwitch*> agg_switches;
        std::vector<FatTreeSwitch*> core_switches;
};


#endif
