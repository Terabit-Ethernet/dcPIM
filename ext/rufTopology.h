#ifndef RUF_TOPO_H
#define RUF_TOPO_H

#include "../coresim/topology.h"
#include "rufhost.h"

class RufAggSwitch : public AggSwitch {
    public:
        RufAggSwitch(uint32_t id, uint32_t nq1, double r1, uint32_t nq2, double r2, uint32_t queue_type);
        Queue* queue_to_arbiter;
};

class RufTopology : virtual public PFabricTopology {
    public:
        RufTopology(
                uint32_t num_hosts,
                uint32_t num_agg_switches,
                uint32_t num_core_switches,
                double bandwidth,
                uint32_t queue_type
                );
        virtual Queue* get_next_hop(Packet* p, Queue* q);
};

#endif
