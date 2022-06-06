#ifndef NODE_H
#define NODE_H

#include <vector>
#include <queue>
#include "queue.h"


#define HOST 0
#define SWITCH 1

#define CORE_SWITCH 10
#define AGG_SWITCH 11
#define FAT_TREE_CORE_SWITCH 12
#define FAT_TREE_AGG_SWITCH 13
#define FAT_TREE_EDGE_SWITCH 14

#define CPU 0
#define MEM 1
#define DISK 2

class Packet;
class Flow;


class FlowComparator{
    public:
        bool operator() (Flow *a, Flow *b);
};


class Node {
    public:
        Node(uint32_t id, uint32_t type);
        uint32_t id;
        uint32_t type;
};

class Host : public Node {
    public:
        Host(uint32_t id, double rate, uint32_t queue_type, uint32_t host_type);
        Queue *queue;
        int host_type;
        virtual ~Host() = default;

};

class Switch : public Node {
    public:
        Switch(uint32_t id, uint32_t switch_type);
        uint32_t switch_type;
        std::vector<Queue *> queues;
        double record() {
            uint64_t bytes_in_switch = 0;
            for(int i = 0; i < queues.size(); i++) {
                bytes_in_switch += queues[i]->bytes_in_queue;
            }
            max_bytes_in_switch = std::max(max_bytes_in_switch, bytes_in_switch);
            total_bytes_in_switch = total_bytes_in_switch + bytes_in_switch;
            record_time += 1;
        };
        // for tracing purpose for recording queue event
        uint64_t max_bytes_in_switch;
        uint64_t total_bytes_in_switch;
        uint64_t record_time;
};

class CoreSwitch : public Switch {
    public:
        //All queues have same rate
        CoreSwitch(uint32_t id, uint32_t nq, double rate, uint32_t queue_type);
};

class AggSwitch : public Switch {
    public:
        // Different Rates
        AggSwitch(uint32_t id, uint32_t nq1, double r1, uint32_t nq2, double r2, uint32_t queue_type);
        Queue* queue_to_arbiter;
};

class FatTreeSwitch : public Switch {
    public:
        FatTreeSwitch(uint32_t id, uint32_t nq, double rate, uint32_t queue_type, uint32_t switch_type);
        Queue* queue_to_arbiter;
};

#endif
