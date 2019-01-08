#include "../coresim/packet.h"
#include "../coresim/queue.h"

#include "rankingTopology.h"

#include "../run/params.h"

extern DCExpParams params;

RankingAggSwitch::RankingAggSwitch(
        uint32_t id, 
        uint32_t nq1, 
        double r1, 
        uint32_t nq2, 
        double r2, 
        uint32_t queue_type
        ) : AggSwitch(id, nq1, r1, nq2, r2, queue_type) {
    queue_to_arbiter = NULL;
}

RankingTopology::RankingTopology(
        uint32_t num_hosts,
        uint32_t num_agg_switches,
        uint32_t num_core_switches,
        double bandwidth,
        uint32_t queue_type
        ) : PFabricTopology(num_hosts, num_agg_switches, num_core_switches, bandwidth, queue_type) {
    for (auto s = this->switches.begin(); s != this->switches.end(); s++) {
        for (auto q = (*s)->queues.begin(); q != (*s)->queues.end(); q++) {
            delete *q; 
        }
        delete *s;
    }

    this->agg_switches.clear();
    this->core_switches.clear();
    this->switches.clear();
    this->hosts.clear();
    Queue::instance_count = 0;

    uint32_t hosts_per_agg_switch = num_hosts / num_agg_switches;
    //std::cout << "\n\n" << hosts_per_agg_switch << "\n\n";

    this->num_hosts = num_hosts;
    this->num_agg_switches = num_agg_switches;
    this->num_core_switches = num_core_switches;

    //Capacities
    double c1 = bandwidth;
    double c2 = hosts_per_agg_switch * bandwidth / num_core_switches;

    // Create Hosts
    for (uint32_t i = 0; i < num_hosts; i++) {
        hosts.push_back(Factory::get_host(i, c1, queue_type, params.host_type));
    }

    arbiter = new RankingArbiter(num_hosts, c1, queue_type);
    // create fake flow to communicate with the arbiter
    for (uint32_t i = 0; i < num_hosts; i++) {
        ((RankingHost*)hosts[i])->fake_flow = new RankingFlow(-1, -1, -1, hosts[i], arbiter);
    }      
    // Create Switches
    for (uint32_t i = 0; i < num_agg_switches; i++) {
        AggSwitch* sw;
        if (i == 0) sw = new RankingAggSwitch(i, hosts_per_agg_switch, c1, num_core_switches, c2, queue_type);
        else sw = new AggSwitch(i, hosts_per_agg_switch, c1, num_core_switches, c2, queue_type);

        agg_switches.push_back(sw); // TODO make generic
        switches.push_back(sw);
    }
    for (uint32_t i = 0; i < num_core_switches; i++) {
        CoreSwitch* sw = new CoreSwitch(i + num_agg_switches, num_agg_switches, c2, queue_type);
        core_switches.push_back(sw);
        switches.push_back(sw);
    }
    ((RankingAggSwitch*) agg_switches[0])->queue_to_arbiter = Factory::get_queue(num_agg_switches + num_core_switches, c1, params.queue_size, queue_type, 0, 3);


    //Connect host queues
    for (uint32_t i = 0; i < num_hosts; i++) {
        hosts[i]->queue->set_src_dst(hosts[i], agg_switches[i/16]);
    }

    arbiter->queue->set_src_dst(arbiter, agg_switches[0]);
    // std::cout << "Linking arbiter with queue " << arbiter->queue->id << " " << arbiter->queue->unique_id << " with agg switch " << agg_switches[0]->id << "\n" ;


    // For agg switches -- REMAINING
    for (uint32_t i = 0; i < num_agg_switches; i++) {
        // Queues to Hosts
        for (uint32_t j = 0; j < hosts_per_agg_switch; j++) { // TODO make generic
            Queue *q = agg_switches[i]->queues[j];
            q->set_src_dst(agg_switches[i], hosts[i * 16 + j]);
            // std::cout << "Linking Agg " << i << " to Host" << i * 16 + j << " with queue " << q->id << " " << q->unique_id << "\n";
        }
        // Queues to Core
        for (uint32_t j = 0; j < num_core_switches; j++) {
            Queue *q = agg_switches[i]->queues[j + 16];
            q->set_src_dst(agg_switches[i], core_switches[j]);
            // std::cout << "Linking Agg " << i << " to Core" << j << " with queue " << q->id << " " << q->unique_id << "\n";
        }
    }

    ((RankingAggSwitch*) agg_switches[0])->queue_to_arbiter->set_src_dst(agg_switches[0], arbiter);
    // std::cout << "Linking arbiter switch " << agg_switches[0]->id << " with queue " << ((RankingAggSwitch*) agg_switches[0])->queue_to_arbiter->id << " " << ((RankingAggSwitch*) agg_switches[0])->queue_to_arbiter->unique_id << "\n";

    //For core switches -- PERFECT
    for (uint32_t i = 0; i < num_core_switches; i++) {
        for (uint32_t j = 0; j < num_agg_switches; j++) {
            Queue *q = core_switches[i]->queues[j];
            q->set_src_dst(core_switches[i], agg_switches[j]);
            // std::cout << "Linking Core " << i << " to Agg" << j << " with queue " << q->id << " " << q->unique_id << "\n";
        }
    }

    for (auto s = this->switches.begin(); s != this->switches.end(); s++) {
        for (auto q = (*s)->queues.begin(); q != (*s)->queues.end(); q++) {
            assert((*q)->src == (*s));
            assert((*q)->src != NULL && (*q)->dst != NULL);
        }
    }
    // set up parameter
    params.rtt = (4 * params.propagation_delay + (1500 * 8 / params.bandwidth) * 2.5) * 2;
    // params.ctrl_pkt_rtt = (4 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2.5) * 2;
    params.BDP = ceil(params.rtt * params.bandwidth / 1500 / 8);
    params.ranking_max_tokens = ceil(params.ranking_max_tokens * params.BDP);
    params.ranking_min_tokens = ceil(params.ranking_min_tokens * params.BDP);
    params.token_window *= params.BDP;
    params.token_initial *= params.BDP;
    params.token_timeout *= params.get_full_pkt_tran_delay();
    params.token_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.rankinghost_idle_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    params.token_window_timeout *= params.BDP * params.get_full_pkt_tran_delay();
    // params.ranking_reset_epoch *= params.BDP * params.get_full_pkt_tran_delay();
    params.ranking_controller_epoch *= params.BDP * params.get_full_pkt_tran_delay();
}

Queue* RankingTopology::get_next_hop(Packet* p, Queue* q) {
    if (q->dst->type == HOST) {
        assert(p->dst->id == q->dst->id);
        return NULL; // Packet Arrival
    }

    // At host level
    if (q->src->type == HOST) { // Same Rack or not
        assert (p->src->id == q->src->id);

        if (p->src->id / 16 == p->dst->id / 16 ||
                (
                 (p->src->host_type == RANKING_ARBITER && p->dst->id / 16 == 0) ||
                 (p->dst->host_type == RANKING_ARBITER && p->src->id / 16 == 0)
                )
           ) {
            // arbiter id = 144; 144 / 16 = 9; no other src can be 9;
            if(p->dst->host_type == RANKING_ARBITER)
                return ((RankingAggSwitch *) q->dst)->queue_to_arbiter;
            else
                return ((Switch *) q->dst)->queues[p->dst->id % 16];
        } 
        else {
            uint32_t hash_port = 0;
            if(params.load_balancing == 0)
                hash_port = q->spray_counter++%4;
            else if(params.load_balancing == 1)
                hash_port = (p->src->id + p->dst->id + p->flow->id) % 4;
            return ((Switch *) q->dst)->queues[16 + hash_port];
        }
    }

    // At switch level
    if (q->src->type == SWITCH) {
        if (((Switch *) q->src)->switch_type == AGG_SWITCH) {
            if (p->dst->host_type == RANKING_ARBITER)
                return ((Switch *) q->dst)->queues[0];
            else
                return ((Switch *) q->dst)->queues[p->dst->id / 16];
        }
        if (((Switch *) q->src)->switch_type == CORE_SWITCH) {
            if (p->dst->host_type == RANKING_ARBITER) {
                assert(((Switch*)q->dst)->id == 0);
                return ((RankingAggSwitch *) q->dst)->queue_to_arbiter;
            }
            else
                return ((Switch *) q->dst)->queues[p->dst->id % 16];
        }
    }

    assert(false);
}

