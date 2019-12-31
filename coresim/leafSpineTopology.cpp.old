#include "leafSpineTopology.h"

extern DCExpParams params;

LeafSpineTopology::LeafSpineTopology(
        uint32_t num_hosts,
        uint32_t num_agg_switches,
        uint32_t num_core_switches,
        double bandwidth,
        uint32_t queue_type
        ) : Topology() {

    this->hosts_per_agg_switch = num_hosts / num_agg_switches;
    this->num_hosts = num_hosts;
    this->num_agg_switches = num_agg_switches;
    this->num_core_switches = num_core_switches;
    //Capacities
    double c1 = bandwidth;
    double c2 = hosts_per_agg_switch * params.os_ratio * bandwidth / num_core_switches;

    // Create Hosts
    this->arbiter = NULL;
    for (uint32_t i = 0; i < num_hosts; i++) {
        hosts.push_back(Factory::get_host(i, c1, queue_type, params.host_type));
    }
    if(params.host_type == RUF_HOST) {
    	this->arbiter = new RufArbiter(num_hosts, c1, queue_type);
	    // Create fake flow to communicate with the arbiter
	    for (uint32_t i = 0; i < num_hosts; i++) {
	        ((RufHost*)hosts[i])->fake_flow = new RufFlow(-1, -1, -1, hosts[i], arbiter);
	    }  
    } else if(params.host_type == FASTPASS_HOST) {
    	this->arbiter = new FastpassArbiter(num_hosts, c1, queue_type);
    }
 
    // Create Switches
    for (uint32_t i = 0; i < num_agg_switches; i++) {
        AggSwitch* sw = new AggSwitch(i, hosts_per_agg_switch, c1, num_core_switches, c2, queue_type);
        if(i == 0) {
            sw->queue_to_arbiter = Factory::get_queue(num_agg_switches + num_core_switches, c1, params.queue_size, queue_type, 0, 3);
        }
        agg_switches.push_back(sw); // TODO make generic
        switches.push_back(sw);
    }
    for (uint32_t i = 0; i < num_core_switches; i++) {
        CoreSwitch* sw = new CoreSwitch(i + num_agg_switches, num_agg_switches, c2, queue_type);
        core_switches.push_back(sw);
        switches.push_back(sw);
    }

    //Connect host queues
    for (uint32_t i = 0; i < num_hosts; i++) {
        hosts[i]->queue->set_src_dst(hosts[i], agg_switches[i/hosts_per_agg_switch]);
    }

    // std::cout << "Linking arbiter with queue " << arbiter->queue->id << " " << arbiter->queue->unique_id << " with agg switch " << agg_switches[0]->id << "\n" ;


    // For agg switches -- REMAINING
    for (uint32_t i = 0; i < num_agg_switches; i++) {
        // Queues to Hosts
        for (uint32_t j = 0; j < hosts_per_agg_switch; j++) { // TODO make generic
            Queue *q = agg_switches[i]->queues[j];
            q->set_src_dst(agg_switches[i], hosts[i * hosts_per_agg_switch + j]);
            // std::cout << "Linking Agg " << i << " to Host" << i * 16 + j << " with queue " << q->id << " " << q->unique_id << "\n";
        }
        // Queues to Core
        for (uint32_t j = 0; j < num_core_switches; j++) {
            Queue *q = agg_switches[i]->queues[j + hosts_per_agg_switch];
            q->set_src_dst(agg_switches[i], core_switches[j]);
            // std::cout << "Linking Agg " << i << " to Core" << j << " with queue " << q->id << " " << q->unique_id << "\n";
        }
    }
    // std::cout << "Linking arbiter switch " << agg_switches[0]->id << " with queue " << ((RufAggSwitch*) agg_switches[0])->queue_to_arbiter->id << " " << ((RufAggSwitch*) agg_switches[0])->queue_to_arbiter->unique_id << "\n";

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

    if(params.host_type == RUF_HOST || params.host_type == FASTPASS_HOST) {
        arbiter->queue->set_src_dst(arbiter, agg_switches[0]);
        ((AggSwitch*)agg_switches[0])->queue_to_arbiter->set_src_dst(agg_switches[0], arbiter);
    }
    // set up parameter
    this->set_up_parameter();
}

void LeafSpineTopology::set_up_parameter() {
    params.rtt = (4 * params.propagation_delay + (1500 * 8 / params.bandwidth) * 2.5) * 2;
    // params.ctrl_pkt_rtt = (4 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2.5) * 2;
    params.BDP = ceil(params.rtt * params.bandwidth / 1500 / 8);
    if (params.host_type == RUF_HOST) {
        params.ruf_max_tokens = ceil(params.ruf_max_tokens * params.BDP);
        params.ruf_min_tokens = ceil(params.ruf_min_tokens * params.BDP);
        params.token_window *= params.BDP;
        params.token_initial *= params.BDP;
        params.token_timeout *= params.get_full_pkt_tran_delay();
        params.token_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
        params.rufhost_idle_timeout *= params.BDP * params.get_full_pkt_tran_delay();
        params.token_window_timeout *= params.BDP * params.get_full_pkt_tran_delay();
        // params.ruf_reset_epoch *= params.BDP * params.get_full_pkt_tran_delay();
        params.ruf_controller_epoch *= params.BDP * params.get_full_pkt_tran_delay();
    } else if (params.host_type == PIM_HOST) {
        params.token_window_timeout *= params.BDP * params.get_full_pkt_tran_delay();
        params.token_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
        params.token_initial *= params.BDP;
        params.token_window *= params.BDP;
        params.token_timeout *= params.get_full_pkt_tran_delay();

        // params.pim_epoch *= params.BDP * params.get_full_pkt_tran_delay();
        params.pim_iter_epoch = params.pim_beta * (this->get_control_pkt_rtt(143));
        params.pim_epoch = params.pim_iter_limit * params.pim_iter_epoch * (1 + params.pim_alpha);
    }
}

bool LeafSpineTopology::is_arbiter(Host* n) {
	if(n->host_type == FASTPASS_ARBITER || n->host_type == RUF_ARBITER)
		return true;
	return false;
}

bool LeafSpineTopology::is_same_rack(Host* a, Host*b) {
	// assume arbiter is at pod 0 and edge switch 0;
	if(is_arbiter(a) || is_arbiter(b)) {
		if(is_arbiter(a) && is_arbiter(b))
			return true;
		if(is_arbiter(a) && b->id / this->hosts_per_agg_switch  == 0)
			return true;
		else if(is_arbiter(b) && a->id / this->hosts_per_agg_switch == 0)
			return true;
		else 
			return false;
	}
	if(a->id / this->hosts_per_agg_switch == b->id / this->hosts_per_agg_switch)
		return true;
	return false;
}

bool LeafSpineTopology::is_same_rack(int a, int b) {
    // assume arbiter is at pod 0 and edge switch 0;
    if(a / this->hosts_per_agg_switch == b / this->hosts_per_agg_switch)
        return true;
    return false;
}

Queue* LeafSpineTopology::get_next_hop(Packet* p, Queue* q) {
    if (q->dst->type == HOST) {
        assert(p->dst->id == q->dst->id);
        return NULL; // Packet Arrival
    }

    // At host level
    if (q->src->type == HOST) { // Same Rack or not
        assert (p->src->id == q->src->id);

        if (this->is_same_rack(p->src, p->dst)) {
            // arbiter id = 144; 144 / 16 = 9; no other src can be 9;
            if(is_arbiter(p->dst))
                return ((AggSwitch *) q->dst)->queue_to_arbiter;
            else
                return ((Switch *) q->dst)->queues[p->dst->id % this->hosts_per_agg_switch];
        } 
        else {
            uint32_t hash_port = 0;
            if(params.load_balancing == 0)
                hash_port = q->spray_counter++ % this->num_core_switches ;
            else if(params.load_balancing == 1)
                hash_port = (p->src->id + p->dst->id + p->flow->id) % this->num_core_switches;
            return ((Switch *) q->dst)->queues[this->hosts_per_agg_switch + hash_port];
        }
    }

    // At switch level
    if (q->src->type == SWITCH) {
        if (((Switch *) q->src)->switch_type == AGG_SWITCH) {
            if (this->is_arbiter(p->dst))
                return ((Switch *) q->dst)->queues[0];
            else
                return ((Switch *) q->dst)->queues[p->dst->id / this->hosts_per_agg_switch];
        }
        if (((Switch *) q->src)->switch_type == CORE_SWITCH) {
            if (this->is_arbiter(p->dst)) {
                assert(((Switch*)q->dst)->id == 0);
                return ((AggSwitch *) q->dst)->queue_to_arbiter;
            }
            else
                return ((Switch *) q->dst)->queues[p->dst->id % this->hosts_per_agg_switch];
        }
    }

    assert(false);
}

double LeafSpineTopology::get_oracle_fct(Flow *f) {
    int num_hops = 4;
    if (f->src->id / hosts_per_agg_switch == f->dst->id / hosts_per_agg_switch) {
        num_hops = 2;
    }
    double propagation_delay;
    if (params.ddc != 0) { 
        if (num_hops == 2) {
            propagation_delay = 0.440;
        }
        if (num_hops == 4) {
            propagation_delay = 2.040;
        }
    }
    else {
        propagation_delay = 2 * 1000000.0 * num_hops * f->src->queue->propagation_delay; //us
    }
   
    double pkts = (double) f->size / params.mss;
    uint32_t np = floor(pkts);
    uint32_t leftover = (pkts - np) * params.mss;
	double incl_overhead_bytes = (params.mss + f->hdr_size) * np + leftover;
    if(leftover != 0) {
        incl_overhead_bytes += f->hdr_size;
    }
    double bandwidth = f->src->queue->rate / 1000000.0; // For us
    double transmission_delay;
    if (params.cut_through) {
        transmission_delay = 
            (
                np * (params.mss + params.hdr_size)
                + 1 * params.hdr_size
                + 2.0 * params.hdr_size // ACK has to travel two hops
            ) * 8.0 / bandwidth;
        if (num_hops == 4) {
            //1 packet and 1 ack
            transmission_delay += 2 * (2*params.hdr_size) * 8.0 / (4 * bandwidth);
        }
        //std::cout << "pd: " << propagation_delay << " td: " << transmission_delay << std::endl;
    }
    else {
		transmission_delay = (incl_overhead_bytes + f->hdr_size) * 8.0 / bandwidth;
		if (num_hops == 4) {
			// 1 packet and 1 ack
			if (leftover != params.mss && leftover != 0) {
				// less than mss sized flow. the 1 packet is leftover sized.
				transmission_delay += 2 * (leftover + 2*params.hdr_size) * 8.0 / (4 * bandwidth);
				
			} else {
				// 1 packet is full sized
				transmission_delay += 2 * (params.mss + 2*params.hdr_size) * 8.0 / (4 * bandwidth);
			}
		}
        if (leftover != params.mss && leftover != 0) {
            // less than mss sized flow. the 1 packet is leftover sized.
            transmission_delay += (leftover + 2*params.hdr_size) * 8.0 / (bandwidth);
            
        } else {
            // 1 packet is full sized
            transmission_delay += (params.mss + 2*params.hdr_size) * 8.0 / (bandwidth);
        }
        //transmission_delay = 
        //    (
        //        (np + 1) * (params.mss + params.hdr_size) + (leftover + params.hdr_size)
        //        + 2.0 * params.hdr_size // ACK has to travel two hops
        //    ) * 8.0 / bandwidth;
        //if (num_hops == 4) {
        //    //1 packet and 1 ack
        //    transmission_delay += 2 * (params.mss + 2*params.hdr_size) * 8.0 / (4 * bandwidth);  //TODO: 4 * bw is not right.
        //}
    }
    return (propagation_delay + transmission_delay); //us
}
double LeafSpineTopology::get_control_pkt_rtt(int host_id) {
    if(host_id / hosts_per_agg_switch == 0) {
        return (2 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2) * 2;
    } else {
        return (4 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2.5) * 2;
    }
}

int LeafSpineTopology::num_hosts_per_tor() {
    return hosts_per_agg_switch;
}