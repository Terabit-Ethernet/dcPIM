#include "topology.h"
#include <map>

extern DCExpParams params;

/*
   uint32_t num_hosts = 144;
   uint32_t num_agg_switches = 9;
   uint32_t num_core_switches = 4;
   */
Topology::Topology() {
    this->arbiter = NULL;
}

void Topology::print_queue_length() {

	std::map<int, std::vector<uint64_t>> total_queue_length;
	std::map<int, uint32_t> max_queue_length;
	for (int i = 0; i < 6; i++) {
		total_queue_length[i] = std::vector<uint64_t>();
		max_queue_length[i] = 0;
	}
	for (int i = 0; i < this->num_hosts; i++) {
		int location = this->hosts[i]->queue->location;
        total_queue_length[location].push_back(this->hosts[i]->queue->total_bytes_in_queue);
        max_queue_length[location] = std::max(this->hosts[i]->queue->max_bytes_in_queue, max_queue_length[location]);
    }
    for(int i = 0; i < this->switches.size(); i++) {
        for (int j = 0; j < this->switches[i]->queues.size(); j++) {
			int location = this->switches[i]->queues[j]->location;
        	total_queue_length[location].push_back(this->switches[i]->queues[j]->total_bytes_in_queue);
			max_queue_length[location] = std::max(this->switches[i]->queues[j]->max_bytes_in_queue, max_queue_length[location]);
        }
    }
    for (int i = 0; i < 6; i++) {
    	uint64_t total = 0;
    	int record_time =  this->hosts[0]->queue->record_time;
    	if(total_queue_length[i].size() == 0) {
    		continue;
    	}
    	for(int j = 0; j < total_queue_length[i].size(); j++) {
    		total += total_queue_length[i][j];
    	}
	    std::cout << "queue pos " << i << " " << double(total) / total_queue_length[i].size() / record_time
	    << " " << max_queue_length[i] << std::endl;
    }
    uint64_t max_switch_queue = 0;
    uint64_t max_avg_switch_queue = 0;
    for(int i = 0; i < this->switches.size(); i++) {
            max_switch_queue = std::max(max_switch_queue, this->switches[i]->max_bytes_in_switch);
            uint64_t average = this->switches[i]->total_bytes_in_switch / this->switches[i]->record_time;
            max_avg_switch_queue = std::max(average, max_avg_switch_queue);        
    }
    std::cout << "queue per switch: " << max_avg_switch_queue << " " << max_switch_queue << std::endl;
}

/*
 * PFabric topology with 144 hosts (16, 9, 4)
 */
// PFabricTopology::PFabricTopology(
//         uint32_t num_hosts, 
//         uint32_t num_agg_switches,
//         uint32_t num_core_switches, 
//         double bandwidth,
//         uint32_t queue_type
//         ) : Topology () {
//     uint32_t hosts_per_agg_switch = num_hosts / num_agg_switches;
//     this->num_hosts = num_hosts;
//     this->num_agg_switches = num_agg_switches;
//     this->num_core_switches = num_core_switches;

//     //Capacities
//     double c1 = bandwidth;
//     double c2 = hosts_per_agg_switch * bandwidth / num_core_switches;

//     // Create Hosts
//     for (uint32_t i = 0; i < num_hosts; i++) {
//         hosts.push_back(Factory::get_host(i, c1, queue_type, params.host_type)); 
//     }

//     // Create Switches
//     for (uint32_t i = 0; i < num_agg_switches; i++) {
//         AggSwitch* sw = new AggSwitch(i, hosts_per_agg_switch, c1, num_core_switches, c2, queue_type);
//         agg_switches.push_back(sw); // TODO make generic
//         switches.push_back(sw);
//     }
//     for (uint32_t i = 0; i < num_core_switches; i++) {
//         CoreSwitch* sw = new CoreSwitch(i + num_agg_switches, num_agg_switches, c2, queue_type);
//         core_switches.push_back(sw);
//         switches.push_back(sw);
//     }

//     //Connect host queues
//     for (uint32_t i = 0; i < num_hosts; i++) {
//         hosts[i]->queue->set_src_dst(hosts[i], agg_switches[i/16]);
//         //std::cout << "Linking Host " << i << " to Agg " << i/16 << "\n";
//     }

//     // For agg switches -- REMAINING
//     for (uint32_t i = 0; i < num_agg_switches; i++) {
//         // Queues to Hosts
//         for (uint32_t j = 0; j < hosts_per_agg_switch; j++) { // TODO make generic
//             Queue *q = agg_switches[i]->queues[j];
//             q->set_src_dst(agg_switches[i], hosts[i * 16 + j]);
//             //std::cout << "Linking Agg " << i << " to Host" << i * 16 + j << "\n";
//         }
//         // Queues to Core
//         for (uint32_t j = 0; j < num_core_switches; j++) {
//             Queue *q = agg_switches[i]->queues[j + 16];
//             q->set_src_dst(agg_switches[i], core_switches[j]);
//             //std::cout << "Linking Agg " << i << " to Core" << j << "\n";
//         }
//     }

//     //For core switches -- PERFECT
//     for (uint32_t i = 0; i < num_core_switches; i++) {
//         for (uint32_t j = 0; j < num_agg_switches; j++) {
//             Queue *q = core_switches[i]->queues[j];
//             q->set_src_dst(core_switches[i], agg_switches[j]);
//             //std::cout << "Linking Core " << i << " to Agg" << j << "\n";
//         }
//     }
//     set_up_parameter();
// }

// void PFabricTopology::set_up_parameter() {
//     params.rtt = (4 * params.propagation_delay + (1500 * 8 / params.bandwidth) * 2.5) * 2;
//     params.BDP = ceil(params.rtt * params.bandwidth / 1500 / 8);
//     if(params.host_type == PIM_HOST) {
//         params.pim_resend_timeout *= params.BDP * params.get_full_pkt_tran_delay();
//         params.pim_epoch *= params.BDP * params.get_full_pkt_tran_delay();
//         params.pim_window_size *= params.BDP;
//         params.pim_small_flow *= params.BDP;
//     }
// }


// Queue *PFabricTopology::get_next_hop(Packet *p, Queue *q) {
//     if (q->dst->type == HOST) {
//         return NULL; // Packet Arrival
//     }

//     // At host level
//     if (q->src->type == HOST) { // Same Rack or not
//         assert (p->src->id == q->src->id);

//         if (p->src->id / 16 == p->dst->id / 16) {
//             return ((Switch *) q->dst)->queues[p->dst->id % 16];
//         } 
//         else {
//             uint32_t hash_port = 0;
//             if(params.load_balancing == 0)
//                 hash_port = q->spray_counter++%4;
//             else if(params.load_balancing == 1)
//                 hash_port = (p->src->id + p->dst->id + p->flow->id) % 4;
//             return ((Switch *) q->dst)->queues[16 + hash_port];
//         }
//     }

//     // At switch level
//     if (q->src->type == SWITCH) {
//         if (((Switch *) q->src)->switch_type == AGG_SWITCH) {
//             return ((Switch *) q->dst)->queues[p->dst->id / 16];
//         }
//         if (((Switch *) q->src)->switch_type == CORE_SWITCH) {
//             return ((Switch *) q->dst)->queues[p->dst->id % 16];
//         }
//     }

//     assert(false);
// }


// double PFabricTopology::get_oracle_fct(Flow *f) {
//     int num_hops = 4;
//     if (f->src->id/16 == f->dst->id/16) {
//         num_hops = 2;
//     }
//     double propagation_delay;
//     if (params.ddc != 0) { 
//         if (num_hops == 2) {
//             propagation_delay = 0.440;
//         }
//         if (num_hops == 4) {
//             propagation_delay = 2.040;
//         }
//     }
//     else {
//         propagation_delay = 2 * 1000000.0 * num_hops * f->src->queue->propagation_delay; //us
//     }
   
//     double pkts = (double) f->size / params.mss;
//     uint32_t np = floor(pkts);
//     uint32_t leftover = (pkts - np) * params.mss;
// 	double incl_overhead_bytes = (params.mss + f->hdr_size) * np + leftover;
//     if(leftover != 0) {
//         incl_overhead_bytes += f->hdr_size;
//     }
//     double bandwidth = f->src->queue->rate / 1000000.0; // For us
//     double transmission_delay;
//     if (params.cut_through) {
//         transmission_delay = 
//             (
//                 np * (params.mss + params.hdr_size)
//                 + 1 * params.hdr_size
//                 + 2.0 * params.hdr_size // ACK has to travel two hops
//             ) * 8.0 / bandwidth;
//         if (num_hops == 4) {
//             //1 packet and 1 ack
//             transmission_delay += 2 * (2*params.hdr_size) * 8.0 / (4 * bandwidth);
//         }
//         //std::cout << "pd: " << propagation_delay << " td: " << transmission_delay << std::endl;
//     }
//     else {
// 		transmission_delay = (incl_overhead_bytes + f->hdr_size) * 8.0 / bandwidth;
// 		if (num_hops == 4) {
// 			// 1 packet and 1 ack
// 			if (leftover != params.mss && leftover != 0) {
// 				// less than mss sized flow. the 1 packet is leftover sized.
// 				transmission_delay += 2 * (leftover + 2*params.hdr_size) * 8.0 / (4 * bandwidth);
				
// 			} else {
// 				// 1 packet is full sized
// 				transmission_delay += 2 * (params.mss + 2*params.hdr_size) * 8.0 / (4 * bandwidth);
// 			}
// 		}
//         if (leftover != params.mss && leftover != 0) {
//             // less than mss sized flow. the 1 packet is leftover sized.
//             transmission_delay += (leftover + 2*params.hdr_size) * 8.0 / (bandwidth);
            
//         } else {
//             // 1 packet is full sized
//             transmission_delay += (params.mss + 2*params.hdr_size) * 8.0 / (bandwidth);
//         }
//         //transmission_delay = 
//         //    (
//         //        (np + 1) * (params.mss + params.hdr_size) + (leftover + params.hdr_size)
//         //        + 2.0 * params.hdr_size // ACK has to travel two hops
//         //    ) * 8.0 / bandwidth;
//         //if (num_hops == 4) {
//         //    //1 packet and 1 ack
//         //    transmission_delay += 2 * (params.mss + 2*params.hdr_size) * 8.0 / (4 * bandwidth);  //TODO: 4 * bw is not right.
//         //}
//     }
//     return (propagation_delay + transmission_delay); //us
// }
// double PFabricTopology::get_control_pkt_rtt(int host_id) {
//     if(host_id / 16 == 0) {
//         return (2 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2) * 2;
//     } else {
//         return (4 * params.propagation_delay + (40 * 8 / params.bandwidth) * 2.5) * 2;
//     }
// }

// /*
//  *BigSwitchTopology  with 144 hosts
//  */
// BigSwitchTopology::BigSwitchTopology(
//         uint32_t num_hosts, 
//         double bandwidth, 
//         uint32_t queue_type
//         ) : Topology () {
//     this->num_hosts = num_hosts;
//     double c1 = bandwidth;

//     // Create Hosts
//     for (uint32_t i = 0; i < num_hosts; i++) {
//         hosts.push_back(Factory::get_host(i, c1, queue_type, params.host_type));
//     }

//     the_switch = new CoreSwitch(0, num_hosts, c1, queue_type);
//     this->switches.push_back(the_switch);

//     assert(this->switches.size() == 1);

//     //Connect host queues
//     for (uint32_t i = 0; i < num_hosts; i++) {
//         hosts[i]->queue->set_src_dst(hosts[i], the_switch);
//         Queue *q = the_switch->queues[i];
//         q->set_src_dst(the_switch, hosts[i]);
//     }
// }

// Queue* BigSwitchTopology::get_next_hop(Packet *p, Queue *q) {
//     if (q->dst->type == HOST) {
//         assert(p->dst->id == q->dst->id);
//         return NULL; // Packet Arrival
//     }

//     // At host level
//     if (q->src->type == HOST) { // Same Rack or not
//         assert (p->src->id == q->src->id);
//         return the_switch->queues[p->dst->id];
//     }

//     assert(false);
// }

// double BigSwitchTopology::get_oracle_fct(Flow *f) {
//     double propagation_delay = 2 * 1000000.0 * 2 * f->src->queue->propagation_delay; //us

//     uint32_t np = ceil(f->size / params.mss); // TODO: Must be a multiple of 1460
//     double bandwidth = f->src->queue->rate / 1000000.0; // For us
//     double transmission_delay;
//     if (params.cut_through) {
//         transmission_delay = 
//             (
//                 np * (params.mss + params.hdr_size)
//                 + 1 * params.hdr_size
//                 + 2.0 * params.hdr_size // ACK has to travel two hops
//             ) * 8.0 / bandwidth;
//     }
//     else {
//         transmission_delay = ((np + 1) * (params.mss + params.hdr_size) 
//                 + 2.0 * params.hdr_size) // ACK has to travel two hops
//             * 8.0 / bandwidth;
//     }
//     return (propagation_delay + transmission_delay); //us
// }

