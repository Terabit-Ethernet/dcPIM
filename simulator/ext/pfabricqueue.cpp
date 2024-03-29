#include "pfabricqueue.h"
#include "../run/params.h"
#include "../coresim/debug.h"
#include "factory.h"
#include <iostream>
#include <limits.h>
#include <assert.h>
extern double get_current_time();
extern void add_to_event_queue(Event *ev);
extern DCExpParams params;

/* PFabric Queue */
PFabricQueue::PFabricQueue(uint32_t id, double rate, uint32_t limit_bytes, int location)
    : Queue(id, rate, limit_bytes, location) {}

void PFabricQueue::enque(Packet *packet) {
    p_arrivals += 1;
    b_arrivals += packet->size;
    packets.push_back(packet);
    bytes_in_queue += packet->size;
    packet->last_enque_time = get_current_time();
    if (bytes_in_queue > limit_bytes && limit_bytes != -1) {
        uint32_t worst_priority = 0;
        uint32_t worst_index = 0;
        for (uint32_t i = 0; i < packets.size(); i++) {
            if (packets[i]->pf_priority >= worst_priority) {
                worst_priority = packets[i]->pf_priority;
                worst_index = i;
            }
        }
        bytes_in_queue -= packets[worst_index]->size;
        Packet *worst_packet = packets[worst_index];

        packets.erase(packets.begin() + worst_index);
        pkt_drop++;
        drop(worst_packet);
    }
//    if(packet->type == PIM_GRANTS_PACKET && packet_transmitting != NULL) {
//        if(debug_host(packet_transmitting->dst->id)) {
//            std::cout << " transmitting a packet now: for flow :" << packet_transmitting->flow->id << " location: " <<  this->location << std::endl;
//            std::cout << " grant flow id:" << packet->flow->id << std::endl;
//        }
//    }    
    // for debugging
    packet->hop++;
}

Packet* PFabricQueue::deque() {
    if (bytes_in_queue > 0) {

        uint32_t best_priority = UINT_MAX;
        Packet *best_packet = NULL;
        uint32_t best_index = 0;
        for (uint32_t i = 0; i < packets.size(); i++) {
            Packet* curr_pkt = packets[i];
            if (curr_pkt->pf_priority < best_priority) {
                best_priority = curr_pkt->pf_priority;
                best_packet = curr_pkt;
                best_index = i;
            }
        }
        if(params.host_type == NORMAL_HOST) {
            for (uint32_t i = 0; i < packets.size(); i++) {
                Packet* curr_pkt = packets[i];
                if (curr_pkt->flow->id == best_packet->flow->id) {
                    best_index = i;
                    break;
                }
            }
        }
        Packet *p = packets[best_index];
        bytes_in_queue -= p->size;
        packets.erase(packets.begin() + best_index);

        p_departures += 1;
        b_departures += p->size;

        p->total_queuing_delay += get_current_time() - p->last_enque_time;
       // if(p->type == PIM_GRANTS_PACKET) {
       //     if(debug_host(p->flow->dst->id)) {
       //        std::cout << "delay:" << get_current_time() - p->last_enque_time << std::endl;
       //         std::cout << " location: " << this->location << std::endl;
       //     }
       // }
        if(p->type ==  NORMAL_PACKET){
            if(p->flow->first_byte_send_time < 0)
                p->flow->first_byte_send_time = get_current_time();
            if(this->location == 0)
                p->flow->first_hop_departure++;
            if(this->location == 3)
                p->flow->last_hop_departure++;
        }
        return p;

    } else {
        return NULL;
    }
}

