#include <math.h>


#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "config.h"
#include "flow.h"

void init_flow(struct flow* f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, 
    struct ether_addr* ether, uint64_t start_time, int receiver_side){
	f->id = id;
    f->start_time = start_time;
    f->size = size;
    f->src_addr = src_addr;
    f->dst_addr = dst_addr;
    f->finish_time = 0;
    f->received_bytes = 0;
    f->received_count = 0;
    f->sent_bytes = 0;
    f->first_byte_send_time = 0;
    f->first_byte_receive_time = -1;
    f->size_in_pkt = (int)ceil((double)size/ params.mss);
    f->priority = get_flow_priority(f, params.small_flow_thre, params.priority_limit);
    uint32_t size_in_pkt = f->size_in_pkt;
    // if(size_in_pkt == 0) {
    //     rte_exit(EXIT_FAILURE, "size_in_pkt is zero\n");
    //     size_in_pkt == 2 * params.BDP;
    // }

    if(receiver_side == 1) {
        ether_addr_copy(ether, &(f->src_ether_addr));

        uint32_t bmp_size = rte_bitmap_get_memory_footprint(size_in_pkt);
        void *mem = rte_zmalloc("bit map", bmp_size, 0);
        if (mem == NULL) {
           printf("Failed to allocate memory for bitmap\n");
           rte_exit(EXIT_FAILURE, "Failed to allocate memory for bitmap\n");
       }
       f->bmp = rte_bitmap_init(size_in_pkt, mem, bmp_size);
    } else {
        ether_addr_copy(ether, &(f->dst_ether_addr));
        f->bmp = NULL;
    }
} 

// pcp value in vlan header
uint8_t get_flow_priority(struct flow* f, uint32_t base, uint32_t limit) {
    if (base == 0)
        return 0;
    uint8_t priority = 1;
    uint32_t size = base;
    while(f->size_in_pkt > size) {
        size *= base;
        priority++;
    }
    if (priority > limit)
        priority = limit;
    return priority;
}
// uint16_t get_tci(uint8_t priority) {
//     switch(priority) {
//         case 6:
//         // PCP 0 is default;
//             return TCI_0;
//         case 5:
//             return TCI_2;
//         case 4:
//             return TCI_3;
//         case 3:
//             return TCI_4;
//         case 2:
//             return TCI_5;
//         case 1: 
//             return TCI_6;        
//         default : /* Optional */
//             return TCI_0;
//     }
//     return TCI_0;
// }

uint8_t get_tos(uint8_t priority) {
    switch(priority) {
        case 6:
        // PCP 0 is default;
            return TOS_1;
        case 5:
            return TOS_2;
        case 4:
            return TOS_3;
        case 3:
            return TOS_4;
        case 2:
            return TOS_5;
        case 1: 
            return TOS_6;        
        default : /* Optional */
            return TOS_0;
    }
    return TOS_0;
}

void flow_dump(struct flow *f) {
    // format: flow id, start_cycle, finish_cycle, fct, oracle fct, received_bytes, priority;
    double fct = (double)(f->finish_time - f->start_time) / (double)(rte_get_tsc_hz());
    double waiting_time = (double)(f->first_byte_send_time - f->start_time) / (double)(rte_get_tsc_hz());
    printf("%u ", f->id);
    printf("%u ", f->src_addr);
    printf("%u ", f->dst_addr);

    // printf("%lu ", f->start_time);
    // printf("%lu ", f->finish_time);
    printf("%u ", f->size);
    printf("%f ", fct);
    printf("%f ", flow_oracle_fct(f));
    printf("%f ", fct / flow_oracle_fct(f));
    printf("%f ", waiting_time);
    printf("%u ", f->sent_bytes);
    printf("%u ", f->finished);
    printf("%u ", f->priority);
    printf("%f ", (double)(f->start_time) / (double)(rte_get_tsc_hz()));
    printf("%f ", (double)(f->finish_time) / (double)(rte_get_tsc_hz()));

}

double flow_oracle_fct(struct flow* f) {
    // double ack_size = 40;
    double trans_delay = (f->size_in_pkt * 1500.0 + 40) * 8 / (double)params.bandwidth;
    // final packet transmission delay
    trans_delay += (1500 + 40) * 8 / (double) params.bandwidth;
    double propagation_delay = 2 * params.propagation_delay;
    return trans_delay + propagation_delay;
}
// flow* flow_new(void) {
// 	// initialize all values to be zero
// 	flow* f = rte_zmalloc("create flow", sizeof(flow), 0);
// 	if (f == NULL) {
// 		rte_exit(EXIT_FAILURE, "No NUMA memory for creating new flow \n");
// 	}
// 	// f->id = 0;
//  //    f->start_time = 0;
//  //    f->finish_time = 0;
//  //    f->size = 0;
//  //    f->src_addr = 0;
//  //    f->dst_addr = 0;
//  //    f->received_bytes = 0;
//  //    f->recv_till = 0;
//  //    f->max_seq_no_recv = 0;
// 	// f->total_pkt_sent = 0;
//  //    f->size_in_pkt = 0;
//  //    f->received_count = 0;
//  //    f->finished = 0;
//     return f;
// }

// void set_flow_id(flow* f, uint32_t id) {
// 	f->id = id;
// }
// void set_flow_addr(flow* f, uint32_t src_addr, uint32_t dst_addr) {
// 	f->src_addr = src_addr;
// 	f->dst_addr = dst_addr;
// }
// void set_flow_size(flow* f, uint32_t size) {
// 	f->size = size;
// 	f->size_in_pkt = size % 1460 == 0? size / 1460 : size / 1460 + 1;
// }
// void set_flow_start_time(flow* f, double start_time) {
// 	f->start_time = start_time;
// }
// void set_flow_finish_time(flow* f, double finish_time) {
// 	f->finish_time = finish_time;
// }
// flow* flow_free(flow* f) {
// 	rte_free(f);
// 	return NULL;
// }