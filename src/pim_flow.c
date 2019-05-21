#include <math.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_memcpy.h>
#include <rte_hash.h>
#include "config.h"
#include "ds.h"
#include "header.h"
#include "pim_flow.h"

struct pim_flow ZERO_FLOW = {0};


void pim_flow_dump(struct pim_flow* f) {
    flow_dump(&f->_f);
    printf("%d", f->rd_ctrl_timeout_times);
    printf("\n");
    // printf("flow mbuf address: %u\n", f->buf);
    // printf("flow rts_received: %d\n", f->rts_received);
    // printf("flow finished_at_receiver: %d\n", f->finished_at_receiver);
    // printf("flow token_goal: %d\n", f->token_goal);
    // printf("flow remaining_pkts_at_sender: %d\n", f->remaining_pkts_at_sender);
    // printf("flow largest_token_seq_received: %d\n", f->largest_token_seq_received);
    // printf("flow last_token_data_seq_num_sent: %d\n", f->last_token_data_seq_num_sent);

}
struct pim_flow* pim_flow_new(struct rte_mempool* pool) {
	struct rte_mbuf* buf = rte_pktmbuf_alloc(pool);
	if (buf == NULL) {
        printf("%d: allocate flow fails\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
	}
    rte_pktmbuf_append(buf, sizeof(struct pim_flow));
	struct pim_flow* flow = rte_pktmbuf_mtod(buf, struct pim_flow*);
    rte_memcpy(flow, &ZERO_FLOW, sizeof(struct pim_flow));
	// *flow = ZERO_FLOW;
	flow->buf = buf;
	return flow;
}
void init_pim_flow(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, double start_time, int receiver_side) {
	init_flow(&(pim_f->_f), id, size, src_addr, dst_addr, start_time, receiver_side);

    pim_f->token_goal = (int)(ceil(pim_f->_f.size_in_pkt * 1.00));
    pim_f->remaining_pkts_at_sender = pim_f->_f.size_in_pkt;
    pim_f->largest_token_seq_received = -1;
    pim_f->largest_token_data_seq_received = -1;
    pim_f->latest_token_sent_time = -1;
    pim_f->latest_data_pkt_sent_time = -1;
	pim_f->last_token_data_seq_num_sent = -1;
    pim_f->rd_ctrl_timeout_times = 0;
	rte_timer_init(&pim_f->rd_ctrl_timeout);
    rte_timer_init(&pim_f->finish_timeout);
    pim_f->rd_ctrl_timeout_params = NULL;
    pim_f->finish_timeout_params = NULL;
}

// void pim_flow_free(struct rte_mempool* pool){}

int pim_init_token_size(struct pim_flow* pim_f) {
    return pim_f->_f.size_in_pkt <= params.small_flow_thre? pim_f->_f.size_in_pkt : 0;
}


bool pim_flow_compare(const void *a, const void* b) {
    if(a == NULL)
        return true;
    if(b == NULL)
        return false;

    if(pim_remaining_pkts((struct pim_flow*)a) - pim_token_gap((struct pim_flow*)a) 
        > pim_remaining_pkts((struct pim_flow*)b) - pim_token_gap((struct pim_flow*)b))
        return true;
    else if(((const struct pim_flow*)a)->_f.start_time > ((const struct pim_flow*)b)->_f.start_time)
        return true;
    else
        return false;
}

// // receiver side
int pim_remaining_pkts(struct pim_flow* f) {
    return 0 > ((int)f->_f.size_in_pkt - (int)f->_f.received_count)? 0 : (f->_f.size_in_pkt - f->_f.received_count);
}
int pim_token_gap(struct pim_flow* f) {
    if(f->token_count - f->largest_token_seq_received < 0) {
        rte_exit(EXIT_FAILURE ,"token gap less than 0");
    }
    return f->token_count - f->largest_token_seq_received - 1;
}
// void pim_relax_token_gap(pim_flow* f) {

// }
int pim_get_next_token_seq_num(struct pim_flow* f) {
    uint32_t count = 0;
    uint32_t data_seq = (f->last_token_data_seq_num_sent + 1) % f->_f.size_in_pkt;
    struct rte_bitmap* bmp = f->_f.bmp;
    while(count < f->_f.size_in_pkt)
    {
        if(rte_bitmap_get(bmp, (uint32_t)data_seq) == 0)
        {
            if(data_seq < f->_f.size_in_pkt) {
                return data_seq;
            } else {
                rte_exit(EXIT_FAILURE, "data seq is in wrong range");
            }
        }
        else
        {
            data_seq++;
            if(data_seq >= f->_f.size_in_pkt)
            {
                data_seq = f->received_until;
            }

        }
        count++;
    }
    rte_exit(EXIT_FAILURE, "get next token should never reaches here");
}
void pim_get_token_pkt(struct pim_flow* pim_f, struct rte_mbuf* p, uint32_t round, int data_seq) {
    add_ether_hdr(p);

    struct ipv4_hdr ipv4_hdr;
    uint16_t size;
    size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
        sizeof(struct pim_hdr) + sizeof(struct pim_token_hdr);
    ipv4_hdr.src_addr = rte_cpu_to_be_32(pim_f->_f.dst_addr);
    ipv4_hdr.dst_addr = rte_cpu_to_be_32(pim_f->_f.src_addr);
    ipv4_hdr.total_length = rte_cpu_to_be_16(size);

    add_ip_hdr(p, &ipv4_hdr);
    
    struct pim_hdr pim_hdr;
    pim_hdr.type = PIM_TOKEN;
    add_pim_hdr(p, &pim_hdr);
    int data_seq_num = data_seq;
    pim_f->last_token_data_seq_num_sent = data_seq_num;
    struct pim_token_hdr pim_token_hdr;
    pim_token_hdr.priority = pim_f->_f.priority;
    pim_token_hdr.flow_id = pim_f->_f.id;
    pim_token_hdr.data_seq = data_seq_num;
    pim_token_hdr.seq_num = pim_f->token_count;
    pim_token_hdr.remaining_size = pim_remaining_pkts(pim_f);

    if(pim_f->_f.size_in_pkt > params.small_flow_thre) {
        pim_token_hdr.round = round;
    } else {
        pim_token_hdr.round = 0;
    }
    add_pim_token_hdr(p, &pim_token_hdr);

    pim_f->token_count++;
    pim_f->token_packet_sent_count++;
}

void pim_get_ack_pkt(struct rte_mbuf* p, struct pim_flow* flow) {
    add_ether_hdr(p);
    struct ipv4_hdr ipv4_hdr;
    struct pim_hdr pim_hdr;
    struct pim_ack_hdr pim_ack_hdr;
    uint16_t size;
    size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
        sizeof(struct pim_hdr) + sizeof(struct pim_ack_hdr);
    ipv4_hdr.src_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr.dst_addr = rte_cpu_to_be_32(flow->_f.src_addr);
    ipv4_hdr.total_length = rte_cpu_to_be_16(size);
    add_ip_hdr(p, &ipv4_hdr);

    pim_hdr.type = PIM_ACK;
    add_pim_hdr(p, &pim_hdr);
    pim_ack_hdr.flow_id = flow->_f.id;
    add_pim_ack_hdr(p, & pim_ack_hdr);
}
// find the smallest of long flows
struct pim_flow* get_src_smallest_unfinished_flow(Pq* pq) {
    struct pim_flow* smallest_flow = NULL;
    // Pq* pq = lookup_table_entry(table, src_addr);
    while(1) {
        smallest_flow = pq_peek(pq);
        if (smallest_flow == NULL)
            return smallest_flow;
        if (smallest_flow->finished_at_receiver) {
            pq_pop(pq);
            // rte_exit(EXIT_FAILURE, "SMALLEST: FLOW FINISH");
            continue;
        }
        if (smallest_flow->rd_ctrl_timeout_params != NULL) {
            pq_pop(pq);
            // rte_exit(EXIT_FAILURE, "SMALLEST: FLOW RD TIMEOUT");
            continue;
        }
        return smallest_flow;
    }
    return smallest_flow;
    // while(1) {
    //     position = rte_hash_iterate(table, (const void**) &flow_id, (void**)&flow, &next);
    //     if(position == -ENOENT) {
    //         break;
    //     }
    //     if(flow->finished_at_receiver) {
    //         continue;
    //     }
    //     if(flow->rd_ctrl_timeout_params != NULL) {
    //         continue;
    //     }
    //     if(flow->_f.src_addr != src_addr) {
    //         continue;
    //     }
    //     if(flow->_f.size_in_pkt <= params.small_flow_thre) {
    //         continue;
    //     }
    //     if(pim_flow_compare(smallest_flow, flow)) {
    //         smallest_flow = flow;
    //         if(smallest_flow != NULL) {
    //             return smallest_flow;
    //         }
    //     }
    // }
    // return smallest_flow;
}

void reset_rd_ctrl_timeout(struct pim_receiver* receiver, struct pim_flow* flow, double time) {
    // double time = params.token_resend_timeout * params.BDP * get_transmission_delay(1500) ;
    if(flow->rd_ctrl_timeout_params == NULL) {
        flow->rd_ctrl_timeout_params = rte_zmalloc("rd ctrl timeout param", 
            sizeof(struct rd_ctrl_timeout_params), 0);
        flow->rd_ctrl_timeout_params->receiver = receiver;
        flow->rd_ctrl_timeout_params->flow = flow;
    }
    if(debug_flow(flow->_f.id)) {
        printf("flow %u: flow received count: %u\n", flow->_f.id, flow->_f.received_count);
    }
    flow->rd_ctrl_timeout_times++;
    int ret = rte_timer_reset(&flow->rd_ctrl_timeout, rte_get_timer_hz() * time, SINGLE,
                    rte_lcore_id(), &rd_ctrl_timeout_handler, (void*)flow->rd_ctrl_timeout_params);
    if(ret != 0) {
        printf("%d: cannot reset timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
}

void rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct rd_ctrl_timeout_params* timeout_params = (struct rd_ctrl_timeout_params*) arg;
    struct pim_flow* flow = timeout_params->flow;
    struct pim_receiver *receiver = timeout_params->receiver;
    flow->rd_ctrl_timeout_params = NULL;
    if(debug_flow(flow->_f.id)){
        printf("redundancy ctl timeout for flow flow%u\n", flow->_f.id);
    }
    rte_free(timeout_params);
    if(flow->finished_at_receiver) {
        return;
    }
    // if flow is short then has to send tokens; otherwise treats the same as new large flow;
    if(flow->_f.size_in_pkt < params.small_flow_thre) {
        uint32_t i = 0;
        for(; i < flow->_f.size_in_pkt; i++) {
            if(rte_bitmap_get(flow->_f.bmp, i) == 0) {
                struct rte_mbuf* p = NULL;
                p = rte_pktmbuf_alloc(pktmbuf_pool);
                uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
                    sizeof(struct pim_hdr) + sizeof(struct pim_token_hdr);
                if(p == NULL) {
                    printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
                    printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
                    rte_exit(EXIT_FAILURE, "%s: pktmbuf_pool is full\n", __func__);
                }
                rte_pktmbuf_append(p, size);
                pim_get_token_pkt(flow, p, -1, i);
                enqueue_ring(receiver->short_flow_token_q, p);
            }
        }
        reset_rd_ctrl_timeout(receiver, flow, get_transmission_delay(1500) * params.BDP);
    } else { 
        Pq* pq = lookup_table_entry(receiver->src_minflow_table, flow->_f.src_addr);
        pq_push(pq, flow);
        if(receiver->gosrc_info.has_gosrc 
            && receiver->gosrc_info.src_addr == flow->_f.src_addr) {
            if(pim_flow_compare(receiver->gosrc_info.current_flow, flow)) {
                receiver->gosrc_info.current_flow = get_src_smallest_unfinished_flow(pq);
            } 
        }
    }
}

void finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct finish_timeout_params* timeout_params = (struct finish_timeout_params*) arg;
    struct pim_receiver*
     receiver = timeout_params->receiver;
    struct pim_flow* flow = lookup_table_entry(receiver->rx_flow_table, timeout_params->flow_id);
    flow->finish_timeout_params = NULL;
    Pq* pq = lookup_table_entry(receiver->src_minflow_table, flow->_f.src_addr);
    get_src_smallest_unfinished_flow(pq);
    // printf("finish timeout handler for flow %u\n", flow->_f.id);
    delete_table_entry(receiver->rx_flow_table, timeout_params->flow_id);
    rte_free(flow->_f.bmp);
    // rte_bitmap_free(flow->_f.bmp);
    if(flow->rd_ctrl_timeout_params == NULL) {
        rte_pktmbuf_free(flow->buf);
    }
    rte_free(timeout_params);
}