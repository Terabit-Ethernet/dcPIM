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


void pflow_dump(struct pim_flow* f) {
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
struct pim_flow* pflow_new(struct rte_mempool* pool) {
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
void pflow_init(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr, double start_time, int receiver_side) {
	init_flow(&(pim_f->_f), id, size, src_addr, dst_addr, start_time, receiver_side);

    pim_f->remaining_pkts_at_sender = pim_f->_f.size_in_pkt;
    pim_f->rd_ctrl_timeout_times = 0;
    pim_f->ack_until = 0;
    pim_f->ack_count = 0;
    pim_f->largest_seq_ack = -1;
    pim_f->last_data_seq_num_sent = -1;
    pim_f->latest_data_pkt_send_time = -1;
    pim_f->first_loop = false;
    pim_f->next_seq_no = 0;
    pim_f->flow_sync_received = false;
	rte_timer_init(&pim_f->rd_ctrl_timeout);
    rte_timer_init(&pim_f->finish_timeout);
    pim_f->rd_ctrl_timeout_params = NULL;
    pim_f->finish_timeout_params = NULL;
}

// void pim_flow_free(struct rte_mempool* pool){}

bool pflow_is_small_flow(struct pim_flow* pim_flow) {
    return pim_flow->_f.size_in_pkt <= params.small_flow_thre;
}

// // receiver side
int pflow_remaining_pkts(const struct pim_flow* f) {
    return 0 > ((int)f->_f.size_in_pkt - (int)f->ack_count)? 0 : (f->_f.size_in_pkt - f->ack_count);
}
int pflow_gap(const struct pim_flow* f) {
    if(f->next_seq_no - f->largest_seq_ack < 0) {
        printf("next seq number: %d; largest seq ack: %d \n", f->next_seq_no, f->largest_seq_ack);
        rte_exit(EXIT_FAILURE ,"token gap less than 0");
    }
    return f->next_seq_no - f->largest_seq_ack - 1;
}
// void pim_relax_token_gap(pim_flow* f) {

// }
int pflow_get_next_data_seq_num(struct pim_flow* f) {
    uint32_t count = 0;
    uint32_t data_seq = (f->last_data_seq_num_sent + 1) % f->_f.size_in_pkt;
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
                data_seq = f->ack_until;
            }

        }
        count++;
    }
    rte_exit(EXIT_FAILURE, "get next token should never reaches here");
}

bool pflow_is_rd_ctrl_timeout_params_null(struct pim_flow* flow) {
    return flow->rd_ctrl_timeout_params == NULL;
}
void pflow_set_rd_ctrl_timeout_params_null(struct pim_flow* flow) {
    if(flow->rd_ctrl_timeout_params != NULL) {
        if(rte_timer_stop(&flow->rd_ctrl_timeout) == -1) {
            rte_exit(EXIT_FAILURE, "RD CTRL TIMEOUT SET NULL FAIL");
        }
        rte_free(flow->rd_ctrl_timeout_params);
    }
    flow->rd_ctrl_timeout_params = NULL;
}
struct rte_mbuf* pflow_send_data_pkt(struct pim_flow* flow) {
    if(flow == NULL) {
        rte_exit(EXIT_FAILURE, "FLOW IS NULL");
    }
    struct rte_mbuf* p = NULL;
    p = rte_pktmbuf_alloc(pktmbuf_pool);
    if (p == NULL) {
        printf("%d: allocate flow fails\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    rte_pktmbuf_append(p, 1500);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_data_hdr* pim_data_hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.src_addr);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(1500);

    pim_hdr->type = DATA;
    pim_data_hdr->flow_id = flow->_f.id;
    pim_data_hdr->seq_no = flow->next_seq_no;
    pim_data_hdr->data_seq_no = pflow_get_next_data_seq_num(flow);
    pim_data_hdr->priority = flow->_f.priority;

    flow->next_seq_no += 1;
    flow->last_data_seq_num_sent = pim_data_hdr->data_seq_no;
    return p;
}

struct rte_mbuf* pflow_get_ack_pkt(struct pim_flow* flow, struct pim_data_hdr* pim_data_hdr) {
    struct rte_mbuf* p = NULL;
    p = rte_pktmbuf_alloc(pktmbuf_pool);
    if (flow == NULL) {
        printf("%d: flow is NULL\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    if (p == NULL) {
        printf("%d: allocate flow fails\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
                sizeof(struct pim_hdr) + sizeof(struct pim_ack_hdr);
    rte_pktmbuf_append(p, size);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_ack_hdr* pim_ack_hdr = rte_pktmbuf_mtod_offset(p, struct pim_ack_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.src_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size);

    pim_hdr->type = PIM_ACK;

    pim_ack_hdr->flow_id = flow->_f.id;
    pim_ack_hdr->data_seq_no_acked = pim_data_hdr->data_seq_no;
    pim_ack_hdr->seq_no = pim_data_hdr->seq_no;

    return p;
}

void pflow_reset_rd_ctrl_timeout(struct pim_host* host, struct pim_flow* flow, double time) {
    // double time = params.token_resend_timeout * params.BDP * get_transmission_delay(1500) ;
    if(flow->rd_ctrl_timeout_params == NULL) {
        flow->rd_ctrl_timeout_params = rte_zmalloc("rd ctrl timeout param", 
            sizeof(struct rd_ctrl_timeout_params), 0);
        flow->rd_ctrl_timeout_params->host = host;
        flow->rd_ctrl_timeout_params->flow = flow;
    }
    if(debug_flow(flow->_f.id)) {
        printf("flow %u: flow received count: %u\n", flow->_f.id, flow->ack_count);
    }
    flow->rd_ctrl_timeout_times++;
    int ret = rte_timer_reset(&flow->rd_ctrl_timeout, rte_get_timer_hz() * time, SINGLE,
                    rte_lcore_id(), &pflow_rd_ctrl_timeout_handler, (void*)flow->rd_ctrl_timeout_params);
    if(ret != 0) {
        printf("%d: cannot reset timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
}

void pflow_receive_ack(struct pim_host* host, struct pim_flow* flow, struct pim_ack_hdr* p) {
    // Determing which ack to send
    // auto sack_list = p->sack_list;
    // if(this->next_seq_no < p->seq_no_acked)
    //     this->next_seq_no = p->seq_no_acked;
    uint32_t data_seq = p->data_seq_no_acked;
    struct rte_bitmap* bmp = flow->_f.bmp;
    if(flow->_f.finished)
        return;
    if(rte_bitmap_get(bmp, data_seq) == 0) {
        rte_bitmap_set(bmp, data_seq);
        flow->ack_count += 1;
        while(flow->ack_until < (int)flow->_f.size_in_pkt && rte_bitmap_get(bmp, flow->ack_until) != 0) {
            flow->ack_until++;
        }
        flow->remaining_pkts_at_sender--;
    }
    if(flow->largest_seq_ack < (int)(p->seq_no)) {
        flow->largest_seq_ack = p->seq_no;
    }
    if(flow->remaining_pkts_at_sender == 0) {
        if(!pflow_is_rd_ctrl_timeout_params_null(flow)){
            pflow_set_rd_ctrl_timeout_params_null(flow); 
        }
        pflow_set_finish_timeout(host, flow);

        return;
    }
}

void pflow_rd_ctrl_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct rd_ctrl_timeout_params* timeout_params = (struct rd_ctrl_timeout_params*) arg;
    struct pim_flow* flow = timeout_params->flow;
    struct pim_host *host = timeout_params->host;
    flow->rd_ctrl_timeout_params = NULL;
    if(debug_flow(flow->_f.id)){
        printf("redundancy ctl timeout for flow flow%u\n", flow->_f.id);
    }
    rte_free(timeout_params);
    if(flow->_f.finished) {
        return;
    }
    // if flow is short then has to send tokens; otherwise treats the same as new large flow;
    if(flow->_f.size_in_pkt < params.small_flow_thre) {
        pq_push(&host->active_short_flows, flow);
    } else { 
        Pq* pq = lookup_table_entry(host->dst_minflow_table, flow->_f.dst_addr);
        pq_push(pq, flow);
    }
}

void pflow_set_finish_timeout(struct pim_host* host, struct pim_flow* flow) {
    flow->finish_timeout_params = rte_zmalloc("finish timeout param", 
        sizeof(struct finish_timeout_params), 0);
    if(flow->finish_timeout_params == NULL) {
        printf("%d: no memory for timeout param \n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    flow->_f.finish_time = rte_get_tsc_cycles();
    flow->_f.finished = true;
    flow->finish_timeout_params->host = host;
    flow->finish_timeout_params->flow_id = flow->_f.id;
    int ret = rte_timer_reset(&flow->finish_timeout, rte_get_timer_hz() * 2 * get_rtt(params.propagation_delay, 3, 1500), SINGLE,
                    rte_lcore_id(), &pflow_finish_timeout_handler, (void *)flow->finish_timeout_params);
    if(ret != 0) {
        printf("%d: cannot set up finish timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
}

void pflow_finish_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct finish_timeout_params* timeout_params = (struct finish_timeout_params*) arg;
    struct pim_host* host = timeout_params->host;
    struct pim_flow* flow = lookup_table_entry(host->tx_flow_table, timeout_params->flow_id);
    flow->finish_timeout_params = NULL;
    Pq* pq = lookup_table_entry(host->dst_minflow_table, flow->_f.dst_addr);
    get_smallest_unfinished_flow(pq);
    // printf("finish timeout handler for flow %u\n", flow->_f.id);
    // delete_table_entry(host->tx_flow_table, timeout_params->flow_id);
    rte_free(flow->_f.bmp);
    // rte_bitmap_free(flow->_f.bmp);
    // if(flow->rd_ctrl_timeout_params == NULL) {
    //     rte_pktmbuf_free(flow->buf);
    // }
    rte_free(timeout_params);
}