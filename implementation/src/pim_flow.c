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
void pflow_init(struct pim_flow* pim_f, uint32_t id, uint32_t size, uint32_t src_addr, uint32_t dst_addr,
struct ether_addr* ether_addr, double start_time, int receiver_side) {
	init_flow(&(pim_f->_f), id, size, src_addr, dst_addr, ether_addr, start_time, receiver_side);
    pim_f->flow_sync_received = false;
    pim_f->token_goal = (int)(ceil(pim_f->_f.size_in_pkt * 1.00));
    pim_f->remaining_pkts_at_sender = pim_f->_f.size_in_pkt;
    pim_f->largest_token_seq_received = -1;
    pim_f->largest_token_data_seq_received = -1;
    pim_f->latest_token_sent_time = 0;
    pim_f->latest_data_pkt_sent_time = -1;
    pim_f->last_token_data_seq_num_sent = -1;
    pim_f->rd_ctrl_timeout_times = 0;
    rte_timer_init(&pim_f->rd_ctrl_timeout);
    rte_timer_init(&pim_f->finish_timeout);
    rte_timer_init(&pim_f->rtx_flow_sync_timeout);
    rte_timer_init(&pim_f->rtx_fin_timeout);
    pim_f->rd_ctrl_timeout_params = NULL;
    pim_f->finish_timeout_params = NULL;
    pim_f->token_count = 0;
}

// void pim_flow_free(struct rte_mempool* pool){}
int pflow_init_token_size(struct pim_flow* pim_flow) {
    return pim_flow->_f.size_in_pkt <= params.small_flow_thre? pim_flow->_f.size_in_pkt : 0;
}

bool pflow_is_small_flow(struct pim_flow* pim_flow) {
    return pim_flow->_f.size_in_pkt <= params.small_flow_thre;
}

// // receiver side
int pflow_remaining_pkts(const struct pim_flow* f) {
    return 0 > ((int)f->_f.size_in_pkt - (int)f->_f.received_count)? 0 : (f->_f.size_in_pkt - f->_f.received_count);
}
int pflow_token_gap(const struct pim_flow* f) {
    if(f->token_count - f->largest_token_seq_received < 0) {
        printf("flow id: %u\n", f->_f.id);
        printf("flow src: %u\n", f->_f.src_addr);
        printf("flow dst:%u\n", f->_f.dst_addr);
        printf("flow size in pkt:%u\n", f->_f.size_in_pkt);
        printf("f->token_count:%u\n", f->token_count);
        printf("f->largest_token_seq_received:%u\n", f->largest_token_seq_received);
        rte_exit(EXIT_FAILURE ,"token gap less than 0");
    }
    return f->token_count - f->largest_token_seq_received - 1;
}

void pflow_relax_token_gap(struct pim_flow* f) {
    f->largest_token_seq_received = f->token_count - params.token_window;
}
bool pflow_get_finish_at_receiver(struct pim_flow* flow) {
    return flow->finished_at_receiver;
}

bool pflow_get_finish(struct pim_flow* flow) {
    return flow->_f.finished;
}

void pflow_set_finish_at_receiver(struct pim_flow* flow) {
    flow->finished_at_receiver = true;
    flow->state = FINISH_WAIT;
}
void pflow_set_finish(struct pim_flow* flow) {
    flow->_f.finished = true;
    flow->_f.finish_time = rte_get_tsc_cycles();
    flow->state = FINISH;
}
// void pim_relax_token_gap(pim_flow* f) {

// }
int pflow_get_next_token_seq_num(struct pim_flow* f) {
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
struct rte_mbuf* pflow_get_token_pkt(struct pim_flow* flow, uint32_t data_seq, bool free_token) {
    if(flow == NULL) {
        rte_exit(EXIT_FAILURE, "FLOW IS NULL");
    }
    struct rte_mbuf* p = NULL;
    p = rte_pktmbuf_alloc(pktmbuf_pool);
    if (p == NULL) {
        return NULL;
        printf("%d: allocate packet fails\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    uint32_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
        sizeof(struct pim_hdr) + sizeof(struct pim_token_hdr);
    rte_pktmbuf_append(p, size);
    if(free_token) {
        struct ether_hdr* ether_hdr = rte_pktmbuf_mtod_offset(p, struct ether_hdr*, 0);
        ether_addr_copy(&params.ether_addr, &ether_hdr->d_addr);
        ether_addr_copy(&flow->_f.dst_ether_addr, &ether_hdr->s_addr);
    } else {
        add_ether_hdr(p, &flow->_f.src_ether_addr);
    }
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.src_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size - sizeof(struct ether_hdr));

    pim_hdr->type = PIM_TOKEN;
    pim_token_hdr->flow_id = flow->_f.id;
    pim_token_hdr->data_seq_no = data_seq;
    pim_token_hdr->priority = flow->_f.priority;
    if(free_token) {
        pim_token_hdr->free_token = 1;
    } else {
        pim_token_hdr->free_token = 0;
        pim_token_hdr->seq_no = flow->token_count;
        pim_token_hdr->remaining_size = pflow_remaining_pkts(flow);
        
        flow->token_count++;
        flow->token_packet_sent_count++;
        flow->last_token_data_seq_num_sent = data_seq;
        flow->latest_token_sent_time = rte_get_tsc_cycles();
    }
    // flow->next_seq_no += 1;
    // flow->last_data_seq_num_sent = pim_token_hdr->data_seq_no;
    return p;
}

struct rte_mbuf* pflow_get_fin_pkt(struct pim_flow* flow) {
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
                sizeof(struct pim_hdr) + sizeof(struct pim_fin_hdr);
    rte_pktmbuf_append(p, size);
    add_ether_hdr(p, &flow->_f.src_ether_addr);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_fin_hdr* pim_fin_hdr = rte_pktmbuf_mtod_offset(p, struct pim_fin_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.src_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size - sizeof(struct ether_hdr));

    pim_hdr->type = PIM_FIN;

    pim_fin_hdr->flow_id = flow->_f.id;
    pim_fin_hdr->rd_ctrl_times = flow->rd_ctrl_timeout_times;
    // pim_ack_hdr->data_seq_no_acked = pim_data_hdr->data_seq_no;
    // pim_ack_hdr->seq_no = pim_data_hdr->seq_no;

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
    flow->rd_ctrl_timeout_times++;
    int ret = rte_timer_reset(&flow->rd_ctrl_timeout, rte_get_timer_hz() * time, SINGLE,
                    rte_lcore_id(), &pflow_rd_ctrl_timeout_handler, (void*)flow->rd_ctrl_timeout_params);
    if(ret != 0) {
        printf("%d: cannot reset timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
}

void pflow_receive_data(struct pim_host* host, struct pim_pacer* pacer, struct pim_flow* f, struct pim_data_hdr* pim_data_hdr) {
    // Determing which ack to send
    // auto sack_list = p->sack_list;
    // if(this->next_seq_no < p->seq_no_acked)
    //     this->next_seq_no = p->seq_no_acked;
    struct rte_bitmap* bmp = f->_f.bmp;
    if(f->finished_at_receiver || f->state == FINISH_WAIT) {
        return;
    }
    if(rte_bitmap_get(bmp, pim_data_hdr->data_seq_no) == 0) {
        rte_bitmap_set(bmp, pim_data_hdr->data_seq_no);
        f->_f.received_count++;
        while(f->received_until < (int)f->_f.size_in_pkt && rte_bitmap_get(bmp, f->received_until) != 0) {
            f->received_until++;
        }
        // if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
        //     num_outstanding_packets -= ((p->size - hdr_size) / (mss));
        // else
        //     num_outstanding_packets = 0;
        if(f->largest_token_data_seq_received < (int)pim_data_hdr->data_seq_no) {
            f->largest_token_data_seq_received =  (int)pim_data_hdr->data_seq_no;
        }
    }
    // hard code part
    f->_f.received_bytes += 1460;

    if(pim_data_hdr->free_token != 1) {
        if((int)pim_data_hdr->seq_no > f->largest_token_seq_received)
            f->largest_token_seq_received = (int)pim_data_hdr->seq_no;
    }
    if (f->_f.received_count >= f->_f.size_in_pkt) {
        struct rte_mbuf* p = pflow_get_fin_pkt(f);
        enqueue_ring(pacer->ctrl_q, p);
        // sending_ack(p->ranking_round);
        pflow_set_finish_at_receiver(f);
        // set rtx timeout for pim ack
        f->flow_fin_resent_timeout_params.host = host;
        f->flow_fin_resent_timeout_params.flow = f;
        f->flow_fin_resent_timeout_params.pacer = pacer;
        f->flow_fin_resent_timeout_params.time = 2 * params.BDP * get_transmission_delay(1500);
	rte_timer_reset(&f->rtx_fin_timeout, rte_get_timer_hz() * f->flow_fin_resent_timeout_params.time,
            SINGLE, rte_lcore_id(), &pflow_rtx_fin_timeout_handler, (void *)&f->flow_fin_resent_timeout_params);
        // clean up memory and timer;
        if(!pflow_is_rd_ctrl_timeout_params_null(f)){
            pflow_set_rd_ctrl_timeout_params_null(f); 
        }
        // this should be comment out
        // pflow_set_finish_timeout(host, f);
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
    if(flow->_f.finished || flow->finished_at_receiver) {
        return;
    }
    if(flow->_f.src_addr == params.ip) {
        Pq* pq = lookup_table_entry(host->dst_minflow_table, flow->_f.dst_addr);
        pq_push(pq, flow);
    } else {
        Pq* pq = lookup_table_entry(host->src_minflow_table, flow->_f.src_addr);
        pq_push(pq, flow);
    }
    // failed short flows will be treated as long flows

    
}

void pflow_rtx_flow_sync_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct flow_sync_resent_timeout_params* timeout_params = (struct flow_sync_resent_timeout_params*) arg;
    struct pim_flow* flow = timeout_params->flow;
    struct pim_host *host = timeout_params->host;
    struct pim_pacer *pacer = timeout_params->pacer;
    if(debug_flow(flow->_f.id)){
        printf("rtx flow sync timeout for flow flow%u\n", flow->_f.id);
    }
    if(flow->state != SYNC_SENT) {
        return;
    }
    pim_send_flow_sync(pacer, host, flow); 
    // reset timer 
    rte_timer_reset(&flow->rtx_flow_sync_timeout, rte_get_timer_hz() * flow->flow_sync_resent_timeout_params.time,
            SINGLE, rte_lcore_id(), &pflow_rtx_flow_sync_timeout_handler, (void *)&flow->flow_sync_resent_timeout_params);
}

void pflow_rtx_fin_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
    struct flow_fin_resent_timeout_params* timeout_params = (struct flow_fin_resent_timeout_params*) arg;
    struct pim_flow* flow = timeout_params->flow;
    struct pim_host *host = timeout_params->host;
    struct pim_pacer *pacer = timeout_params->pacer;

    if(debug_flow(flow->_f.id)){
        printf("rtx flow sync timeout for flow flow%u\n", flow->_f.id);
    }
    if(flow->state != FINISH_WAIT) {
        return;
    }
    struct rte_mbuf* p = pflow_get_fin_pkt(flow);
    enqueue_ring(pacer->ctrl_q, p);
            // reset timer 
    rte_timer_reset(&flow->rtx_fin_timeout, rte_get_timer_hz() * flow->flow_fin_resent_timeout_params.time,
            SINGLE, rte_lcore_id(), &pflow_rtx_fin_timeout_handler, (void *)&flow->flow_fin_resent_timeout_params);
}

void pflow_set_finish_timeout(struct pim_host* host, struct pim_flow* flow) {
    flow->finish_timeout_params = rte_zmalloc("finish timeout param", 
        sizeof(struct finish_timeout_params), 0);
    if(flow->finish_timeout_params == NULL) {
        printf("%d: no memory for timeout param \n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
    }
    // flow->_f.finish_time = rte_get_tsc_cycles();
    // flow->_f.finished = true;
    // cancel rtx fin timer
    rte_timer_stop(&flow->rtx_fin_timeout);
    flow->state = FINISH;
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
    struct pim_flow* flow = lookup_table_entry(host->rx_flow_table, timeout_params->flow_id);
    flow->finish_timeout_params = NULL;
    Pq* pq = lookup_table_entry(host->src_minflow_table, flow->_f.src_addr);
    get_smallest_unfinished_flow(pq);
    // printf("finish timeout handler for flow %u\n", flow->_f.id);
    delete_table_entry(host->rx_flow_table, timeout_params->flow_id);
    rte_free(flow->_f.bmp);
    // rte_bitmap_free(flow->_f.bmp);
    // flow->state = FINISH;
    if(flow->rd_ctrl_timeout_params == NULL) {
        rte_pktmbuf_free(flow->buf);
    }
    rte_free(timeout_params);
}
