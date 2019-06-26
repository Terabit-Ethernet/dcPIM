#include <rte_bitmap.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include "config.h"
#include "ds.h"
#include "pim_host.h"
#include "pim_pacer.h"

extern struct rte_mempool* pktmbuf_pool;

bool pim_pflow_compare(const void* a, const void* b) {
    if(a == NULL)
        return true;
    if(b == NULL)
        return false;

    if(pflow_remaining_pkts((const struct pim_flow*)a) - pflow_token_gap((const struct pim_flow*)a) 
        >= pflow_remaining_pkts((const struct pim_flow*)b) - pflow_token_gap((const struct pim_flow*)b))
        return true;
    else if(((const struct pim_flow*)a)->_f.start_time >= ((const struct pim_flow*)b)->_f.start_time)
        return true;
    else
        return false;
}

// initialize epoch
void pim_init_epoch(struct pim_epoch* pim_epoch, struct pim_host* pim_host, struct pim_pacer* pim_pacer) {
	rte_rwlock_init(&pim_epoch->rw_lock);
	pim_epoch->epoch = 0;
	pim_epoch->iter = 0;
	pim_epoch->match_src_addr = 0;
	pim_epoch->match_dst_addr = 0;
	pim_epoch->grant_size = 0;
	pim_epoch->rts_size = 0;
	pim_epoch->min_rts = NULL;
	pim_epoch->min_grant = NULL;
	pim_epoch->prompt = false;
	rte_timer_init(&pim_epoch->epoch_timer);
	uint32_t i;
	for(i = 0; i < params.pim_iter_limit; i++) {
		rte_timer_init(&pim_epoch->sender_iter_timers[i]);
		rte_timer_init(&pim_epoch->receiver_iter_timers[i]);
	}
	// rte_timer_init(&pim_epoch->sender_iter_timer);
	// rte_timer_init(&pim_epoch->receiver_iter_timer);
	pim_epoch->pim_timer_params.pim_epoch = pim_epoch;
	pim_epoch->pim_timer_params.pim_host = pim_host;
	pim_epoch->pim_timer_params.pim_pacer = pim_pacer;
}

void pim_advance_iter(struct pim_epoch* pim_epoch) {
	// rte_rwlock_write_lock (pim_epoch->rw_lock);
	pim_epoch->iter += 1;
	// pim_epoch->grant_size = 0;
	// pim_epoch->rts_size = 0;
	// pim_epoch->min_rts = NULL;
	// pim_epoch->min_grant = NULL;
	// rte_rwlock_write_unlock(pim_epoch->rw_lock);
}
 
void pim_init_host(struct pim_host* host, uint32_t socket_id) {
	host->cur_epoch = 0;
	// sender
	host->cur_match_dst_addr = 0;
	host->finished_flow = 0;
	host->sent_bytes = 0;
	host->tx_flow_pool = create_mempool("tx_flow_pool", sizeof(struct pim_flow) + RTE_PKTMBUF_HEADROOM, 131072, socket_id);
	host->tx_flow_table = create_hash_table("tx_flow_table", sizeof(uint32_t), 131072, RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY, socket_id);
	host->dst_minflow_table = create_hash_table("dst_minflow_table", sizeof(uint32_t), 16, 0, socket_id);
	host->src_minflow_table = create_hash_table("src_minflow_table", sizeof(uint32_t), 16, 0, socket_id);
	host->num_token_sent = 0;
	pq_init(&host->active_short_flows, pim_pflow_compare);
	rte_timer_init(&host->pim_send_token_timer);
	// receiver
	host->cur_match_src_addr = 0;
	host->received_bytes = 0;
	host->rx_flow_table = create_hash_table("rx_flow_table", sizeof(uint32_t), 65536, 0, socket_id);
	host->temp_pkt_buffer = create_ring("temp_pkt_buffer", 1500, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);	
	host->rx_flow_pool = create_mempool("rx_flow_pool", sizeof(struct pim_flow) + RTE_PKTMBUF_HEADROOM, 65536, socket_id);
	host->event_q = create_ring("event queue", sizeof(struct event_params), 1024, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	host->short_flow_token_q = create_ring("tx_short_flow_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	host->long_flow_token_q = create_ring("tx_long_flow_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	host->send_token_q = create_ring("send_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);

	// printf("pim_flow_size:%u\n", sizeof(pim_flow) + RTE_PKTMBUF_HEADROOM);
}

void pim_host_dump(struct pim_host* host, struct pim_pacer* pacer) {
	printf("size of temp_pkt_buffer: %u\n",rte_ring_count(host->temp_pkt_buffer));
	printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q)); 
}

void pim_new_flow_comes(struct pim_host* host, struct pim_pacer* pacer, uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size) {
	struct pim_flow* exist_flow = lookup_table_entry(host->tx_flow_table, flow_id);
	if(exist_flow != NULL) {
		rte_exit(EXIT_FAILURE, "Twice new flows comes");
	}
	struct pim_flow* new_flow = pflow_new(host->tx_flow_pool);
	if(new_flow == NULL) {
		printf("flow is NULL");
		rte_exit(EXIT_FAILURE, "flow is null");
	}

	pflow_init(new_flow, flow_id, flow_size, params.ip, dst_addr, rte_get_tsc_cycles(), 0);
	insert_table_entry(host->tx_flow_table, new_flow->_f.id, new_flow);
	// send rts
	if(debug_flow(flow_id)) {
		printf("%"PRIu64" new flow arrives:%u; size: %u\n", rte_get_tsc_cycles(), flow_id, flow_size);
	}
	pim_send_flow_sync(pacer, new_flow);
	// push all tokens
	if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
		uint32_t i = 0;	
		for(; i < new_flow->_f.size_in_pkt; i++) {
	    	int data_seq = pflow_get_next_token_seq_num(new_flow);
    		// allocate new packet
		 	struct rte_mbuf* p = pflow_get_token_pkt(new_flow, data_seq);
			enqueue_ring(host->short_flow_token_q , p);
		}
	} else {
		if(lookup_table_entry(host->dst_minflow_table, dst_addr) == NULL) {
			Pq* pq = rte_zmalloc("Prioirty Queue", sizeof(Pq), 0);
			pq_init(pq, pim_pflow_compare);
			insert_table_entry(host->dst_minflow_table,dst_addr, pq);
		}
		Pq* pq = lookup_table_entry(host->dst_minflow_table, dst_addr);
		pq_push(pq, new_flow);
	}
	// printf("finish\n");
}
// receiver logic 
void pim_rx_packets(struct pim_epoch* epoch, struct pim_host* host, struct pim_pacer* pacer,
struct rte_mbuf* p) {
	struct pim_hdr *pim_hdr;
	struct ipv4_hdr *ipv4_hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	// get ip header
	ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, sizeof(struct ether_hdr));
	// get pim header
	pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, offset);
	offset += sizeof(struct pim_hdr);
	// parse packet
	if(pim_hdr->type == PIM_FLOW_SYNC) {
		struct pim_flow_sync_hdr *pim_flow_sync_hdr = rte_pktmbuf_mtod_offset(p, struct pim_flow_sync_hdr*, offset);
		pim_receive_flow_sync(host, pacer, ipv4_hdr, pim_flow_sync_hdr);
	} else if(pim_hdr->type == PIM_RTS) {
		struct pim_rts_hdr *pim_rts_hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, offset);
		pim_receive_rts(epoch, ipv4_hdr, pim_rts_hdr);
	} else if (pim_hdr->type == PIM_GRANT) {
		struct pim_grant_hdr *pim_grant_hdr = rte_pktmbuf_mtod_offset(p, struct pim_grant_hdr*, offset);
		pim_receive_grant(epoch, ipv4_hdr, pim_grant_hdr);

	} else if (pim_hdr->type == PIM_ACCEPT) {
		struct pim_accept_hdr *pim_accept_hdr = rte_pktmbuf_mtod_offset(p, struct pim_accept_hdr*, offset);
		pim_receive_accept(epoch, host, pacer, ipv4_hdr, pim_accept_hdr);
	} else if (pim_hdr->type == PIM_GRANTR) {
		struct pim_grantr_hdr *pim_grantr_hdr = rte_pktmbuf_mtod_offset(p, struct pim_grantr_hdr*, offset);
		pim_receive_grantr(epoch, host, pim_grantr_hdr);
		// free p is the repsonbility of the sender
	} else if (pim_hdr->type == PIM_ACK) {
		struct pim_ack_hdr *pim_ack_hdr = rte_pktmbuf_mtod_offset(p, struct pim_ack_hdr*, offset);
		struct pim_flow* flow = lookup_table_entry(host->tx_flow_table, pim_ack_hdr->flow_id);
    	pflow_set_finish(flow);
    	host->finished_flow += 1;
	} else if (pim_hdr->type == PIM_TOKEN) {
		struct pim_token_hdr *pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr*, offset);
		pim_receive_token(host, pim_token_hdr, p);
		return;
	} else if(pim_hdr->type == DATA) {
		struct pim_data_hdr *pim_data_hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
		host->received_bytes += 1500;
		pim_receive_data(host, pacer, pim_data_hdr, p);
		return;
	} else if (pim_hdr->type == PIM_START) {
		pim_receive_start(epoch, host, pacer);
	}
	else {
		printf("%d\n", pim_hdr->type);
        printf("%d: receive unknown packets\n", __LINE__);
        rte_exit(EXIT_FAILURE, "receive unknown types");
	}
	rte_pktmbuf_free(p);
}
struct rte_mbuf* pim_get_grantr_pkt(struct ipv4_hdr* ipv4_hdr, int iter, int epoch) {
    struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
				sizeof(struct pim_hdr) + sizeof(struct pim_grantr_hdr);
	if(p == NULL) {
				printf("%s: Pktbuf pool full\n", __func__);
				rte_exit(EXIT_FAILURE ,"Pktbuf full");
	}
	rte_pktmbuf_append(p, size);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr2 = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
				sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_grantr_hdr* pim_grantr_hdr = rte_pktmbuf_mtod_offset(p, struct pim_grantr_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr2->src_addr = rte_cpu_to_be_32(params.ip);
    ipv4_hdr2->dst_addr = ipv4_hdr->src_addr;
    ipv4_hdr2->total_length = rte_cpu_to_be_16(size);
    // add_ip_hdr(p, &ipv4_hdr2);

    pim_hdr->type = PIM_GRANTR;
    // add_pim_hdr(p, &pim_hdr);
    pim_grantr_hdr->epoch = epoch;
    pim_grantr_hdr->iter = iter;
    // add_pim_grantr_hdr(p, &pim_grantr_hdr);
    return p;
}

struct rte_mbuf* pim_get_grant_pkt(struct pim_rts* pim_rts, int iter, int epoch, bool prompt) {
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
				sizeof(struct pim_hdr) + sizeof(struct pim_grant_hdr);
	if(p == NULL) {
		printf("%s: Pktbuf pool full\n", __func__);
		rte_exit(EXIT_FAILURE ,"Pktbuf full");
	}
	rte_pktmbuf_append(p, size);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
				sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_grant_hdr* pim_grant_hdr = rte_pktmbuf_mtod_offset(p, struct pim_grant_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(params.ip);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(pim_rts->src_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size);
    // add_ip_hdr(p, &ipv4_hdr);

    pim_hdr->type = PIM_GRANT;
    // add_pim_hdr(p, &pim_hdr);
    pim_grant_hdr->epoch = epoch;
    pim_grant_hdr->iter = iter;
    pim_grant_hdr->prompt = prompt;
    pim_grant_hdr->remaining_sz = pim_rts->remaining_sz;
    // add_pim_grant_hdr(p, &pim_grant_hdr);
    return p;
}

struct rte_mbuf* pim_get_accept_pkt(struct pim_grant* pim_grant, int iter, int epoch) {
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
				sizeof(struct pim_hdr) + sizeof(struct pim_accept_hdr);
	if(p == NULL) {
		printf("%s: Pktbuf pool full\n", __func__);
		rte_exit(EXIT_FAILURE ,"Pktbuf full");
	}
	rte_pktmbuf_append(p, size);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
				sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_accept_hdr* pim_accept_hdr = rte_pktmbuf_mtod_offset(p, struct pim_accept_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(params.ip);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(pim_grant->dst_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size);
    // add_ip_hdr(p, &ipv4_hdr);

    pim_hdr->type = PIM_ACCEPT;
    // add_pim_hdr(p, &pim_hdr);
    pim_accept_hdr->epoch = epoch;
    pim_accept_hdr->iter = iter;
    pim_accept_hdr->accept = 1;
    // add_pim_accept_hdr(p, &pim_accept_hdr);
    return p;
}

struct rte_mbuf* pim_get_rts_pkt(struct pim_flow* flow, int iter, int epoch) {
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
				sizeof(struct pim_hdr) + sizeof(struct pim_rts_hdr);
	if(p == NULL) {
		printf("%s: Pktbuf pool full\n", __func__);
		rte_exit(EXIT_FAILURE ,"Pktbuf full");
	}
	rte_pktmbuf_append(p, size);
    add_ether_hdr(p);
    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
				sizeof(struct ether_hdr));
    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    struct pim_rts_hdr* pim_rts_hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
    ipv4_hdr->src_addr = rte_cpu_to_be_32(params.ip);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
    ipv4_hdr->total_length = rte_cpu_to_be_16(size);
    // add_ip_hdr(p, &ipv4_hdr);

    pim_hdr->type = PIM_RTS;
    // add_pim_hdr(p, &pim_hdr);
    pim_rts_hdr->epoch = epoch;
    pim_rts_hdr->iter = iter;
    pim_rts_hdr->remaining_sz = pflow_remaining_pkts(flow);
    // add_pim_rts_hdr(p, &pim_rts_hdr);
    return p;
}

void pim_receive_rts(struct pim_epoch* pim_epoch, struct ipv4_hdr* ipv4_hdr, struct pim_rts_hdr* pim_rts_hdr) {
	// if(pim_rts_hdr->epoch == pim_epoch->epoch) {
	// 	if(pim_epoch->iter == params.pim_iter_limit + 1) {
	// 		return;
	// 	}
	// 	if(pim_epoch->iter >= pim_rts_hdr->iter + 1 || pim_epoch->iter + 1 < pim_rts_hdr->iter) {
	// 		double epoch_size = (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit);
	// 		double precise_epoch = (double)(rte_get_tsc_cycles() - pim_epoch->start_cycle) / rte_get_timer_hz() / epoch_size;
	// 		printf("rts iter:%d\n", pim_rts_hdr->iter);
	// 		printf("pim epoch iter:%d\n", pim_epoch->iter);
	// 		printf("rts epoch:%d\n", pim_rts_hdr->epoch);
	// 		printf("pim epoch:%d\n", pim_epoch->epoch);
	// 		printf("precise epoch:%f\n", precise_epoch);
	// 		rte_exit(EXIT_FAILURE, "Iter diff");
	// 	}
	// }
	// if(pim_rts_hdr->epoch == pim_epoch->epoch + 1) {
	// 	if(pim_epoch->iter != params.pim_iter_limit + 1) {
	// 		double epoch_size = (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit);
	// 		double precise_epoch = (double)(rte_get_tsc_cycles() - pim_epoch->start_cycle) / rte_get_timer_hz() / epoch_size;	
	// 		printf("rts iter:%d\n", pim_rts_hdr->iter);
	// 		printf("pim epoch iter:%d\n", pim_epoch->iter);
	// 		printf("rts epoch:%d\n", pim_rts_hdr->epoch);
	// 		printf("pim epoch:%d\n", pim_epoch->epoch);
	// 		printf("precise epoch:%f\n", precise_epoch);

	// 		rte_exit(EXIT_FAILURE, "Iter diff");
	// 	}
	// }
	// if(pim_rts_hdr->epoch + 1 == pim_epoch->epoch) {
	// 	double epoch_size = (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit);
	// 	double precise_epoch = (double)(rte_get_tsc_cycles() - pim_epoch->start_cycle) / rte_get_timer_hz() / epoch_size;

	// 	printf("rts iter:%d\n", pim_rts_hdr->iter);
	// 	printf("pim epoch iter:%d\n", pim_epoch->iter);
	// 	printf("rts epoch:%d\n", pim_rts_hdr->epoch);
	// 	printf("pim epoch:%d\n", pim_epoch->epoch);
	// 	printf("precise epoch:%f\n", precise_epoch);
	// 	rte_exit(EXIT_FAILURE, "Iter diff");
	// }
	// if(pim_rts_hdr->epoch != pim_epoch->epoch) {
	// 	printf("rts packet epoch: %u; now epoch: %u\n", pim_rts_hdr->epoch, pim_epoch->epoch);
	// 	printf("rts packet iter: %u; now iter: %u\n", pim_rts_hdr->iter, pim_epoch->iter);

	// 	rte_exit(EXIT_FAILURE, "failure \n");
	// }
	// if(pim_rts_hdr->iter == pim_epoch->iter && pim_rts_hdr->epoch == pim_epoch->epoch) {

		struct pim_rts *pim_rts = &pim_epoch->rts_q[pim_epoch->rts_size];
		pim_rts->src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		pim_rts->remaining_sz = pim_rts_hdr->remaining_sz;
		pim_epoch->rts_size++;
		if(pim_epoch->min_rts == NULL || pim_epoch->min_rts->remaining_sz > pim_rts->remaining_sz) {
			pim_epoch->min_rts = pim_rts;
		}
	// }
} 
void pim_receive_grant(struct pim_epoch* pim_epoch, struct ipv4_hdr* ipv4_hdr, struct pim_grant_hdr* pim_grant_hdr) {
	// if(pim_grant_hdr->iter != pim_epoch->iter || pim_grant_hdr->epoch != pim_epoch->epoch) {
	// 	double epoch_size = (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit);
	// 	double precise_epoch = (double)(rte_get_tsc_cycles() - pim_epoch->start_cycle) / rte_get_timer_hz() / epoch_size;
	// 	printf("grant iter:%d\n", pim_grant_hdr->iter);
	// 	printf("pim epoch iter:%d\n", pim_epoch->iter);
	// 	printf("grant epoch:%d\n", pim_grant_hdr->epoch);
	// 	printf("pim epoch:%d\n", pim_epoch->epoch);
	// 	printf("precise epoch:%f\n", precise_epoch);
	// 	printf("diff time:%"PRIu64"\n", rte_get_tsc_cycles() - pim_epoch->start_cycle);

	// 	rte_exit(EXIT_FAILURE, "Iter diff");
	// }
	// if(pim_grant_hdr->iter == pim_epoch->iter && pim_grant_hdr->epoch == pim_epoch->epoch) {
		struct pim_grant *pim_grant = &pim_epoch->grants_q[pim_epoch->grant_size];
		pim_grant->dst_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		pim_grant->remaining_sz = pim_grant_hdr->remaining_sz;
		pim_grant->prompt = pim_grant_hdr->prompt;
		pim_epoch->grant_size++;
		if(pim_epoch->min_grant == NULL || pim_epoch->min_grant->remaining_sz > pim_grant->remaining_sz) {
			pim_epoch->min_grant = pim_grant;
		}
	// }
}
void pim_receive_grantr(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_grantr_hdr* pim_grantr_hdr) {
	if(pim_grantr_hdr->epoch == pim_epoch->epoch) {
		pim_epoch->match_dst_addr = 0;
		if(host->cur_epoch == pim_epoch->epoch || pim_epoch->prompt) {
			pim_epoch->prompt = false;
			host->cur_match_dst_addr = 0;
		}
	}
}
void pim_receive_start(struct pim_epoch* pim_epoch, struct pim_host* pim_host, struct pim_pacer* pim_pacer) {
	pim_init_epoch(pim_epoch, pim_host, pim_pacer);
	uint64_t epoch_size = rte_get_timer_hz() * (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit);
	rte_timer_reset(&pim_epoch->epoch_timer, epoch_size,
	PERIODICAL, rte_lcore_id(), &pim_start_new_epoch, (void *)(&pim_epoch->pim_timer_params));
	uint32_t i = 0;
	for(; i <= params.pim_iter_limit; i++) {
		rte_timer_reset(&pim_epoch->sender_iter_timers[i], epoch_size, PERIODICAL,
    		rte_lcore_id(), &pim_schedule_sender_iter_evt, (void *)(&pim_epoch->pim_timer_params));	
 		if (i == params.pim_iter_limit)
			break;	
		rte_delay_us_block(params.pim_iter_epoch / 2 * 1000000);
		rte_timer_reset(&pim_epoch->receiver_iter_timers[i], epoch_size, PERIODICAL,
        	rte_lcore_id(), &pim_schedule_receiver_iter_evt, (void *)(&pim_epoch->pim_timer_params));	
		rte_delay_us_block(params.pim_iter_epoch / 2 * 1000000);
	}
	// rte_timer_reset(&pim_epoch->epoch_timer, 0,
	//  SINGLE, rte_lcore_id(), &pim_start_new_epoch, (void *)(&pim_epoch->pim_timer_params));
}

void pim_receive_accept(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer, struct ipv4_hdr* ipv4_hdr, struct pim_accept_hdr* pim_accept_hdr) {
	if(pim_epoch->epoch == pim_accept_hdr->epoch) {
		if(pim_epoch->match_src_addr != 0) {
			struct rte_mbuf *p = pim_get_grantr_pkt(ipv4_hdr, pim_epoch->iter, pim_epoch->epoch);
			//rte_eth_tx_burst(get_port_by_ip(rte_be_to_cpu_32(ipv4_hdr->src_addr)) ,0, &p, 1);
			enqueue_ring(pacer->ctrl_q, p);
		} else {
			pim_epoch->match_src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		}
		if(pim_epoch->iter > params.pim_iter_limit && host->cur_epoch == pim_epoch->epoch) {
			host->cur_match_src_addr = pim_epoch->match_src_addr;
		}
	}
}
void pim_handle_all_rts(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer) {
    uint32_t index = 0;
    if (params.pim_select_min_iters > 0 && pim_epoch->iter <= params.pim_select_min_iters) {
        if(pim_epoch->min_rts != NULL) {
            struct rte_mbuf *p = pim_get_grant_pkt(pim_epoch->min_rts, pim_epoch->iter, pim_epoch->epoch, pim_epoch->epoch - 1 == host->cur_epoch && host->cur_match_src_addr == 0);
        	enqueue_ring(pacer->ctrl_q, p);
        	//rte_eth_tx_burst(get_port_by_ip(pim_epoch->min_rts->src_addr) ,0, &p, 1);
        }
    }
    else {
        if(pim_epoch->rts_size > 0) {
            index =  (uint32_t)(rte_rand() % pim_epoch->rts_size);
        	struct rte_mbuf *p = pim_get_grant_pkt(&pim_epoch->rts_q[index], pim_epoch->iter, pim_epoch->epoch, pim_epoch->epoch - 1 == host->cur_epoch && host->cur_match_src_addr == 0);
        	enqueue_ring(pacer->ctrl_q, p);
        	// rte_eth_tx_burst(get_port_by_ip(pim_epoch->rts_q[index].src_addr) ,0, &p, 1);

        }
    }
    pim_epoch->min_rts = NULL;
    pim_epoch->rts_size = 0;

}

void pim_handle_all_grant(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer) {
	uint32_t index = 0;
	struct pim_grant* grant = NULL;
	if (params.pim_select_min_iters > 0 && pim_epoch->iter <= params.pim_select_min_iters) {
		if(pim_epoch->min_grant != NULL) {
			grant = pim_epoch->min_grant;
			pim_epoch->match_dst_addr = grant->dst_addr;
			struct rte_mbuf *p = pim_get_accept_pkt(pim_epoch->min_grant, pim_epoch->iter, pim_epoch->epoch);
			enqueue_ring(pacer->ctrl_q, p);
        	// rte_eth_tx_burst(get_port_by_ip(grant->dst_addr) ,0, &p, 1);

		}
	}
	else {
		if(pim_epoch->grant_size > 0) {
			if(pim_epoch->grant_size > 0) {

				index = (uint32_t)(rte_rand() % pim_epoch->grant_size);
				grant = &pim_epoch->grants_q[index];
				pim_epoch->match_dst_addr = grant->dst_addr;
				struct rte_mbuf *p = pim_get_accept_pkt(&pim_epoch->grants_q[index], pim_epoch->iter, pim_epoch->epoch);
				enqueue_ring(pacer->ctrl_q, p);
	        	// rte_eth_tx_burst(get_port_by_ip(grant->dst_addr) ,0, &p, 1);

			}
		}
	}
	if(grant != NULL && grant->prompt) {
		host->cur_match_dst_addr = pim_epoch->match_dst_addr;
		pim_epoch->prompt = true;
	}
	pim_epoch->min_grant = NULL;
	pim_epoch->grant_size = 0;
}

void pim_send_all_rts(struct pim_epoch* pim_epoch, struct pim_host* host, struct pim_pacer* pacer) {
    if(pim_epoch->match_dst_addr != 0)
        return;
	uint32_t* dst_addr = 0;
	int32_t position = 0;
	uint32_t next = 0;
	Pq *pq;
    while(1) {

    	position = rte_hash_iterate(host->dst_minflow_table,(const void**) &dst_addr, (void**)&pq, &next);
		if(position == -ENOENT) {
			break;
		}


		struct pim_flow* smallest_flow = get_smallest_unfinished_flow(pq);

		if(smallest_flow != NULL) {
            struct rte_mbuf *p = pim_get_rts_pkt(smallest_flow, pim_epoch->iter, pim_epoch->epoch);
        	// rte_eth_tx_burst(get_port_by_ip(smallest_flow->_f.dst_addr) ,0, &p, 1);
			enqueue_ring(pacer->ctrl_q, p);
		} 
    }
}

void pim_schedule_sender_iter_evt(__rte_unused struct rte_timer *timer, void* arg) {
	struct pim_timer_params* pim_timer_params = (struct pim_timer_params*)arg;
	struct pim_epoch* pim_epoch = pim_timer_params->pim_epoch;
	struct pim_host* pim_host = pim_timer_params->pim_host;
	struct pim_pacer* pim_pacer = pim_timer_params->pim_pacer;

	if(pim_epoch->iter > 0) {
		pim_handle_all_grant(pim_epoch, pim_host, pim_pacer);
	}
	pim_advance_iter(pim_epoch);
	// printf("%"PRIu64"sender iter: %d epoch: %d\n", rte_get_tsc_cycles(), pim_epoch->iter, pim_epoch->epoch);

	if(pim_epoch->iter > params.pim_iter_limit) {
		pim_host->cur_match_src_addr = pim_epoch->match_src_addr;
		pim_host->cur_match_dst_addr = pim_epoch->match_dst_addr;;
		pim_host->cur_epoch = pim_epoch->epoch;
		pim_epoch->min_rts = NULL;
		pim_epoch->min_grant = NULL;
		pim_epoch->rts_size = 0;
		pim_epoch->grant_size = 0;
		return;
	}

	pim_send_all_rts(pim_epoch, pim_host, pim_pacer);

	// rte_timer_reset(&pim_epoch->sender_iter_timer, rte_get_timer_hz() * params.pim_iter_epoch,
	//  SINGLE, rte_lcore_id(), &pim_schedule_sender_iter_evt, (void *)pim_timer_params);

}

void pim_schedule_receiver_iter_evt(__rte_unused struct rte_timer *timer, void* arg) {
	struct pim_timer_params* pim_timer_params = (struct pim_timer_params*)arg;
	struct pim_epoch* pim_epoch = pim_timer_params->pim_epoch;
	struct pim_host* pim_host = pim_timer_params->pim_host;
	struct pim_pacer* pim_pacer = pim_timer_params->pim_pacer;
	// printf("%"PRIu64"receiver iter: %d epoch: %d\n", rte_get_tsc_cycles(), pim_epoch->iter, pim_epoch->epoch);

	if(pim_epoch->iter > params.pim_iter_limit) {
		return;
	}
	// if(pim_epoch->epoch % 1000 == 0 && pim_epoch->iter == 5) {
	// 	uint64_t step = rte_get_tsc_cycles();
	// 	printf("%"PRIu64" sender iter %d event\n", step, pim_epoch->iter);
	// } 
	pim_handle_all_rts(pim_epoch, pim_host, pim_pacer);
	// rte_timer_reset(&pim_epoch->receiver_iter_timer, rte_get_timer_hz() * params.pim_iter_epoch,
	//  SINGLE, rte_lcore_id(), &pim_schedule_receiver_iter_evt, (void *)pim_timer_params);
}

void pim_start_new_epoch(__rte_unused struct rte_timer *timer, void* arg) {
	struct pim_timer_params* pim_timer_params = (struct pim_timer_params*)arg;
	struct pim_epoch* pim_epoch = pim_timer_params->pim_epoch;
	// struct pim_host* pim_host = pim_timer_params->pim_host;
	// struct pim_pacer* pim_pacer = pim_timer_params->pim_pacer;

	// if(pim_epoch->epoch == 0) {
	// 	pim_epoch->start_cycle = rte_get_tsc_cycles();
	// }
	// uint64_t correction = 0;
	// if((pim_epoch->epoch) % 5 == 0) {
	// 	uint64_t precise_time = rte_get_timer_hz() * (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit) * (pim_epoch->epoch);
	// 	uint64_t current_time = rte_get_tsc_cycles() - pim_epoch->start_cycle;
	// 	correction = current_time - precise_time;
	// }
	// rte_timer_reset(&pim_epoch->epoch_timer, rte_get_timer_hz() * (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit) - correction,
	//  SINGLE, rte_lcore_id(), &pim_start_new_epoch, (void *)(&pim_epoch->pim_timer_params));

	pim_epoch->epoch += 1;
	pim_epoch->iter = 0;
	pim_epoch->match_dst_addr = 0;
	pim_epoch->match_src_addr = 0;
	pim_epoch->prompt = false;
	// int i = 0;
	// uint64_t time = 0;
	// for(; i < params.pim_iter_limit; i++) {
	// 	if(i != 0) {
	// 		rte_timer_reset(&pim_epoch->sender_iter_timer, time, SINGLE,
 //        		rte_lcore_id(), &pim_schedule_sender_iter_evt, (void *)(&pim_epoch->pim_timer_params));		
	// 	}

	// 	rte_timer_reset(&pim_epoch->receiver_iter_timer, time + rte_get_timer_hz() * params.pim_iter_epoch / 2, SINGLE,
 //        	rte_lcore_id(), &pim_schedule_receiver_iter_evt, (void *)(&pim_epoch->pim_timer_params));	
	// 	time += rte_get_timer_hz() * params.pim_iter_epoch;
	// }

	// pim_epoch->min_rts = NULL;
	// pim_epoch->min_grant = NULL;
	// pim_epoch->rts_size = 0;
	// pim_epoch->grant_size = 0;
	// if((pim_epoch->epoch - 1) % 100 == 0) {
	// 	double time = ((double)(rte_get_tsc_cycles() - pim_epoch->start_cycle)) / rte_get_timer_hz() * 1000000;
	// 	printf("%f start new epoch: %d\n", time, pim_epoch->epoch);
	// }
	// do the first iteration sender event here
	// pim_schedule_sender_iter_evt(&pim_epoch->sender_iter_timer, (void *)(&pim_epoch->pim_timer_params));
}
void pim_receive_flow_sync(struct pim_host* host, struct pim_pacer* pacer, 
	struct ipv4_hdr* ipv4_hdr, struct pim_flow_sync_hdr* pim_flow_sync_hdr) {
	struct pim_flow* exist_flow = lookup_table_entry(host->rx_flow_table, pim_flow_sync_hdr->flow_id);
	if(exist_flow != NULL && exist_flow->_f.size_in_pkt > params.small_flow_thre) {
		pflow_dump(exist_flow);
		printf("long flow send twice RTS");
		rte_exit(EXIT_FAILURE, "Twice RTS for long flow");
	}
	if(exist_flow != NULL) {
		return;
	}
	uint32_t src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	struct pim_flow* new_flow = pflow_new(host->rx_flow_pool);
	pflow_init(new_flow, pim_flow_sync_hdr->flow_id, pim_flow_sync_hdr->flow_size, src_addr, dst_addr, pim_flow_sync_hdr->start_time, 1);
	new_flow->flow_sync_received = true;
	// pim_flow_dump(new_flow);
	// insert new flow to the table entry
	insert_table_entry(host->rx_flow_table, new_flow->_f.id, new_flow);
	if(lookup_table_entry(host->src_minflow_table, src_addr) == NULL) {
		Pq* pq = rte_zmalloc("Prioirty Queue", sizeof(Pq), 0);
		pq_init(pq, pim_pflow_compare);
		insert_table_entry(host->src_minflow_table,src_addr, pq);
	}
	if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
		int init_token = pflow_init_token_size(new_flow);
    	// set rd ctrl timeout
    	pflow_reset_rd_ctrl_timeout(host, new_flow, (init_token + params.BDP) * get_transmission_delay(1500));
		// printf("ctrl timeout setup: %f\n", (init_token + params.BDP) * get_transmission_delay(1500));
		if(rte_ring_count(host->temp_pkt_buffer) != 0) {
			pim_iterate_temp_pkt_buf(host, pacer, pim_flow_sync_hdr->flow_id);
		}
		// add hold on?

		// token scheduling event?
	} else {
		Pq* pq = lookup_table_entry(host->src_minflow_table, src_addr);
		pq_push(pq, new_flow);
	}
}

void pim_receive_data(struct pim_host* host, struct pim_pacer* pacer,
 struct pim_data_hdr * pim_data_hdr, struct rte_mbuf* p) {
	uint32_t flow_id = pim_data_hdr->flow_id;
	struct pim_flow* f = lookup_table_entry(host->rx_flow_table, flow_id);
	if(f == NULL && pim_data_hdr->priority == 1) {
		if(rte_ring_free_count(host->temp_pkt_buffer) == 0) {
			struct rte_mbuf *temp = 
			(struct rte_mbuf*) dequeue_ring(host->temp_pkt_buffer);
			rte_pktmbuf_free(temp);
		}

		enqueue_ring(host->temp_pkt_buffer, p);
        // printf("%s: the receiver doesn't receive rts;\n", __func__);
        // printf("flow id:%u, data seq:%u \n ",pim_data_hdr->flow_id, pim_data_hdr->data_seq);
        return;
        // rte_exit(EXIT_FAILURE, "fail");
	}
	if(f == NULL) {
		// large flow should not hold, since the flow is finished and removed from the 
		// data structure;
		rte_pktmbuf_free(p);
		return;
	}

	if(pflow_get_finish_at_receiver(f)) {
		rte_pktmbuf_free(p); 
		return;
	}
	pflow_receive_data(host, pacer, f, pim_data_hdr);
	rte_pktmbuf_free(p);
}


// void pim_flow_finish_at_receiver(struct pim_receiver *receiver, struct pim_flow * f) {
// 	if(debug_flow(f->_f.id)) {
// 		printf("flow finish at receiver:%u\n", f->_f.id);
// 	}
// 	if(f->_f.size_in_pkt <= params.small_flow_thre)
// 		return;
// 	if(f->_f.src_addr == receiver->gosrc_info.src_addr) {
// 		// if(f == receiver->gosrc_info.send_flow && !receiver->gosrc_info.send_nrts) {
// 	 //        printf("%d: Should send nrts when flow finishes\n", __LINE__);
// 	 //        rte_exit(EXIT_FAILURE, "fail");
// 		// }
// 	}
// }
// sender logic

void pim_send_flow_sync(struct pim_pacer* pacer, struct pim_flow* flow) {
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
		sizeof(struct pim_hdr) + sizeof(struct pim_flow_sync_hdr);
	if(p == NULL) {
		printf("new flow comes:%u\n", flow->_f.id);
		printf("size of sender control q: %u\n", rte_ring_count(pacer->ctrl_q));
		rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
	}
	rte_pktmbuf_append(p, size);
	if(p == NULL) {
		// printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
		// printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
		// printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver->temp_pkt_buffer));
		// printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));
		rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
	}
	struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));;
	struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	struct pim_flow_sync_hdr* pim_flow_sync_hdr = rte_pktmbuf_mtod_offset(p, struct pim_flow_sync_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
	add_ether_hdr(p);
	ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.src_addr);

	ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);

	ipv4_hdr->total_length = rte_cpu_to_be_16(size); 

	pim_hdr->type = PIM_FLOW_SYNC;
	pim_flow_sync_hdr->flow_id = flow->_f.id;
	pim_flow_sync_hdr->flow_size = flow->_f.size;
	pim_flow_sync_hdr->start_time = flow->_f.start_time;
	//push the packet
    if(debug_flow(flow->_f.id)){
        printf("send rts %u\n", flow->_f.id);
    }
	enqueue_ring(pacer->ctrl_q, p);
}

void pim_send_token_evt_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct pim_timer_params* pim_timer_params = (struct pim_timer_params*)arg;
	struct pim_host* pim_host = pim_timer_params->pim_host;

	int sent_token = 0;

    Pq *pq = lookup_table_entry(pim_host->src_minflow_table, pim_host->cur_match_src_addr);
    if(pq == NULL)
    	return;
    struct pim_flow* pim_flow = get_smallest_unfinished_flow(pq);
    	//pq_pop(pq);
 
	// case: when a flow finishes after receiving gosrc and no other flow exists.
	if (pim_flow == NULL) {
		return;
	}
    
    // push the batch_token number of tokens to the long flow token queue;
    int num_tokens = params.batch_tokens;
  	int i = 0;
    for(; i < num_tokens; i++) {
    	if(pim_flow == NULL) {
    		break;
    	}
    	int data_seq = pflow_get_next_token_seq_num(pim_flow);
    	// allocate new packet
	 	struct rte_mbuf* p = pflow_get_token_pkt(pim_flow, data_seq);
		
		// printf("size of token q: %u\n", rte_ring_count(pim_host->send_token_q));

		enqueue_ring(pim_host->send_token_q, p);

		sent_token += 1;

		// check whether should set up the redundancy ctrl timeout
    	if (data_seq >= pflow_get_next_token_seq_num(pim_flow)) {
    		if(!pflow_is_rd_ctrl_timeout_params_null(pim_flow)) {
    			rte_exit(EXIT_FAILURE, "rd ctrl timeout is not null");
    		}
    		// set up redundancy ctrl timeout
    		pflow_reset_rd_ctrl_timeout(pim_host, pim_flow, params.BDP * get_transmission_delay(1500));
			pim_flow = get_smallest_unfinished_flow(pq);
			//pq_pop(pq);
			// receiver->gosrc_info.current_flow = ruf_flow;
    	}

    }
    // check whether all tokens has been used up
	// if(receiver->gosrc_info.remain_tokens == 0) {
	// 	if(receiver->gosrc_info.send_nrts == false) {
	// 		rte_exit(EXIT_FAILURE, "Doesn't send nrts\n");
	// 	}
	// 	ruf_reset_gosrc(&receiver->gosrc_info);
	// 	rte_free(receiver->send_token_evt_params);
	// 	receiver->send_token_evt_params = NULL;
	// } else {
	// 	ruf_reset_send_tokens_evt(receiver, pacer, sent_token);
	// }
}

void pim_iterate_temp_pkt_buf(struct pim_host* host, struct pim_pacer* pacer,
 uint32_t flow_id) {
	struct rte_ring* buf = host->temp_pkt_buffer;
	uint32_t size = rte_ring_count(buf);
	uint32_t i = 0;
	for(; i < size; i++) {
		struct rte_mbuf* p = NULL;
		p = (struct rte_mbuf*)dequeue_ring(buf);
		uint32_t offset = sizeof(struct ether_hdr) + 
		sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr);
		struct pim_data_hdr *pim_data_hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
		if(pim_data_hdr->flow_id == flow_id) {
			// packet free by pim_receive_data
			pim_receive_data(host, pacer, pim_data_hdr, p);
		} else {
			enqueue_ring(buf, p);
		}
	}
}
// find the smallest of long flows
struct pim_flow* get_smallest_unfinished_flow(Pq* pq) {
    struct pim_flow* smallest_flow = NULL;
    // Pq* pq = lookup_table_entry(table, src_addr);
    while(1) {
        smallest_flow = pq_peek(pq);
        if (smallest_flow == NULL)
            return smallest_flow;
        if (pflow_get_finish(smallest_flow) || pflow_get_finish_at_receiver(smallest_flow)) {
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
}

void pim_receive_token(struct pim_host *pim_host, struct pim_token_hdr* pim_token_hdr, struct rte_mbuf* p) {
	uint32_t flow_id = pim_token_hdr->flow_id;
	struct pim_flow* f = lookup_table_entry(pim_host->tx_flow_table, flow_id);
	if(f == NULL || pflow_get_finish(f)) {
		rte_pktmbuf_free(p);
		return;
	}
	f->remaining_pkts_at_sender = pim_token_hdr->remaining_size;
	// need token timeout?
	if(pim_token_hdr->priority == 1) {
		enqueue_ring(pim_host->short_flow_token_q, p);
	} else {
		enqueue_ring(pim_host->long_flow_token_q, p);
	}
}