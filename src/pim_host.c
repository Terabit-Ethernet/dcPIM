#include <rte_bitmap.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include "config.h"
#include "ds.h"
#include "pim_host.h"
#include "pim_pacer.h"

extern struct rte_mempool* pktmbuf_pool;
// set go src
 void init_gosrc(struct gosrc_info *gosrc) {
    gosrc->max_tokens = -1;
    gosrc->remain_tokens = -1;
    gosrc->round = 0;
    gosrc->src_addr = 0;
    gosrc->send_nrts = false;
    gosrc->has_gosrc = false;
    gosrc->current_flow = NULL;
};

void reset_gosrc(struct gosrc_info *gosrc) {
    gosrc->max_tokens = -1;
    gosrc->remain_tokens = -1;
    gosrc->src_addr = 0;
    gosrc->current_flow = NULL;
    gosrc->has_gosrc = false;
}

void init_sender(struct pim_sender *sender, uint32_t socket_id) {
	sender->tx_flow_pool = create_mempool("tx_flow_pool", sizeof(struct pim_flow) + RTE_PKTMBUF_HEADROOM, 131072, socket_id);
	sender->short_flow_token_q = create_ring("tx_short_flow_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ, socket_id);
	sender->long_flow_token_q = create_ring("tx_long_flow_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	// allow multiple read/write
	sender->tx_flow_table = create_hash_table("tx_flow_table", sizeof(uint32_t), 131072, RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY, socket_id);
	sender->finished_flow = 0;
	sender->sent_bytes = 0;
	// sender->control_message_q = create_ring("tx_control_message_queue", 1500, 256, RING_F_SC_DEQ | RING_F_SP_ENQ);
}
void init_receiver(struct pim_receiver *receiver, uint32_t socket_id) {
	rte_timer_init(&receiver->idle_timeout);
	rte_timer_init(&receiver->send_token_evt_timer);
	// rte_timer_init(&receiver->send_listsrc_timer);
	receiver->idle_timeout_params = NULL;
	receiver->send_token_evt_params = NULL;
	// receiver->send_listsrc_params = NULL;
///---------	
	init_gosrc(&receiver->gosrc_info);
	receiver->num_token_sent = 0;
	receiver->idle_timeout_times = 0;
	receiver->received_bytes = 0;
    receiver->invoke_sent_nrts_num = 0;
	receiver->sent_nrts_num = 0;
	receiver->src_minflow_table = create_hash_table("src_minflow_table", sizeof(uint32_t), 16, 0, socket_id);
	receiver->rx_flow_table = create_hash_table("rx_flow_table", sizeof(uint32_t), 65536, 0, socket_id);
	receiver->short_flow_token_q = create_ring("rx_short_flow_token_q", sizeof(struct pim_token_hdr), 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	receiver->long_flow_token_q = create_ring("rx_long_flow_token_q", 1500, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	receiver->temp_pkt_buffer = create_ring("temp_pkt_buffer", 1500, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);	
	receiver->rx_flow_pool = create_mempool("rx_flow_pool", sizeof(struct pim_flow) + RTE_PKTMBUF_HEADROOM, 65536, socket_id);
	receiver->event_q = create_ring("event queue", sizeof(struct event_params), 1024, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	// printf("pim_flow_size:%u\n", sizeof(pim_flow) + RTE_PKTMBUF_HEADROOM);
}

void host_dump(struct pim_sender* sender, struct pim_receiver *receiver, struct pim_pacer *pacer) {
	printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
	printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
	printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver->temp_pkt_buffer));
	printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q)); 
}

void pim_new_flow_comes(struct pim_sender * sender, struct pim_pacer* pacer, uint32_t flow_id, uint32_t dst_addr, uint32_t flow_size) {
	struct pim_flow* exist_flow = lookup_table_entry(sender->tx_flow_table, flow_id);
	if(exist_flow != NULL) {
		rte_exit(EXIT_FAILURE, "Twice new flows comes");
	}
	struct pim_flow* new_flow = pim_flow_new(sender->tx_flow_pool);
	if(new_flow == NULL) {
		printf("flow is NULL");
		rte_exit(EXIT_FAILURE, "flow is null");
	}
	init_pim_flow(new_flow, flow_id, flow_size, params.ip, dst_addr, rte_get_tsc_cycles(), 0);

	if(debug_flow(flow_id)){
		pim_flow_dump(new_flow);
	}
	insert_table_entry(sender->tx_flow_table, new_flow->_f.id, new_flow);
	// send rts
	if(debug_flow(flow_id)) {
		printf("%"PRIu64" new flow arrives:%u; size: %u\n", rte_get_tsc_cycles(), flow_id, flow_size);
	}
	send_rts(sender, pacer, new_flow);
	// push all tokens
	if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
		uint32_t i = 0;	
		for(; i < new_flow->_f.size_in_pkt; i++) {
		 	struct rte_mbuf* p = NULL;
			p = rte_pktmbuf_alloc(pktmbuf_pool);
			uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
				sizeof(struct pim_hdr) + sizeof(struct pim_token_hdr);
			if(p == NULL) {
				printf("%s: Pktbuf pool full\n", __func__);
				rte_exit(EXIT_FAILURE ,"");
			}
			rte_pktmbuf_append(p, size);
			pim_get_token_pkt(new_flow, p, -1, i);
			enqueue_ring(sender->short_flow_token_q , p);
		}
	}
	// printf("finish\n");
}
// receiver logic 
void pim_rx_packets(struct pim_receiver* receiver, struct pim_sender* sender, struct pim_pacer* pacer,
struct rte_mbuf* p) {
	struct pim_hdr *pim_hdr;
	struct ipv4_hdr *ipv4_hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	// get ip header
	ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
	// get pim header
	pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr *, offset);
	offset += sizeof(struct pim_hdr);
	// parse packet
	if(pim_hdr->type == PIM_RTS) {
		struct pim_rts_hdr *pim_rts_hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, offset);
		if(debug_flow(pim_rts_hdr->flow_id)) {
			printf("receive rts header; flow id:%d\n", pim_rts_hdr->flow_id);
		}
		pim_receive_rts(receiver, pacer, ipv4_hdr, pim_rts_hdr);
	} else if (pim_hdr->type == PIM_GOSRC) {
		struct pim_gosrc_hdr *pim_gosrc_hdr = rte_pktmbuf_mtod_offset(p, struct pim_gosrc_hdr*, offset);
		pim_receive_gosrc(receiver, pacer, pim_gosrc_hdr);

	} else if (pim_hdr->type == PIM_TOKEN) {
		struct pim_token_hdr *pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr*, offset);
		pim_receive_token(sender, pim_token_hdr, p);
		// free p is the repsonbility of the sender
		return;
	} else if (pim_hdr->type == PIM_ACK) {
		struct pim_ack_hdr *pim_ack_hdr = rte_pktmbuf_mtod_offset(p, struct pim_ack_hdr*, offset);
		pim_receive_ack(sender, pim_ack_hdr);
	}  else if (pim_hdr->type == PIM_LISTSRCS) {
        // printf("%d: should not recieve listsrc\n", __LINE__);
        // rte_exit(EXIT_FAILURE, "receive listsrc");
	} else if(pim_hdr->type == DATA) {
		struct pim_data_hdr *pim_data_hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
		// if(debug_flow(pim_data_hdr->flow_id)) {
		// 	printf("receive data %u for flow id:%d\n",pim_data_hdr->data_seq, pim_data_hdr->flow_id);
		// }
		receiver->received_bytes += 1500;
		pim_receive_data(receiver, pacer, pim_data_hdr, p);
		return;
	}
	else {
        printf("%d: receive unknown packets\n", __LINE__);
        rte_exit(EXIT_FAILURE, "receive unknown types");
	}
	rte_pktmbuf_free(p);
}

void pim_receive_rts(struct pim_receiver* receiver, struct pim_pacer *pacer, 
	struct ipv4_hdr* ipv4_hdr, struct pim_rts_hdr* pim_rts_hdr) {
	struct pim_flow* exist_flow = lookup_table_entry(receiver->rx_flow_table, pim_rts_hdr->flow_id);
	if(exist_flow != NULL && exist_flow->_f.size_in_pkt > params.small_flow_thre) {
		pim_flow_dump(exist_flow);
		printf("long flow send twice RTS");
		rte_exit(EXIT_FAILURE, "Twice RTS for long flow");
	}
	if(exist_flow != NULL) {
		return;
	}
	uint32_t src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	struct pim_flow* new_flow = pim_flow_new(receiver->rx_flow_pool);
	new_flow->rts_received = true;
	init_pim_flow(new_flow, pim_rts_hdr->flow_id, pim_rts_hdr->flow_size, src_addr, dst_addr, pim_rts_hdr->start_time, 1);
	// pim_flow_dump(new_flow);
	// insert new flow to the table entry
	if(lookup_table_entry(receiver->src_minflow_table, src_addr) == NULL) {
		Pq* pq = rte_zmalloc("Prioirty Queue", sizeof(Pq), 0);
		pq_init(pq, pim_flow_compare);
		insert_table_entry(receiver->src_minflow_table,src_addr, pq);
	}
	Pq* pq = lookup_table_entry(receiver->src_minflow_table, src_addr);
	pq_push(pq, new_flow);

	insert_table_entry(receiver->rx_flow_table, new_flow->_f.id, new_flow);
	if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
		int init_token = pim_init_token_size(new_flow);
		new_flow->token_count = init_token;
    	new_flow->last_token_data_seq_num_sent = init_token - 1;
    	// set rd ctrl timeout
    	reset_rd_ctrl_timeout(receiver, new_flow, (init_token + params.BDP) * get_transmission_delay(1500));
		// printf("ctrl timeout setup: %f\n", (init_token + params.BDP) * get_transmission_delay(1500));
		if(rte_ring_count(receiver->temp_pkt_buffer) != 0) {
			iterate_temp_pkt_buf(receiver, pacer, pim_rts_hdr->flow_id);
		}
		// add hold on?

		// token scheduling event?
	} else {
		if(!receiver->gosrc_info.has_gosrc) {
			// int ret = rte_timer_stop(&receiver->idle_timeout);
			// if(ret != 0) {
		 //        printf("%d: cannot stop timer\n", __LINE__);
		 //        rte_exit(EXIT_FAILURE, "fail");
			// }
			// send listsrc
			invoke_send_listsrc(receiver, pacer, -1);
			// reset idle_timeout
			reset_idle_timeout(receiver, pacer);	
		} else if(receiver->gosrc_info.has_gosrc 
			&& receiver->gosrc_info.src_addr == new_flow->_f.src_addr) {
			if(pim_flow_compare(receiver->gosrc_info.current_flow, new_flow)) {
				receiver->gosrc_info.current_flow = get_src_smallest_unfinished_flow(pq);
			} 
			// invoke token send evt;
		}
	}
}

void pim_receive_gosrc(struct pim_receiver *receiver, struct pim_pacer *pacer,
struct pim_gosrc_hdr *pim_gosrc_hdr) {
	Pq* pq = lookup_table_entry(receiver->src_minflow_table, pim_gosrc_hdr->target_src_addr);
	struct pim_flow* f = get_src_smallest_unfinished_flow(pq);
	// pq_pop(pq);
	if (f == NULL) {
		// 
		invoke_send_listsrc(receiver, pacer, pim_gosrc_hdr->target_src_addr);
		reset_idle_timeout(receiver, pacer);
		reset_gosrc(&receiver->gosrc_info);
		rte_timer_stop(&receiver->send_token_evt_timer);
		rte_free(receiver->send_token_evt_params);
		receiver->send_token_evt_params = NULL;
	} else {
	    receiver->gosrc_info.max_tokens = pim_gosrc_hdr->max_tokens;
	    receiver->gosrc_info.remain_tokens = pim_gosrc_hdr->max_tokens;
	    receiver->gosrc_info.src_addr = pim_gosrc_hdr->target_src_addr;
	    receiver->gosrc_info.round += 1;
	    receiver->gosrc_info.send_nrts = false;
	    receiver->gosrc_info.has_gosrc = true;
	    receiver->gosrc_info.current_flow = f;	
	    int ret = rte_timer_stop(&receiver->idle_timeout);
		if(ret != 0) {
	        printf("%d: cannot stop timer\n", __LINE__);
	        rte_exit(EXIT_FAILURE, "fail");
		}
		rte_free(receiver->idle_timeout_params);
		receiver->idle_timeout_params = NULL;
		// send token event
		reset_send_tokens_evt(receiver, pacer, 0);
	}
}

void pim_receive_data(struct pim_receiver *receiver, struct pim_pacer* pacer,
 struct pim_data_hdr * pim_data_hdr, struct rte_mbuf* p) {
	uint32_t flow_id = pim_data_hdr->flow_id;
	struct pim_flow* f = lookup_table_entry(receiver->rx_flow_table, flow_id);
	if(f == NULL && pim_data_hdr->priority == 1) {
		if(rte_ring_free_count(receiver->temp_pkt_buffer) == 0) {
			struct rte_mbuf *temp = 
			(struct rte_mbuf*) dequeue_ring(receiver->temp_pkt_buffer);
			rte_pktmbuf_free(temp);
		}

		enqueue_ring(receiver->temp_pkt_buffer, p);
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
	if(f->_f.id != flow_id) {
        printf("%d: flow id mismatch;\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
	}
	if(f->finished_at_receiver) {
		rte_pktmbuf_free(p); 
		return;
	}
	struct rte_bitmap* bmp = f->_f.bmp;
    if(rte_bitmap_get(bmp, pim_data_hdr->data_seq) == 0) {
    	rte_bitmap_set(bmp, pim_data_hdr->data_seq);
        f->_f.received_count++;
        while(f->received_until < (int)f->_f.size_in_pkt && rte_bitmap_get(bmp, f->received_until) != 0) {
            f->received_until++;
        }
        // if(num_outstanding_packets >= ((p->size - hdr_size) / (mss)))
        //     num_outstanding_packets -= ((p->size - hdr_size) / (mss));
        // else
        //     num_outstanding_packets = 0;
        if(f->largest_token_data_seq_received < (int)pim_data_hdr->data_seq) {
            f->largest_token_data_seq_received =  (int)pim_data_hdr->data_seq;
        }
    }
    // hard code part
    f->_f.received_bytes += 1460;

    if((int)pim_data_hdr->seq_num > f->largest_token_seq_received)
        f->largest_token_seq_received = (int)pim_data_hdr->seq_num;
    if (f->_f.received_count >= f->_f.size_in_pkt) {
    	struct rte_mbuf* p = NULL;
		p = rte_pktmbuf_alloc(pktmbuf_pool);

		uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
			sizeof(struct pim_hdr) + sizeof(struct pim_ack_hdr);
		char* data = rte_pktmbuf_append(p, size);
		if(data == NULL) {
			printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
			printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
			printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver->temp_pkt_buffer));
			printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));
			rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
		}
		pim_get_ack_pkt(p, f);
		enqueue_ring(pacer->ctrl_q, p);
        // sending_ack(p->ranking_round);
        f->finished_at_receiver = true;
        pim_flow_finish_at_receiver(receiver, f);
        // clean up memory and timer;
        if(f->rd_ctrl_timeout_params != NULL){
			rte_timer_stop(&f->rd_ctrl_timeout);
			rte_free(f->rd_ctrl_timeout_params);
			f->rd_ctrl_timeout_params = NULL;
        }
		f->finish_timeout_params = rte_zmalloc("finish timeout param", 
			sizeof(struct finish_timeout_params), 0);
		if(f->finish_timeout_params == NULL) {
	        printf("%d: no memory for timeout param \n", __LINE__);
	        rte_exit(EXIT_FAILURE, "fail");
		}
		f->finish_timeout_params->receiver = receiver;
		f->finish_timeout_params->flow_id = flow_id;
		int ret = rte_timer_reset(&f->finish_timeout, rte_get_timer_hz() * 2 * get_rtt(params.propagation_delay, 3, 1500), SINGLE,
	                    rte_lcore_id(), &finish_timeout_handler, (void *)f->finish_timeout_params);
		if(ret != 0) {
	        printf("%d: cannot set up finish timer\n", __LINE__);
	        rte_exit(EXIT_FAILURE, "fail");
		}
    }
    rte_pktmbuf_free(p); 
}


void pim_flow_finish_at_receiver(struct pim_receiver *receiver, struct pim_flow * f) {
	if(debug_flow(f->_f.id)) {
		printf("flow finish at receiver:%u\n", f->_f.id);
	}
	if(f->_f.size_in_pkt <= params.small_flow_thre)
		return;
	if(f->_f.src_addr == receiver->gosrc_info.src_addr) {
		// if(f == receiver->gosrc_info.send_flow && !receiver->gosrc_info.send_nrts) {
	 //        printf("%d: Should send nrts when flow finishes\n", __LINE__);
	 //        rte_exit(EXIT_FAILURE, "fail");
		// }
	}
}
void invoke_send_listsrc(struct pim_receiver* receiver, struct pim_pacer *pacer, int nrts_src_addr) {
	// if(receiver->send_listsrc_params != NULL && nrts_src_addr != -1) {
	// 	if(nrts_src_addr != -1) {
	// 		while(receiver->send_listsrc_params != NULL) {
	// 		}
	// 	} else {
	// 		return;
	// 	}
	// 	// rte_exit(EXIT_FAILURE, "send_listsrc_params is not NULL");
	// }
	if(nrts_src_addr == -1 && !rte_ring_empty(receiver->event_q)) {
		return;
	}
	struct send_listsrc_params* send_listsrc_params = rte_zmalloc(" send_listsrc_params", 
            sizeof(struct send_listsrc_params), 0);
	send_listsrc_params->receiver = receiver;
	send_listsrc_params->pacer = pacer;
	send_listsrc_params->nrts_src_addr = nrts_src_addr;

	struct event_params* event_params = rte_zmalloc("event_params", 
            sizeof(struct event_params), 0);
	event_params->func = send_listsrc;
	event_params->params = send_listsrc_params;
	enqueue_ring(receiver->event_q, event_params);
	if(nrts_src_addr != -1) {
		// rte_timer_reset_sync(&receiver->send_listsrc_timer, 0, SINGLE,
		//                     5, &send_listsrc, (void *)send_listsrc_params);
		receiver->invoke_sent_nrts_num += 1;
	} else {
		// int ret = rte_timer_reset(&receiver->send_listsrc_timer, 0, SINGLE,
		//                     5, &send_listsrc, (void *)send_listsrc_params);
		// if(ret != 0){
		// 	rte_free(send_listsrc_params);
		// }
	}
}
void send_listsrc(void* arg) {
	// printf("cycels:%"PRIu64" send listsrc \n", rte_get_tsc_cycles());

	struct send_listsrc_params* timeout_params = (struct send_listsrc_params*)arg;
	struct pim_receiver * receiver = timeout_params->receiver;
	struct pim_pacer* pacer = timeout_params->pacer;

	// hard core part
	struct pim_src_size_pair listsrc_pairs[16];
	int count = 0;
	int nrts_src_addr = timeout_params->nrts_src_addr;

	uint32_t* src_addr = 0;
	int32_t position = 0;
	uint32_t next = 0;
	Pq *pq;
	// rte_hash_reset(receiver->src_minflow_table);
	while(1) {
		position = rte_hash_iterate(receiver->src_minflow_table, (const void**) &src_addr, (void**)&pq, &next);
		if(position == -ENOENT) {
			break;
		}
		struct pim_flow* smallest_flow = get_src_smallest_unfinished_flow(pq);
		if(smallest_flow != NULL) {
			listsrc_pairs[count].src_addr = smallest_flow->_f.src_addr;
			listsrc_pairs[count].flow_size = pim_remaining_pkts(smallest_flow) - 
				pim_token_gap(smallest_flow);
			count += 1;
		}
	}
	// generate listsrc packets and pushes to the queue
	next = 0;
	struct ipv4_hdr ipv4_hdr;
	struct pim_hdr pim_hdr;
	struct pim_listsrc_hdr pim_listsrc_hdr;
	struct pim_nrts_hdr pim_nrts_hdr;
	if(count == 0 && nrts_src_addr == -1){
		// rte_free(timeout_params);
		// receiver->send_listsrc_params = NULL;
		return;
	}
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
		sizeof(struct pim_hdr) + sizeof(struct pim_listsrc_hdr);
	if(nrts_src_addr != -1) {
		size += sizeof(struct pim_nrts_hdr);
		receiver->sent_nrts_num += 1;
	}
	size += count * sizeof(struct pim_src_size_pair);
	if(p == NULL) {
		printf("---------------------------");
		printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
		printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
		printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver->temp_pkt_buffer));
		printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));
		printf("size: %u\n", size);
		rte_exit(EXIT_FAILURE, "%s, p is NULL\n", __func__);
	}
	rte_pktmbuf_append(p, size);
	add_ether_hdr(p);
	ipv4_hdr.src_addr = rte_cpu_to_be_32(params.ip);
	ipv4_hdr.dst_addr = rte_cpu_to_be_32(params.controller_ip);
	ipv4_hdr.total_length = rte_cpu_to_be_16(size); 
	add_ip_hdr(p, &ipv4_hdr);
	pim_hdr.type = PIM_LISTSRCS;
	add_pim_hdr(p, &pim_hdr);
	pim_listsrc_hdr.num_srcs = count;
	if(nrts_src_addr != -1) {
		pim_nrts_hdr.nrts_src_addr = (uint32_t)nrts_src_addr;
		pim_nrts_hdr.nrts_dst_addr = (uint32_t)params.ip;
		pim_listsrc_hdr.has_nrts = 1;
		add_pim_listsrc_hdr(p, &pim_listsrc_hdr);
		add_pim_nrts_hdr(p, &pim_nrts_hdr);
	} else {
		pim_listsrc_hdr.has_nrts = 0;
		add_pim_listsrc_hdr(p, &pim_listsrc_hdr);
	}
	if(count != 0){
		uint32_t offset = size - count * sizeof(struct pim_src_size_pair);
		// printf("send list src\n");
		void* pairs = rte_pktmbuf_mtod_offset(p, void*, offset);
		rte_memcpy(pairs, listsrc_pairs, count * sizeof(struct pim_src_size_pair));
	}
		// printf("send listsrc: src address: %u; flow: %u\n", *src_addr, flow->_f.id);
	// push the packet to the control packet of the pacer
	enqueue_ring(pacer->ctrl_q, p);
	// rte_free(timeout_params);
	// receiver->send_listsrc_params = NULL;
}

void send_rts(struct pim_sender *sender, struct pim_pacer* pacer, struct pim_flow* flow) {
	struct rte_mbuf* p = NULL;
	struct ipv4_hdr ipv4_hdr;
	struct pim_hdr pim_hdr;
	struct pim_rts_hdr pim_rts_hdr;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
		sizeof(struct pim_hdr) + sizeof(struct pim_rts_hdr);
	if(p == NULL) {
		printf("new flow comes:%u\n", flow->_f.id);
		uint32_t q_size_0 = rte_ring_count(sender->long_flow_token_q);
		uint32_t q_size_1 = rte_ring_count(sender->short_flow_token_q);
		printf("size of sender long flow token q: %u\n", q_size_0);
		printf("size of sender short flow token q: %u\n", q_size_1);
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
	add_ether_hdr(p);
	ipv4_hdr.src_addr = rte_cpu_to_be_32(flow->_f.src_addr);

	ipv4_hdr.dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);

	ipv4_hdr.total_length = rte_cpu_to_be_16(size); 

	add_ip_hdr(p, &ipv4_hdr);

	pim_hdr.type = PIM_RTS;
	add_pim_hdr(p, &pim_hdr);
	pim_rts_hdr.flow_id = flow->_f.id;
	pim_rts_hdr.flow_size = flow->_f.size;
	pim_rts_hdr.start_time = flow->_f.start_time;
	add_pim_rts_hdr(p, & pim_rts_hdr);
	//push the packet
    if(debug_flow(flow->_f.id)){
        printf("send rts %u\n", flow->_f.id);
    }
	enqueue_ring(pacer->ctrl_q, p);
}
void reset_idle_timeout(struct pim_receiver *receiver, struct pim_pacer* pacer) {
	double time = ((double)params.BDP) * params.idle_timeout * get_transmission_delay(1500);
	if(rte_hash_count(receiver->rx_flow_table) == 0) {
		return;
	}
	if(receiver->idle_timeout_params == NULL) {
		receiver->idle_timeout_params = rte_zmalloc("idle timeout param", 
    		sizeof(struct idle_timeout_params), 0);
		receiver->idle_timeout_params->receiver = receiver;
		receiver->idle_timeout_params->pacer = pacer;
	}
    int ret = rte_timer_reset(&receiver->idle_timeout, rte_get_timer_hz() * time, SINGLE,
                        rte_lcore_id(), &idle_timeout_handler, (void*)receiver->idle_timeout_params);
	if(ret != 0) {
        printf("%d: cannot reset timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
	}
}

void reset_send_tokens_evt(struct pim_receiver *receiver, struct pim_pacer* pacer, int sent_token) {
	double time = sent_token * get_transmission_delay(1500);
	if(receiver->send_token_evt_params == NULL) {
		receiver->send_token_evt_params = rte_zmalloc("idle timeout param", 
    		sizeof(struct send_token_evt_params), 0);
		receiver->send_token_evt_params->receiver = receiver;
		receiver->send_token_evt_params->pacer = pacer;
	}
    int ret = rte_timer_reset(&receiver->send_token_evt_timer, rte_get_timer_hz() * time, SINGLE,
                        rte_lcore_id(), &send_token_evt_handler, (void*)receiver->send_token_evt_params);
	if(ret != 0) {
        printf("%d: cannot reset timer\n", __LINE__);
        rte_exit(EXIT_FAILURE, "fail");
	}
}


void idle_timeout_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct idle_timeout_params *timeout_params = (struct idle_timeout_params *) arg;
	if(timeout_params->receiver->gosrc_info.has_gosrc && !timeout_params->receiver->gosrc_info.send_nrts) {
		printf("idle happens while the host has go_src");
		rte_exit(EXIT_FAILURE, "idle happens while the host has go_src");
	}
	timeout_params->receiver->idle_timeout_times += 1;
	invoke_send_listsrc(timeout_params->receiver, timeout_params->pacer, -1);
    reset_idle_timeout(timeout_params->receiver, timeout_params->pacer);
}

void send_token_evt_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct send_token_evt_params* evt_params = (struct send_token_evt_params*) arg;
	struct pim_receiver* receiver = evt_params->receiver;
	struct pim_pacer* pacer = evt_params->pacer;
	int rd_ctrl_set = 0;
	int sent_token = 0;
	if(!receiver->gosrc_info.has_gosrc) {
		rte_exit(EXIT_FAILURE, "send token without gosrc");
	}
    struct pim_flow* pim_flow = receiver->gosrc_info.current_flow;
    if(pim_flow == NULL || pim_flow->finished_at_receiver || pim_flow->rd_ctrl_timeout_params != NULL) {
    	Pq *pq = lookup_table_entry(receiver->src_minflow_table, receiver->gosrc_info.src_addr);
    	pim_flow = get_src_smallest_unfinished_flow(pq);
    	//pq_pop(pq);
		receiver->gosrc_info.current_flow = pim_flow;
    }
	// case: when a flow finishes after receiving gosrc and no other flow exists.
	if (pim_flow == NULL) {
		if(!receiver->gosrc_info.send_nrts) {
			receiver->gosrc_info.send_nrts = true;
			invoke_send_listsrc(receiver, pacer, receiver->gosrc_info.src_addr);
            if(receiver->idle_timeout_params != NULL) {
		        rte_exit(EXIT_FAILURE, "idle timeout params should be null");
            }
			reset_idle_timeout(receiver, pacer);
		}
		reset_gosrc(&receiver->gosrc_info);
		rte_free(receiver->send_token_evt_params);
		receiver->send_token_evt_params = NULL;
		return;
	}
    
    // push the batch_token number of tokens to the long flow token queue;
    int num_tokens;
    num_tokens = params.batch_tokens < receiver->gosrc_info.remain_tokens? 
    	params.batch_tokens: receiver->gosrc_info.remain_tokens;
  	int i = 0;
    for(; i < num_tokens; i++) {
    	if(pim_flow == NULL) {
    		break;
    	}
    	int data_seq = pim_get_next_token_seq_num(pim_flow);
    	// allocate new packet
	 	struct rte_mbuf* p = NULL;
		p = rte_pktmbuf_alloc(pktmbuf_pool);
		if(p == NULL) {
			printf("---------------------------");
			printf("size of long flow token q: %u\n",rte_ring_count(receiver->long_flow_token_q));
			printf("size of short flow token q: %u\n",rte_ring_count(receiver->short_flow_token_q));
			printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver->temp_pkt_buffer));
			printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));
			rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
		}
		uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
			sizeof(struct pim_hdr) + sizeof(struct pim_token_hdr);
		rte_pktmbuf_append(p, size);
		pim_get_token_pkt(pim_flow, p, receiver->gosrc_info.round, data_seq);
		
		enqueue_ring(receiver->long_flow_token_q, p);
		receiver->gosrc_info.remain_tokens -= 1;

		sent_token += 1;

		// check whether should set up the redundancy ctrl timeout
    	if (data_seq >= pim_get_next_token_seq_num(pim_flow)) {
    		if(pim_flow->rd_ctrl_timeout_params != NULL) {
    			rte_exit(EXIT_FAILURE, "rd ctrl timeout is not null");
    		}
    		// set up redundancy ctrl timeout
    		reset_rd_ctrl_timeout(receiver, pim_flow, params.BDP * get_transmission_delay(1500));
			rd_ctrl_set = 1;
			Pq* pq = lookup_table_entry(receiver->src_minflow_table, receiver->gosrc_info.src_addr);
			pim_flow = get_src_smallest_unfinished_flow(pq);
			//pq_pop(pq);
			receiver->gosrc_info.current_flow = pim_flow;
    	}

    }
    // For pipeline; send listsrc to the controller
    if(!receiver->gosrc_info.send_nrts) {
		int gap = 0;
	    double ctrl_pkt_rtt = get_rtt(params.propagation_delay, 3, 40);
	    if(pim_flow == NULL) {
	    	gap = receiver->gosrc_info.remain_tokens;
	    	if(rd_ctrl_set != 1) {
		        printf("flow should be rd ctrl timeout: %u\n", __LINE__);
		        rte_exit(EXIT_FAILURE, "fail");
	    	}
	    }
	    else if(receiver->gosrc_info.remain_tokens > pim_remaining_pkts(pim_flow) - pim_token_gap(pim_flow)) {
	        gap = (int)(pim_remaining_pkts(pim_flow) - pim_token_gap(pim_flow));
	    } else {
	        gap = receiver->gosrc_info.remain_tokens;
	    }
        if ((rd_ctrl_set == 1 || 
            gap * get_transmission_delay(1500) <= 
            ctrl_pkt_rtt + 
            params.control_epoch * params.BDP * get_transmission_delay(1500))) {
            // this->fake_flow->sending_nrts_to_arbiter(f->src->id, f->dst->id);
            // this->gosrc_info.send_nrts = true;
			receiver->gosrc_info.send_nrts = true;
			// if(receiver->gosrc_info.src_addr == -1) {
			// 	rte_exit(EXIT_FAILURE, "src address becomes -1");
			// }
			invoke_send_listsrc(receiver, pacer, receiver->gosrc_info.src_addr);
            if(receiver->idle_timeout_params != NULL) {
		        rte_exit(EXIT_FAILURE, "idle timeout params should be null");
            }
			reset_idle_timeout(receiver, pacer);
        } 
    }
    // check whether all tokens has been used up
	if(receiver->gosrc_info.remain_tokens == 0) {
		if(receiver->gosrc_info.send_nrts == false) {
			rte_exit(EXIT_FAILURE, "Doesn't send nrts\n");
		}
		reset_gosrc(&receiver->gosrc_info);
		rte_free(receiver->send_token_evt_params);
		receiver->send_token_evt_params = NULL;
		printf("tokens is 0\n");
	} else {
		reset_send_tokens_evt(receiver, pacer, sent_token);
	}
}

// sender logic

void pim_receive_token(struct pim_sender *sender, struct pim_token_hdr *pim_token_hdr, struct rte_mbuf* p) {
	uint32_t flow_id = pim_token_hdr->flow_id;
	struct pim_flow* f = lookup_table_entry(sender->tx_flow_table, flow_id);
	if(f == NULL || f->_f.finished) {
		rte_pktmbuf_free(p);
		return;
	}
	f->remaining_pkts_at_sender = pim_token_hdr->remaining_size;
	// need token timeout?
	if(pim_token_hdr->priority == 1) {
		enqueue_ring(sender->short_flow_token_q, p);
	} else {
		enqueue_ring(sender->long_flow_token_q, p);
	}
	// schedule send event??
}
void iterate_temp_pkt_buf(struct pim_receiver* receiver, struct pim_pacer* pacer,
 uint32_t flow_id) {
	struct rte_ring* buf = receiver->temp_pkt_buffer;
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
			pim_receive_data(receiver, pacer, pim_data_hdr, p);
		} else {
			enqueue_ring(buf, p);
		}
	}
}

void pim_receive_ack(struct pim_sender *sender, struct pim_ack_hdr *pim_ack_hdr) {
	uint32_t flow_id = pim_ack_hdr->flow_id;
	struct pim_flow* f = lookup_table_entry(sender->tx_flow_table, flow_id);
	f->_f.finished = true;
	f->_f.finish_time = rte_get_tsc_cycles();

	// struct finish_timeout_params *timeout_params = rte_zmalloc("finish timeout param", 
	// 	sizeof(struct finish_timeout_params), 0);
	// if(timeout_params == NULL) {
 //        printf("%d: no memory for timeout param \n", __LINE__);
 //        rte_exit(EXIT_FAILURE, "fail");
	// }
	sender->finished_flow += 1;
	// timeout_params->hash = sender->tx_flow_table;
	// // timeout_params->pool = sender->tx_flow_pool;
	// timeout_params->flow_id = flow_id;
	// printf("flow finish:%d\n", f->_f.id);
	// int ret = rte_timer_reset(&f->finish_timeout, rte_get_timer_hz() * 2 * get_rtt(params.propagation_delay, 3, 1500), SINGLE,
 //                    rte_lcore_id(), &finish_timeout_handler, (void *)timeout_params);
	// if(ret != 0) {
 //        printf("%d: cannot set up finish timer\n", __LINE__);
 //        rte_exit(EXIT_FAILURE, "fail");
	// }
}

//controller logic
bool src_dst_compare(const void* a, const void* b) {
	const struct src_dst_pair* a_const = a;
	const struct src_dst_pair* b_const = b;
	if(a_const->flow_size > b_const->flow_size)
		return true;
	else
		return false;
}

void init_controller(struct pim_controller* controller, uint32_t socket_id) {
	// controller->node_pool = create_mempool("mode_pool", sizeof(Node) + RTE_PKTMBUF_HEADROOM, 65536);
	// controller->element_pool = create_mempool("mode_pool", sizeof(64) + RTE_PKTMBUF_HEADROOM, 65536);
	controller->sender_state = create_hash_table("sender_state_table", sizeof(uint32_t), 100, 0, socket_id);
	controller->receiver_state = create_hash_table("receiver_state_table", sizeof(uint32_t), 100, 0, socket_id);
	uint32_t i = 0;
	for(; i < 16; i++) {
		insert_table_entry(controller->sender_state, i, (void*)1);
		insert_table_entry(controller->receiver_state, i, (void*)1);
	}
	pq_init(&controller->pq, src_dst_compare);
	// controller->head = NULL;
	rte_timer_init(&controller->handle_rq_timer);
}

void pim_receive_listsrc(struct pim_controller *controller, struct rte_mbuf *p) {
	struct ipv4_hdr* ipv4_hdr = NULL;
	struct pim_hdr* pim_hdr = NULL;
	struct pim_listsrc_hdr* listsrc_hdr = NULL;
	struct pim_nrts_hdr* nrts_hdr = NULL;
	parse_header(p, &ipv4_hdr, &pim_hdr);
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
		sizeof(struct pim_hdr);
	if(pim_hdr->type == PIM_LISTSRCS) {
		listsrc_hdr = rte_pktmbuf_mtod_offset(p, struct pim_listsrc_hdr*, offset);
		offset += sizeof(struct pim_listsrc_hdr);
		if(listsrc_hdr->has_nrts == 1) {
			nrts_hdr = rte_pktmbuf_mtod_offset(p, struct pim_nrts_hdr*, offset);
			offset += sizeof(struct pim_nrts_hdr);
			 // printf("receive nrts src:%u dst %u\n",nrts_hdr->nrts_src_addr, 
			// nrts_hdr->nrts_dst_addr);
			delete_table_entry(controller->sender_state, ip_to_id(nrts_hdr->nrts_src_addr));
			insert_table_entry(controller->sender_state, ip_to_id(nrts_hdr->nrts_src_addr), (void*)1);
			delete_table_entry(controller->receiver_state, ip_to_id(nrts_hdr->nrts_dst_addr));
			insert_table_entry(controller->receiver_state, ip_to_id(nrts_hdr->nrts_dst_addr), (void*)1);
		}
		struct pim_src_size_pair* pim_src_size_pair = NULL;
		uint32_t i = 0;
		uint32_t size = listsrc_hdr->num_srcs;
		for(; i < size; i++) {
			pim_src_size_pair = rte_pktmbuf_mtod_offset(p, struct pim_src_size_pair*, offset);
			struct src_dst_pair* src_dst_pair = rte_zmalloc("", sizeof(struct src_dst_pair), 0);
			src_dst_pair->src = ip_to_id(pim_src_size_pair->src_addr);
			// src address is the receiver address
			src_dst_pair->dst = ip_to_id(rte_be_to_cpu_32(ipv4_hdr->src_addr));
			src_dst_pair->flow_size = pim_src_size_pair->flow_size;
			pq_push(&controller->pq, src_dst_pair);
			offset += sizeof(struct pim_src_size_pair);
		}
		rte_pktmbuf_free(p);

	} else {
		rte_exit(EXIT_FAILURE, "should only receive PIM_LISTSRCS");
	}
}

void handle_requests(__rte_unused struct rte_timer *timer, void* arg) {
	struct pim_controller* controller = (struct pim_controller*) arg;
	while(!pq_isEmpty(&controller->pq)) {
		struct src_dst_pair* src_dst_pair = pq_peek(&controller->pq);
		void* src_state = lookup_table_entry(controller->sender_state, src_dst_pair->src);
		void* dst_state = lookup_table_entry(controller->receiver_state, src_dst_pair->dst);
		if(src_state == (void*)1 && dst_state == (void*)1) {
			// printf("src_state:%d dst_state:%d\n", src_state, dst_state);
			delete_table_entry(controller->sender_state, src_dst_pair->src);
			delete_table_entry(controller->receiver_state, src_dst_pair->dst);
			insert_table_entry(controller->sender_state, src_dst_pair->src, 0);
			insert_table_entry(controller->receiver_state, src_dst_pair->dst, 0);
			// send gosrc packets
			uint32_t src_addr = id_to_ip[src_dst_pair->src];
			uint32_t dst_addr = id_to_ip[src_dst_pair->dst];
			uint32_t token_num = ((uint32_t)rte_rand()) % 
				((uint32_t)(params.max_tokens * params.BDP - params.min_tokens * params.BDP)) + params.min_tokens * params.BDP;
			struct rte_mbuf* p = NULL;
			p = rte_pktmbuf_alloc(pktmbuf_pool);
			uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
			sizeof(struct pim_hdr) + sizeof(struct pim_gosrc_hdr);
			if(p == NULL) {
				rte_exit(EXIT_FAILURE, "P is NULL");
			}
			rte_pktmbuf_append(p, size);
			get_gosrc_pkt(p, src_addr, dst_addr, token_num);
			rte_eth_tx_burst(get_port_by_ip(dst_addr) ,0,&p,1);
			// printf("assign sender %u to receiver %d; tokens:%u \n", src_addr, dst_addr, token_num);
		}
		rte_free(src_dst_pair);
		pq_pop(&controller->pq);
	}
}

void get_gosrc_pkt(struct rte_mbuf* p, uint32_t src_addr, uint32_t dst_addr, uint32_t token_num) {
    add_ether_hdr(p);
    struct ipv4_hdr ipv4_hdr;
    struct pim_hdr pim_hdr;
    struct pim_gosrc_hdr pim_gosrc_hdr;
    uint16_t size;
    size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
        sizeof(struct pim_hdr) + sizeof(struct pim_gosrc_hdr);
    ipv4_hdr.src_addr = rte_cpu_to_be_32(params.ip);
    ipv4_hdr.dst_addr = rte_cpu_to_be_32(dst_addr);
    ipv4_hdr.total_length = rte_cpu_to_be_16(size);
    add_ip_hdr(p, &ipv4_hdr);

    pim_hdr.type = PIM_GOSRC;
    add_pim_hdr(p, &pim_hdr);
    pim_gosrc_hdr.target_src_addr = src_addr;
    pim_gosrc_hdr.max_tokens = token_num;
    add_pim_gosrc_hdr(p, & pim_gosrc_hdr);
}