#include <rte_bitmap.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include "config.h"
#include "ds.h"
#include "zedro_host.h"
#include "zedro_pacer.h"

extern struct rte_mempool* pktmbuf_pool;

bool zedro_zflow_compare(const void* a, const void* b) {
    if(a == NULL)
        return true;
    if(b == NULL)
        return false;

    if(zflow_remaining_pkts((const struct zedro_flow*)a) 
        > zflow_remaining_pkts((const struct zedro_flow*)b))
        return true;
    if(zflow_remaining_pkts((const struct zedro_flow*)a) 
        < zflow_remaining_pkts((const struct zedro_flow*)b))
        return false;

    if(((const struct zedro_flow*)a)->_f.start_time >= ((const struct zedro_flow*)b)->_f.start_time)
        return true;
    else
        return false;
}
 
void zedro_init_host(struct zedro_host* host, uint32_t socket_id) {
	// host->cur_epoch = 0;
	// sender
	host->finished_flow = 0;
	host->sent_bytes = 0;
	host->tx_flow_pool = create_mempool("tx_flow_pool", sizeof(struct zedro_flow) + RTE_PKTMBUF_HEADROOM, 131072, socket_id);
	host->tx_flow_table = create_hash_table("tx_flow_table", sizeof(uint32_t), 131072, 0, socket_id);
	host->sender_k = 0;
	pq_init(&host->inactive_flows, zedro_zflow_compare);
	host->num_cts_received = 0;
	host->num_nts_sent = 0;
	// receiver
	host->received_bytes = 0;
	host->receiver_k = 0;
	host->rx_flow_table = create_hash_table("rx_flow_table", sizeof(uint32_t), 65536, 0, socket_id);
	host->rx_flow_pool = create_mempool("rx_flow_pool", sizeof(struct zedro_flow) + RTE_PKTMBUF_HEADROOM, 65536, socket_id);
	// host->event_q = create_ring("event queue", sizeof(struct event_params), 1024, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	host->num_cts_sent = 0;
	host->num_nts_received = 0;
	int i = 0;
	for (; i < params.k; i++) {
		// sender
		host->sender_link_params[i].link_id = i;
		host->sender_link_params[i].host = NULL;
		host->sender_link_params[i].pacer = NULL;
		host->sender_link_params[i].flow = NULL;
		host->sender_link_params[i].receiver_link_id = -1;
		host->sender_link_params[i].used = false;
		host->sender_link_params[i].num_pkts = 0;
		rte_timer_init(&host->sender_link_timers[i]);
		// receiver
		host->zedro_receiver_links[i].link_id = i;
		host->zedro_receiver_links[i].flow = NULL;
		host->zedro_receiver_links[i].used = false;
	}

	// printf("zedro_flow_size:%u\n", sizeof(zedro_flow) + RTE_PKTMBUF_HEADROOM);
}

void zedro_host_dump(struct zedro_host* host) {
	uint32_t i = 0;
	for (; i < params.k; i++) {
		// sender
		printf("sender link id:%u\n", host->sender_link_params[i].link_id);
		// printf("flow id:%u\n", host->sender_link_params[i].flow->_f.id);
		// printf("receiver_link_id: %u\n", host->sender_link_params[i].receiver_link_id);
		printf("used: %d\n", host->sender_link_params[i].used);
		printf("num packets: %u\n", host->sender_link_params[i].num_pkts);
	}

}

void zedro_new_flow_comes(struct zedro_host* host, struct zedro_pacer* pacer, uint32_t flow_id, 
	uint32_t dst_addr, struct ether_addr* dst_ether, uint32_t flow_size) {
	struct zedro_flow* exist_flow = lookup_table_entry(host->tx_flow_table, flow_id);
	if(exist_flow != NULL) {
		rte_exit(EXIT_FAILURE, "Twice new flows comes");
	}
	struct zedro_flow* new_flow = zflow_new(host->tx_flow_pool);
	if(new_flow == NULL) {
		printf("flow is NULL");
		rte_exit(EXIT_FAILURE, "flow is null");
	}

	zflow_init(new_flow, flow_id, flow_size, params.ip, dst_addr, dst_ether, rte_get_tsc_cycles(), 0);
	insert_table_entry(host->tx_flow_table, new_flow->_f.id, new_flow);
	// send rts
	if(debug_flow(flow_id)) {
		printf("%"PRIu64" new flow arrives:%u; size: %u\n", rte_get_tsc_cycles(), flow_id, flow_size);
	}
	zedro_send_rts(pacer, new_flow);
	// push all tokens
	// if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
	// 	uint32_t i = 0;	
	// 	for(; i < new_flow->_f.size_in_pkt; i++) {
	//     	int data_seq = i;
 //    		// allocate new packet
	// 	 	struct rte_mbuf* p = zflow_get_token_pkt(new_flow, data_seq, true);
	// 		enqueue_ring(host->short_flow_token_q , p);
	// 	}
	// } else {
	// 	if(lookup_table_entry(host->dst_minflow_table, dst_addr) == NULL) {
	// 		Pq* pq = rte_zmalloc("Prioirty Queue", sizeof(Pq), 0);
	// 		pq_init(pq, zedro_zflow_compare);
	// 		insert_table_entry(host->dst_minflow_table,dst_addr, pq);
	// 	}
	// 	Pq* pq = lookup_table_entry(host->dst_minflow_table, dst_addr);
	// 	pq_push(pq, new_flow);
	// }
	// printf("finish\n");
}
// receiver logic 
void zedro_rx_packets(struct zedro_host* host, struct zedro_pacer* pacer,
struct rte_mbuf* p) {
    struct ether_hdr * ether_hdr;
	struct zedro_hdr *zedro_hdr;
	struct ipv4_hdr *ipv4_hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);

	// get ethernet header
    ether_hdr = rte_pktmbuf_mtod_offset(p, struct ether_hdr*, 0);
	// get ip header
	ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, sizeof(struct ether_hdr));
	// get zedro header
	zedro_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_hdr*, offset);
	offset += sizeof(struct zedro_hdr);
    if(ether_hdr->ether_type != rte_cpu_to_be_16(0x0800) || ipv4_hdr->next_proto_id != 143) {
        rte_pktmbuf_free(p);
        return;
    }
    if(ipv4_hdr->dst_addr != rte_cpu_to_be_32(params.ip)) {
        // printf("packet type: %u\n", pim_hdr->type);
        // printf("source addr: %u\n", rte_be_to_cpu_32(ipv4_hdr->src_addr));
        // printf("dst addr: %u\n", rte_be_to_cpu_32(ipv4_hdr->dst_addr));
        // printf("ip addr: %u\n", params.ip);
        // printf("ether addr same: %u\n",is_same_ether_addr(&ether_hdr->d_addr,&params.dst_ethers[0]));
    	printf("dst address: %u \n", ipv4_hdr->dst_addr);
        rte_pktmbuf_free(p);
        // return;
        rte_exit(EXIT_FAILURE, "receive wrong packets\n");
    }
	// parse packet
	if(zedro_hdr->type == ZEDRO_RTS) {
		struct zedro_rts_hdr *zedro_rts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_rts_hdr*, offset);
		zedro_receive_rts(host, pacer, ether_hdr, ipv4_hdr, zedro_hdr, zedro_rts_hdr);
	} else if (zedro_hdr->type == ZEDRO_NTS) {
		struct zedro_nts_hdr *zedro_nts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_nts_hdr*, offset);
		zedro_receive_nts(host, pacer, zedro_nts_hdr);

	} else if (zedro_hdr->type == ZEDRO_CTS) {
		struct zedro_cts_hdr *zedro_cts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_cts_hdr*, offset);
		zedro_receive_cts(host, pacer, zedro_hdr, zedro_cts_hdr);
	} else if (zedro_hdr->type == ZEDRO_ACK) {
		// struct zedro_ack_hdr *zedro_ack_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_ack_hdr*, offset);
		struct zedro_flow* flow = lookup_table_entry(host->tx_flow_table, zedro_hdr->flow_id);
    	zflow_set_finish(flow);
    	host->finished_flow += 1;
	}  else if(zedro_hdr->type == DATA) {
		struct zedro_data_hdr *zedro_data_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_data_hdr*, offset);
		host->received_bytes += 1500;
		zedro_receive_data(host, pacer, zedro_hdr, zedro_data_hdr, p);
		return;
	} else if (zedro_hdr->type == ZEDRO_START) {
		zedro_receive_start();
	} else if (zedro_hdr->type == ZEDRO_ACCEPT_CTS) {
		struct zedro_flow* flow = lookup_table_entry(host->tx_flow_table, zedro_hdr->flow_id);
		struct zedro_accept_cts_hdr *zedro_accept_cts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_accept_cts_hdr*, offset);
		zedro_receive_accept_cts(flow, zedro_accept_cts_hdr);
	}
	else {
		printf("%d\n", zedro_hdr->type);
        printf("%d: receive unknown packets\n", __LINE__);
        rte_exit(EXIT_FAILURE, "receive unknown types");
	}
	rte_pktmbuf_free(p);
}

// struct rte_mbuf* zedro_get_rts_pkt(struct zedro_flow* flow) {
// 	struct rte_mbuf* p = NULL;
// 	p = rte_pktmbuf_alloc(pktmbuf_pool);
// 	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
// 				sizeof(struct zedro_hdr) + sizeof(struct zedro_rts_hdr);
// 	if(p == NULL) {
// 		printf("%s: Pktbuf pool full\n", __func__);
// 		rte_exit(EXIT_FAILURE ,"Pktbuf full");
// 	}
// 	rte_pktmbuf_append(p, size);
//     add_ether_hdr(p);
//     struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
// 				sizeof(struct ether_hdr));
//     struct zedro_hdr* zedro_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_hdr*, 
// 				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
//     struct zedro_rts_hdr* zedro_rts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_rts_hdr*, 
// 				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct zedro_hdr));
//     ipv4_hdr->src_addr = rte_cpu_to_be_32(params.ip);
//     ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);
//     ipv4_hdr->total_length = rte_cpu_to_be_16(size);
//     // add_ip_hdr(p, &ipv4_hdr);

//     zedro_hdr->type = ZEDRO_RTS;
//     // add_zedro_hdr(p, &zedro_hdr);
//     zedro_rts_hdr->epoch = epoch;
//     zedro_rts_hdr->iter = iter;
//     zedro_rts_hdr->remaining_sz = zflow_remaining_pkts(flow);
//     // add_zedro_rts_hdr(p, &zedro_rts_hdr);
//     return p;
// }
void zedro_receive_accept_cts(struct zedro_flow *flow, struct zedro_accept_cts_hdr* zedro_accept_cts_hdr) {
	if(flow == NULL) {
		return;
	}
	zflow_set_declare_received_pkts(flow, zedro_accept_cts_hdr->num_pkts);
}
void zedro_receive_nts(struct zedro_host* host, struct zedro_pacer* pacer, 
	struct zedro_nts_hdr* zedro_nts_hdr) {
	if(!host->zedro_receiver_links[zedro_nts_hdr->link_id].used) {
        printf("%d: the link is free! \n", __LINE__);
        rte_exit(EXIT_FAILURE, "!");
	}
	host->num_nts_received += 1;


	struct zedro_flow* flow = host->zedro_receiver_links[zedro_nts_hdr->link_id].flow;
	// change the declare sent packet
	zflow_set_declare_received_pkts(flow, zedro_nts_hdr->num_pkts);
	// decrease the receiver link
	zedro_decrease_receiver_k(host);

	host->zedro_receiver_links[zedro_nts_hdr->link_id].used = false;
	host->zedro_receiver_links[zedro_nts_hdr->link_id].flow = NULL;

	// decrease the flow link count
	zflow_decrease_links(flow);

	if(flow->num_links == 0) {
		if(!zflow_is_rampup_timeout_params_null(flow)) {
			zflow_set_rampup_timeout_params_null(flow);
		}
		// push back the flow if the flow has not been declared receving all packets
		if(flow->declare_received_pkts < flow->_f.size_in_pkt) {
			pq_push(&host->inactive_flows, flow);
		} else if(zflow_get_finish_at_receiver(flow)) {
			zflow_free_at_receiver(host, flow);
		}
	}

	zedro_try_send_cts_pkt(host, pacer);
}
// void zedro_receive_grantr(struct zedro_host* host, struct zedro_grantr_hdr* zedro_grantr_hdr) {
// 	if(zedro_grantr_hdr->epoch == zedro_epoch->epoch) {
// 		zedro_epoch->match_dst_addr = 0;
// 		if(host->cur_epoch == zedro_epoch->epoch || zedro_epoch->prompt) {
// 			zedro_epoch->prompt = false;
// 			host->cur_match_dst_addr = 0;
// 		}
// 	}
// }
void zedro_receive_start(void) {
	// if(core_id == 0) {
	// 	core_id = rte_lcore_id();
	// }
    start_signal = true;

	// rte_timer_reset(&zedro_epoch->epoch_timer, 0,
	//  SINGLE, rte_lcore_id(), &zedro_start_new_epoch, (void *)(&zedro_epoch->zedro_timer_params));
}

void zedro_receive_cts(struct zedro_host* host, struct zedro_pacer* pacer,
 struct zedro_hdr* zedro_hdr, struct zedro_cts_hdr* zedro_cts_hdr) {
	// to do: change the flowlet size
	host->num_cts_received += 1;
	struct zedro_flow* flow = lookup_table_entry(host->tx_flow_table, zedro_hdr->flow_id);
	// this condition may change later
	if (host->sender_k >= params.k || flow->declare_sent_pkts == flow->_f.size_in_pkt) {
		enqueue_ring(pacer->ctrl_q, zflow_get_nts_pkt(flow, zedro_cts_hdr->link_id));
		host->num_nts_sent += 1; 
		return;
	}

	// debug

	int i = 0;
	for (; i < params.k; i++) {
		if (!host->sender_link_params[i].used) {
			// set up timeout params
			flow->num_cts_received += 1;
			host->sender_link_params[i].host = host;
			host->sender_link_params[i].pacer = pacer;
			host->sender_link_params[i].flow = flow;
			host->sender_link_params[i].receiver_link_id = zedro_cts_hdr->link_id;
			host->sender_link_params[i].used = true;
			host->sender_link_params[i].num_pkts = (uint32_t)params.T > flow->_f.size_in_pkt - flow->declare_sent_pkts ? 
				flow->_f.size_in_pkt - flow->declare_sent_pkts: (uint32_t)params.T;
			if(flow->declare_sent_pkts == flow->_f.size_in_pkt &&
				 flow->declare_sent_pkts != flow->_f.size_in_pkt - host->sender_link_params[i].num_pkts) {
				printf("flow->declare_sent_pkts  %u\n", flow->declare_sent_pkts);
				printf("host->sender_link_params[i].num_pkts: %u\n", host->sender_link_params[i].num_pkts);
				printf("flow->size_in_pkt: %u\n",  flow->_f.size_in_pkt);
				printf("host->sender_link_params[i].num_pkts + flow->send_until  %u\n", (host->sender_link_params[i].num_pkts + flow->send_until));
				rte_exit(EXIT_FAILURE, "the quantity is not euqal");
			}
			// set up timeout
			int ret = rte_timer_reset(&host->sender_link_timers[i], rte_get_timer_hz() * get_transmission_delay(1500), PERIODICAL,
                    rte_lcore_id(), &zedro_send_data_evt_handler, (void*)(&host->sender_link_params[i]));
		    if(ret != 0) {
        		printf("%d: cannot reset timer\n", __LINE__);
        		rte_exit(EXIT_FAILURE, "fail");
    		}
			break;
		}
	}
	// get and send accept_cts packets
	zflow_increase_declare_sent_pkts(flow);
	enqueue_ring(pacer->ctrl_q, zflow_get_accept_cts_pkt(flow));
	zedro_increase_sender_k(host);
}

void zedro_receive_rts(struct zedro_host* host, struct zedro_pacer* pacer, struct ether_hdr* ether_hdr,
	struct ipv4_hdr* ipv4_hdr, struct zedro_hdr* zedro_hdr, struct zedro_rts_hdr* zedro_rts_hdr) {
	struct zedro_flow* exist_flow = lookup_table_entry(host->rx_flow_table, zedro_hdr->flow_id);
	if(exist_flow != NULL) {
		zflow_dump(exist_flow);
		printf("long flow send twice RTS");
		rte_exit(EXIT_FAILURE, "Twice RTS for long flow");
	}
	uint32_t src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	struct zedro_flow* new_flow = zflow_new(host->rx_flow_pool);
	zflow_init(new_flow, zedro_hdr->flow_id, zedro_rts_hdr->flow_size, src_addr, 
		dst_addr, &ether_hdr->s_addr, rte_get_tsc_cycles(), 1);
	new_flow->rts_received = true;
	// zedro_flow_dump(new_flow);
	// insert new flow to the table entry
	insert_table_entry(host->rx_flow_table, new_flow->_f.id, new_flow);
	// if(lookup_table_entry(host->src_minflow_table, src_addr) == NULL) {
	// 	Pq* pq = rte_zmalloc("Prioirty Queue", sizeof(Pq), 0);
	// 	pq_init(pq, zedro_zflow_compare);
	// 	insert_table_entry(host->src_minflow_table,src_addr, pq);
	// }
	// if(new_flow->_f.size_in_pkt <= params.small_flow_thre) {
	// 	int init_token = zflow_init_token_size(new_flow);
 //    	// set rd ctrl timeout
 //    	zflow_reset_rd_ctrl_timeout(host, new_flow, (init_token + params.BDP) * get_transmission_delay(1500));
	// 	// printf("ctrl timeout setup: %f\n", (init_token + params.BDP) * get_transmission_delay(1500));
	// 	if(rte_ring_count(host->temp_pkt_buffer) != 0) {
	// 		zedro_iterate_temp_pkt_buf(host, pacer, zedro_flow_sync_hdr->flow_id);
	// 	}
	// 	// add hold on?

	// 	// token scheduling event?
	// } else {
	// 	Pq* pq = lookup_table_entry(host->src_minflow_table, src_addr);
		pq_push(&host->inactive_flows, new_flow);
	// }
	

	// To Do: check if the receiver can send CTS
	zedro_try_send_cts_pkt(host, pacer);
}

void zedro_receive_data(struct zedro_host* host, struct zedro_pacer* pacer, struct zedro_hdr* zedro_hdr,
 struct zedro_data_hdr * zedro_data_hdr, struct rte_mbuf* p) {
	uint32_t flow_id = zedro_hdr->flow_id;
	struct zedro_flow* f = lookup_table_entry(host->rx_flow_table, flow_id);
	// if(f == NULL && zedro_data_hdr->free_token == 1) {
	// 	if(rte_ring_free_count(host->temp_pkt_buffer) == 0) {
	// 		struct rte_mbuf *temp = 
	// 		(struct rte_mbuf*) dequeue_ring(host->temp_pkt_buffer);
	// 		rte_pktmbuf_free(temp);
	// 	}

	// 	enqueue_ring(host->temp_pkt_buffer, p);
 //        // printf("%s: the receiver doesn't receive rts;\n", __func__);
 //        // printf("flow id:%u, data seq:%u \n ",zedro_data_hdr->flow_id, zedro_data_hdr->data_seq);
 //        return;
 //        // rte_exit(EXIT_FAILURE, "fail");
	// }
	if(f == NULL) {
		// it should never be reached here
		rte_pktmbuf_free(p);
        printf("%d: flow is NULL \n", __LINE__);
        rte_exit(EXIT_FAILURE, "!");
	}

	// if(zflow_get_finish_at_receiver(f)) {
	// 	rte_pktmbuf_free(p); 
	// 	return;
	// }
	zflow_receive_data(host, pacer, f, zedro_data_hdr);
	rte_pktmbuf_free(p);
}

// sender logic

void zedro_send_rts(struct zedro_pacer* pacer, struct zedro_flow* flow) {
	struct rte_mbuf* p = NULL;
	p = rte_pktmbuf_alloc(pktmbuf_pool);
	uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
		sizeof(struct zedro_hdr) + sizeof(struct zedro_rts_hdr);
	if(p == NULL) {
		printf("new flow comes:%u\n", flow->_f.id);
		printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));		
		rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
	}
	rte_pktmbuf_append(p, size);
	if(p == NULL) {
		printf("size of control q: %u\n", rte_ring_count(pacer->ctrl_q));
		rte_exit(EXIT_FAILURE, "%s: pkt buffer is FULL\n", __func__);
	}
	struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, 
                sizeof(struct ether_hdr));;
	struct zedro_hdr* zedro_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	struct zedro_rts_hdr* zedro_rts_hdr = rte_pktmbuf_mtod_offset(p, struct zedro_rts_hdr*, 
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct zedro_hdr));
	add_ether_hdr(p,  &flow->_f.dst_ether_addr);
	ipv4_hdr->src_addr = rte_cpu_to_be_32(flow->_f.src_addr);

	ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow->_f.dst_addr);

	ipv4_hdr->total_length = rte_cpu_to_be_16(size); 

	zedro_hdr->type = ZEDRO_RTS;
	zedro_hdr->flow_id = flow->_f.id;
	zedro_rts_hdr->flow_size = flow->_f.size;
	//push the packet
    if(debug_flow(flow->_f.id)){
        printf("send rts %u\n", flow->_f.id);
    }
	enqueue_ring(pacer->ctrl_q, p);
}


// send CTS based on SPRT
void zedro_try_send_cts_pkt(struct zedro_host* host, struct zedro_pacer* pacer) {
	if(host->receiver_k >= params.k) {
		return;
	}
	struct zedro_flow* flow = get_smallest_unfinished_flow(&host->inactive_flows);
	if(flow == NULL) {
		return;
	}
	pq_pop(&host->inactive_flows);
	if(flow->num_links != 0) {
        printf("%d: the number of link is not zero!\n", __LINE__);
        rte_exit(EXIT_FAILURE, "!");
	}

	// find available link
    int link = zedro_find_available_receiver_link(host);

    if(link == -1) {
        printf("%d: the link is -1!\n", __LINE__);
        rte_exit(EXIT_FAILURE, "!");
    }
    zedro_set_receiver_link(host, link, flow);

	// increase the link
	zedro_increase_receiver_k(host);
	zflow_increase_links(flow);

	// set the rampup timeout
	zflow_set_rampup_timeout(host, pacer, flow);

   	// send cts link
    enqueue_ring(pacer->ctrl_q, zflow_get_cts_pkt(flow, link));
	host->num_cts_sent += 1;
}

void zedro_send_data_evt_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct zedro_send_data_evt_param* zedro_timer_params = (struct zedro_send_data_evt_param*)arg;
	struct zedro_host* host = zedro_timer_params->host;
	struct zedro_pacer* pacer  = zedro_timer_params->pacer;
	struct zedro_flow* flow = zedro_timer_params->flow;

    
    // push the batch_token number of tokens to the long flow token queue;
    uint32_t num_data = params.batch_data_pkts > zedro_timer_params->num_pkts?  
    	zedro_timer_params->num_pkts : params.batch_data_pkts;
    // num_data = num_data > flow->_f.size_in_pkt - flow->send_until? 
    // flow->_f.size_in_pkt - flow->send_until : num_data;

  	uint32_t i = 0;
    for(; i < num_data; i++) {
    	
    	uint32_t data_seq = flow->send_until;
    	if(data_seq == flow->_f.size_in_pkt) {
    		break;
    	}
    	// allocate new packet
	   	struct rte_mbuf* sent_p = zflow_get_data_pkt(flow, host, pacer, data_seq);
    	flow->send_until += 1;

		enqueue_ring(pacer->data_q, sent_p);
    }
    zedro_timer_params->num_pkts -= num_data;
    if(zedro_timer_params->num_pkts == 0 || flow->_f.size_in_pkt == flow->send_until) {
    	// set the timer stop
        if(rte_timer_stop(timer) == -1) {
            rte_exit(EXIT_FAILURE, "RD CTRL TIMEOUT SET NULL FAIL");
        }
    	// send nts packets
    	enqueue_ring(pacer->ctrl_q, zflow_get_nts_pkt(flow, zedro_timer_params->receiver_link_id));
   		host->num_nts_sent += 1;
    	// invalidate the sender link state
		zedro_decrease_sender_k(host);
        zedro_timer_params->used = false;
        zedro_timer_params->receiver_link_id = -1;
        zedro_timer_params->flow = NULL;
    }
}

void zedro_increase_receiver_k(struct zedro_host* host) {
	host->receiver_k += 1;
}
void zedro_decrease_receiver_k(struct zedro_host* host) {
	host->receiver_k -= 1;
}
void zedro_increase_sender_k(struct zedro_host* host) {
	host->sender_k += 1;
}
void zedro_decrease_sender_k(struct zedro_host* host) {
	host->sender_k -= 1;
}

int zedro_find_available_receiver_link(struct zedro_host* host) {
	int i = 0;
	for(; i < params.k; i++) {
		if(!host->zedro_receiver_links[i].used) {
			return i;
		}
	}
	return -1;
}

// 
void zedro_set_receiver_link(struct zedro_host* host, int link_id, struct zedro_flow* flow) {

    if(host->zedro_receiver_links[link_id].used) {
        printf("%d: the link is in use!\n", __LINE__);
        rte_exit(EXIT_FAILURE, "!");
    }
	host->zedro_receiver_links[link_id].flow = flow;
	host->zedro_receiver_links[link_id].used = true;
}

// find the smallest of long flows
struct zedro_flow* get_smallest_unfinished_flow(Pq* pq) {
    struct zedro_flow* smallest_flow = NULL;
    // Pq* pq = lookup_table_entry(table, src_addr);
    while(1) {
        smallest_flow = pq_peek(pq);
        if (smallest_flow == NULL)
            return smallest_flow;
        if (zflow_get_finish(smallest_flow) || zflow_get_finish_at_receiver(smallest_flow)) {
            pq_pop(pq);
            // rte_exit(EXIT_FAILURE, "SMALLEST: FLOW FINISH");
            continue;
        }
        if (smallest_flow->declare_received_pkts == smallest_flow->_f.size_in_pkt) {
            pq_pop(pq);
            // rte_exit(EXIT_FAILURE, "SMALLEST: FLOW RD TIMEOUT");
            continue;
        }
        return smallest_flow;
    }
    return smallest_flow;
}
