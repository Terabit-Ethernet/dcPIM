#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#include "config.h"
#include "ds.h"
#include "header.h"
#include "pim_pacer.h"
#include "pim_host.h"

#define INFINITESIMAL_CYCLE 3
extern volatile bool force_quit;
extern struct rte_mempool* pktmbuf_pool;
// uint64_t time_keep[100];
// int timer_size = 0;
void init_pacer(struct pim_pacer* pacer, struct pim_receiver* receiver,
	struct pim_sender* sender, uint32_t socket_id) {
	pacer->last_update_time = rte_get_timer_cycles();
	pacer->remaining_bytes = 0;
	// pacer->data_q = create_ring("pacer_data_q", sizeof(1500), 256, RING_F_SC_DEQ | RING_F_SP_ENQ);
	pacer->ctrl_q = create_ring("pacer_ctl_q", 200, 256, RING_F_SC_DEQ, socket_id);
	rte_timer_init(&pacer->data_timer);
	rte_timer_init(&pacer->token_timer);
	pacer->send_token_timeout_params = rte_zmalloc("pacer send token param", 
			sizeof(struct send_token_timeout_params), 0);
	pacer->send_token_timeout_params->pacer = pacer;
	pacer->send_token_timeout_params->receiver = receiver;

	pacer->send_data_timeout_params = rte_zmalloc("pacer send data param", 
			sizeof(struct send_data_timeout_params), 0);
	pacer->send_data_timeout_params->pacer = pacer;
	pacer->send_data_timeout_params->sender = sender;
}

void pim_pacer_send_pkts(struct pim_pacer* pacer) {
	// while(!force_quit){
	// 	update_time_byte(pacer);
	// 	while(!rte_ring_empty(pacer->ctrl_q)) {
	// 		struct rte_mbuf* p = (struct rte_mbuf*)dequeue_ring(pacer->ctrl_q);
	// 		struct ipv4_hdr* ipv4_hdr;
	// 		struct pim_hdr *pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
	// 			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	// 		// printf("timer cycles %"PRIu64": send control packets:%u \n",rte_get_timer_cycles(), pim_hdr->type);
	// 		ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
	// 		pacer->remaining_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length) + sizeof(struct ether_hdr) + sizeof(struct vlan_hdr);
	// 		// insert vlan header with highest priority;
	// 		p->vlan_tci = TCI_7;
	// 		if(pim_hdr->type == PIM_RTS) {
	// 			struct pim_rts_hdr *pim_rts_hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, 
	// 				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_rts_hdr));
	// 			if(debug_flow(pim_rts_hdr->flow_id)) {
	// 				printf("send rts for flow%u\n", pim_rts_hdr->flow_id);
	// 			}
	// 		}
	// 		rte_vlan_insert(&p); 
	// 		// send packets; hard code the port;
	// 		rte_eth_tx_burst(params.send_port ,0, &p, 1);
	// 	}
	// 	rte_timer_manage();
	// }
}

void pim_pacer_send_token_handler(__rte_unused struct rte_timer *timer, void* arg) {

	struct send_token_timeout_params* timeout_params = (struct send_token_timeout_params*) arg;
	struct rte_ring* short_flow_token_q = timeout_params->receiver->short_flow_token_q;
	struct rte_ring* long_flow_token_q = timeout_params->receiver->long_flow_token_q;
	struct pim_pacer* pacer = timeout_params->pacer;
	int token_sent = 0;

	struct rte_mbuf* p = NULL;
	struct pim_flow* flow = NULL;
	struct ipv4_hdr* ipv4_hdr = NULL;

	// update_time_byte(pacer);
	while(!rte_ring_empty(short_flow_token_q)) {
		p = (struct rte_mbuf*)dequeue_ring(short_flow_token_q);
		struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) + 
				sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
		flow = lookup_table_entry(timeout_params->receiver->rx_flow_table, pim_token_hdr->flow_id);
		if(flow == NULL || flow->finished_at_receiver) {
			rte_pktmbuf_free(p);
			p = NULL;
		} else {
			break;
		}
	}
	if(p == NULL) {
		while(!rte_ring_empty(long_flow_token_q)) {
			p = (struct rte_mbuf*)dequeue_ring(long_flow_token_q);
			struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) + 
					sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
			flow = lookup_table_entry(timeout_params->receiver->rx_flow_table, pim_token_hdr->flow_id);
			if(flow == NULL || flow->finished_at_receiver) {
				rte_pktmbuf_free(p);
				p = NULL;
			} else {
				break;
			}
		}
	}
	if(p != NULL) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		// this part need to change after the topology set up;
		uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		// insert vlan header with highest priority or tos for ip;
		ipv4_hdr->type_of_service = TOS_7;
		// p->vlan_tci = TCI_7;
		// rte_vlan_insert(&p); 
		// send packets; hard code the port;
		rte_eth_tx_burst(get_port_by_ip(dst_addr), 0, &p, 1);
		token_sent = 1;
	}
	if(token_sent == 1) {
		timeout_params->receiver->num_token_sent += 1;
		pacer->remaining_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length) + sizeof(struct ether_hdr);
		// return;
	}
	rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(1500), SINGLE,
        rte_lcore_id(), &pim_pacer_send_token_handler, (void *)timeout_params);
	// rte_free(timeout_params);

}

void pim_pacer_send_data_pkt_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct send_data_timeout_params* timeout_params = (struct send_data_timeout_params*) arg;
	struct pim_pacer* pacer = timeout_params->pacer;
	struct pim_sender* sender = timeout_params->sender;
	struct rte_ring* short_flow_token_q = timeout_params->sender->short_flow_token_q;
	struct rte_ring* long_flow_token_q = timeout_params->sender->long_flow_token_q;
	int data_sent = 0;
	// update time and bytes

	update_time_byte(pacer);
	if(pacer->remaining_bytes >= 3000) {
		rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(pacer->remaining_bytes) + INFINITESIMAL_CYCLE
			, SINGLE, rte_lcore_id(), &pim_pacer_send_data_pkt_handler, (void *)timeout_params);
		// printf("remaining bytes > 0;\n");
		return;
	}
	// fetch non-finish flows tokens
	struct rte_mbuf* p = NULL;
	// struct pim_flow* flow = NULL;
	if(!rte_ring_empty(short_flow_token_q)) {
		p = (struct rte_mbuf*)dequeue_ring(short_flow_token_q);
		// struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) + 
		// 		sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
		// flow = lookup_table_entry(timeout_params->sender->tx_flow_table, pim_token_hdr->flow_id);
		// if(flow == NULL || flow->_f.finished) {
		// 	flow->_f.sent_bytes += 1460;
		// 	rte_pktmbuf_free(p);
		// 	p = NULL;

		// } else {
		// 	break;
		// }
	}
	if(p == NULL) {
		if(!rte_ring_empty(long_flow_token_q)) {
			p = (struct rte_mbuf*)dequeue_ring(long_flow_token_q);
			// struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) + 
			// 		sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
			// flow = lookup_table_entry(timeout_params->sender->tx_flow_table, pim_token_hdr->flow_id);
			// if(flow == NULL || flow->_f.finished) {
			// 	flow->_f.sent_bytes += 1460;

			// 	rte_pktmbuf_free(p);
			// 	p = NULL;
			// } else {
			// 	break;
			// }
		}
	}
	if(p != NULL) {
		// fetch token info and ip info
		struct pim_token_hdr* pim_token_hdr;
		struct ipv4_hdr* token_ip_hdr;
		struct ipv4_hdr ipv4_hdr;
		struct pim_hdr pim_hdr;
		struct pim_data_hdr pim_data_hdr;

		token_ip_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) 
			+ sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
		ipv4_hdr.src_addr = token_ip_hdr->dst_addr;
		ipv4_hdr.dst_addr = token_ip_hdr->src_addr;
		ipv4_hdr.total_length = rte_cpu_to_be_16(1500);
		ipv4_hdr.type_of_service = get_tos(pim_token_hdr->priority);
		pim_hdr.type = DATA;
		pim_data_hdr.flow_id = pim_token_hdr->flow_id;
		pim_data_hdr.round = pim_token_hdr->round;
		pim_data_hdr.data_seq = pim_token_hdr->data_seq;
		pim_data_hdr.seq_num = pim_token_hdr->seq_num;
		pim_data_hdr.priority = pim_token_hdr->priority;
		if(debug_flow(pim_token_hdr->flow_id)) {
			printf("send data for flow%u: data seq %u\n", pim_token_hdr->flow_id, pim_token_hdr->data_seq);
		}
		rte_pktmbuf_free(p);
		// construct new packet
		p = rte_pktmbuf_alloc(pktmbuf_pool);
		void* data = rte_pktmbuf_append(p, 1500);
		if(data == NULL) {
			rte_exit(EXIT_FAILURE, "Fail to append data");
		}
		add_ether_hdr(p);
		add_ip_hdr(p, &ipv4_hdr);
		add_pim_hdr(p, &pim_hdr);
		add_pim_data_hdr(p, &pim_data_hdr);
		if(pim_data_hdr.seq_num == 0) {
			struct pim_flow* f = lookup_table_entry(sender->tx_flow_table, pim_token_hdr->flow_id);
			f->_f.first_byte_send_time = rte_get_timer_cycles();
		}
		// flow->_f.sent_bytes += 1460;
		sender->sent_bytes += 1500; 
		// p->vlan_tci = get_tci(flow->_f.priority);
		//rte_vlan_insert(&p);
		data_sent = 1;

		rte_eth_tx_burst(get_port_by_ip(rte_be_to_cpu_32(ipv4_hdr.dst_addr)) ,0, &p, 1);
		// uint64_t cycle = rte_get_timer_cycles();

		// printf("timer cycle: %" PRIu64 ": send data packets %u for flow%u\n", 
		// 	cycle, pim_data_hdr.data_seq, pim_data_hdr.flow_id);
	}
	if(data_sent) {
		pacer->remaining_bytes += 1500;
		// time_keep[timer_size] = rte_get_timer_cycles();
		// timer_size++;
		// if(timer_size == 8) {
		// 	int i = 0;
		// 	for (; i < timer_size; i++) {
		// 		printf("next cycle:%"PRIu64 " \n", time_keep[i]);
		// 	}
		// 	timer_size = 0;
		// 	rte_exit(EXIT_FAILURE, "ds");
		// }
		// uint64_t timer2 = rte_get_timer_cycles();
		// printf("send packets: \n");
		// printf("cycle_end:%"PRIu64 " \n", timer2);
	}



	// printf("remaining_bytes:%u \n", pacer->remaining_bytes);
	rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(pacer->remaining_bytes) + INFINITESIMAL_CYCLE
		, SINGLE, rte_lcore_id(), &pim_pacer_send_data_pkt_handler, (void *)timeout_params);

	// rte_free(timeout_params);
}

void update_time_byte(struct pim_pacer* pacer) {
	uint64_t current_cycle = rte_get_timer_cycles();
	uint64_t diff = current_cycle - pacer->last_update_time;
	if (diff * params.bandwidth / rte_get_timer_hz() / 8 == 0)
		return;
	pacer->last_update_time = current_cycle;
	if(pacer->remaining_bytes < diff * params.bandwidth / rte_get_timer_hz() / 8) {
		pacer->remaining_bytes = 0;
	} else {
		pacer->remaining_bytes -= diff * params.bandwidth / rte_get_timer_hz() / 8;
	}
}