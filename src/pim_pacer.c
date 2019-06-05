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
void pim_init_pacer(struct pim_pacer* pacer, struct pim_host* host, uint32_t socket_id) {
	pacer->last_update_time = rte_get_timer_cycles();
	pacer->remaining_bytes = 0;
	// pacer->data_q = create_ring("pacer_data_q", sizeof(1500), 256, RING_F_SC_DEQ | RING_F_SP_ENQ);
	pacer->ctrl_q = create_ring("pacer_ctl_q", 200, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	pacer->data_q = create_ring("pacer_data_q", 200, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);

	rte_timer_init(&pacer->data_timer);

	pacer->send_data_timeout_params = rte_zmalloc("pacer send data param", 
			sizeof(struct send_data_timeout_params), 0);
	pacer->send_data_timeout_params->pacer = pacer;
	pacer->send_data_timeout_params->host = host;
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

void pim_pacer_send_data_pkt_handler(__rte_unused struct rte_timer *timer, void* arg) {
	struct send_data_timeout_params* timeout_params = (struct send_data_timeout_params*) arg;
	struct pim_pacer* pacer = timeout_params->pacer;
	struct pim_host* host = timeout_params->host;
	int data_sent = 0;
	// update time and bytes

	update_time_byte(pacer);
	if(pacer->remaining_bytes >= 3000) {
		rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(pacer->remaining_bytes) + INFINITESIMAL_CYCLE
			, SINGLE, rte_lcore_id(), &pim_pacer_send_data_pkt_handler, (void *)timeout_params);
		// printf("remaining bytes > 0;\n");
		return;
	}
	struct rte_mbuf* p = (struct rte_mbuf*)dequeue_ring(pacer->data_q);
	if(p != NULL) {
		// fetch token info and ip info
		// flow->_f.sent_bytes += 1460;
		struct ipv4_hdr* ipv4_hdr;
	 	ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		host->sent_bytes += 1500; 
		// p->vlan_tci = get_tci(flow->_f.priority);
		//rte_vlan_insert(&p);
		data_sent = 1;

		rte_eth_tx_burst(get_port_by_ip(rte_be_to_cpu_32(ipv4_hdr->dst_addr)) ,0, &p, 1);

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