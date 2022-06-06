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
	pacer->ctrl_q = create_ring("pacer_ctl_q", 200, 256, RING_F_SC_DEQ, socket_id);
	pacer->data_q = create_ring("pacer_data_q", 200, 256, RING_F_SC_DEQ | RING_F_SP_ENQ, socket_id);
	rte_timer_init(&pacer->data_timer);
	rte_timer_init(&pacer->token_timer);

	pacer->send_token_timeout_params = rte_zmalloc("pacer send token param", 
			sizeof(struct send_token_timeout_params), 0);
	pacer->send_token_timeout_params->pacer = pacer;
	pacer->send_token_timeout_params->host = host;

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
	// uint64_t start_cycle = rte_get_timer_cycles();

	struct rte_ring* short_flow_token_q = host->short_flow_token_q;
	struct rte_ring* long_flow_token_q = host->long_flow_token_q;
	int data_sent = 0;
	// update time and bytes
	update_time_byte(pacer);
	// if(pacer->remaining_bytes >= 3000) {
	// 	// rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(pacer->remaining_bytes) + INFINITESIMAL_CYCLE
	// 		// , SINGLE, rte_lcore_id(), &pim_pacer_send_data_pkt_handler, (void *)timeout_params);
	// 	// printf("remaining bytes > 0;\n");
	// 	return;
	// }
	// fetch non-finish flows tokens
	struct rte_mbuf* p = NULL;
	struct rte_mbuf* sent_p = NULL;
	// struct ruf_flow* flow = NULL;
	if(!rte_ring_empty(short_flow_token_q)) {
		p = (struct rte_mbuf*)dequeue_ring(short_flow_token_q);
	}

	if(p == NULL) {
		if(!rte_ring_empty(long_flow_token_q)) {
			p = (struct rte_mbuf*)dequeue_ring(long_flow_token_q);
		}
	}

	if(p != NULL) {
		// fetch token info and ip info
		// construct new packet
		struct ether_hdr* ether_token_hdr =  rte_pktmbuf_mtod_offset(p, struct ether_hdr *, 0);
		struct pim_token_hdr* pim_token_hdr =  rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) 
			+ sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
		struct ipv4_hdr* token_ip_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		// struct pim_hdr* pim_hdr2 = rte_pktmbuf_mtod_offset(p, struct pim_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

		// if(rte_be_to_cpu_32(token_ip_hdr->src_addr) == 22) {
		// 	printf("pim hdr type:%u\n", pim_hdr2->type);
		// 	printf("token src address: %u\n", rte_be_to_cpu_32(token_ip_hdr->src_addr));

		// 	printf("token dst address: %u\n", rte_be_to_cpu_32(token_ip_hdr->dst_addr));
		// 	printf("token ip \n");
		// }

		sent_p = rte_pktmbuf_alloc(pktmbuf_pool);
		void* data = rte_pktmbuf_append(sent_p, 1500);
		if(data == NULL) {
			rte_exit(EXIT_FAILURE, "Fail to append data");
		}
		add_ether_hdr(sent_p, &ether_token_hdr->s_addr);

		struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(sent_p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(sent_p, struct pim_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
		struct pim_data_hdr* pim_data_hdr = rte_pktmbuf_mtod_offset(sent_p, struct pim_data_hdr *, 
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));


		ipv4_hdr->src_addr = token_ip_hdr->dst_addr;
		ipv4_hdr->dst_addr = token_ip_hdr->src_addr;
		ipv4_hdr->total_length = rte_cpu_to_be_16(1500 - sizeof(struct ether_hdr));
		ipv4_hdr->version_ihl = (0x40 | 0x05);
		ipv4_hdr->type_of_service = get_tos(pim_token_hdr->priority);
		ipv4_hdr->time_to_live = 64;
		ipv4_hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
		//ipv4_hdr->next_proto_id = 6;
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		// printf("ipv4_hdr->src_addr:%u\n", rte_be_to_cpu_32(ipv4_hdr->src_addr));
		// printf("ipv4_hdr->dst_addr:%u\n", rte_be_to_cpu_32(ipv4_hdr->dst_addr));
		// rte_pktmbuf_dump(stdout, p, 60);
		// fflush(stdout);
		// rte_exit(EXIT_FAILURE ,"exit");
		pim_hdr->type = DATA;
		pim_data_hdr->flow_id = pim_token_hdr->flow_id;
		pim_data_hdr->data_seq_no = pim_token_hdr->data_seq_no;
		pim_data_hdr->seq_no = pim_token_hdr->seq_no;
		pim_data_hdr->priority = pim_token_hdr->priority;
		pim_data_hdr->free_token = pim_token_hdr->free_token;
		rte_pktmbuf_free(p);
		// if(pim_data_hdr->free_token == 1) {
		// 	printf("send free token data\n");
		// }
		p = NULL;
		if(pim_data_hdr->seq_no == 0) {
			struct pim_flow* f = lookup_table_entry(host->tx_flow_table, pim_data_hdr->flow_id);
			f->_f.first_byte_send_time = rte_get_timer_cycles();
		}
		// flow->_f.sent_bytes += 1460;
		host->sent_bytes += 1500; 
		// p->vlan_tci = get_tci(flow->_f.priority);
		//rte_vlan_insert(&p);
		data_sent = 1;
		int sent = rte_eth_tx_burst(get_port_by_ip(rte_be_to_cpu_32(ipv4_hdr->dst_addr)) ,0, &sent_p, 1);
		while(sent != 1) {
			sent = rte_eth_tx_burst(get_port_by_ip(rte_be_to_cpu_32(ipv4_hdr->dst_addr)) ,0, &sent_p, 1);
   //  		printf("pacer main loop: %d:sent fails\n", __LINE__);
			// rte_exit(EXIT_FAILURE, "");
		}
	}
	if(data_sent) {
		pacer->remaining_bytes += 1500;
	}
}
void pim_pacer_send_token_handler(__rte_unused struct rte_timer *timer, void* arg) {

	struct send_token_timeout_params* timeout_params = (struct send_token_timeout_params*) arg;
	struct rte_ring* send_token_q = timeout_params->host->send_token_q;
	struct pim_pacer* pacer = timeout_params->pacer;
	struct pim_host* host = timeout_params->host;
	// static int i = 0;
	int token_sent = 0;

	struct rte_mbuf* p = NULL;
	struct pim_flow* flow = NULL;
	struct ipv4_hdr* ipv4_hdr = NULL;

	// update_time_byte(pacer);
	while(!rte_ring_empty(send_token_q)) {
		p = (struct rte_mbuf*)dequeue_ring(send_token_q);
		struct pim_token_hdr* pim_token_hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr *, sizeof(struct ether_hdr) + 
				sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr));
		flow = lookup_table_entry(host->rx_flow_table, pim_token_hdr->flow_id);
		if(flow == NULL || flow->finished_at_receiver) {
			rte_pktmbuf_free(p);
			p = NULL;
		} else {
			break;
		}
	}
	if(p != NULL) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
		// this part need to change after the topology set up;
		uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		// insert vlan header with highest priority or tos for ip;
		ipv4_hdr->version_ihl = (0x40 | 0x05);
		ipv4_hdr->type_of_service = TOS_7;
		ipv4_hdr->time_to_live = 64;
		ipv4_hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
		//ipv4_hdr->next_proto_id = 6;
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		// p->vlan_tci = TCI_7;
		// rte_vlan_insert(&p); 
		// send packets; hard code the port;
		// if(i % 100 == 0) {
		// 	printf("%d\n",i);
		// 	printf("%"PRIu64" send token\n",rte_get_timer_cycles());
		// }
		// i++;

		int sent = rte_eth_tx_burst(get_port_by_ip(dst_addr), 0, &p, 1);
		while(sent != 1) {
			sent = rte_eth_tx_burst(get_port_by_ip(dst_addr), 0, &p, 1);
   //  		printf("pacer main loop: %d:sent fails\n", __LINE__);
			// rte_exit(EXIT_FAILURE, "");
		}
		token_sent = 1;
	}
	if(token_sent == 1) {
		host->num_token_sent += 1;
		pacer->remaining_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length) + sizeof(struct ether_hdr);
		// return;
	}
	// rte_timer_reset(timer, rte_get_timer_hz() * get_transmission_delay(1500), SINGLE,
 //        rte_lcore_id(), &pim_pacer_send_token_handler, (void *)timeout_params);
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
