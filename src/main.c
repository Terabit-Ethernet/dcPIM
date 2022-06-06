/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_sched.h>
#include <rte_timer.h>
// #include <rte_event_timer_adapter.h>
#include "config.h"
#include "debug.h"
#include "ds.h"
#include "header.h"
#include "flow.h"
#include "pim_flow.h"
#include "pim_host.h"
#include "pim_pacer.h"
#include "random_variable.h"

int mode;
uint64_t start, end;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics prev_stats[RTE_MAX_ETHPORTS];
struct l2fwd_port_statistics flow_stats;

// char sendpath[8];
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_NONE
		//.split_hdr_size = 0,
		//.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

// static struct ether_addr r2c2_ports_eth_addr[RTE_MAX_ETHPORTS];

/*mbuf pool*/
struct rte_mempool * pktmbuf_pool = NULL;
struct pim_epoch epoch;
struct pim_host host;
struct pim_pacer pacer;

char *cdf_file;
static volatile bool force_quit;

bool start_signal;

#define TARGET_NUM 5000

static unsigned char
outgoing_port(unsigned char id) {
	switch(id) {
	case PORT_0:
		return 0;
	case PORT_1:
		return 1;
	default:
		return 255;
	}
}

static void host_main_loop(void) {
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *p;
	unsigned lcore_id;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;

	qconf = &lcore_queue_conf[lcore_id];
	//bool print = false;
	params.pim_iter_epoch = params.pim_beta * get_rtt(params.propagation_delay, 3, 40) + params.clock_bias;
	params.pim_epoch = params.pim_iter_limit * params.pim_iter_epoch * (1 + params.pim_alpha);
	printf("control packet rtt :%f\n", get_rtt(params.propagation_delay, 3, 40)* 1000000);
	printf("iter size :%f\n",params.pim_iter_epoch * 1000000);
	printf("epoch:%f\n", params.pim_epoch * 1000000);
	printf("new epoch start:%f\n", 1000000 * (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit));
	uint64_t cycle_per_us = (uint64_t)(rte_get_timer_hz() / 1000000.0);
	printf("cycle per us:%"PRIu64"\n", cycle_per_us);
	// pim_init_epoch(&epoch, &host, &pacer);
	// pim_eceive_start(&epoch, &host, &pacer);

	// pim_receive_start(&epoch, &host, &pacer);
	// rte_timer_reset(&host.pim_send_token_timer, rte_get_timer_hz() * get_transmission_delay(1500) * params.batch_tokens,
	//  	PERIODICAL, rte_lcore_id(), &pim_send_token_evt_handler, (void *)&epoch.pim_timer_params);

	// rte_timer_reset(&epoch.epoch_timer, rte_get_timer_hz() * (params.pim_epoch - params.pim_iter_epoch * params.pim_iter_limit),
	//  PERIODICAL, 1, &pim_start_new_epoch, (void *)(&epoch.pim_timer_params));
	while(!force_quit) {
		for (i = 0; i < qconf->n_rx_port; i++) {
			if(i == 0)
				continue;
			portid = qconf->rx_port_list[i];

			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);
			for (j = 0; j < nb_rx; j++) {
				p = pkts_burst[j];
				// rte_vlan_strip(p);
				pim_rx_packets(&epoch, &host, &pacer, p);
			}
		}
		cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
         if (diff_tsc > cycle_per_us / 10) {
                rte_timer_manage();
                 prev_tsc = cur_tsc;
         }
	}
}

static void pacer_main_loop(void) {
	printf("pacer core:%u\n", rte_lcore_id());
	rte_timer_reset(&pacer.token_timer, get_transmission_delay(1500) * rte_get_timer_hz(), PERIODICAL,
        rte_lcore_id(), &pim_pacer_send_token_handler, (void *)pacer.send_token_timeout_params);
	rte_timer_reset(&pacer.data_timer, get_transmission_delay(1500) * rte_get_timer_hz(), PERIODICAL,
    	rte_lcore_id(), &pim_pacer_send_data_pkt_handler, (void *)pacer.send_data_timeout_params);

	// uint64_t cycles[16];
	// bool rts_sent = false;
	while(!force_quit){
		update_time_byte(&pacer);
		while(!rte_ring_empty(pacer.ctrl_q)) {

			struct rte_mbuf* p = (struct rte_mbuf*)dequeue_ring(pacer.ctrl_q);
			if(p == NULL){
				rte_exit(EXIT_FAILURE, "deque ring\n");
			}
			struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, sizeof(struct ether_hdr));
    	                struct pim_hdr *pim_hdr;

    		        uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);

   		 	pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, offset);

			pacer.remaining_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length) + sizeof(struct ether_hdr);
			
			uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
			// insert vlan header with highest priority;
			// use tos in ipheader instead;

			ipv4_hdr->version_ihl = (0x40 | 0x05);
			ipv4_hdr->type_of_service = TOS_7;
			ipv4_hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
			//ipv4_hdr->next_proto_id = 6;
			ipv4_hdr->time_to_live = 64;
			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
			//if(pim_hdr->type == PIM_RTS) {
			// 	printf("send control packet type:%u\n", pim_hdr->type);
			//}
			// p->vlan_tci = TCI_7;
			// rte_vlan_insert(&p); 
			// send packets; hard code the port;
			// cycles[0] = rte_get_timer_cycles();
		//	printf("dst:%u\n", dst_addr);
	//		printf("port:%d\n", get_port_by_ip(dst_addr));
			//rte_pktmbuf_dump(stdout, p, rte_pktmbuf_pkt_len(p));
			int sent = rte_eth_tx_burst(get_port_by_ip(dst_addr) ,0, &p, 1);
		   	while(sent != 1) {
		   		sent = rte_eth_tx_burst(get_port_by_ip(dst_addr) ,0, &p, 1);
        		// printf("pacer main loop: %d:sent fails\n", __LINE__);
        		// rte_exit(EXIT_FAILURE, "");
		   	}
			// cycles[1] = rte_get_timer_cycles();
			// rts_sent = true;

		}
		// cycles[2] = rte_get_timer_cycles();
		rte_timer_manage();
		// cycles[3] = rte_get_timer_cycles();
		// if(rts_sent) {
		// 	uint32_t i = 0;
		// 	for (; i < 5; i++) {
		// 		printf("cycle:%"PRIu64 "\n", cycles[i]);
		// 	}
		// 	rts_sent = false;
		// }

	}

}
static void start_main_loop(void) {
	// unsigned lcore_id;
	rte_delay_us_block(2000000);
	int ips[1] = {24};
	unsigned i = 0;
	for (; i < params.num_hosts; i++) {
		if(params.dst_ips[i] == params.ip){
			continue;
		}
		struct rte_mbuf* p = NULL;
	    p = rte_pktmbuf_alloc(pktmbuf_pool);
	    uint16_t size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
	                sizeof(struct pim_hdr);
	    rte_pktmbuf_append(p, size);
	    add_ether_hdr(p, &params.dst_ethers[i]);
	    struct ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(p, 
	    	struct ipv4_hdr*, sizeof(struct ether_hdr));
	    struct pim_hdr* pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, 
	    	sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	    ipv4_hdr->src_addr = rte_cpu_to_be_32(params.ip);
	    ipv4_hdr->dst_addr = rte_cpu_to_be_32(params.dst_ips[i]);
	    ipv4_hdr->total_length = rte_cpu_to_be_16(size - sizeof(struct ether_hdr));
		ipv4_hdr->version_ihl = (0x40 | 0x05);
		ipv4_hdr->type_of_service = TOS_7;
	        ipv4_hdr->next_proto_id = 6;
		ipv4_hdr->time_to_live = 64;
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	    pim_hdr->type = PIM_START;
		//rte_pktmbuf_dump(stdout, p, rte_pktmbuf_pkt_len(p));
	    	rte_eth_tx_burst(get_port_by_ip(ips[i]) ,0, &p, 1);
		start = rte_get_timer_cycles();
	}
	pim_receive_start(&epoch, &host, &pacer, 1);
	// lcore_id = rte_lcore_id();
 //    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
 //    rte_timer_reset(&epoch.epoch_timer, 0,
	//  SINGLE, rte_lcore_id(), &pim_start_new_epoch, (void *)(epoch.pim_timer_params));
	// while(!force_quit) {
	// 	cur_tsc = rte_get_tsc_cycles();
	// 	diff_tsc = cur_tsc - prev_tsc;
 //        // if (diff_tsc > 1) {
	// 	while(!rte_ring_empty(receiver.event_q)) {
	// 		struct event_params* event_params = dequeue_ring(receiver.event_q);
	// 		if(event_params == NULL) {
	// 			rte_exit(EXIT_FAILURE, "Failure for NULL event");
	// 		}
	// 		event_params->func(event_params->params);
	// 		rte_free(event_params->params);
	// 		rte_free(event_params);
	// 	}
 //                // rte_timer_manage();
 //        //         prev_tsc = cur_tsc;
 //        // }
	// }
}

static void flow_generate_loop(void) {
	// rte_delay_us_block(5000000);
	int i = 0;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    double TIMER_RESOLUTION_CYCLES = rte_get_timer_hz() / 1000000.0; /* how many cycles in 1 us */

    uint64_t prev_tsc_2 = 0, diff_tsc_2 = TIMER_RESOLUTION_CYCLES * 100000;
	struct exp_random_variable exp_r;
	struct empirical_random_variable emp_r;
	init_empirical_random_variable(&emp_r, cdf_file ,true);
	double lambda = params.bandwidth * params.load / (emp_r.mean_flow_size * 8.0 / 1460 * 1500);
    init_exp_random_variable(&exp_r, 1.0 / lambda);
    uint32_t flow_size = (uint32_t)(value_emp(&emp_r) + 0.5) * 1460;
    double time = value_exp(&exp_r);
    // double acc_time = 0;
    // double acc_flow_size = 0;
    while(!start_signal && !force_quit) {
	    rte_delay_us_block(10000);
    }
	while(!force_quit) {
		cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
         if (diff_tsc > TIMER_RESOLUTION_CYCLES * time * 1000000.0 && i < TARGET_NUM) {
         	if(i == 0) {
			 	host.start_cycle = rte_get_tsc_cycles();
         	}
        	// acc_time += time;
        	// acc_flow_size += flow_size;
			// printf("flow size:%u\n", flow_size);
			// printf("acc_time:%f\n", acc_time);
			// printf("avg load: %f\n", acc_flow_size * 8 / (params.bandwidth * acc_time));
			uint32_t dst_ip = params.ip;
			struct ether_addr dst_ether;
			while(1) {
				uint32_t index = (uint32_t)(rte_rand() % params.num_hosts);
			 	dst_ip = params.dst_ips[index];
			 	if(dst_ip == params.ip){
			 		continue;
			 	}
			 	ether_addr_copy(&params.dst_ethers[index], &dst_ether);
			 	break;
			}

			pim_new_flow_comes(&host, & pacer, i + params.index * 100000, dst_ip, &dst_ether, flow_size);
            // printf("flow id%u\n", i);
            // printf("flow size:%u\n", flow_size);
            // printf("time:%f\n", time);
         	i++;
            prev_tsc = cur_tsc;
            flow_size = (uint32_t)(value_emp(&emp_r) + 0.5) * 1460;
        	time = value_exp(&exp_r);
         }
        if(cur_tsc - prev_tsc_2 > diff_tsc_2) {
			// host.end_cycle = rte_get_tsc_cycles();
			// double time = (double)(host.end_cycle - host.start_cycle) / (double)rte_get_tsc_hz();
			// uint32_t old_sentbytes = host.sent_bytes;
			// uint32_t old_receivebytes = host.received_bytes;
			// double sent_tpt = (double)(old_sentbytes) * 8 / time;
			// double receive_tpt = (double)(old_receivebytes) * 8 / time;
			
			// host.start_cycle = host.end_cycle;

			// printf("-------------------------------\n");
			// printf("sent throughput: %f\n", sent_tpt);
			// printf("received throughput: %f\n", receive_tpt); 
			// printf("size of long flow token q: %u\n",rte_ring_count(host.long_flow_token_q));
			// printf("size of short flow token q: %u\n",rte_ring_count(host.short_flow_token_q));

			// printf("size of temp_pkt_buffer: %u\n",rte_ring_count(host.temp_pkt_buffer));
			// printf("size of control q: %u\n", rte_ring_count(pacer.ctrl_q));
			// printf("size of data q: %u\n", rte_ring_count(pacer.data_q));
			// //printf("number of unfinished flow: %u\n", rte_hash_count(host.rx_flow_table));

			// host.sent_bytes -= old_sentbytes;
			// host.received_bytes -= old_receivebytes;
			// prev_tsc_2 = cur_tsc;
        }
	}
}


static int
launch_host_lcore(__attribute__((unused)) void *dummy) {
	host_main_loop();
	return 0;
}

static int
launch_flowgen_lcore(__attribute__((unused)) void *dummy) {
	flow_generate_loop();
	return 0;
}

static int
launch_pacer_lcore(__attribute__((unused)) void *dummy) {
	pacer_main_loop();
	return 0;
}

static int
launch_start_lcore(__attribute__((unused)) void *dummy) {
	start_main_loop();
	return 0;
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 1;
	struct rte_eth_link link;

	printf("\nChecking link status... ");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
		if(mode == 1 || mode == 2) {
			uint32_t* flow_id = 0;
			int32_t position = 0;
			uint32_t next = 0;
			struct pim_flow* flow;
			uint32_t finished_flow = 0;
			while(1) {
				position = rte_hash_iterate(host.tx_flow_table, (const void**) &flow_id, (void**)&flow, &next);
				if(position == -ENOENT) {
					break;
				}
				if(!flow->_f.finished) {
					continue;
				}
				// if(flow->rd_ctrl_timeout_params != NULL) {
				// 	continue;
				// }
				finished_flow += 1;
				pflow_dump(flow);
			}
			printf("Finished flow:%u \n", finished_flow);
			printf("------------\n");
			printf("Unfinished flows\n");
			position = 0;
 			next = 0;
			while(1) {
				position = rte_hash_iterate(host.tx_flow_table, (const void**) &flow_id, (void**)&flow, &next);
				if(position == -ENOENT) {
					break;
				}
				if(flow->_f.finished) {
					continue;
				}
				// if(flow->rd_ctrl_timeout_params != NULL) {
				// 	continue;
				// }
				pflow_dump(flow);
			}
			printf("------------\n");
			//printf("Unfinished received flows:%u\n", rte_hash_count(host.rx_flow_table));
			position = 0;
 			next = 0;
			while(1) {
				position = rte_hash_iterate(host.rx_flow_table, (const void**) &flow_id, (void**)&flow, &next);
				if(position == -ENOENT) {
					break;
				}
				if(flow->finished_at_receiver) {
					continue;
				}
				// if(flow->rd_ctrl_timeout_params != NULL) {
				// 	continue;
				// }
				pflow_dump(flow);
			} 
			struct rte_ring* buf = host.temp_pkt_buffer;
			uint32_t size = rte_ring_count(buf);
			uint32_t i = 0;
			// printf("iteration start\n");
			for(; i < size; i++) {
				struct rte_mbuf* p = NULL;
				p = (struct rte_mbuf*)dequeue_ring(buf);
				uint32_t offset = sizeof(struct ether_hdr) + 
				sizeof(struct ipv4_hdr) + sizeof(struct pim_hdr);
				struct pim_data_hdr *pim_data_hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
				// printf("flow id:%u\n", flow_id);
				// struct pim_flow* f = lookup_table_entry(host->rx_flow_table, pim_data_hdr->flow_id);
				// printf("data header flow id:%u\n", pim_data_hdr->flow_id);
				// if(f != NULL)
				printf("flow id:%u\n", pim_data_hdr->flow_id);

			}
			pim_host_dump(&host, &pacer);
		}

	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t num_ports;
	uint16_t portid;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
	mode = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	start_signal = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse command line opts */
	if(argc >= 2 && !strcmp("send", argv[1])) {
		mode = 1;	
	} else if (argc >= 2 && !strcmp("start", argv[1])) {
		mode = 2;
	}
	if(argc >= 3) {
		cdf_file = argv[2];
	}
	/* exit if no ports open*/
	num_ports = rte_eth_dev_count();
	if (num_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/*initialize lcore 1 as RX for ports 0 and 1*/
	qconf = &lcore_queue_conf[RECEIVE_CORE];
	// if(params.ip == 22) {
	// 	qconf->rx_port_list[0] = 0;
	// } else if (params.ip == 24) {
	// 	qconf->rx_port_list[0] = 0;
	// }
	// qconf->n_rx_port++;

	qconf->rx_port_list[0] = 0;
	qconf->n_rx_port++;
	qconf->rx_port_list[1] = 1;
	qconf->n_rx_port++;


	/* create the mbuf pool */
	nb_mbufs = RTE_MAX(num_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		0);
	printf("RTE_MBUF_DEFAULT_BUF_SIZE:%lu\n", sizeof(struct pim_flow));
	printf("nb_mbufs:%d\n", nb_mbufs);
	printf("default timer cycles:%"PRIu64"\n", rte_get_timer_hz());
	printf("tsc timer cycles:%"PRIu64"\n", rte_get_tsc_hz());

	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		
		if(portid != 1)
			continue;
		/* init port*/
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, portid);
		}

		// ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);

		// if (ret < 0){
		// 	rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%u\n", ret, portid);
		// }

		// rte_eth_macaddr_get(portid, &r2c2_ports_eth_addr[portid]);

		/*init one RX queue*/
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		// rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, pktmbuf_pool);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
		}
		/* init one TX queues on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		// txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		// printf("socket id for port:%u\n",rte_eth_dev_socket_id(portid));
		// ret = rte_eth_tx_queue_setup(portid, 1, nb_txd,
		// 		rte_eth_dev_socket_id(portid),
		// 		&txq_conf);
		// if (ret < 0)
		// 	rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
		// 		ret, portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if(ret < 0){
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, portid);
		}

		printf("done: \n");

		rte_eth_promiscuous_disable(portid);

		// printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		// 		portid,
		// 		r2c2_ports_eth_addr[portid].addr_bytes[0],
		// 		r2c2_ports_eth_addr[portid].addr_bytes[1],
		// 		r2c2_ports_eth_addr[portid].addr_bytes[2],
		// 		r2c2_ports_eth_addr[portid].addr_bytes[3],
		// 		r2c2_ports_eth_addr[portid].addr_bytes[4],
		// 		r2c2_ports_eth_addr[portid].addr_bytes[5]);

	}
    /* init RTE timer library */
    // uint64_t hz;
    rte_timer_subsystem_init();

	check_all_ports_link_status();
	ret = 0;
	init_config(&params);
	printf("window timeout cycle:%"PRIu64"\n", params.token_window_timeout_cycle);
	rte_eth_macaddr_get(1, &params.ether_addr);
	/* initialize flow rates and flow nums */
	// for(int i = 0; i < NUM_FLOW_TYPES; i++) {
	// 	flow_remainder[i] = 0;
	// 	flow_rate[i] = 250000000 / 12000.0 / rte_get_tsc_hz();
	// 	num_flows[i] = 8;
	// }

	if(mode == 1 || mode == 2) {
		// allocate all data structure on socket 1(Numa node 1) because
		// NIC is connected to node 1.
	    pim_init_host(&host, 0);
	    pim_init_pacer(&pacer, &host, 0);
	    pim_init_epoch(&epoch, &host, &pacer);
	    rte_eal_remote_launch(launch_host_lcore, NULL, RECEIVE_CORE);
		rte_eal_remote_launch(launch_pacer_lcore, NULL, 2);
	    rte_eal_remote_launch(launch_flowgen_lcore, NULL, 3);
		// rte_eal_remote_launch(launch_start_lcore, NULL, 4);

	}  
	if(mode == 2){
		printf("launch start\n");
		rte_eal_remote_launch(launch_start_lcore, NULL, 4);
	}

	while(!force_quit){
		// print_stats();
//		printf("in force quiit\n");
		rte_delay_us_sleep(1000000);
	}

	if(rte_eal_wait_lcore(RECEIVE_CORE) < 0){
	ret = -1;
	}
	if(rte_eal_wait_lcore(2) < 0){
		ret = -1;
	}
	if(rte_eal_wait_lcore(3) < 0){
		ret = -1;
	}
	if(rte_eal_wait_lcore(4) < 0){
		ret = -1;
	}
	// print_stats();


	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
