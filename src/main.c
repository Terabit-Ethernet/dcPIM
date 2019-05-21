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
#include "ruf_flow.h"
#include "ruf_host.h"
#include "ruf_pacer.h"

#define TIMER_RESOLUTION_CYCLES 4500UL /* around 10ms at 2 Ghz */

int mode;
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
		.split_hdr_size = 0,
		//.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.offloads = 0,
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

struct ruf_sender sender;
struct ruf_receiver receiver; 
struct ruf_pacer pacer;
struct ruf_controller controller;

static volatile bool force_quit;

#define TARGET_NUM 2000

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
	bool print = false;

	while(!force_quit) {
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);
			for (j = 0; j < nb_rx; j++) {
				p = pkts_burst[j];
				// rte_vlan_strip(p);
				ruf_rx_packets(&receiver, &sender, &pacer, p);
			}
		}
		cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
                rte_timer_manage();
                prev_tsc = cur_tsc;
        }
	}
}

static void pacer_main_loop(void) {
	printf("pacer core:%u\n", rte_lcore_id());
	rte_timer_reset(&pacer.token_timer, 0, SINGLE,
        rte_lcore_id(), &ruf_pacer_send_token_handler, (void *)pacer.send_token_timeout_params);

	rte_timer_reset(&pacer.data_timer, 0, SINGLE,
    	rte_lcore_id(), &ruf_pacer_send_data_pkt_handler, (void *)pacer.send_data_timeout_params);

	// uint64_t cycles[16];
	// bool rts_sent = false;
	while(!force_quit){
		update_time_byte(&pacer);
		while(!rte_ring_empty(pacer.ctrl_q)) {
			struct rte_mbuf* p = (struct rte_mbuf*)dequeue_ring(pacer.ctrl_q);
			struct ipv4_hdr* ipv4_hdr;
			struct ruf_hdr *ruf_hdr = rte_pktmbuf_mtod_offset(p, struct ruf_hdr*, 
				sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
			// printf("timer cycles %"PRIu64": send control packets:%u \n",rte_get_timer_cycles(), ruf_hdr->type);
			ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
			pacer.remaining_bytes += rte_be_to_cpu_16(ipv4_hdr->total_length) + sizeof(struct ether_hdr);
			uint32_t dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
			// insert vlan header with highest priority;
			// use tos in ipheader instead;
			ipv4_hdr->type_of_service = TOS_7;
			// p->vlan_tci = TCI_7;
			if(ruf_hdr->type == RTP_LISTSRCS) {
				struct ruf_listsrc_hdr *ruf_listsrc_hdr = rte_pktmbuf_mtod_offset(p, struct ruf_listsrc_hdr*, 
					sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct ruf_hdr));
				if(debug_flow(ruf_listsrc_hdr->has_nrts)) {
					printf("send nrts for %u\n", ruf_listsrc_hdr->num_srcs);
				}
			}
			// rte_vlan_insert(&p); 
			// send packets; hard code the port;
			// cycles[0] = rte_get_timer_cycles();
			rte_eth_tx_burst(get_port_by_ip(dst_addr) ,0, &p, 1);
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
static void temp_main_loop(void) {
	unsigned lcore_id;

	lcore_id = rte_lcore_id();
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;

	while(!force_quit) {
		cur_tsc = rte_get_tsc_cycles();
		diff_tsc = cur_tsc - prev_tsc;
        // if (diff_tsc > 1) {
		while(!rte_ring_empty(receiver.event_q)) {
			struct event_params* event_params = dequeue_ring(receiver.event_q);
			if(event_params == NULL) {
				rte_exit(EXIT_FAILURE, "Failure for NULL event");
			}
			event_params->func(event_params->params);
			rte_free(event_params->params);
			rte_free(event_params);
		}
                // rte_timer_manage();
        //         prev_tsc = cur_tsc;
        // }
	}
}
static void controller_main_loop(void) {
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *p;
	unsigned lcore_id;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];
	printf("controller starts\n");
	rte_timer_reset(&controller.handle_rq_timer, 
	rte_get_timer_hz() * params.BDP * get_transmission_delay(1500) * params.control_epoch,
	PERIODICAL, rte_lcore_id(), &handle_requests, (void*) &controller);
	while(!force_quit) {
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);
			for (j = 0; j < nb_rx; j++) {
				p = pkts_burst[j];
				// rte_vlan_strip(p);
				ruf_receive_listsrc(&controller, p);
			}
		}
		rte_timer_manage();
	}
}

static void flow_generate_loop(void) {
	rte_delay_us_block(5000000);
	int i = 0;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t prev_tsc_2 = 0, diff_tsc_2 = TIMER_RESOLUTION_CYCLES * 100000;
	while(!force_quit) {
		cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
         if (diff_tsc > TIMER_RESOLUTION_CYCLES * 1200) {
         	if(i == 0) {
			 	receiver.start_cycle = rte_get_tsc_cycles();
         	}
			 ruf_new_flow_comes(&sender, & pacer, i, params.dst_ip, 1460 * 1000);
         	i++;
             prev_tsc = cur_tsc;
         }
        if(cur_tsc - prev_tsc_2 > diff_tsc_2) {
			receiver.end_cycle = rte_get_tsc_cycles();
			double time = (double)(receiver.end_cycle - receiver.start_cycle) / (double)rte_get_tsc_hz();
			uint32_t old_sentbytes = sender.sent_bytes;
			uint32_t old_receivebytes = receiver.received_bytes;
			uint32_t old_num_token_sent = receiver.num_token_sent;
			uint32_t old_idle_timeout_times = receiver.idle_timeout_times;
			double sent_tpt = (double)(old_sentbytes) * 8 / time;
			double receive_tpt = (double)(old_receivebytes) * 8 / time;
			
			receiver.start_cycle = receiver.end_cycle;

			printf("-------------------------------\n");
			printf("sent throughput: %f\n", sent_tpt);
			printf("received throughput: %f\n", receive_tpt); 
			printf("idle timeout times:%u\n", receiver.idle_timeout_times);
			printf("sent token: %u\n", receiver.num_token_sent);
			printf("size of long flow token q: %u\n",rte_ring_count(sender.long_flow_token_q));
			printf("size of short flow token q: %u\n",rte_ring_count(sender.short_flow_token_q));
			printf("size of temp_pkt_buffer: %u\n",rte_ring_count(receiver.temp_pkt_buffer));
			printf("size of control q: %u\n", rte_ring_count(pacer.ctrl_q));
			printf("number of unfinished flow: %u\n", rte_hash_count(receiver.rx_flow_table));
			printf("size of event q: %u\n", rte_ring_count(receiver.event_q));
			printf("send nrts: %u\n", receiver.sent_nrts_num);

			sender.sent_bytes -= old_sentbytes;
			receiver.received_bytes -= old_receivebytes;
			receiver.num_token_sent -= old_num_token_sent;
			receiver.idle_timeout_times -= old_idle_timeout_times;
			prev_tsc_2 = cur_tsc;
        }
        if(i == TARGET_NUM * 20) {
        	break;
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
launch_temp_lcore(__attribute__((unused)) void *dummy) {
	temp_main_loop();
	return 0;
}

static int
launch_controller_lcore(__attribute__((unused)) void *dummy) {
	controller_main_loop();
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
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
		if(mode == 1) {
			uint32_t* flow_id = 0;
			int32_t position = 0;
			uint32_t next = 0;
			struct ruf_flow* flow;
			uint32_t finished_flow = 0;
			while(1) {
				position = rte_hash_iterate(sender.tx_flow_table, (const void**) &flow_id, (void**)&flow, &next);
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
				ruf_flow_dump(flow);
			}
			printf("Finished flow:%u \n", finished_flow);    
			host_dump(&sender, &receiver, &pacer);
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
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse command line opts */
	if(argc >= 2 && !strcmp("send", argv[1])) {
		mode = 1;	
	} else if (argc >= 2 && !strcmp("control", argv[1])) {
		mode = 2;
	}

	/* exit if no ports open*/
	num_ports = rte_eth_dev_count_avail();
	if (num_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/*initialize lcore 1 as RX for ports 0 and 1*/
	if(mode == 1) {
		qconf = &lcore_queue_conf[1];
		qconf->rx_port_list[0] = 0;
		qconf->n_rx_port++;
		qconf->rx_port_list[1] = 1;
		qconf->n_rx_port++;
	} else if(mode == 2) {
		/*initialize lcore 17 for controller as RX for ports 0 and 1*/

		qconf = &lcore_queue_conf[17];
		qconf->rx_port_list[0] = 0;
		qconf->n_rx_port++;
		qconf->rx_port_list[1] = 1;
		qconf->n_rx_port++;
	}

	/* create the mbuf pool */
	nb_mbufs = RTE_MAX(num_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		1);
	printf("RTE_MBUF_DEFAULT_BUF_SIZE:%lu\n", sizeof(struct ruf_flow));
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
		
		/* init port*/
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, portid);
		}

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);

		if (ret < 0){
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%u\n", ret, portid);
		}

		// rte_eth_macaddr_get(portid, &r2c2_ports_eth_addr[portid]);

		/*init one RX queue*/
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, pktmbuf_pool);
		if (ret < 0){
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
		}
		/* init one TX queues on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
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

		rte_eth_promiscuous_enable(portid);

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

	/* initialize flow rates and flow nums */
	// for(int i = 0; i < NUM_FLOW_TYPES; i++) {
	// 	flow_remainder[i] = 0;
	// 	flow_rate[i] = 250000000 / 12000.0 / rte_get_tsc_hz();
	// 	num_flows[i] = 8;
	// }

	if(mode == 1) {
		// allocate all data structure on socket 1(Numa node 1) because
		// NIC is connected to node 1.
	    init_receiver(&receiver, 1);
	    init_sender(&sender, 1);
	    init_pacer(&pacer, &receiver, &sender, 1);
		rte_eal_remote_launch(launch_host_lcore, NULL, 1);
		rte_eal_remote_launch(launch_pacer_lcore, NULL, 3);
		rte_eal_remote_launch(launch_temp_lcore, NULL, 5);
		rte_eal_remote_launch(launch_flowgen_lcore, NULL, 7);
	} else if(mode == 2){
		init_controller(& controller, 1);
		rte_eal_remote_launch(launch_controller_lcore, NULL, 17);
	}

	while(!force_quit){
		// print_stats();
		rte_delay_us_block(100000);
	}

	if(rte_eal_wait_lcore(3) < 0){
		ret = -1;
	}
	if(rte_eal_wait_lcore(5) < 0){
		ret = -1;
	}
	if(rte_eal_wait_lcore(7) < 0){
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
