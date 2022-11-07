/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCACP protocol.
 *
 * Version:	@(#)dcacp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_DCACP_H
#define _LINUX_DCACP_H

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <net/netns/hash.h>
#include "uapi_linux_dcacp.h"

struct dcacp_sock;

enum {
	/* Core State */
	DCACP_IDLE = 1,
	DCACP_IN_QUEUE,
	DCACP_ACTIVE,
};

enum {
	/* The initial state is TCP_CLOSE */
	/* Sender and receiver state are easier to debug.*/
	DCACP_ESTABLISHED = TCP_ESTABLISHED,
	/* to match TCP_LISTEN */
	DCACP_LISTEN = TCP_LISTEN,
	DCACP_CLOSE = TCP_CLOSE,
	/* use TCP_CLOSE because of inet_bind use TCP_CLOSE to
	 check whether the port should be assigned TCP CLOSE = 7;*/ 
	// RCP_CLOSE,
};

enum {
	// DCACPF_NEW = (1 << DCACP_NEW),
	DCACPF_ESTABLISHED = (1 << DCACP_ESTABLISHED),
	DCACPF_LISTEN	 = (1 << DCACP_LISTEN),
	DCACPF_CLOSE = (1 << DCACP_CLOSE),
};

enum dcacpcsq_enum {
	// TSQ_THROTTLED, 
	// TSQ_QUEUED, /* this twos are defined in tcp.h*/
	DCACP_TSQ_DEFERRED = 2,	   /* tcp_tasklet_func() found socket was owned */
	DCACP_CLEAN_TIMER_DEFERRED,  /* dcacp_handle_token_pkts() found socket was owned */
	DCACP_TOKEN_TIMER_DEFERRED, /* dcacp_xmit_token() found socket was owned */
	DCACP_RMEM_CHECK_DEFERRED,  /* Read Memory Check once release sock */
	DCACP_RTX_DEFERRED,
	DCACP_WAIT_DEFERRED,
};

enum dcacpcsq_flags {
	// TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	// TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	DCACPF_TSQ_DEFERRED		= (1UL << DCACP_TSQ_DEFERRED),
	DCACPF_CLEAN_TIMER_DEFERRED	= (1UL << DCACP_CLEAN_TIMER_DEFERRED),
	DCACPF_TOKEN_TIMER_DEFERRED	= (1UL << DCACP_TOKEN_TIMER_DEFERRED),
	DCACPF_RMEM_CHECK_DEFERRED	= (1UL << DCACP_RMEM_CHECK_DEFERRED),
	DCACPF_RTX_DEFERRED	= (1UL << DCACP_RTX_DEFERRED),
	DCACPF_WAIT_DEFERRED = (1UL << DCACP_WAIT_DEFERRED),
};

struct dcacp_params {
	int clean_match_sock;
	int fct_round;
	int match_socket_port;
	int bandwidth;
	// in microsecond
	int rtt;
	int control_pkt_rtt;
	int control_pkt_bdp;
	int bdp;
	int short_flow_size;
	// int gso_size;
	// matching related parameters
	int alpha;
	int beta;
	int num_rounds;
	int epoch_length;
	int round_length;

	int rmem_default;
	int wmem_default;

	int data_budget;

};

struct dcacp_pq {
	struct list_head list;
	// struct spinlock lock;
	int count;
	bool (*comp)(const struct list_head*, const struct list_head*);
};

// struct message_table {
// 	struct message_hslot* hash;
// };

#define DCACP_MATCH_BUCKETS 1024


struct rcv_core_entry {
	int state;
	int core_id;

	struct spinlock lock;
	struct hrtimer flowlet_done_timer;
	/*receiver side */
	/* remaining tokens */
	atomic_t remaining_tokens;
	// atomic_t pending_flows;
	// struct hrtimer token_xmit_timer;
	// struct work_struct token_xmit_struct;
	/* for phost queue */
	struct dcacp_pq flow_q;
	struct list_head list_link;
	struct work_struct token_xmit_struct;

};

struct rcv_core_table {
	struct spinlock lock;
	// atomic_t remaining_tokens;
	int num_active_cores;
	struct list_head sche_list;
	struct rcv_core_entry table[NR_CPUS];
	struct workqueue_struct *wq;

};

struct xmit_core_entry {
	int core_id;
	struct spinlock lock;
	struct sk_buff_head token_q;
	// struct hrtimer data_xmit_timer;
	struct list_head list_link;
	struct work_struct data_xmit_struct;
};
struct xmit_core_table {
	struct spinlock lock;
	int num_active_cores;
	struct xmit_core_entry table[NR_CPUS];
	struct list_head sche_list;

	struct workqueue_struct *wq;

}; 

struct dcacp_epoch {

	uint64_t epoch;
	uint64_t cur_epoch;
	uint32_t round;
	uint32_t cpu;
	/* in ns */
	int epoch_length;
	/* in ns */
	int round_length;
	int k;
	bool prompt;
	// __be32 match_src_addr;
	// __be32 match_dst_addr;
	struct spinlock lock;

	struct spinlock rts_lock;
	struct list_head rts_q;
	int unmatched_grant_bytes;
	int rts_size;

	struct spinlock grant_lock;
	struct list_head grants_q;
	int unmatched_accept_bytes;
	int grant_size;

	int epoch_bytes_per_k;
	int epoch_bytes;
	int matched_bytes;
	struct dcacp_rts *min_rts;
	struct dcacp_grant *min_grant;
	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	// uint64_t start_cycle;
	/* remaining tokens */
	// atomic_t remaining_tokens;
	// atomic_t pending_flows;
	// struct hrtimer token_xmit_timer;
	// struct work_struct token_xmit_struct;
	/* for phost queue */
	struct dcacp_pq flow_q;

	// current epoch and address
	// uint32_t cur_match_src_addr;
	// uint32_t cur_match_dst_addr;

	// thread for running Matching logic
	// struct task_struct thread;
	struct hrtimer epoch_timer;
	struct hrtimer sender_round_timer;
	struct hrtimer receiver_round_timer;
	struct socket *sock;
	struct workqueue_struct *wq;
	struct work_struct sender_matching_work;
	struct work_struct receiver_matching_work;
	struct work_struct epoch_work;


};

// dcacp matching logic data structure
struct dcacp_rts {
    struct dcacp_sock* dsk;
    int remaining_sz;
 	struct list_head list_link;
};
struct dcacp_grant {
    bool prompt;
    struct dcacp_sock* dsk;
    int remaining_sz;
	struct list_head list_link;
};

struct dcacp_match_entry {
	struct spinlock lock;
	struct dcacp_pq pq;
	struct hlist_node hash_link;
	struct list_head list_link;
	// struct dcacp_peer *peer;
	__be32 dst_addr;
};

struct dcacp_match_slot {
	struct hlist_head head;
	int	count;
	struct spinlock	lock;
};
struct dcacp_match_tab {
	/* hash table: matching ip_address => list pointer*/
	struct dcacp_match_slot *buckets;

	/* the lock is for the hash_list, not for buckets.*/
	struct spinlock lock;
	/* list of current active hash entry for iteration*/
	struct list_head hash_list;
	bool (*comp)(const struct list_head*, const struct list_head*);

	// struct list_node rts_list;
	// struct list_node grant_list;

	// struct list_node *current_entry;
	// struct list_node
};
/* DCACP match table slot */
static inline struct dcacp_match_slot *dcacp_match_bucket(
		struct dcacp_match_tab *table, __be32 addr)
{
	return &table->buckets[addr & (DCACP_MATCH_BUCKETS - 1)];
}


static inline struct dcacphdr *dcacp_hdr(const struct sk_buff *skb)
{
	return (struct dcacphdr *)skb_transport_header(skb);
}

static inline struct dcacp_data_hdr *dcacp_data_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_data_hdr *)skb_transport_header(skb);
}

static inline struct dcacp_ack_hdr *dcacp_ack_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_ack_hdr *)skb_transport_header(skb);
}


static inline struct dcacp_flow_sync_hdr *dcacp_flow_sync_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_flow_sync_hdr *)skb_transport_header(skb);
}

static inline struct dcacp_token_hdr *dcacp_token_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_token_hdr *)skb_transport_header(skb);
}

static inline struct dcacp_rts_hdr *dcacp_rts_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_rts_hdr *)skb_transport_header(skb);
}

static inline struct dcacp_grant_hdr *dcacp_grant_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_grant_hdr *)skb_transport_header(skb);
}

static inline struct dcacp_accept_hdr *dcacp_accept_hdr(const struct sk_buff *skb)
{
	return (struct dcacp_accept_hdr *)skb_transport_header(skb);
}

/**
 * dcacp_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:   Packet header whose doff field is to be set.
 */
static inline void dcacp_set_doff(struct dcacp_data_hdr *h)
{
        h->common.doff = (sizeof(struct dcacp_data_hdr) - sizeof(struct data_segment)) << 2;
}

static inline unsigned int __dcacp_hdrlen(const struct dcacphdr *dh)
{
	return dh->doff * 4;
}

#define DCACP_HTABLE_SIZE_MIN		(CONFIG_BASE_SMALL ? 128 : 256)

/* This defines a selective acknowledgement block. */
struct dcacp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct dcacp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct dcacp_sock {
	/* inet_connection_sock has to be the first member of dcacp_sock */
	struct inet_connection_sock	dccps_inet_connection;
	/* GRO functions for DCACP socket */
	struct sk_buff *	(*gro_receive)(struct sock *sk,
					       struct list_head *head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sock *sk,
						struct sk_buff *skb,
						int nhoff);

	/* dcacp_recvmsg try to use this before splicing sk_receive_queue */
	
	/**
	 * flow id
	 */
    int core_id;

	struct rb_root	out_of_order_queue;
	/**
	 * size of flow in bytes
	 */
    // uint32_t total_length;
	
	/* protected by socket user lock*/
    uint32_t num_sacks;
	struct dcacp_sack_block selective_acks[16]; /* The SACKS themselves*/

    // ktime_t start_time;
	struct list_head match_link;
    /* sender */
    struct dcacp_sender {
		uint32_t token_seq;
	    /* next sequence from the user; Also equals total bytes written by user. */
	    uint32_t write_seq;
	    /* the next sequence will be sent (at the first time)*/
	    uint32_t snd_nxt;

	    /* the last unack byte.*/
	    uint32_t snd_una;

	    // uint32_t total_bytes_sent;
	    // uint32_t bytes_from_user;
	    int remaining_pkts_at_sender;

		/* DCACP metric */
	    // uint64_t first_byte_send_time;
	    // uint64_t start_time;
	    // uint64_t finish_time;
	    // double latest_data_pkt_sent_time;
    } sender;
    struct dcacp_receiver {
		// link for DCACP matching table
		// struct list_head match_link;
	    bool flow_sync_received;
		/* protected by user lock */
	 	bool finished_at_receiver;
		bool flow_finish_wait;
		int rmem_exhausted;
		/* short flow waiting timer or long flow waiting timer; after all tokens arer granted */
		// struct hrtimer flow_wait_timer;
	    ktime_t last_rtx_time;
		uint32_t copied_seq;
	    uint32_t bytes_received;
	    // uint32_t received_count;
	    /* current received bytes + 1*/
	    uint32_t rcv_nxt;
	    uint32_t last_ack;
	    // struct dcacp_sack_block duplicate_sack[1]; /* D-SACK block */
	    // uint32_t max_seq_no_recv;
		/** @priority: Priority level to include in future GRANTS. */
		int priority;
		/* DCACP metric */
	    // uint64_t latest_token_sent_time;
	    // uint64_t first_byte_receive_time;
		// struct list_head ready_link;
		/* protected by entry lock */
		bool in_pq;
		uint32_t prev_token_nxt;
		uint32_t token_nxt;
		uint32_t max_congestion_win;
	    uint32_t token_batch;
		atomic_t backlog_len;
		atomic_t inflight_bytes;
		struct hrtimer token_pace_timer;
		atomic_t matched_bw;
		// struct work_struct token_xmit_struct;
    } receiver;


	// atomic64_t next_outgoing_id;
};

struct dcacp_request_sock {
	struct inet_request_sock 	req;
	// const struct tcp_request_sock_ops *af_specific;
	// u64				snt_synack;  first SYNACK sent time 
	// bool				tfo_listener;
	// bool				is_mptcp;
	// u32				txhash;
	// u32				rcv_isn;
	// u32				snt_isn;
	// u32				ts_off;
	// u32				last_oow_ack_time;  last SYNACK 
	// u32				rcv_nxt; /* the ack # by SYNACK. For
	// 					  * FastOpen it's the seq#
	// 					  * after data-in-SYN.
	// 					  */
};


#define DCACP_MAX_SEGMENTS	(1 << 6UL)

static inline struct dcacp_sock *dcacp_sk(const struct sock *sk)
{
	return (struct dcacp_sock *)sk;
}
#endif	/* _LINUX_DCACP_H */
