/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCPIM protocol.
 *
 * Version:	@(#)dcpim.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_DCPIM_H
#define _LINUX_DCPIM_H

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <net/netns/hash.h>
#include "uapi_linux_dcpim.h"

struct dcpim_sock;

enum {
	/* Core State */
	DCPIM_IDLE = 1,
	DCPIM_IN_QUEUE,
	DCPIM_ACTIVE,
};

enum {
	/* The initial state is TCP_CLOSE */
	/* Sender and receiver state are easier to debug.*/
	DCPIM_ESTABLISHED = TCP_ESTABLISHED,
	/* to match TCP_LISTEN */
	DCPIM_LISTEN = TCP_LISTEN,
	DCPIM_CLOSE = TCP_CLOSE,
	/* use TCP_CLOSE because of inet_bind use TCP_CLOSE to
	 check whether the port should be assigned TCP CLOSE = 7;*/ 
	// RCP_CLOSE,
};

/* dcPIM short message state */
enum {
	DCPIM_INIT = 0,
	DCPIM_WAIT_FOR_FIN,
	DCPIM_ENTER_MATCH,
	DCPIM_FINISH,
};

enum {
	// DCPIMF_NEW = (1 << DCPIM_NEW),
	DCPIMF_ESTABLISHED = (1 << DCPIM_ESTABLISHED),
	DCPIMF_LISTEN	 = (1 << DCPIM_LISTEN),
	DCPIMF_CLOSE = (1 << DCPIM_CLOSE),
};

enum dcpimcsq_enum {
	// TSQ_THROTTLED, 
	// TSQ_QUEUED, /* this twos are defined in tcp.h*/
	DCPIM_TSQ_DEFERRED = 2,	   /* tcp_tasklet_func() found socket was owned */
	DCPIM_CLEAN_TIMER_DEFERRED,  /* dcpim_handle_token_pkts() found socket was owned */
	DCPIM_TOKEN_TIMER_DEFERRED, /* dcpim_xmit_token() found socket was owned */
	DCPIM_RMEM_CHECK_DEFERRED,  /* Read Memory Check once release sock */
	DCPIM_RTX_DEFERRED,
	DCPIM_WAIT_DEFERRED,
};

enum dcpimcsq_flags {
	// TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	// TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	DCPIMF_TSQ_DEFERRED		= (1UL << DCPIM_TSQ_DEFERRED),
	DCPIMF_CLEAN_TIMER_DEFERRED	= (1UL << DCPIM_CLEAN_TIMER_DEFERRED),
	DCPIMF_TOKEN_TIMER_DEFERRED	= (1UL << DCPIM_TOKEN_TIMER_DEFERRED),
	DCPIMF_RMEM_CHECK_DEFERRED	= (1UL << DCPIM_RMEM_CHECK_DEFERRED),
	DCPIMF_RTX_DEFERRED	= (1UL << DCPIM_RTX_DEFERRED),
	DCPIMF_WAIT_DEFERRED = (1UL << DCPIM_WAIT_DEFERRED),
};

struct dcpim_params {
	int clean_match_sock;
	int fct_round;
	int match_socket_port;
	unsigned long bandwidth;
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

/* dcPIM message for holding data strucutre of short flows */
struct dcpim_message {
	// /**
	//  * @dsk: dcPIM socket that creates this message
	//  */
	// struct dcpim_sock *dsk;
	
	/** @dsk: dcPIM socket corresponds to the socket
	 */
	struct dcpim_sock *dsk;

	/** @state: dcPIM message state
	 */
	 int state;
	
	/** @id: ID of the message.
	 */
	uint64_t id;
	
	/** @lock: Used to synchronize modifications to this structure;
	 */
	spinlock_t lock;

	// /** @saddr: source IP address
	//  */
	// uint32_t saddr;

	// /** @sport: source port number
	//  */
	// uint16_t sport;

	// /** @daddr: dest IP address
	//  */
	// uint32_t daddr;

	// /** @sk_dport: dest port number
	//  */
	// uint16_t dport;

	/**
	 * @pkt_queue: DATA packets received for this message so far. The list
	 * is sorted in order of offset (head is lowest offset), but
	 * packets can be received out of order, so there may be times
	 * when there are holes in the list. Packets in this list contain
	 * exactly one data_segment.
	 */
	struct sk_buff_head pkt_queue;

	/**
	 * @total_len: Size of the entire message, in bytes. A value
	 * less than 0 means this structure is uninitialized and therefore
	 * not in use.
	 */
	uint32_t total_len;
	
	/**
	 * @remaining_len: Amount of data for this message that has
	 * not yet been received; will determine the message's priority.
	 */
	uint32_t remaining_len;
	
	/**
	 * @rtx_timer: Retransmission timer. Handling the case when packet drops happen and
	 * sender needs to perform retransmission.
	 */
	struct hrtimer rtx_timer;

	/* Belows are attributes not protected by the lock */
	
	/**
	 * @hash_link: Used to link this object into a hash bucket for
	 * dcpim message hash table.
	 */
	struct hlist_node hash_link;

	/** @hash: hash of five tuples + id.
	 */
	uint32_t hash;

	/**
	 * @match_link: Used to link this object into
	 * &dcpim_match_list (sender) or &dcpim_socket.message_list (receiver).
	 */
	struct list_head table_link;

	/**
	 * @refcnt: The reference count of dcPIM message. When the count is 0,
	 * the message should be destroyed.
	 */
	refcount_t	refcnt;

	/**
	 * @flow_sync_skb: The skb for holding flow_sync packet.
	 */
	struct sk_buff* flow_sync_skb;

};

struct dcpim_pq {
	struct list_head list;
	// struct spinlock lock;
	int count;
	bool (*comp)(const struct list_head*, const struct list_head*);
};

// struct message_table {
// 	struct message_hslot* hash;
// };

#define DCPIM_BUCKETS 1024

struct dcpim_message_bucket {
	/**
	 * @lock: for adding/removing new message
	 */
	spinlock_t lock;
	
	/** @bucket: list of messages that hash to this slot. */
	struct hlist_head slot;
};


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
	struct dcpim_pq flow_q;
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

struct dcpim_flow {
	/* the sock of the corresponding flow */
	struct sock* sock;
	bool matched;
	int cur_matched_bytes;
	int next_matched_bytes;
	struct list_head entry;
};

// struct dcpim_matched_flow {
// 	/* the sock of the corresponding flow */
// 	struct sock* sock;
// 	int matched_bytes;
// 	struct net *net;
//  	/* ip hdr */
// 	__be32 saddr;
// 	__be32 daddr;
// 	/* tcp port number */
// 	__be16 sport;
// 	__be16 dport;
// 	int dif;
// 	int sdif;
// };

struct dcpim_epoch {

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
	int max_array_size;
	// __be32 match_src_addr;
	// __be32 match_dst_addr;
	struct dcpim_sock** cur_matched_arr;
	struct dcpim_sock** next_matched_arr;
	int cur_matched_flows;
	int next_matched_flows;
	spinlock_t list_lock;
	spinlock_t matched_lock;

	spinlock_t receiver_lock;
	struct dcpim_rts *rts_array;
	struct sk_buff** rts_skb_array;
	atomic_t unmatched_recv_bytes;
	atomic_t rts_size;
	// int rts_size;

	spinlock_t sender_lock;
	struct list_head flow_list;
	struct dcpim_grant *grants_array;
	struct sk_buff** grant_skb_array;

	int unmatched_sent_bytes;
	atomic_t grant_size;
	// int grant_size;

	int epoch_bytes_per_k;
	int epoch_bytes;
	int matched_bytes;
	struct dcpim_rts *min_rts;
	struct dcpim_grant *min_grant;
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
	// struct dcpim_pq flow_q;

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

// dcpim matching logic data structure
struct dcpim_rts {
    // struct dcpim_sock *dsk;
	uint64_t epoch;
	uint32_t round;
    int remaining_sz;
	struct sk_buff *skb;
 	// struct list_head entry;
	// struct llist_node lentry;
};
struct dcpim_grant {
    // bool prompt;
    // struct dcpim_sock *dsk;
	uint64_t epoch;
	uint32_t round;
    int remaining_sz;
	struct sk_buff *skb;
	/* ether hdr */
	// unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	// unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	/* ip hdr */
	__be32 saddr;
	__be32 daddr;
	/* tcp port number */
	__be16 sport;
	__be16 dport;
	// struct list_head entry;
	// struct llist_node lentry;
};

// struct dcpim_match_entry {
// 	struct spinlock lock;
// 	struct dcpim_pq pq;
// 	struct hlist_node hash_link;
// 	struct list_head list_link;
// 	// struct dcpim_peer *peer;
// 	__be32 dst_addr;
// };

// struct dcpim_match_slot {
// 	struct hlist_head head;
// 	int	count;
// 	struct spinlock	lock;
// };
// struct dcpim_match_tab {
// 	/* hash table: matching ip_address => list pointer*/
// 	struct dcpim_match_slot *buckets;

// 	/* the lock is for the hash_list, not for buckets.*/
// 	struct spinlock lock;
// 	/* list of current active hash entry for iteration*/
// 	struct list_head hash_list;
// 	bool (*comp)(const struct list_head*, const struct list_head*);

// 	// struct list_node rts_list;
// 	// struct list_node grant_list;

// 	// struct list_node *current_entry;
// 	// struct list_node
// };
// /* DCPIM match table slot */
// static inline struct dcpim_match_slot *dcpim_match_bucket(
// 		struct dcpim_match_tab *table, __be32 addr)
// {
// 	return &table->buckets[addr & (DCPIM_BUCKETS - 1)];
// }


static inline struct dcpimhdr *dcpim_hdr(const struct sk_buff *skb)
{
	return (struct dcpimhdr *)skb_transport_header(skb);
}

static inline struct dcpim_data_hdr *dcpim_data_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_data_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_ack_hdr *dcpim_ack_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_ack_hdr *)skb_transport_header(skb);
}


static inline struct dcpim_flow_sync_hdr *dcpim_flow_sync_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_flow_sync_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_token_hdr *dcpim_token_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_token_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_rts_hdr *dcpim_rts_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_rts_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_grant_hdr *dcpim_grant_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_grant_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_accept_hdr *dcpim_accept_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_accept_hdr *)skb_transport_header(skb);
}

/**
 * dcpim_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:   Packet header whose doff field is to be set.
 */
static inline void dcpim_set_doff(struct dcpim_data_hdr *h)
{
        h->common.doff = (sizeof(struct dcpim_data_hdr) - sizeof(struct data_segment)) << 2;
}

static inline unsigned int __dcpim_hdrlen(const struct dcpimhdr *dh)
{
	return dh->doff * 4;
}

#define DCPIM_HTABLE_SIZE_MIN		(CONFIG_BASE_SMALL ? 128 : 256)

/* This defines a selective acknowledgement block. */
struct dcpim_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct dcpim_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct dcpim_sock {
	/* inet_connection_sock has to be the first member of dcpim_sock */
	struct inet_connection_sock	dccps_inet_connection;
	/* GRO functions for DCPIM socket */
	struct sk_buff *	(*gro_receive)(struct sock *sk,
					       struct list_head *head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sock *sk,
						struct sk_buff *skb,
						int nhoff);

	/* dcpim_recvmsg try to use this before splicing sk_receive_queue */
	
	/**
	 * flow id
	 */
    int core_id;
	/**
	 * Monotonically increment
	 */
	uint64_t short_message_id;
	struct rb_root	out_of_order_queue;
	/**
	 * size of flow in bytes
	 */
    // uint32_t total_length;
	
	/* protected by socket user lock; this is for receiver */
    uint32_t num_sacks;
	struct dcpim_sack_block selective_acks[16]; /* The SACKS themselves*/

    // ktime_t start_time;
	struct list_head match_link;
    /* sender */
    struct dcpim_sender {
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
   		uint32_t num_sacks;
		struct dcpim_sack_block selective_acks[16]; /* The SACKS themselves*/
		/* DCPIM metric */
	    // uint64_t first_byte_send_time;
	    // uint64_t start_time;
	    // uint64_t finish_time;
	    // double latest_data_pkt_sent_time;
    } sender;
    struct dcpim_receiver {
		// link for DCPIM matching table
		// struct list_head match_link;
	    bool flow_sync_received;
		/* protected by user lock */
	 	bool finished_at_receiver;
		bool flow_finish_wait;
		int rmem_exhausted;
		/* short flow waiting timer or long flow waiting timer; after all tokens arer granted */
		// struct hrtimer flow_wait_timer;
	    ktime_t last_rtx_time;
		ktime_t latest_token_sent_time;

		uint32_t copied_seq;
	    uint32_t bytes_received;
	    // uint32_t received_count;
	    /* current received bytes + 1*/
	    uint32_t rcv_nxt;
	    uint32_t last_ack;
	    // struct dcpim_sack_block duplicate_sack[1]; /* D-SACK block */
	    // uint32_t max_seq_no_recv;
		/** @priority: Priority level to include in future GRANTS. */
		int priority;
		/* DCPIM metric */
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
		// atomic_t matched_bw;
		unsigned long next_pacing_rate;
		/* protected by bh_lock_sock */
		struct list_head message_backlog;
		/* protected by user socket lock */
		struct list_head message_list;
		// struct work_struct token_xmit_struct;
    } receiver;


	// atomic64_t next_outgoing_id;
};

struct dcpim_request_sock {
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


#define DCPIM_MAX_SEGMENTS	(1 << 6UL)

static inline struct dcpim_sock *dcpim_sk(const struct sock *sk)
{
	return (struct dcpim_sock *)sk;
}
#endif	/* _LINUX_DCPIM_H */
