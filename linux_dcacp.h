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

#define DCACP_MESSAGE_BUCKETS 1024
/**
 * define DCACP_PEERTAB_BUCKETS - Number of bits in the bucket index for a
 * dcacp_peertab.  Should be large enough to hold an entry for every server
 * in a datacenter without long hash chains.
 */
#define DCACP_PEERTAB_BUCKET_BITS 20
/** define DCACP_PEERTAB_BUCKETS - Number of buckets in a dcacp_peertab. */
#define DCACP_PEERTAB_BUCKETS (1 << DCACP_PEERTAB_BUCKET_BITS)

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
	DCACP_RECEIVER = 1,
	DCACP_SENDER,
	DCACP_LISTEN,
	/* use TCP_CLOSE because of inet_bind use TCP_CLOSE to
	 check whether the port should be assigned TCP CLOSE = 7;*/ 
	// RCP_CLOSE,
};

enum {
	// DCACPF_NEW = (1 << DCACP_NEW),
	DCACPF_SENDER = (1 << DCACP_SENDER),
	DCACPF_RECEIVER = (1 << DCACP_RECEIVER),
	DCACPF_LISTEN	 = (1 << DCACP_LISTEN),
};

enum dcacpcsq_enum {
	// TSQ_THROTTLED, 
	// TSQ_QUEUED, /* this twos are defined in tcp.h*/
	DCACP_TSQ_DEFERRED = 2,	   /* tcp_tasklet_func() found socket was owned */
	DCACP_CLEAN_TIMER_DEFERRED,  /* dcacp_handle_token_pkts() found socket was owned */
	DCACP_TOKEN_TIMER_DEFERRED, /* dcacp_xmit_token() found socket was owned */
	DCACP_RMEM_CHECK_DEFERRED,  /* Read Memory Check once release sock */
	DCACP_RTX_DEFERRED,
};

enum dcacpcsq_flags {
	// TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	// TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	DCACPF_TSQ_DEFERRED		= (1UL << DCACP_TSQ_DEFERRED),
	DCACPF_CLEAN_TIMER_DEFERRED	= (1UL << DCACP_CLEAN_TIMER_DEFERRED),
	DCACPF_TOKEN_TIMER_DEFERRED	= (1UL << DCACP_TOKEN_TIMER_DEFERRED),
	DCACPF_RMEM_CHECK_DEFERRED	= (1UL << DCACP_RMEM_CHECK_DEFERRED),
	DCACPF_RTX_DEFERRED	= (1UL << DCACP_RTX_DEFERRED),
};

struct dcacp_params {
	int clean_match_sock;
	int min_iter;
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
	int num_iters;
	int epoch_size;
	int iter_size;

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

/**
 * struct dcacp_peertab - A hash table that maps from IPV4 addresses
 * to dcacp_peer objects. Entries are gradually added to this table,
 * but they are never removed except when the entire table is deleted.
 * We can't safely delete because results returned by dcacp_peer_find
 * may be retained indefinitely.
 *
 * This table is managed exclusively by dcacp_peertab.c, using RCU to
 * permit efficient lookups.
 */
struct dcacp_peertab {
	/**
	 * @write_lock: Synchronizes addition of new entries; not needed
	 * for lookups (RCU is used instead).
	 */
	struct spinlock write_lock;
	
	/**
	 * @buckets: Pointer to heads of chains of dcacp_peers for each bucket.
	 * Malloc-ed, and must eventually be freed. NULL means this structure
	 * has not been initialized.
	 */
	struct hlist_head *buckets;
};

struct dcacp_peer {
	/** @daddr: IPV4 address for the machine. */
	__be32 addr;
	
	/** @flow: Addressing info needed to send packets. */
	struct flowi flow;
	
	/**
	 * @dst: Used to route packets to this peer; we own a reference
	 * to this, which we must eventually release.
	 */
	struct dst_entry *dst;
	/**
	 * @peertab_links: Links this object into a bucket of its
	 * dcacp_peertab.
	 */
	struct hlist_node peertab_links;
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
	uint32_t iter;
	bool prompt;
	__be32 match_src_addr;
	__be32 match_dst_addr;
	struct list_head rts_q;
	struct list_head grants_q;
	uint32_t grant_size;
	uint32_t rts_size;
	struct dcacp_rts *min_rts;
	struct dcacp_grant *min_grant;
	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	uint64_t start_cycle;
	/* remaining tokens */
	atomic_t remaining_tokens;
	// atomic_t pending_flows;
	struct hrtimer token_xmit_timer;
	struct work_struct token_xmit_struct;
	/* for phost queue */
	struct dcacp_pq flow_q;

	// current epoch and address
	uint64_t cur_epoch;
	uint32_t cur_match_src_addr;
	uint32_t cur_match_dst_addr;

	struct spinlock lock;
	// thread for running Matching logic
	// struct task_struct thread;
	struct hrtimer epoch_timer;
	struct hrtimer sender_iter_timer;
	struct hrtimer receiver_iter_timer;
	struct socket *sock;
	struct workqueue_struct *wq;
	struct work_struct sender_iter_struct;
	struct work_struct receiver_iter_struct;

};

// dcacp matching logic data structure
struct dcacp_rts {
    struct dcacp_peer* peer;
    int remaining_sz;
 	struct list_head list_link;

};
struct dcacp_grant {
    bool prompt;
    struct dcacp_peer* peer;
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

static inline struct dcacphdr *inner_dcacp_hdr(const struct sk_buff *skb)
{
	return (struct dcacphdr *)skb_inner_transport_header(skb);
}

#define DCACP_HTABLE_SIZE_MIN		(CONFIG_BASE_SMALL ? 128 : 256)

static inline u32 dcacp_hashfn(const struct net *net, u32 num, u32 mask)
{
	return (num + net_hash_mix(net)) & mask;
}

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
	/* inet_sock has to be the first member */
	struct inet_sock inet;
#define dcacp_port_hash		inet.sk.__sk_common.skc_u16hashes[0]
#define dcacp_portaddr_hash	inet.sk.__sk_common.skc_u16hashes[1]
#define dcacp_portaddr_node	inet.sk.__sk_common.skc_portaddr_node

	struct inet_bind_bucket	  *icsk_bind_hash;
	struct hlist_node         icsk_listen_portaddr_node;
	struct request_sock_queue icsk_accept_queue;
	struct dcacp_peer* peer;

	int		 pending;	/* Any pending frames ? */
	unsigned int	 corkflag;	/* Cork is required */
	__u8		 encap_type;	/* Is this an Encapsulation socket? */
	unsigned char	 no_check6_tx:1,/* Send zero DCACP6 checksums on TX? */
			 no_check6_rx:1,/* Allow zero DCACP6 checksums on RX? */
			 encap_enabled:1, /* This socket enabled encap
					   * processing; DCACP tunnels and
					   * different encapsulation layer set
					   * this
					   */
			 gro_enabled:1;	/* Can accept GRO packets */
	/*
	 * Following member retains the information to create a DCACP header
	 * when the socket is uncorked.
	 */
	__u16		 len;		/* total length of pending frames */
	__u16		 gso_size;
	/*
	 * Fields specific to DCACP-Lite.
	 */
	__u16		 pcslen;
	__u16		 pcrlen;
/* indicator bits used by pcflag: */
#define DCACPLITE_BIT      0x1  		/* set by dcacplite proto init function */
#define DCACPLITE_SEND_CC  0x2  		/* set via dcacplite setsockopt         */
#define DCACPLITE_RECV_CC  0x4		/* set via dcacplite setsocktopt        */
	__u8		 pcflag;        /* marks socket as DCACP-Lite if > 0    */
	__u8		 unused[3];
	/*
	 * For encapsulation sockets.
	 */
	int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
	int (*encap_err_lookup)(struct sock *sk, struct sk_buff *skb);
	void (*encap_destroy)(struct sock *sk);

	/* GRO functions for DCACP socket */
	struct sk_buff *	(*gro_receive)(struct sock *sk,
					       struct list_head *head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sock *sk,
						struct sk_buff *skb,
						int nhoff);

	/* dcacp_recvmsg try to use this before splicing sk_receive_queue */
	struct sk_buff_head	reader_queue ____cacheline_aligned_in_smp;

	/* This field is dirtied by dcacp_recvmsg() */
	int		forward_deficit;
	
	/**
	 * flow id
	 */
    int core_id;

	struct rb_root	out_of_order_queue;
	/**
	 * size of flow in bytes
	 */
    uint32_t total_length;
	
	uint32_t grant_nxt;
	uint32_t prev_grant_nxt;
	uint32_t new_grant_nxt;
    uint32_t num_sacks;
	struct dcacp_sack_block selective_acks[16]; /* The SACKS themselves*/
    ktime_t start_time;
	struct list_head match_link;
    /* sender */
    struct dcacp_sender {
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
	    uint64_t first_byte_send_time;

	    uint64_t start_time;
	    uint64_t finish_time;
	    double latest_data_pkt_sent_time;
    } sender;
    struct dcacp_receiver {
		/**
		 * size of message in bytes
		 */
		bool is_ready;
		/* short flow and hasn't reached timeout yet */
		bool free_flow;
		bool in_pq;
	    bool flow_sync_received;
	 	bool finished_at_receiver;
		uint32_t copied_seq;
	    uint32_t bytes_received;
	    uint32_t received_count;
	    uint32_t grant_batch;
	    uint32_t max_gso_data;
	    ktime_t last_rtx_time;
	    /* current received bytes + 1*/
	    uint32_t rcv_nxt;
	    // struct dcacp_sack_block duplicate_sack[1]; /* D-SACK block */
	    // uint32_t max_seq_no_recv;
		/** @priority: Priority level to include in future GRANTS. */
		int priority;
	    // int last_token_data_seq_sent;

	    // int token_count;
	    // int token_goal;
	    // int largest_token_seq_received;
	    // int largest_token_data_seq_received;
		/* DCACP metric */
	    // uint64_t latest_token_sent_time;
	    // uint64_t first_byte_receive_time;

		// struct list_head ready_link;

		// link for DCACP matching table
		struct list_head match_link;
		int rmem_exhausted;
		/* short flow waiting timer or long flow waiting timer; after all tokens arer granted */
		struct hrtimer flow_wait_timer;
		bool flow_wait;
		int prev_grant_bytes;
		atomic_t backlog_len;
		atomic_t in_flight_bytes;

		// struct work_struct token_xmit_struct;

    } receiver;


	// atomic64_t next_outgoing_id;

	int unsolved;
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

static inline void dcacp_set_no_check6_tx(struct sock *sk, bool val)
{
	dcacp_sk(sk)->no_check6_tx = val;
}

static inline void dcacp_set_no_check6_rx(struct sock *sk, bool val)
{
	dcacp_sk(sk)->no_check6_rx = val;
}

static inline bool dcacp_get_no_check6_tx(struct sock *sk)
{
	return dcacp_sk(sk)->no_check6_tx;
}

static inline bool dcacp_get_no_check6_rx(struct sock *sk)
{
	return dcacp_sk(sk)->no_check6_rx;
}

static inline void dcacp_cmsg_recv(struct msghdr *msg, struct sock *sk,
				 struct sk_buff *skb)
{
	int gso_size;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_DCACP_L4) {
		gso_size = skb_shinfo(skb)->gso_size;
		put_cmsg(msg, SOL_DCACP, DCACP_GRO, sizeof(gso_size), &gso_size);
	}
}

static inline bool dcacp_unexpected_gso(struct sock *sk, struct sk_buff *skb)
{
	return !dcacp_sk(sk)->gro_enabled && skb_is_gso(skb) &&
	       skb_shinfo(skb)->gso_type & SKB_GSO_DCACP_L4;
}

#define dcacp_portaddr_for_each_entry(__sk, list) \
	hlist_for_each_entry(__sk, list, __sk_common.skc_portaddr_node)

#define dcacp_portaddr_for_each_entry_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, __sk_common.skc_portaddr_node)

// #define IS_DCACPLITE(__sk) (__sk->sk_protocol == IPPROTO_DCACPLITE)

#endif	/* _LINUX_DCACP_H */
