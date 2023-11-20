#ifndef _LINUX_DCPIM_H
#define _LINUX_DCPIM_H

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <net/netns/hash.h>
#include "uapi_linux_dcpim.h"
#include "dcpim_ioat.h"

struct dcpim_sock;

#define DCPIM_MATCH_DEFAULT_HOST 256
#define DCPIM_MATCH_DEFAULT_HOST_BITS 8
#define DCPIM_MATCH_DEFAULT_FLOWS 256

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
	DCPIM_WAIT_FIN_TX,
	DCPIM_WAIT_FOR_MATCHING,
	DCPIM_WAIT_FIN_RX,
	DCPIM_WAIT_ACK, /* wait for fin_ack */
	DCPIM_FINISH_TX,
	DCPIM_FINISH_RX,
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
	DCPIM_TOKEN_TIMER_DEFERRED,
	DCPIM_RTX_FLOW_SYNC_DEFERRED,
	DCPIM_MSG_RX_DEFERRED,
	DCPIM_MSG_TX_DEFERRED,
	DCPIM_MSG_RTX_DEFERRED, 
};

enum dcpimcsq_flags {
	// TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	// TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	DCPIMF_TOKEN_TIMER_DEFERRED = (1UL << DCPIM_TOKEN_TIMER_DEFERRED),
	DCPIMF_RTX_FLOW_SYNC_DEFERRED = (1UL << DCPIM_RTX_FLOW_SYNC_DEFERRED),
	DCPIMF_MSG_RX_DEFERRED = (1UL << DCPIM_MSG_RX_DEFERRED),
	DCPIMF_MSG_TX_DEFERRED = (1UL << DCPIM_MSG_TX_DEFERRED),
	DCPIMF_MSG_RTX_DEFERRED = (1UL << DCPIM_MSG_RTX_DEFERRED),
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
	int rtx_messages;
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

	/** @saddr: source IP address
	 */
	uint32_t saddr;

	/** @sport: source port number
	 */
	uint16_t sport;

	/** @daddr: dest IP address
	 */
	uint32_t daddr;

	/** @sk_dport: dest port number
	 */
	uint16_t dport;

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

	/**
	 * @fast_rtx_timer: Fast retransmission timer. Handling the case when packet drops happen, the receiver sends resync packet to sender.
	 */
	struct hrtimer fast_rtx_timer;
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
	 * @table_link: Used to link this object into
	 * &sender.rtx_msg_list (sender) or &receiver.msg_list (receiver).
	 */
	struct list_head table_link;

	/**
	 * @fin_link: Used to link this object into
	 * &sender.fin_backlog (sender).
	 */
	struct list_head fin_link;

	/**
	 * @refcnt: The reference count of dcPIM message. When the count is 0,
	 * the message should be destroyed.
	 */
	refcount_t	refcnt;

	/**
	 * @fin_skb: The skb for holding fin packet.
	 */
	struct sk_buff* fin_skb;

	/**
	 * @last_rtx_time: The last rtx time
	 */
	ktime_t last_rtx_time;
	
	/**
	 * @timeout: Timeout for retransmission in ns.
	 */
	int timeout;

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

struct dcpim_host {
	/* key of the host */
	__be32 src_ip;
	__be32 dst_ip;
	/* lock only protects flow_list, sk, num_flows and hash */
	spinlock_t lock;
	/* active long flow socket list */
	struct list_head flow_list;
	/* idle long flow socket list */
	struct list_head idle_flow_list;
	/* message socket list */
	struct list_head short_flow_list;
	int num_flows;
	int num_long_flows;
	int idle_long_flows;
	int num_short_flows;
	u32 hash;
	/* one member of socket used for sending rts */
	struct sock* sk;
	/* sender only */
	atomic_t total_unsent_bytes;
	/* sender only: number of messages for retransmission */
	atomic_t rtx_msg_size;
	/* receiver only: protected by matched_lock */
	unsigned long next_pacing_rate;
	struct hlist_node hlist;
	/* sender only: for sending RTS */
	struct list_head entry;
	refcount_t refcnt;
	/* grant_index is protected by receiver_lock */
	int grant_index;
	/* grant is protected by receiver_lock */
	struct dcpim_grant* grant;
	/* rts_index is protected by sender_lock */
	int rts_index;	
	/* rts is protected by sender_lock */
	struct dcpim_rts* rts;

};

struct dcpim_epoch {

	uint64_t epoch;
	uint64_t cur_epoch;
	uint32_t round;
	uint32_t cpu;
	__be16 port;
	__be16 port_range;
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
	struct dcpim_host** next_matched_host_arr;
	int cur_matched_flows;
	int next_matched_flows;
	int next_matched_hosts;
	unsigned long rate_per_channel;
	spinlock_t table_lock;
	struct list_head host_list;
	/* it has DCPIM_MATCH_DEFAULT_HOST_BITS slots */
	DECLARE_HASHTABLE(host_table, DCPIM_MATCH_DEFAULT_HOST_BITS);

	struct dcpim_accept *accept_array;
	spinlock_t matched_lock;

	spinlock_t sender_lock;
	struct dcpim_rts *rts_array;
	struct sk_buff** rts_skb_array;
	int rts_size;
	atomic_t unmatched_sent_bytes;
	/* last epoch's unmatched sent bytes for prompt transmission */
	atomic_t last_unmatched_sent_bytes;
	// int rts_size;

	spinlock_t receiver_lock;
	struct dcpim_grant *grants_array;
	struct sk_buff** grant_skb_array;

	int grant_size;
	// int grant_size;
	struct sk_buff** rtx_msg_array;
	struct sk_buff** temp_rtx_msg_array;
	int rtx_msg_size;
	int unmatched_recv_bytes;
	int last_unmatched_recv_bytes;
	int epoch_bytes_per_k;
	int epoch_bytes;
	int matched_bytes;
	struct dcpim_rts *min_rts;
	struct dcpim_grant *min_grant;
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
    struct dcpim_host *host;
	uint64_t epoch;
	uint32_t round;
    int remaining_sz;
	int prompt_remaining_sz;
	int skb_size;
	int rtx_channel;
	int flow_size;
	struct sk_buff **skb_arr;
};
struct dcpim_grant {
    // bool prompt;
    struct dcpim_host *host;
	uint64_t epoch;
	uint32_t round;
    int remaining_sz;
	int prompt_remaining_sz;
	int skb_size;
	int rtx_channel;
	struct sk_buff **skb_arr;
};

struct dcpim_accept {
    // bool prompt;
    struct dcpim_host *host;
    int remaining_sz;
	int rtx_channel;
	int prompt_channel;
	struct dcpim_sock *dsk;
};

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

static inline struct dcpim_syn_ack_hdr *dcpim_syn_ack_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_syn_ack_hdr *)skb_transport_header(skb);
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

static inline struct dcpim_rtx_msg_hdr *dcpim_rtx_msg_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_rtx_msg_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_fin_hdr *dcpim_fin_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_fin_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_fin_ack_hdr *dcpim_fin_ack_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_fin_ack_hdr *)skb_transport_header(skb);
}

static inline struct dcpim_resync_msg_hdr *dcpim_resync_msg_hdr(const struct sk_buff *skb)
{
	return (struct dcpim_resync_msg_hdr *)skb_transport_header(skb);
}

/**
 * dcpim_set_doff() - Fills in the doff TCP header field for a dcPIM packet.
 * @h:   Packet header whose doff field is to be set.
 */
static inline void dcpim_set_doff(struct dcpim_data_hdr *h)
{
        h->common.doff = (sizeof(struct dcpim_data_hdr) - sizeof(struct data_segment)) >> 2;
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

struct dcpim_msgid_entry{
	uint64_t msg_id;
	struct list_head entry;
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
	/**
	 * flow id
	 */
    int core_id;
	/**
	 * Monotonically increment
	 */
	uint64_t short_message_id;
	struct rb_root	out_of_order_queue;
	/* protected by socket user lock; this is for receiver */
    uint32_t num_sacks;
	struct dcpim_sack_block selective_acks[16]; /* The SACKS themselves*/

	/* the socket is in DCPIM_ESTABLISHED before and not received fin or fin_ack */
	bool delay_destruct;
	struct hrtimer rtx_fin_timer;
	int fin_sent_times;
	struct work_struct rtx_fin_work;
	struct ioat_dma_device *dma_device;
    // ktime_t start_time;
	struct list_head match_link;
	/* protectd by dcpim_host lock */
	struct list_head entry;
	bool in_host_table;
	bool is_idle;
	struct dcpim_host* host;

	
    /* sender */
    struct dcpim_sender {
		uint32_t token_seq;
	    /* next sequence from the user; Also equals total bytes written by user. */
	    uint32_t write_seq;
	    /* the next sequence will be sent (at the first time)*/
	    uint32_t snd_nxt;

	    /* the last unack byte.*/
	    uint32_t snd_una;
	    int remaining_pkts_at_sender;
   		uint32_t num_sacks;
		struct dcpim_sack_block selective_acks[16]; /* The SACKS themselves*/
		bool syn_ack_recvd;
		struct hrtimer rtx_flow_sync_timer;
		int sync_sent_times;

		/* Below protected by epoch->sender_lock */
		int next_matched_bytes;
		int grant_index;
		struct dcpim_grant* grant;
		/* Short messages retransmission data structures */
		struct list_head rtx_msg_list;
		/* the number of rtx msg in the list */
		int num_rtx_msgs;
		struct list_head rtx_msg_backlog;
		/* number of message allowed retransmssion */
		atomic_t rtx_msg_size;
		struct work_struct rtx_msg_work;


		struct list_head fin_msg_backlog;
		int inflight_msgs;
		int accmu_rx_msgs;
		int msg_threshold;
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
	    ktime_t last_rtx_time;
		ktime_t latest_token_sent_time;
		uint32_t copied_seq;
	    uint32_t bytes_received;
	    /* current received bytes + 1*/
	    uint32_t rcv_nxt;
	    uint32_t last_ack;
		bool delay_ack;
		struct hrtimer delay_ack_timer;
		struct work_struct delay_ack_work;
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
		int inflight_bytes;
		atomic_t backlog_len;
		struct hrtimer token_pace_timer;
		uint32_t rtx_rcv_nxt;
		/* 0: rtx timer is not set; 1: timer should be set; */
		atomic_t rtx_status;
		/* 0: work is not queued; 1: work is queued */
		atomic_t token_work_status;
		struct work_struct token_work;

		/* I/OAT data structure */
		atomic_t in_flight_copy_bytes;
		struct llist_head	clean_req_list;
		/* Message data structure */
		uint64_t rcv_msg_nxt;
		/* protected by bh_lock_sock */
		struct list_head msg_backlog;
		/* protected by user socket lock */
		struct list_head msg_list;
		/* protected by bh lock */
		struct list_head reordered_msgid_list;
		struct list_head unfinished_list;
		// struct work_struct token_xmit_struct;

		/* protected by epoch->matched_lock */
		unsigned long next_pacing_rate;
		atomic64_t pacing_rate;
		/* proteced by epoch->receiver_lock */
		int rts_index;
		struct dcpim_rts* rts;
		int num_msgs;
		int last_sent_num_msgs;

    } receiver;


	// atomic64_t next_outgoing_id;
};

struct dcpim_request_sock {
	struct inet_request_sock 	req;
};


#define DCPIM_MAX_SEGMENTS	(1 << 6UL)

static inline struct dcpim_sock *dcpim_sk(const struct sock *sk)
{
	return (struct dcpim_sock *)sk;
}
#endif	/* _LINUX_DCPIM_H */
