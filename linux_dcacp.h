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


struct message_hslot {
	struct hlist_head	head;
	int			count;
	spinlock_t		lock;

}__attribute__((aligned(2 * sizeof(long))));

// struct message_table {
// 	struct message_hslot* hash;
// };

struct dcacp_message_in {
    __u64 id;

    /* message out id from the sender; */
    __u64 message_out_id;
	/**
	 * @packets: DATA packets received for this message so far. The list
	 * is sorted in order of offset (head is lowest offset), but
	 * packets can be received out of order, so there may be times
	 * when there are holes in the list. Packets in this list contain
	 * exactly one data_segment.
	 */
	struct sk_buff_head packets;
	/**
	 * @num_skbs:  Total number of buffers in @packets. Will be 0 if
	 * @total_length is less than 0.
	 */
	int num_skbs;

	/** @lock: Used to synchronize modifications to this structure;
	 * points to the lock in hsk->client_rpc_buckets or
	 * hsk->server_rpc_buckets.
	 */
	struct spinlock lock;

	/**
 	 * retransmission list of tokens
	 */
	struct list_head rtx_list;

	/* DCACP socket */
	struct dcacp_sock* dsk;

	__u32 dport;
	/**
	 * size of message in bytes
	 */
    uint64_t total_length;

    struct dcacp_peer* peer;
    uint32_t received_bytes;
    uint32_t received_count;
    uint32_t recv_till;
    // uint32_t max_seq_no_recv;
	/** @priority: Priority level to include in future GRANTS. */
	int priority;

    bool flow_sync_received;
 	bool finished_at_receiver;
    int last_token_data_seq_sent;

    int token_count;
    int token_goal;
    int largest_token_seq_received;
    int largest_token_data_seq_received;
	/* DCACP metric */
    uint64_t latest_token_sent_time;
    double first_byte_receive_time;

	struct hlist_node sk_table_link;
	struct list_head ready_link;

};

struct dcacp_message_out {
    __u64 id;
	/**
	 * @packets: singly-linked list of all packets in message, linked
	 * using dcacp_next_skb. The list is in order of offset in the message
	 * (offset 0 first); each sk_buff can potentially contain multiple
	 * data_segments, which will be split into separate packets by GSO.
	 */
	struct sk_buff *packets;
	
	/**
	 * @num_skbs:  Total number of buffers in @packets. Will be 0 if
	 * @length is less than 0.
	 */
	int num_skbs;

	
	/** @lock: Used to synchronize modifications to this structure;
	 * points to the lock in hsk->client_rpc_buckets or
	 * hsk->server_rpc_buckets.
	 */
	struct spinlock lock;

	/* DCACP socket */
	struct dcacp_sock* dsk;

	__u32 dport;

	/**
	 * @next_packet: Pointer within @token of the next packet to transmit.
	 * 
	 * All packets before this one have already been sent. NULL means
	 * entire message has been sent.
	 */
	struct sk_buff *next_packet;
	/**
	 * size of message in bytes
	 */
    uint64_t total_length;

    struct dcacp_peer* peer;

    uint32_t total_bytes_sent;

	/** @priority: Priority level to include in future GRANTS. */
	int priority;

    int remaining_pkts_at_sender;

	/* DCACP metric */
    uint64_t first_byte_send_time;

    uint64_t start_time;
    uint64_t finish_time;
    double latest_data_pkt_sent_time;

	struct hlist_node sk_table_link;

};

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

/**
 * dcacp_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:   Packet header whose doff field is to be set.
 */
static inline void dcacp_set_doff(struct dcacp_data_hdr *h)
{
        h->common.doff = (sizeof(struct dcacp_data_hdr)
                        - sizeof(struct data_segment)) << 2;
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

struct dcacp_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
#define dcacp_port_hash		inet.sk.__sk_common.skc_u16hashes[0]
#define dcacp_portaddr_hash	inet.sk.__sk_common.skc_u16hashes[1]
#define dcacp_portaddr_node	inet.sk.__sk_common.skc_portaddr_node
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

	/* DCACP message hash table */
	struct message_hslot* mesg_in_table;

	struct message_hslot* mesg_out_table;

	atomic64_t next_outgoing_id;

	struct spinlock ready_queue_lock;

	struct list_head ready_message_queue;
};

/* DCACP message hslot handling function */
static inline struct message_hslot *dcacp_message_out_bucket(
		struct dcacp_sock *dsk, __u64 id)
{
	 // Each client allocates message ids sequentially, so they will
	 // * naturally distribute themselves across the hash space.
	 // * Thus we can use the id directly as hash.
	 
	return &dsk->mesg_out_table[id & (DCACP_MESSAGE_BUCKETS - 1)];
}

static inline struct dcacp_message_out * get_dcacp_message_out(struct dcacp_sock *dsk, __u64 id) {
	struct dcacp_message_out *mesg;
	struct message_hslot *slot;
	slot = dcacp_message_out_bucket(dsk, id);
	// spin_lock_bh(&slot->lock);
	hlist_for_each_entry(mesg, &slot->head, sk_table_link) {
		if(mesg->id == id) {
			// spin_unlock_bh(&slot->lock);
			return mesg;
		}
	}
	// spin_unlock_bh(&slot->lock);
	return NULL;
}

static inline void add_dcacp_message_out(struct dcacp_sock *dsk, struct dcacp_message_out *mesg) {
	struct message_hslot *slot;
	slot = dcacp_message_out_bucket(dsk, mesg->id);
	// spin_lock_bh(&slot->lock);
	hlist_add_head(&mesg->sk_table_link, &slot->head);
	slot->count++;
	// spin_unlock_bh(&slot->lock);
}

static inline void delete_dcacp_message_out(struct dcacp_sock *dsk, struct dcacp_message_out *mesg) {
	struct message_hslot *slot;
	slot = dcacp_message_out_bucket(dsk, mesg->id);
	// spin_lock_bh(&slot->lock);
	hlist_del(&mesg->sk_table_link);
	slot->count--;
	// spin_unlock_bh(&slot->lock);
}

static inline struct message_hslot *dcacp_message_in_bucket(
		struct dcacp_sock *dsk, __u64 id)
{
	 // Each client allocates message ids sequentially, so they will
	 // * naturally distribute themselves across the hash space.
	 // * Thus we can use the id directly as hash.
	 
	return &dsk->mesg_in_table[id & (DCACP_MESSAGE_BUCKETS - 1)];
}

static inline struct dcacp_message_in * get_dcacp_message_in(struct dcacp_sock *dsk, 
 __be32 saddr, __u16 sport, __u64 id) {
	struct dcacp_message_in *mesg;
	struct message_hslot *slot;
	slot = dcacp_message_in_bucket(dsk, id);
	// spin_lock_bh(&slot->lock);
	hlist_for_each_entry(mesg, &slot->head, sk_table_link) {
		if((mesg->id == id) && (mesg->dport == sport) && (mesg->peer->addr == saddr)) {
			// spin_unlock_bh(&slot->lock);
			return mesg;
		}
	}
	// spin_unlock_bh(&slot->lock);
	return NULL;
}

static inline void add_dcacp_message_in(struct dcacp_sock *dsk, struct dcacp_message_in *mesg) {
	struct message_hslot *slot;
	slot = dcacp_message_in_bucket(dsk, mesg->id);
	// spin_lock_bh(&slot->lock);
	hlist_add_head(&mesg->sk_table_link, &slot->head);
	slot->count++;
	// spin_unlock_bh(&slot->lock);
}

static inline void delete_dcacp_message_in(struct dcacp_sock *dsk, struct dcacp_message_in *mesg) {
	struct message_hslot *slot;
	slot = dcacp_message_in_bucket(dsk, mesg->id);
	// spin_lock_bh(&slot->lock);
	hlist_del(&mesg->sk_table_link);
	slot->count--;
	// spin_unlock_bh(&slot->lock);
}

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

#define IS_DCACPLITE(__sk) (__sk->sk_protocol == IPPROTO_DCACPLITE)

#endif	/* _LINUX_DCACP_H */
