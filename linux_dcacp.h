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

struct message_hslot {
	struct hlist_head	head;
	int			count;
	spinlock_t		lock;

}__attribute__((aligned(2 * sizeof(long))));

struct message_table {
	struct message_hslot* hash;
};

static inline struct dcacphdr *dcacp_hdr(const struct sk_buff *skb)
{
	return (struct dcacphdr *)skb_transport_header(skb);
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
	struct message_table mesg_in_table;

	struct message_table mesg_out_table;
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

#define IS_DCACPLITE(__sk) (__sk->sk_protocol == IPPROTO_DCACPLITE)

#endif	/* _LINUX_DCACP_H */
