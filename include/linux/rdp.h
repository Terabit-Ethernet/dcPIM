/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the RDP protocol.
 *
 * Version:	@(#)rdp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_RDP_H
#define _LINUX_RDP_H

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <net/netns/hash.h>
#include <uapi/linux/rdp.h>

static inline struct rdphdr *rdp_hdr(const struct sk_buff *skb)
{
	return (struct rdphdr *)skb_transport_header(skb);
}

static inline struct rdphdr *inner_rdp_hdr(const struct sk_buff *skb)
{
	return (struct rdphdr *)skb_inner_transport_header(skb);
}

#define RDP_HTABLE_SIZE_MIN		(CONFIG_BASE_SMALL ? 128 : 256)

static inline u32 rdp_hashfn(const struct net *net, u32 num, u32 mask)
{
	return (num + net_hash_mix(net)) & mask;
}

struct rdp_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
#define rdp_port_hash		inet.sk.__sk_common.skc_u16hashes[0]
#define rdp_portaddr_hash	inet.sk.__sk_common.skc_u16hashes[1]
#define rdp_portaddr_node	inet.sk.__sk_common.skc_portaddr_node
	int		 pending;	/* Any pending frames ? */
	unsigned int	 corkflag;	/* Cork is required */
	__u8		 encap_type;	/* Is this an Encapsulation socket? */
	unsigned char	 no_check6_tx:1,/* Send zero RDP6 checksums on TX? */
			 no_check6_rx:1,/* Allow zero RDP6 checksums on RX? */
			 encap_enabled:1, /* This socket enabled encap
					   * processing; RDP tunnels and
					   * different encapsulation layer set
					   * this
					   */
			 gro_enabled:1;	/* Can accept GRO packets */
	/*
	 * Following member retains the information to create a RDP header
	 * when the socket is uncorked.
	 */
	__u16		 len;		/* total length of pending frames */
	__u16		 gso_size;
	/*
	 * Fields specific to RDP-Lite.
	 */
	__u16		 pcslen;
	__u16		 pcrlen;
/* indicator bits used by pcflag: */
#define RDPLITE_BIT      0x1  		/* set by rdplite proto init function */
#define RDPLITE_SEND_CC  0x2  		/* set via rdplite setsockopt         */
#define RDPLITE_RECV_CC  0x4		/* set via rdplite setsocktopt        */
	__u8		 pcflag;        /* marks socket as RDP-Lite if > 0    */
	__u8		 unused[3];
	/*
	 * For encapsulation sockets.
	 */
	int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
	int (*encap_err_lookup)(struct sock *sk, struct sk_buff *skb);
	void (*encap_destroy)(struct sock *sk);

	/* GRO functions for RDP socket */
	struct sk_buff *	(*gro_receive)(struct sock *sk,
					       struct list_head *head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sock *sk,
						struct sk_buff *skb,
						int nhoff);

	/* rdp_recvmsg try to use this before splicing sk_receive_queue */
	struct sk_buff_head	reader_queue ____cacheline_aligned_in_smp;

	/* This field is dirtied by rdp_recvmsg() */
	int		forward_deficit;
};

#define RDP_MAX_SEGMENTS	(1 << 6UL)

static inline struct rdp_sock *rdp_sk(const struct sock *sk)
{
	return (struct rdp_sock *)sk;
}

static inline void rdp_set_no_check6_tx(struct sock *sk, bool val)
{
	rdp_sk(sk)->no_check6_tx = val;
}

static inline void rdp_set_no_check6_rx(struct sock *sk, bool val)
{
	rdp_sk(sk)->no_check6_rx = val;
}

static inline bool rdp_get_no_check6_tx(struct sock *sk)
{
	return rdp_sk(sk)->no_check6_tx;
}

static inline bool rdp_get_no_check6_rx(struct sock *sk)
{
	return rdp_sk(sk)->no_check6_rx;
}

static inline void rdp_cmsg_recv(struct msghdr *msg, struct sock *sk,
				 struct sk_buff *skb)
{
	int gso_size;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_RDP_L4) {
		gso_size = skb_shinfo(skb)->gso_size;
		put_cmsg(msg, SOL_RDP, RDP_GRO, sizeof(gso_size), &gso_size);
	}
}

static inline bool rdp_unexpected_gso(struct sock *sk, struct sk_buff *skb)
{
	return !rdp_sk(sk)->gro_enabled && skb_is_gso(skb) &&
	       skb_shinfo(skb)->gso_type & SKB_GSO_RDP_L4;
}

#define rdp_portaddr_for_each_entry(__sk, list) \
	hlist_for_each_entry(__sk, list, __sk_common.skc_portaddr_node)

#define rdp_portaddr_for_each_entry_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, __sk_common.skc_portaddr_node)

#define IS_RDPLITE(__sk) (__sk->sk_protocol == IPPROTO_RDPLITE)

#endif	/* _LINUX_RDP_H */
