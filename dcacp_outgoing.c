// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		DATACENTER ADMISSION CONTROL PROTOCOL(DCACP) 
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 */

#define pr_fmt(fmt) "DCACP: " fmt

#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "dcacp_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_dcacp.h"
 #include "net_dcacp.h"
// #include "net_dcacplite.h"
#include "uapi_linux_dcacp.h"
#include "dcacp_impl.h"




struct sk_buff* __construct_control_skb(struct sock* sk) {
	struct sk_buff *skb = alloc_skb(sizeof(struct iphdr) + DCACP_HEADER_MAX_SIZE, 
		GFP_KERNEL);
	skb->sk = sk;
	// int extra_bytes;
	if (unlikely(!skb))
		return NULL;
	skb_reserve(skb, sizeof(struct iphdr));
	skb_reset_transport_header(skb);

	// h = (struct dcacp_hdr *) skb_put(skb, length);
	// memcpy(h, contents, length);
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	// skb->priority = sk.sk_priority = 7;
	// dst_hold(peer->dst);
	// skb_dst_set(skb, peer->dst);

	return skb;
}

struct sk_buff* construct_flow_sync_pkt(struct dcacp_sock* d_sk, __u64 message_id, 
	int message_size, __u64 start_time) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb((struct sock*)d_sk);
	struct dcacp_flow_sync_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_flow_sync_hdr *) skb_put(skb, sizeof(struct dcacp_flow_sync_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = sizeof(struct dcacp_flow_sync_hdr);
	dh->type = NOTIFICATION;
	fh->message_id = message_id;
	fh->message_size = message_size;
	fh->start_time = start_time;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_token_pkt(struct dcacp_sock* d_sk, bool free_token, unsigned short priority,
	 __u64 message_id, __u32 seq_no, __u32 data_seq_no, __u32 remaining_size) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb((struct sock*)d_sk);
	struct dcacp_token_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_token_hdr *) skb_put(skb, sizeof(struct dcacp_token_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = sizeof(struct dcacp_token_hdr);
	dh->type = TOKEN;
	fh->free_token = free_token;
	fh->priority = priority;
	fh->message_id = message_id;
	fh->seq_no = seq_no;
	fh->data_seq_no = data_seq_no;
	fh->remaining_size = remaining_size;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_ack_pkt(struct dcacp_sock* d_sk, __u64 message_id) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb((struct sock*)d_sk);
	struct dcacp_ack_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_ack_hdr *) skb_put(skb, sizeof(struct dcacp_ack_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = sizeof(struct dcacp_ack_hdr);
	dh->type = ACK;
	fh->message_id = message_id;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

/**
 * dcacp_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as NOTIFICATION.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of common_header except type, will be set from this.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
// int dcacp_xmit_control(enum dcacp_packet_type type, struct sk_buff *skb,
// 	size_t len, struct flowi4 *fl4)
// {
// 	struct sock *sk = skb->sk;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct dcacp_header *dh = dcacp_hdr(skb);
// 	dh->type = type;
// 	dh->source = inet->inet_sport;
// 	dh->dest = fl4->fl4_dport;
// 	uh->check = 0;
// 	uh->len = htons(len);

// 	// if (rpc->is_client) {
// 	// 	h->sport = htons(rpc->hsk->client_port);
// 	// } else {
// 	// 	h->sport = htons(rpc->hsk->server_port);
// 	// }
// 	h->dport = htons(rpc->dport);
// 	h->id = rpc->id;
// 	return __dcacp_xmit_control(contents, length, rpc->peer, rpc->hsk);
// }

/**
 * __dcacp_xmit_control() - Lower-level version of dcacp_xmit_control: sends
 * a control packet.
 * @contents:  Address of buffer containing the contents of the packet.
 *             The caller must have filled in all of the information,
 *             including the common header.
 * @length:    Length of @contents.
 * @peer:      Destination to which the packet will be sent.
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int dcacp_xmit_control(struct sk_buff* skb, struct dcacp_peer *peer, struct dcacp_sock *dcacp_sk, int dport)
{
	// struct dcacp_hdr *h;
	int result;
	struct dcacphdr* dh;
	struct sock* sk = (struct sock*)dcacp_sk;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = dcacp_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = dport;
	dh->check = 0;
	sk->sk_priority = skb->priority = 7;
	dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(peer->dst);
	skb_dst_set(skb, peer->dst);
	skb_get(skb);
	result = ip_queue_xmit(sk, skb, &peer->flow);
	if (unlikely(result != 0)) {
		// INC_METRIC(control_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		if (refcount_read(&skb->users) > 1)
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"Homa control packet after error\n");
	}
	kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}
