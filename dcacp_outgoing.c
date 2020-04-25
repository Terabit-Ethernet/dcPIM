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


#define DCACP_DEFERRED_ALL (DCACPF_TSQ_DEFERRED |		\
			  DCACPF_WRITE_TIMER_DEFERRED |	\
			  DCACPF_TOKEN_TIMER_DEFERRED |	\
			  DCACPF_RMEM_CHECK_DEFERRED)

/**
 * dcacp_release_cb - dcacp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void dcacp_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & DCACP_DEFERRED_ALL))
			return;
		nflags = flags & ~DCACP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	// if (flags & TCPF_TSQ_DEFERRED) {
	// 	tcp_tsq_write(sk);
	// 	__sock_put(sk);
	// }
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	/* First check read memory */
	if (flags & DCACPF_RMEM_CHECK_DEFERRED) {
		dcacp_rem_check_handler(sk);
	}

	if (flags & DCACPF_WRITE_TIMER_DEFERRED) {
		dcacp_write_timer_handler(sk);
		// __sock_put(sk);
	}
	if (flags & DCACPF_TOKEN_TIMER_DEFERRED) {
		dcacp_token_timer_defer_handler(sk);
		// __sock_put(sk);
	}
	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(dcacp_release_cb);


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
	// ((struct inet_sock *) sk)->tos = TOS_7;
	// skb->priority = sk.sk_priority = 7;
	// dst_hold(peer->dst);
	// skb_dst_set(skb, peer->dst);

	return skb;
}

struct sk_buff* construct_flow_sync_pkt(struct sock* sk, __u64 message_id, 
	int message_size, __u64 start_time) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_flow_sync_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_flow_sync_hdr *) skb_put(skb, sizeof(struct dcacp_flow_sync_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_flow_sync_hdr));
	dh->type = NOTIFICATION;
	fh->flow_id = message_id;
	fh->flow_size = message_size;
	fh->start_time = start_time;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority,
	 __u32 grant_nxt) {
	// int extra_bytes = 0;
	struct dcacp_sock *dsk = dcacp_sk(sk);
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_token_hdr* fh;
	struct dcacphdr* dh;
	struct dcacp_sack_block_wire *sack;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_token_hdr *) skb_put(skb, sizeof(struct dcacp_token_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_token_hdr));
	dh->type = TOKEN;
	fh->priority = priority;
	fh->rcv_nxt = dsk->receiver.rcv_nxt;
	fh->grant_nxt = grant_nxt;
	fh->num_sacks = 0;
	while(fh->num_sacks < dsk->receiver.num_sacks) {
		sack = (struct dcacp_sack_block_wire*) skb_put(skb, sizeof(struct dcacp_sack_block_wire));
		sack->start_seq = dsk->receiver.selective_acks[fh->num_sacks].start_seq;
		sack->end_seq = dsk->receiver.selective_acks[fh->num_sacks].end_seq;
		fh->num_sacks++;
	}
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_ack_pkt(struct sock* sk, __u64 message_id) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_ack_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_ack_hdr *) skb_put(skb, sizeof(struct dcacp_ack_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_ack_hdr));
	dh->type = ACK;
	fh->message_id = message_id;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_rts_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_rts_hdr *) skb_put(skb, sizeof(struct dcacp_rts_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_rts_hdr));
	dh->type = RTS;
	fh->iter = iter;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool prompt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_grant_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_grant_hdr *) skb_put(skb, sizeof(struct dcacp_grant_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_grant_hdr));
	dh->type = GRANT;
	fh->iter = iter;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->prompt = prompt;
	// extra_bytes = DCACP_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short iter, int epoch) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk);
	struct dcacp_accept_hdr* fh;
	struct dcacphdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcacp_accept_hdr *) skb_put(skb, sizeof(struct dcacp_accept_hdr));
	dh = (struct dcacphdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcacp_accept_hdr));
	dh->type = ACCEPT;
	fh->iter = iter;
	fh->epoch = epoch;
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
int dcacp_xmit_control(struct sk_buff* skb, struct dcacp_peer *peer, struct sock *sk, int dport)
{
	// struct dcacp_hdr *h;
	int result;
	struct dcacphdr* dh;
	struct inet_sock *inet = inet_sk(sk);
	// struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = dcacp_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = inet->inet_dport;
	dh->check = 0;
	inet->tos = TOS_7;
	skb->sk = sk;
	// dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, __sk_dst_get(sk));
	skb_get(skb);
	result = ip_queue_xmit(sk, skb, &inet->cork.fl);
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
					"DCACP control packet after error\n");
	}
	kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 * dcacp_xmit_data() - If an message_out has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent (some may be sent immediately; others may be sent
 * later by the pacer thread).
 * @mesg:       message_out to check for transmittable packets. Must be locked by
 *             caller.
 * @force:     True means send at least one packet, even if the NIC queue
 *             is too long. False means that zero packets may be sent, if
 *             the NIC queue is sufficiently long.
 */
void dcacp_xmit_data(struct sk_buff *skb, struct dcacp_sock* dsk, bool free_token)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb)))
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcacp_xmit_data(skb, dsk, free_token);
	/* change the state of queue and metadata*/

	dcacp_unlink_write_queue(oskb, sk);
	dcacp_rbtree_insert(&sk->tcp_rtx_queue, oskb);
	WRITE_ONCE(dsk->sender.snd_nxt, DCACP_SKB_CB(oskb)->end_seq);
	// sk_wmem_queued_add(sk, -skb->truesize);

	// if (!skb_queue_empty(&sk->sk_write_queue)) {
	// 	struct sk_buff *skb = dcacp_send_head(sk);
	// 	WRITE_ONCE(dsk->sender.snd_nxt, DCACP_SKB_CB(skb)->end_seq);
	// 	__dcacp_xmit_data(skb, dsk);
	// }
	// while (msg->next_packet) {
	// 	// int priority = TOS_1;
	// 	struct sk_buff *skb = msg->next_packet;
	// 	// struct dcacp_sock* dsk = msg->dsk;
	// 	// int offset = homa_data_offset(skb);
		
	// 	// if (homa == NULL) {
	// 	// 	printk(KERN_NOTICE "NULL homa pointer in homa_xmit_"
	// 	// 		"data, state %d, shutdown %d, id %llu, socket %d",
	// 	// 		rpc->state, rpc->hsk->shutdown, rpc->id,
	// 	// 		rpc->hsk->client_port);
	// 	// 	BUG();
	// 	// }
		
	// 	// if (offset >= rpc->msgout.granted)
	// 	// 	break;
		
	// 	// if ((rpc->msgout.length - offset) >= homa->throttle_min_bytes) {
	// 	// 	if (!homa_check_nic_queue(homa, skb, force)) {
	// 	// 		homa_add_to_throttled(rpc);
	// 	// 		break;
	// 	// 	}
	// 	// }
		
	// 	// if (offset < rpc->msgout.unscheduled) {
	// 	// 	priority = homa_unsched_priority(homa, rpc->peer,
	// 	// 			rpc->msgout.length);
	// 	// } else {
	// 	// 	priority = rpc->msgout.sched_priority;
	// 	// }
	// 	msg->next_packet = *dcacp_next_skb(skb);
		
	// 	skb_get(skb);
	// 	__dcacp_xmit_data(skb, dsk);
	// 	force = false;
	// }
}

/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __dcacp_xmit_data(struct sk_buff *skb, struct dcacp_sock* dsk, bool free_token)
{
	int err;
	// struct dcacp_data_hder *h = (struct dcacp_data_hder *)
	// 		skb_transport_header(skb);
	struct sock* sk = (struct sock*)dsk;
	struct inet_sock *inet = inet_sk(sk);
	struct dcacp_data_hdr *h = (struct dcacp_data_hdr *)
				skb_transport_header(skb);
	// struct dcacphdr* dh;

	// dh = dcacp_hdr(skb);

	// dh->source = inet->inet_sport;

	// dh->dest = dport;

	inet->tos = TOS_1;

	// set_priority(skb, rpc->hsk, priority);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, peer->dst);
	skb->sk = sk;
	skb_dst_set(skb, __sk_dst_get(sk));
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct dcacphdr, check);
	h->common.source = inet->inet_sport;
	h->common.dest = inet->inet_dport;
	h->free_token = free_token;
	dcacp_set_doff(h);

	// h->common.seq = htonl(200);
	err = ip_queue_xmit(sk, skb, &inet->cork.fl);
//	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
//			"next_offset %d",
//			h->common.id, ntohl(h->seg.offset), skb->len,
//			rpc->msgout.next_offset);
	if (err) {
		// INC_METRIC(data_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code raises an alert if this
		 * isn't actually the case.
		 */
		if (refcount_read(&skb->users) > 1) {
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"DCACP data packet after error\n");
			kfree_skb(skb);
		}
	}
	// INC_METRIC(packets_sent[0], 1);
}

/* Called with bottom-half processing disabled.
   Called by tcp_write_timer() */
void dcacp_write_timer_handler(struct sock *sk)
{    
	struct dcacp_sock *dsk = dcacp_sk(sk);
	while(!skb_queue_empty(&sk->sk_write_queue)) {
		struct sk_buff *skb = dcacp_send_head(sk);
		if (DCACP_SKB_CB(skb)->end_seq <= dsk->grant_nxt) {
			dcacp_xmit_data(skb, dsk, false);
		} else {
			break;
		}
	}


//         struct inet_connection_sock *icsk = inet_csk(sk);
//         int event;
        
//         if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
//             !icsk->icsk_pending)
//                 goto out;
        
//         if (time_after(icsk->icsk_timeout, jiffies)) {
//                 sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
//                 goto out;
//         }
        
//         tcp_mstamp_refresh(tcp_sk(sk));
//         event = icsk->icsk_pending;
        
//         switch (event) {
//         case ICSK_TIME_REO_TIMEOUT:
//                 tcp_rack_reo_timeout(sk);
//                 break;
//         case ICSK_TIME_LOSS_PROBE:
//                 tcp_send_loss_probe(sk);
//                 break;
//         case ICSK_TIME_RETRANS:
//                 icsk->icsk_pending = 0;
//                 tcp_retransmit_timer(sk);
//                 break;
//         case ICSK_TIME_PROBE0:
//                 icsk->icsk_pending = 0;
//                 tcp_probe_timer(sk);
//                 break;
//         }

// out:
//         sk_mem_reclaim(sk);
}
