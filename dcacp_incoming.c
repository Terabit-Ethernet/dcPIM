
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
// #include "dcacp_hashtables.h"
// static inline struct sock *__dcacp4_lib_lookup_skb(struct sk_buff *skb,
// 						 __be16 sport, __be16 dport,
// 						 struct udp_table *dcacptable)
// {
// 	const struct iphdr *iph = ip_hdr(skb);

// 	return __dcacp4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
// 				 iph->daddr, dport, inet_iif(skb),
// 				 inet_sdif(skb), dcacptable, skb);
// }

/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
static void dcacp_rcv_nxt_update(struct dcacp_sock *dsk, u32 seq)
{
	struct sock *sk = (struct sock*) dsk;
	u32 delta = seq - dsk->receiver.rcv_nxt;
	dsk->receiver.bytes_received += delta;
	WRITE_ONCE(dsk->receiver.rcv_nxt, seq);
	if(!dsk->receiver.finished_at_receiver && dsk->receiver.rcv_nxt == dsk->total_length) {
		struct inet_sock *inet = inet_sk(sk);
		dsk->receiver.finished_at_receiver = true;
		dcacp_xmit_control(construct_ack_pkt(sk, 0), dsk->peer, sk, inet->inet_dport); 
	}
}

static void dcacp_drop(struct sock *sk, struct sk_buff *skb)
{
        sk_drops_add(sk, skb);
        // __kfree_skb(skb);
}

static void dcacp_v4_fill_cb(struct sk_buff *skb, const struct iphdr *iph,
                           const struct dcacp_data_hdr *dh)
{
        /* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
         * barrier() makes sure compiler wont play fool^Waliasing games.
         */
        memmove(&DCACP_SKB_CB(skb)->header.h4, IPCB(skb),
                sizeof(struct inet_skb_parm));
        barrier();
        DCACP_SKB_CB(skb)->seq = ntohl(dh->seg.offset);
        DCACP_SKB_CB(skb)->end_seq = (DCACP_SKB_CB(skb)->seq + ntohl(dh->seg.segment_length));
        // TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
        // TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
        // TCP_SKB_CB(skb)->tcp_tw_isn = 0;
        // TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
        // TCP_SKB_CB(skb)->sacked  = 0;
        // TCP_SKB_CB(skb)->has_rxtstamp =
        //                 skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}

static int dcacp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct dcacp_sock *dsk = dcacp_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	/* Disable header prediction. */
	// tp->pred_flags = 0;
	// inet_csk_schedule_ack(sk);

	// tp->rcv_ooopack += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	seq = DCACP_SKB_CB(skb)->seq;
	end_seq = DCACP_SKB_CB(skb)->end_seq;

	p = &dsk->out_of_order_queue.rb_node;
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
		/* Initial out of order segment, build 1 SACK. */
		// if (tcp_is_sack(tp)) {
		// 	tp->rx_opt.num_sacks = 1;
		// 	tp->selective_acks[0].start_seq = seq;
		// 	tp->selective_acks[0].end_seq = end_seq;
		// }
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
		// tp->ooo_last_skb = skb;
		goto end;
	}

	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
// 	if (tcp_ooo_try_coalesce(sk, tp->ooo_last_skb,
// 				 skb, &fragstolen)) {
// coalesce_done:
// 		tcp_grow_window(sk, skb);
// 		kfree_skb_partial(skb, fragstolen);
// 		skb = NULL;
// 		goto add_sack;
// 	}
// 	 Can avoid an rbtree lookup if we are adding skb after ooo_last_skb 
// 	if (!before(seq, TCP_SKB_CB(tp->ooo_last_skb)->end_seq)) {
// 		parent = &tp->ooo_last_skb->rbnode;
// 		p = &parent->rb_right;
// 		goto insert;
// 	}

	/* Find place to insert this segment. Handle overlaps on the way. */
	parent = NULL;
	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (before(seq, DCACP_SKB_CB(skb1)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		if (before(seq, DCACP_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, DCACP_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				dcacp_rmem_free_skb(sk, skb);
				dcacp_drop(sk, skb);
				skb = NULL;

				// tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, DCACP_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				// tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				rb_replace_node(&skb1->rbnode, &skb->rbnode,
						&dsk->out_of_order_queue);
				// tcp_dsack_extend(sk,
				// 		 TCP_SKB_CB(skb1)->seq,
				// 		 TCP_SKB_CB(skb1)->end_seq);
				// NET_INC_STATS(sock_net(sk),
				// 	      LINUX_MIB_TCPOFOMERGE);
				dcacp_rmem_free_skb(sk, skb1);
				dcacp_drop(sk, skb1);
				goto merge_right;
			}
		} 
		// else if (tcp_ooo_try_coalesce(sk, skb1,
		// 				skb, &fragstolen)) {
		// 	goto coalesce_done;
		// }
		p = &parent->rb_right;
	}
// insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
merge_right:
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) {
		if (!after(end_seq, DCACP_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, DCACP_SKB_CB(skb1)->end_seq)) {
			// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
			// 		 end_seq);
			break;
		}
		rb_erase(&skb1->rbnode, &dsk->out_of_order_queue);
		// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
		// 		 TCP_SKB_CB(skb1)->end_seq);
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		dcacp_rmem_free_skb(sk, skb1);
		dcacp_drop(sk, skb1);

	}
	/* If there is no skb after us, we are the last_skb ! */
	// if (!skb1)
	// 	tp->ooo_last_skb = skb;
end:
add_sack:
	return 0;
	// if (tcp_is_sack(tp))
	// 	tcp_sack_new_ofo_skb(sk, seq, end_seq);
// end:
	// if (skb) {
	// 	tcp_grow_window(sk, skb);
	// 	skb_condense(skb);
	// 	skb_set_owner_r(skb, sk);
	// }
}

static void dcacp_ofo_queue(struct sock *sk)
{
	struct dcacp_sock *dsk = dcacp_sk(sk);
	// __u32 dsack_high = dcacp->receiver.rcv_nxt;
	// bool fin, fragstolen, eaten;
	struct sk_buff *skb;
	struct rb_node *p;

	p = rb_first(&dsk->out_of_order_queue);
	while (p) {
		skb = rb_to_skb(p);
		if (after(DCACP_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))
			break;

		// if (before(DCACP_SKB_CB(skb)->seq, dsack_high)) {
		// 	// __u32 dsack = dsack_high;
		// 	// if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
		// 	// 	dsack_high = TCP_SKB_CB(skb)->end_seq;
		// 	// tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		// }
		p = rb_next(p);
		rb_erase(&skb->rbnode, &dsk->out_of_order_queue);

		if (unlikely(!after(DCACP_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt))) {
			dcacp_rmem_free_skb(sk, skb);
			dcacp_drop(sk, skb);
			continue;
		}

		// tail = skb_peek_tail(&sk->sk_receive_queue);
		// eaten = tail && tcp_try_coalesce(sk, tail, skb, &fragstolen);
		dcacp_rcv_nxt_update(dsk, DCACP_SKB_CB(skb)->end_seq);
		// fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
		// if (!eaten)
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		// else
		// 	kfree_skb_partial(skb, fragstolen);

		// if (unlikely(fin)) {
		// 	tcp_fin(sk);
		// 	 tcp_fin() purges tp->out_of_order_queue,
		// 	 * so we must end this loop right now.
			 
		// 	break;
		// }
	}
}

void dcacp_data_ready(struct sock *sk)
{
        const struct dcacp_sock *dsk = dcacp_sk(sk);
        int avail = dsk->receiver.rcv_nxt - dsk->receiver.copied_seq;

        if ((avail < sk->sk_rcvlowat || dsk->receiver.rcv_nxt == dsk->total_length) && !sock_flag(sk, SOCK_DONE))
        	return;

        sk->sk_data_ready(sk);
}

int dcacp_handle_flow_sync_pkt(struct sk_buff *skb) {
	// struct dcacp_sock *dsk;
	// struct inet_sock *inet;
	// struct dcacp_message_in *msg;
	// struct dcacp_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	struct dcacp_flow_sync_hdr *fh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	printk("flow sync header:%lu\n", sizeof(struct dcacp_flow_sync_hdr));
	printk("skb len:%d\n", skb->len);
	if (!pskb_may_pull(skb, sizeof(struct dcacp_flow_sync_hdr))) {
		goto drop;		/* No space for header. */
	}
	fh =  dcacp_flow_sync_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&fh->common), fh->common.source,
            fh->common.dest, sdif, &refcounted);
		// sk = __dcacp4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &dcacp_table);
	// }
	if(sk) {
		dcacp_conn_request(sk, skb);
		printk("receive notification\n");
		// dsk = dcacp_sk(sk);
		// inet = inet_sk(sk);
		// iph = ip_hdr(skb);

		// peer = dcacp_peer_find(&dcacp_peers_table, iph->saddr, inet);
		// printk("message size:%d\n", fh->message_size);
		// msg = dcacp_message_in_init(peer, dsk, fh->message_id, fh->message_size, fh->common.source);
		// slot = dcacp_message_in_bucket(dsk, fh->message_id);
		// spin_lock_bh(&slot->lock);
		// add_dcacp_message_in(dsk, msg);
		// spin_unlock_bh(&slot->lock);
		// dsk->unsolved += 1;
		// printk("msg address: %p LINE:%d\n", msg, __LINE__);
		// printk("fh->message_id:%d\n", msg->id);
		// printk("fh->message_size:%d\n", msg->total_length);
		// printk("source port: %u\n", fh->common.source);
		// printk("dest port: %u\n", fh->common.dest);
		// printk("socket is NULL?: %d\n", sk == NULL);
	}


drop:
    if (refcounted) {
        sock_put(sk);
    }
	kfree_skb(skb);

	return 0;
}

int dcacp_handle_token_pkt(struct sk_buff *skb) {
	kfree_skb(skb);

	return 0;
}

int dcacp_handle_ack_pkt(struct sk_buff *skb) {
	struct dcacp_sock *dsk;
	// struct inet_sock *inet;
	// struct dcacp_peer *peer;
	// struct iphdr *iph;
	struct dcacp_ack_hdr *ah;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	if (!pskb_may_pull(skb, sizeof(struct dcacp_ack_hdr)))
		goto drop;		/* No space for header. */
	ah = dcacp_ack_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&ah->common), ah->common.source,
            ah->common.dest, sdif, &refcounted);
    // }
	if(sk) {
		dsk = dcacp_sk(sk);
		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);
		dcacp_set_state(sk, TCP_CLOSE);
		dcacp_write_queue_purge(sk);

	} else {
		printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}
drop:
    if (refcounted) {
        sock_put(sk);
    }
	kfree_skb(skb);

	return 0;
}


// static void  dcacp_queue_rcv(struct sock *sk, struct sk_buff *skb)
// {
// 	// int eaten;
// 	// struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

// 	// eaten = (tail &&
// 	// 	 tcp_try_coalesce(sk, tail,
// 	// 			  skb, fragstolen)) ? 1 : 0;
// 	// tcp_rcv_nxt_update(tcp_sk(sk), TCP_SKB_CB(skb)->end_seq);
// 	// if (!eaten) {
// 		__skb_queue_tail(&sk->sk_receive_queue, skb);
// 	// 	skb_set_owner_r(skb, sk);
// 	// }
// 	// return eaten;
// }

int dcacp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct dcacp_sock *dsk = dcacp_sk(sk);
	// bool fragstolen;
	// int eaten;
	if (DCACP_SKB_CB(skb)->seq == DCACP_SKB_CB(skb)->end_seq) {
		dcacp_rmem_free_skb(sk, skb);
		return 0;
	}
	// skb_dst_drop(skb);
	__skb_pull(skb, (dcacp_hdr(skb)->doff >> 2) + sizeof(struct data_segment));



	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (DCACP_SKB_CB(skb)->seq == dsk->receiver.rcv_nxt) {
		// if (tcp_receive_window(tp) == 0) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }

		/* Ok. In sequence. In window. */
// queue_and_out:
		// if (skb_queue_len(&sk->sk_receive_queue) == 0)
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// else if (tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
		// 	goto drop;
		// }
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		dcacp_rcv_nxt_update(dsk, DCACP_SKB_CB(skb)->end_seq);

		// eaten = dcacp_queue_rcv(sk, skb, &fragstolen);

		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
			dcacp_ofo_queue(sk);
		}
		dcacp_data_ready(sk);
		// 	/* RFC5681. 4.2. SHOULD send immediate ACK, when
		// 	 * gap in queue is filled.
		// 	 */
		// 	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue))
		// 		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		// }

		// if (dsk->rx_opt.num_sacks)
		// 	tcp_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		// if (eaten > 0)
		// 	kfree_skb_partial(skb, fragstolen);
		// if (!sock_flag(sk, SOCK_DEAD))
		// 	tcp_data_ready(sk);
		return 0;
	}
	if (!after(DCACP_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt)) {
		dcacp_rmem_free_skb(sk, skb);
		dcacp_drop(sk, skb);
		return 0;
	}

	/* Out of window. F.e. zero window probe. */
	// if (!before(DCACP_SKB_CB(skb)->seq, dsk->rcv_nxt + tcp_receive_window(dsk)))
	// 	goto out_of_window;

	if (unlikely(before(DCACP_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))) {
		/* Partial packet, seq < rcv_next < end_seq; unlikely */
		// tcp_dsack_set(sk, DCACP_SKB_CB(skb)->seq, dsk->rcv_nxt);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		dcacp_rcv_nxt_update(dsk, DCACP_SKB_CB(skb)->end_seq);
		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
			dcacp_ofo_queue(sk);
		}
		dcacp_data_ready(sk);

		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		// if (!tcp_receive_window(dsk)) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }
		// goto queue_and_out;
		return 0;
	}

	dcacp_data_queue_ofo(sk, skb);
	return 0;
}

bool dcacp_add_backlog(struct sock *sk, struct sk_buff *skb)
{
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        
        /* Only socket owner can try to collapse/prune rx queues
         * to reduce memory overhead, so add a little headroom here.
         * Few sockets backlog are possibly concurrently non empty.
         */
        limit += 64*1024;

        if (unlikely(sk_add_backlog(sk, skb, limit))) {
                bh_unlock_sock(sk);
                // __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
                return true;
        }
        atomic_add_return(skb->truesize, &sk->sk_rmem_alloc);
        return false;

 }
/**
 * dcacp_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
int dcacp_handle_data_pkt(struct sk_buff *skb)
{
	struct dcacp_sock *dsk;
	struct dcacp_data_hdr *dh;
	struct sock *sk;
	struct iphdr *iph;
	int sdif = inet_sdif(skb);

	bool refcounted = false;
	// printk("receive data pkt\n");
	if (!pskb_may_pull(skb, sizeof(struct dcacp_data_hdr)))
		goto drop;		/* No space for header. */
	dh =  dcacp_data_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&dh->common), dh->common.source,
            dh->common.dest, sdif, &refcounted);
    // }
	// it is unclear why UDP and Homa doesn't grab the socket lock
	if(sk && sk->sk_state == DCACP_RECEIVER) {
		printk("get the socket\n");
		printk("socket buffer truesize:%d\n", skb->truesize);
		printk("dh->common.dest:%d\n",dh->common.dest);
		printk("dh->seg length:%d\n", ntohl(dh->seg.segment_length));
		dsk = dcacp_sk(sk);
		iph = ip_hdr(skb);
		dcacp_v4_fill_cb(skb, iph, dh);
 		bh_lock_sock_nested(sk);
        // ret = 0;
        if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize < sk->sk_rcvbuf) {
	        if (!sock_owned_by_user(sk)) {
			        atomic_add_return(skb->truesize, &sk->sk_rmem_alloc);
	                dcacp_data_queue(sk, skb);

	        } else {
	                if (dcacp_add_backlog(sk, skb))
	                        goto discard_and_relse;
	        }
        } else {
	        bh_unlock_sock(sk);
        	goto discard_and_relse;
        }
        bh_unlock_sock(sk);
	}
    if (refcounted) {
        sock_put(sk);
    }
    return 0;
drop:
    /* Discard frame. */
    kfree_skb(skb);
    return 0;

discard_and_relse:
    sk_drops_add(sk, skb);
    if (refcounted)
            sock_put(sk);
    goto drop;
	// kfree_skb(skb);
}
