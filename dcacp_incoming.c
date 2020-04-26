
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


/* called inside release_cb; BH is disabled by the calller. */
void dcacp_rem_check_handler(struct sock *sk) {
	bool pq_empty = false;
	struct dcacp_sock* dsk = dcacp_sk(sk);
	printk("handle rmem checker\n");
	if(sk->sk_rcvbuf - atomic_read(&sk->sk_rmem_alloc) == 0) {
    	test_and_set_bit(DCACP_RMEM_CHECK_DEFERRED, &sk->sk_tsq_flags);
    	return;
	}
	/* Deadlock won't happen because flow is not in flow_q. */
	spin_lock(&dcacp_epoch.lock);
	pq_empty = dcacp_pq_empty(&dcacp_epoch.flow_q);
	dcacp_pq_push(&dcacp_epoch.flow_q, &dsk->match_link);
	if(pq_empty) {
		/* this part may change latter. */
		hrtimer_start(&dcacp_epoch.token_xmit_timer, ktime_set(0, 0), HRTIMER_MODE_ABS);
		dcacp_epoch.token_xmit_timer.function = &dcacp_token_xmit_event;
	}
	spin_unlock(&dcacp_epoch.lock);

}

void dcacp_token_timer_defer_handler(struct sock *sk) {
	bool pq_empty = false;
	bool not_push_bk = xmit_token(sk);
	struct dcacp_sock* dsk = dcacp_sk(sk);

	if(!not_push_bk) {
	/* Deadlock won't happen because flow is not in flow_q. */
		spin_lock(&dcacp_epoch.lock);
		pq_empty = dcacp_pq_empty(&dcacp_epoch.flow_q);
		dcacp_pq_push(&dcacp_epoch.flow_q, &dsk->match_link);
		if(pq_empty) {
			// printk("timer expire time:%d\n", dcacp_params.rtt * 10 * 1000);
			// hrtimer_start(&dcacp_epoch.token_xmit_timer, ktime_set(0,  dcacp_params.rtt * 10 * 1000), HRTIMER_MODE_ABS);
			// dcacp_epoch.token_xmit_timer.function = &dcacp_token_xmit_event;
		}
		spin_unlock(&dcacp_epoch.lock);
	}
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
static int dcacp_clean_rtx_queue(struct sock *sk)
{
	// const struct inet_connection_sock *icsk = inet_csk(sk);
	struct dcacp_sock *dsk = dcacp_sk(sk);
	// u64 first_ackt, last_ackt;
	// u32 prior_sacked = tp->sacked_out;
	// u32 reord = tp->snd_nxt;  lowest acked un-retx un-sacked seq 
	struct sk_buff *skb, *next;
	bool fully_acked = true;
	// long sack_rtt_us = -1L;
	// long seq_rtt_us = -1L;
	// long ca_rtt_us = -1L;
	// u32 pkts_acked = 0;
	// u32 last_in_flight = 0;
	// bool rtt_update;
	int flag = 0;

	// first_ackt = 0;

	for (skb = skb_rb_first(&sk->tcp_rtx_queue); skb; skb = next) {
		struct dcacp_skb_cb *scb = DCACP_SKB_CB(skb);
		// const u32 start_seq = scb->seq;
		// u8 sacked = scb->sacked;
		// u32 acked_pcount;

		// tcp_ack_tstamp(sk, skb, prior_snd_una);

		/* Determine how many packets and what bytes were acked, tso and else */
		if (after(scb->end_seq, dsk->sender.snd_una)) {
			// if (tcp_skb_pcount(skb) == 1 ||
			//     !after(tp->snd_una, scb->seq))
			// 	break;

			// acked_pcount = tcp_tso_acked(sk, skb);
			// if (!acked_pcount)
			// 	break;
			fully_acked = false;
		} else {
			// acked_pcount = tcp_skb_pcount(skb);
		}

		// if (unlikely(sacked & TCPCB_RETRANS)) {
		// 	if (sacked & TCPCB_SACKED_RETRANS)
		// 		tp->retrans_out -= acked_pcount;
		// 	flag |= FLAG_RETRANS_DATA_ACKED;
		// } else if (!(sacked & TCPCB_SACKED_ACKED)) {
		// 	last_ackt = tcp_skb_timestamp_us(skb);
		// 	WARN_ON_ONCE(last_ackt == 0);
		// 	if (!first_ackt)
		// 		first_ackt = last_ackt;

		// 	last_in_flight = TCP_SKB_CB(skb)->tx.in_flight;
		// 	if (before(start_seq, reord))
		// 		reord = start_seq;
		// 	if (!after(scb->end_seq, tp->high_seq))
		// 		flag |= FLAG_ORIG_SACK_ACKED;
		// }

		// if (sacked & TCPCB_SACKED_ACKED) {
		// 	tp->sacked_out -= acked_pcount;
		// } else if (tcp_is_sack(tp)) {
		// 	tp->delivered += acked_pcount;
		// 	if (!tcp_skb_spurious_retrans(tp, skb))
		// 		tcp_rack_advance(tp, sacked, scb->end_seq,
		// 				 tcp_skb_timestamp_us(skb));
		// }
		// if (sacked & TCPCB_LOST)
		// 	tp->lost_out -= acked_pcount;

		// tp->packets_out -= acked_pcount;
		// pkts_acked += acked_pcount;
		// tcp_rate_skb_delivered(sk, skb, sack->rate);

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		// if (likely(!(scb->tcp_flags & TCPHDR_SYN))) {
		// 	flag |= FLAG_DATA_ACKED;
		// } else {
		// 	flag |= FLAG_SYN_ACKED;
		// 	tp->retrans_stamp = 0;
		// }

		if (!fully_acked)
			break;

		next = skb_rb_next(skb);
		// if (unlikely(skb == tp->retransmit_skb_hint))
		// 	tp->retransmit_skb_hint = NULL;
		// if (unlikely(skb == tp->lost_skb_hint))
		// 	tp->lost_skb_hint = NULL;
		// tcp_highest_sack_replace(sk, skb, next);
		dcacp_rtx_queue_unlink_and_free(skb, sk);
	}

	// if (!skb)
	// 	tcp_chrono_stop(sk, TCP_CHRONO_BUSY);

	// if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
	// 	tp->snd_up = tp->snd_una;

	// if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
	// 	flag |= FLAG_SACK_RENEGING;

	// if (likely(first_ackt) && !(flag & FLAG_RETRANS_DATA_ACKED)) {
	// 	seq_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, first_ackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);

	// 	if (pkts_acked == 1 && last_in_flight < tp->mss_cache &&
	// 	    last_in_flight && !prior_sacked && fully_acked &&
	// 	    sack->rate->prior_delivered + 1 == tp->delivered &&
	// 	    !(flag & (FLAG_CA_ALERT | FLAG_SYN_ACKED))) {
	// 		/* Conservatively mark a delayed ACK. It's typically
	// 		 * from a lone runt packet over the round trip to
	// 		 * a receiver w/o out-of-order or CE events.
	// 		 */
	// 		flag |= FLAG_ACK_MAYBE_DELAYED;
	// 	}
	// }
	// if (sack->first_sackt) {
	// 	sack_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->first_sackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->last_sackt);
	// }
	// rtt_update = tcp_ack_update_rtt(sk, flag, seq_rtt_us, sack_rtt_us,
	// 				ca_rtt_us, sack->rate);

	// if (flag & FLAG_ACKED) {
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// 	if (unlikely(icsk->icsk_mtup.probe_size &&
	// 		     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
	// 		tcp_mtup_probe_success(sk);
	// 	}

	// 	if (tcp_is_reno(tp)) {
	// 		tcp_remove_reno_sacks(sk, pkts_acked);

	// 		/* If any of the cumulatively ACKed segments was
	// 		 * retransmitted, non-SACK case cannot confirm that
	// 		 * progress was due to original transmission due to
	// 		 * lack of TCPCB_SACKED_ACKED bits even if some of
	// 		 * the packets may have been never retransmitted.
	// 		 */
	// 		if (flag & FLAG_RETRANS_DATA_ACKED)
	// 			flag &= ~FLAG_ORIG_SACK_ACKED;
	// 	} else {
	// 		int delta;

	// 		/* Non-retransmitted hole got filled? That's reordering */
	// 		if (before(reord, prior_fack))
	// 			tcp_check_sack_reordering(sk, reord, 0);

	// 		delta = prior_sacked - tp->sacked_out;
	// 		tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
	// 	}
	// } else if (skb && rtt_update && sack_rtt_us >= 0 &&
	// 	   sack_rtt_us > tcp_stamp_us_delta(tp->tcp_mstamp,
	// 					    tcp_skb_timestamp_us(skb))) {
	// 	/* Do not re-arm RTO if the sack RTT is measured from data sent
	// 	 * after when the head was last (re)transmitted. Otherwise the
	// 	 * timeout may continue to extend in loss recovery.
	// 	 */
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// }

	// if (icsk->icsk_ca_ops->pkts_acked) {
	// 	struct ack_sample sample = { .pkts_acked = pkts_acked,
	// 				     .rtt_us = sack->rate->rtt_us,
	// 				     .in_flight = last_in_flight };

	// 	icsk->icsk_ca_ops->pkts_acked(sk, &sample);
	// }
	return flag;
}

/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
static void dcacp_rcv_nxt_update(struct dcacp_sock *dsk, u32 seq)
{
	struct sock *sk = (struct sock*) dsk;
	u32 delta = seq - dsk->receiver.rcv_nxt;
	dsk->receiver.bytes_received += delta;
	WRITE_ONCE(dsk->receiver.rcv_nxt, seq);
	// printk("update the seq:%d\n", dsk->receiver.rcv_nxt);

	if(!dsk->receiver.finished_at_receiver && dsk->receiver.rcv_nxt == dsk->total_length) {
		struct inet_sock *inet = inet_sk(sk);
		dsk->receiver.finished_at_receiver = true;
		printk("send ack pkt\n");
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
        DCACP_SKB_CB(skb)->seq = ntohl(dh->common.seq);
        DCACP_SKB_CB(skb)->end_seq = (DCACP_SKB_CB(skb)->seq + ntohs(dh->common.len));
        // TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
        // TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
        // TCP_SKB_CB(skb)->tcp_tw_isn = 0;
        // TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
        // TCP_SKB_CB(skb)->sacked  = 0;
        // TCP_SKB_CB(skb)->has_rxtstamp =
        //                 skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}


/**
 * dcacp_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @dest: destination queue
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
static bool dcacp_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	int delta;
	int skb_truesize = from->truesize;
	*fragstolen = false;

	/* Its possible this segment overlaps with prior segment in queue */
	if (DCACP_SKB_CB(from)->seq != DCACP_SKB_CB(to)->end_seq)
		return false;

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;
	/* assume we have alrady add true size beforehand*/
	atomic_sub(skb_truesize, &sk->sk_rmem_alloc);
	atomic_add(delta, &sk->sk_rmem_alloc);
	// sk_mem_charge(sk, delta);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	DCACP_SKB_CB(to)->end_seq = DCACP_SKB_CB(from)->end_seq;
	// DCACP_SKB_CB(to)->ack_seq = DCACP_SKB_CB(from)->ack_seq;
	// DCACP_SKB_CB(to)->tcp_flags |= DCACP_SKB_CB(from)->tcp_flags;

	// if (DCACP_SKB_CB(from)->has_rxtstamp) {
	// 	TCP_SKB_CB(to)->has_rxtstamp = true;
	// 	to->tstamp = from->tstamp;
	// 	skb_hwtstamps(to)->hwtstamp = skb_hwtstamps(from)->hwtstamp;
	// }

	return true;
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

	// printk("insert to data queue ofo:%d\n", seq);

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
	bool fragstolen, eaten;
	// bool fin;
	struct sk_buff *skb, *tail;
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

		tail = skb_peek_tail(&sk->sk_receive_queue);
		eaten = tail && dcacp_try_coalesce(sk, tail, skb, &fragstolen);
		dcacp_rcv_nxt_update(dsk, DCACP_SKB_CB(skb)->end_seq);
		// fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
		if (!eaten)
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		else
			kfree_skb_partial(skb, fragstolen);

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
	// struct dcacp_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	struct dcacp_flow_sync_hdr *fh;
	struct sock *sk, *child;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
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
		child = dcacp_conn_request(sk, skb);
		if(child) {
			struct dcacp_sock *dsk = dcacp_sk(child);
			if(dsk->total_length >= dcacp_params.short_flow_size) {
				spin_lock_bh(&dcacp_epoch.lock);
				/* push the long flow to the control plane for scheduling*/
				dcacp_pq_push(&dcacp_epoch.flow_q, &dsk->match_link);
				if(dcacp_pq_size(&dcacp_epoch.flow_q) == 1) {
					dcacp_xmit_token(&dcacp_epoch);
				}
				spin_unlock_bh(&dcacp_epoch.lock);
			} else {
				/* set short flow timer */
			}
		}
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
	struct dcacp_sock *dsk;
	// struct inet_sock *inet;
	// struct dcacp_peer *peer;
	// struct iphdr *iph;
	struct dcacp_token_hdr *th;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	if (!pskb_may_pull(skb, sizeof(struct dcacp_token_hdr))) {
		kfree_skb(skb);
		return 0;
	}
	th = dcacp_token_hdr(skb);
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&th->common), th->common.source,
            th->common.dest, sdif, &refcounted);
	if(sk) {
 		dsk = dcacp_sk(sk);
 		bh_lock_sock_nested(sk);
 		if (!sock_owned_by_user(sk)) {
			/* clean rtx queue */
			dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
	 		dcacp_clean_rtx_queue(sk);
			/* add token */
	 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;

			/* start doing transmission (this part may move to different places later)*/
			dcacp_write_timer_handler(sk);
	        kfree_skb(skb);

        } else {
            dcacp_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);
	}
    if (refcounted) {
        sock_put(sk);
    }
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

	if (!pskb_may_pull(skb, sizeof(struct dcacp_ack_hdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	ah = dcacp_ack_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&ah->common), ah->common.source,
            ah->common.dest, sdif, &refcounted);
    // }
	if(sk) {
 		bh_lock_sock_nested(sk);
		dsk = dcacp_sk(sk);
		if (!sock_owned_by_user(sk)) {
	        dcacp_set_state(sk, TCP_CLOSE);
	        dcacp_write_queue_purge(sk);
	        kfree_skb(skb);
        } else {
            dcacp_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} else {
		kfree_skb(skb);
		printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}


static int  dcacp_queue_rcv(struct sock *sk, struct sk_buff *skb,  bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

	eaten = (tail &&
		 dcacp_try_coalesce(sk, tail,
				  skb, fragstolen)) ? 1 : 0;
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		// skb_set_owner_r(skb, sk);
	}
	dcacp_rcv_nxt_update(dcacp_sk(sk), DCACP_SKB_CB(skb)->end_seq);
	return eaten;
}

int dcacp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct dcacp_sock *dsk = dcacp_sk(sk);
	bool fragstolen;
	int eaten;
	if (DCACP_SKB_CB(skb)->seq == DCACP_SKB_CB(skb)->end_seq) {
		dcacp_rmem_free_skb(sk, skb);
		return 0;
	}
	// skb_dst_drop(skb);
	__skb_pull(skb, (dcacp_hdr(skb)->doff >> 2));
	// printk("handle packet data queue?:%d\n", DCACP_SKB_CB(skb)->seq);

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
		// __skb_queue_tail(&sk->sk_receive_queue, skb);
queue_and_out:
		eaten = dcacp_queue_rcv(sk, skb, &fragstolen);

		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
			dcacp_ofo_queue(sk);
		}

		// 	/* RFC5681. 4.2. SHOULD send immediate ACK, when
		// 	 * gap in queue is filled.
		// 	 */
		// 	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue))
		// 		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		// }

		// if (dsk->rx_opt.num_sacks)
		// 	tcp_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		if (!sock_flag(sk, SOCK_DEAD))
			dcacp_data_ready(sk);
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


		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		// if (!tcp_receive_window(dsk)) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }
		goto queue_and_out;
	}

	dcacp_data_queue_ofo(sk, skb);
	return 0;
}

bool dcacp_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check)
{
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        
        /* Only socket owner can try to collapse/prune rx queues
         * to reduce memory overhead, so add a little headroom here.
         * Few sockets backlog are possibly concurrently non empty.
         */
        limit += 64*1024;
        if (omit_check) {
        	limit = UINT_MAX;
        }
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
	if(sk && sk->sk_state == DCACP_RECEIVER) {
		dsk = dcacp_sk(sk);
		iph = ip_hdr(skb);
		dcacp_v4_fill_cb(skb, iph, dh);
		// printk("data seq:%d\n", ntohl(dh->seg.offset));
		if (!dh->free_token) {
			spin_lock_bh(&dcacp_epoch.lock);
			atomic_sub(ntohs(dh->common.len), &dcacp_epoch.remaining_tokens);

			if (!dcacp_pq_empty(&dcacp_epoch.flow_q) &&
				atomic_read(&dcacp_epoch.remaining_tokens) < dcacp_params.control_pkt_bdp / 2
				) {
				printk("number of remaining tokens:%d\n", atomic_read(&dcacp_epoch.remaining_tokens));
				dcacp_xmit_token(&dcacp_epoch);
			}
			spin_unlock_bh(&dcacp_epoch.lock);
		} 
 		bh_lock_sock_nested(sk);
        // ret = 0;
        if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize < sk->sk_rcvbuf) {
	        if (!sock_owned_by_user(sk)) {
			        atomic_add_return(skb->truesize, &sk->sk_rmem_alloc);
	                dcacp_data_queue(sk, skb);

	        } else {
	                if (dcacp_add_backlog(sk, skb, false))
	                        goto discard_and_relse;
	        }
        } else {
	        bh_unlock_sock(sk);
	        printk("discard packet due to memory:%d\n", __LINE__);
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

/* should hold the lock, before calling this function；
 * This function is only called for backlog handling from the release_sock()
 */
int dcacp_v4_do_rcv(struct sock *sk, struct sk_buff *skb) {
	struct dcacphdr* dh;
	struct dcacp_sock *dsk = dcacp_sk(sk);
	dh = dcacp_hdr(skb);
	if(dh->type == DATA) {
		return dcacp_data_queue(sk, skb);
		// return __dcacp4_lib_rcv(skb, &dcacp_table, IPPROTO_DCACP);
	} else if (dh->type == ACK) {
        dcacp_set_state(sk, TCP_CLOSE);
        dcacp_write_queue_purge(sk);
		atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	} else if (dh->type == TOKEN) {
		/* clean rtx queue */
		struct dcacp_token_hdr *th = dcacp_token_hdr(skb);
		dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
 		dcacp_clean_rtx_queue(sk);
		/* add token */
 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 		// will be handled by dcacp_release_cb
 		test_and_set_bit(DCACP_WRITE_TIMER_DEFERRED, &sk->sk_tsq_flags);
		atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	}
	kfree_skb(skb);
	return 0;
}
