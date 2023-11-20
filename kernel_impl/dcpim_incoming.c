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
#include "dcpim_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_dcpim.h"
 #include "net_dcpim.h"
// #include "net_dcpimlite.h"
#include "uapi_linux_dcpim.h"
#include "dcpim_impl.h"
#include "dcpim_ioat.h"

// #include "dcpim_hashtables.h"

// static inline struct sock *__dcpim4_lib_lookup_skb(struct sk_buff *skb,
// 						 __be16 sport, __be16 dport,
// 						 struct udp_table *dcpimtable)
// {
// 	const struct iphdr *iph = ip_hdr(skb);

// 	return __dcpim4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
// 				 iph->daddr, dport, inet_iif(skb),
// 				 inet_sdif(skb), dcpimtable, skb);
// }

static inline void dcpim_flip_header(struct sk_buff* skb, int type) {
	struct dcpimhdr* dh = dcpim_hdr(skb);
	dh->type = type;
	dcpim_swap_dcpim_header(skb);
	dcpim_swap_ip_header(skb);
	dcpim_swap_eth_header(skb);
	skb_push(skb, skb->data - skb_mac_header(skb));
}
static inline bool before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)


static inline bool dcpim_sack_extend(struct dcpim_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void dcpim_sack_maybe_coalesce(struct dcpim_sock *dsk)
{
	int this_sack;
	struct dcpim_sack_block *sp = &dsk->selective_acks[0];
	struct dcpim_sack_block *swalk = sp + 1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < dsk->num_sacks;) {
		if (dcpim_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			dsk->num_sacks--;
			for (i = this_sack; i < dsk->num_sacks; i++)
				sp[i] = sp[i + 1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static void dcpim_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct dcpim_sack_block *sp = &dsk->selective_acks[0];
	int cur_sacks = dsk->num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack = 0; this_sack < cur_sacks; this_sack++, sp++) {
		if (dcpim_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack > 0; this_sack--, sp--)
				swap(*sp, *(sp - 1));
			if (cur_sacks > 1)
				dcpim_sack_maybe_coalesce(dsk);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	if (this_sack > DCPIM_NUM_SACKS) {
		// if (tp->compressed_ack > TCP_FASTRETRANS_THRESH)
		// 	tcp_send_ack(sk);
		WARN_ON(true);
		this_sack--;
		dsk->num_sacks--;
		sp--;
	}
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp - 1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	dsk->num_sacks++;
}

/* RCV.NXT advances, some SACKs should be eaten. */

static void dcpim_sack_remove(struct dcpim_sock *dsk)
{
	struct dcpim_sack_block *sp = &dsk->selective_acks[0];
	int num_sacks = dsk->num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
		dsk->num_sacks = 0;
		return;
	}

	for (this_sack = 0; this_sack < num_sacks;) {
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(dsk->receiver.rcv_nxt, sp->start_seq)) {
			int i;

			/* RCV.NXT must cover all the block! */
			WARN_ON(before(dsk->receiver.rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i = this_sack+1; i < num_sacks; i++)
				dsk->selective_acks[i-1] = dsk->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	dsk->num_sacks = num_sacks;
}

/* read sack info */
void dcpim_get_sack_info(struct sock *sk, struct sk_buff *skb) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	const unsigned char *ptr = (skb_transport_header(skb) +
				    sizeof(struct dcpim_token_hdr));
	struct dcpim_token_hdr *th = dcpim_token_hdr(skb);
	struct dcpim_sack_block_wire *sp_wire = (struct dcpim_sack_block_wire *)(ptr);
	struct dcpim_sack_block *sp = dsk->sender.selective_acks;
	// struct sk_buff *skb;
	int used_sacks;
	int i;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_token_hdr) + sizeof(struct dcpim_sack_block_wire) * th->num_sacks)) {
		return;		/* No space for header. */
	}
	dsk->sender.num_sacks = th->num_sacks;
	used_sacks = 0;
	for (i = 0; i < dsk->sender.num_sacks; i++) {
		/* get_unaligned_be32 will host change the endian to be CPU order */
		sp[used_sacks].start_seq = get_unaligned_be32(&sp_wire[i].start_seq);
		sp[used_sacks].end_seq = get_unaligned_be32(&sp_wire[i].end_seq);

		used_sacks++;
	}

	/* order SACK blocks to allow in order walk of the retrans queue */
	// for (i = used_sacks - 1; i > 0; i--) {
	// 	for (j = 0; j < i; j++) {
	// 		if (after(sp[j].start_seq, sp[j + 1].start_seq)) {
	// 			swap(sp[j], sp[j + 1]);
	// 		}
	// 	}
	// }
}

/* assume hold the socket spinlock*/
void dcpim_flow_wait_handler(struct sock *sk) {
	// struct dcpim_sock *dsk = dcpim_sk(sk);
	// struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];

	// atomic_sub(atomic_read(&dsk->receiver.inflight_bytes), &entry->remaining_tokens);
	// atomic_set(&dsk->receiver.inflight_bytes, 0);
	// dsk->receiver.flow_finish_wait = false;
	// // dsk->receiver.prev_grant_bytes = 0;
	// // dsk->prev_grant_nxt = dsk->grant_nxt;
	// // printk("flow_wait_timer");
	// // printk("entry remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
	// // printk("inet dport:%d\n",  ntohs(inet->inet_dport));
	// if(test_and_clear_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
	// 	// atomic_sub(dsk->receiver.grant_batch,  &entry->remaining_tokens);
	// }
	// if(!dsk->receiver.finished_at_receiver)
	// 	dcpim_update_and_schedule_sock(dsk);
	// bh_unlock_sock(sk);
	// flowlet_done_event(&entry->flowlet_done_timer);
	// bh_lock_sock(sk);
}
/* ToDO: should be protected by user lock called inside softIRQ context */
enum hrtimer_restart dcpim_flow_wait_event(struct hrtimer *timer) {
	// struct dcpim_grant* grant, temp;
	// struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, receiver.flow_wait_timer);
	// struct sock *sk = (struct sock*)dsk;
	// // struct inet_sock* inet = inet_sk(sk);
	// WARN_ON(!in_softirq());
	// // printk("call flow wait\n");
	// bh_lock_sock(sk);
	// if(!sock_owned_by_user(sk)) {
	// 	dcpim_flow_wait_handler(sk);
	// } else {
	// 	test_and_set_bit(DCPIM_WAIT_DEFERRED, &sk->sk_tsq_flags);
	// }
	// bh_unlock_sock(sk);
	return HRTIMER_NORESTART;
}

/* Called inside release_cb or by flow_wait_event; BH is disabled by the caller and lock_sock is hold by caller.
 * Either read buffer is limited or all toknes has been sent but some pkts are dropped.
 */
void dcpim_rem_check_handler(struct sock *sk) {
	// struct dcpim_sock* dsk = dcpim_sk(sk);
	// printk("handle rmem checker\n");
	// // printk("dsk->receiver.copied_seq:%u\n", dsk->receiver.copied_seq);
	// if(sk->sk_rcvbuf - atomic_read(&sk->sk_rmem_alloc) == 0) {
 //    	test_and_set_bit(DCPIM_RMEM_CHECK_DEFERRED, &sk->sk_tsq_flags);
 //    	return;
	// }
	// /* Deadlock won't happen because flow is not in flow_q. */
	// spin_lock(&dcpim_epoch.lock);
	// dcpim_pq_push(&dcpim_epoch.flow_q, &dsk->match_link);
	// if(atomic_read(&dcpim_epoch.remaining_tokens) <= dcpim_params.control_pkt_bdp / 2) {
	// 	/* this part may change latter. */
	// 	hrtimer_start(&dcpim_epoch.token_xmit_timer, ktime_set(0, 0), HRTIMER_MODE_REL_PINNED_SOFT);
	// }
	// spin_unlock(&dcpim_epoch.lock);

}

// void dcpim_token_timer_defer_handler(struct sock *sk) {
// 	// bool pq_empty = false;
// 	// int grant_bytes = calc_grant_bytes(sk);
// 	bool not_push_bk = false;
// 	struct dcpim_sock* dsk = dcpim_sk(sk);
// 	// struct inet_sock *inet = inet_sk(sk);
// 	struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];
// 	__u32 prev_token_nxt = dsk->receiver.prev_token_nxt;
// 	// printk("timer defer handling\n");
// 	WARN_ON(!in_softirq());
// 	if(!dsk->receiver.flow_finish_wait && !dsk->receiver.finished_at_receiver) {
// 		int grant_bytes = calc_grant_bytes(sk);
// 		int rtx_bytes = rtx_bytes_count(dsk, prev_token_nxt);
// 		// printk("defer grant bytes:%d\n", grant_bytes);
// 		if(!dsk->receiver.finished_at_receiver && (rtx_bytes != 0 || grant_bytes != 0)) {
// 			// printk("call timer defer xmit token\n");
// 			not_push_bk = xmit_batch_token(sk, grant_bytes, true);
// 		}
// 	} else {
// 		not_push_bk = true;
// 	}

// 	// printk("timer defer\n");
// 	// if(dsk->receiver.prev_grant_bytes == 0) {
// 	// 	int grant_bytes = calc_grant_bytes(sk);
// 	// 	not_push_bk = xmit_batch_token(sk, grant_bytes, true);
// 	// } else {
// 	// 	int rtx_bytes = rtx_bytes_count(dsk, prev_grant_nxt);
// 	// 	if(rtx_bytes && sk->sk_state == DCPIM_RECEIVER) {
// 	// 		dcpim_xmit_control(construct_token_pkt((struct sock*)dsk, 3, prev_grant_nxt, dsk->new_grant_nxt, true),
// 	// 	 	dsk->peer, sk, inet->inet_dport);
// 	// 		atomic_add(rtx_bytes, &dcpim_epoch.remaining_tokens);
// 	// 		dsk->receiver.prev_grant_bytes += rtx_bytes;
// 	// 	}
// 	// 	if(dsk->new_grant_nxt == dsk->total_length) {
// 	// 		not_push_bk = true;
// 	// 		/* TO DO: setup a timer here */
// 	// 		/* current set timer to be 10 RTT */
// 	// 		hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(dcpim_params.rtt * 10 * 1000), 
// 	// 			HRTIMER_MODE_REL_PINNED_SOFT);
// 	// 	}
// 	// }
// 	/* Deadlock won't happen because flow is not in flow_q. */
// 	if(!not_push_bk) {
// 		dcpim_update_and_schedule_sock(dsk);
// 	}
// 	bh_unlock_sock(sk);
// 	flowlet_done_event(&entry->flowlet_done_timer);
// 	bh_lock_sock(sk);

// }

void sk_stream_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct socket_wq *wq;

	if (__sk_stream_is_writeable(sk, 1) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		rcu_read_lock();
		wq = rcu_dereference(sk->sk_wq);
		if (skwq_has_sleeper(wq))
			wake_up_interruptible_poll(&wq->wait, EPOLLOUT |
						EPOLLWRNORM | EPOLLWRBAND);
		if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(wq, SOCK_WAKE_SPACE, POLL_OUT);
		rcu_read_unlock();
	}
}


/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
int dcpim_clean_rtx_queue(struct sock *sk)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff *skb, *next;
	bool fully_acked = true;
	int flag = 0;

	for (skb = skb_rb_first(&sk->tcp_rtx_queue); skb; skb = next) {
		struct dcpim_skb_cb *scb = DCPIM_SKB_CB(skb);
		/* Determine how many packets and what bytes were acked, tso and else */
		if (after(scb->end_seq, dsk->sender.snd_una)) {
			fully_acked = false;
		}
		if (!fully_acked)
			break;

		next = skb_rb_next(skb);
		dcpim_rtx_queue_unlink_and_free(skb, sk);
		sk_stream_write_space(sk);
	}
	/* change socket to idle if needed */
	if(sk->sk_wmem_queued == 0 && dsk->host && !READ_ONCE(dsk->is_idle)) {
		dcpim_host_set_sock_idle(dsk->host, (struct sock*)dsk);
	}
	return flag;
}

// check flow finished at receiver; assuming holding user lock and local bh is disabled
// static void dcpim_check_flow_finished_at_receiver(struct dcpim_sock *dsk) {
// 	if(!dsk->receiver.finished_at_receiver && dsk->receiver.rcv_nxt == dsk->total_length) {
// 		struct sock* sk = (struct sock*) dsk;
// 		struct inet_sock *inet = inet_sk(sk);
// 		struct rcv_core_entry *entry = &rcv_core_tab.table[dsk->core_id];

// 		dsk->receiver.finished_at_receiver = true;
// 		if(dsk->receiver.flow_finish_wait) {
// 			hrtimer_cancel(&dsk->receiver.flow_wait_timer);
// 			test_and_clear_bit(DCPIM_WAIT_DEFERRED, &sk->sk_tsq_flags);
// 			dsk->receiver.flow_finish_wait = false;
// 		} 
// 		// printk("send fin pkt\n");
// 		printk("dsk->in_flight:%d\n", atomic_read(&dsk->receiver.inflight_bytes));
// 		printk("dentry->remaining_tokens:%d\n", atomic_read(&entry->remaining_tokens));
// 		atomic_sub(atomic_read(&dsk->receiver.inflight_bytes), &entry->remaining_tokens);
// 		sk->sk_prot->unhash(sk);
// 		/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
// 		if (inet_csk(sk)->icsk_bind_hash) {
// 			printk("put port\n");
// 			inet_put_port(sk);
// 		} else {
// 			printk("userlook and SOCK_BINDPORT_LOCK:%d\n", !(sk->sk_userlocks & SOCK_BINDPORT_LOCK));
// 			printk("cannot put port\n");
// 		}
// 		/* remove the socket from scheduing */
// 		dcpim_unschedule_sock(dsk);
// 		dcpim_xmit_control(construct_fin_pkt(sk), sk, inet->inet_dport); 
// 		if(atomic_read(&entry->remaining_tokens) <= dcpim_params.control_pkt_bdp / 2) {
// 			flowlet_done_event(&entry->flowlet_done_timer);
// 		}
// 	}

// }

/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
static void dcpim_rcv_nxt_update(struct dcpim_sock *dsk, u32 seq)
{
	struct sock *sk = (struct sock*) dsk;
	// struct inet_sock *inet = inet_sk(sk);
	u32 delta = seq - dsk->receiver.rcv_nxt;
	uint32_t token_bytes = 0;
	// int grant_bytes = calc_grant_bytes(sk);

	dsk->receiver.bytes_received += delta;
	WRITE_ONCE(dsk->receiver.rcv_nxt, seq);
	// printk("update the seq:%d\n", dsk->receiver.rcv_nxt);
	token_bytes = dcpim_token_timer_defer_handler(sk);
	// if(token_bytes <= 0) {
	// 	if(dsk->receiver.rcv_nxt > dsk->receiver.last_ack + dsk->receiver.token_batch) {
	// 		dcpim_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk); 
	// 		dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	// 		if(hrtimer_is_queued(&dsk->receiver.delay_ack_timer))
	// 			hrtimer_cancel(&dsk->receiver.delay_ack_timer);
	// 	} 
	// 	else if(!dsk->receiver.delay_ack){
	// 		hrtimer_start(&dsk->receiver.delay_ack_timer, ns_to_ktime(dcpim_params.epoch_length * 10), HRTIMER_MODE_REL_PINNED_SOFT);
	// 	}
	// }
}

static void dcpim_drop(struct sock *sk, struct sk_buff *skb)
{
        sk_drops_add(sk, skb);
        // __kfree_skb(skb);
}

static void dcpim_v4_fill_cb(struct sk_buff *skb, const struct iphdr *iph,
                           const struct dcpim_data_hdr *dh)
{
        /* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
         * barrier() makes sure compiler wont play fool^Waliasing games.
         */
        memmove(&DCPIM_SKB_CB(skb)->header.h4, IPCB(skb),
                sizeof(struct inet_skb_parm));
        barrier();
        DCPIM_SKB_CB(skb)->seq = ntohl(dh->seg.offset);
        // printk("skb len:%d\n", skb->len);
        // printk("segment length:%d\n", ntohl(dh->seg.segment_length));
        DCPIM_SKB_CB(skb)->end_seq = (DCPIM_SKB_CB(skb)->seq + skb->len - (dh->common.doff * 4 + sizeof(struct data_segment)));
        // TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
        // TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
        // TCP_SKB_CB(skb)->tcp_tw_isn = 0;
        // TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
        // TCP_SKB_CB(skb)->sacked  = 0;
        // TCP_SKB_CB(skb)->has_rxtstamp =
        //                 skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}


/**
 * dcpim_try_coalesce - try to merge skb to prior one
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
static bool dcpim_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	int delta;
	int skb_truesize = from->truesize;
	*fragstolen = false;

	/* Its possible this segment overlaps with prior segment in queue */
	if (DCPIM_SKB_CB(from)->seq != DCPIM_SKB_CB(to)->end_seq)
		return false;

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;
	/* assume we have alrady add true size beforehand*/
	atomic_sub(skb_truesize, &sk->sk_rmem_alloc);
	atomic_add(delta, &sk->sk_rmem_alloc);
	// sk_mem_charge(sk, delta);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	DCPIM_SKB_CB(to)->end_seq = DCPIM_SKB_CB(from)->end_seq;
	// DCPIM_SKB_CB(to)->ack_seq = DCPIM_SKB_CB(from)->ack_seq;
	// DCPIM_SKB_CB(to)->tcp_flags |= DCPIM_SKB_CB(from)->tcp_flags;

	// if (DCPIM_SKB_CB(from)->has_rxtstamp) {
	// 	TCP_SKB_CB(to)->has_rxtstamp = true;
	// 	to->tstamp = from->tstamp;
	// 	skb_hwtstamps(to)->hwtstamp = skb_hwtstamps(from)->hwtstamp;
	// }

	return true;
}


static int dcpim_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	int old_skbsize;
	/* Disable header prediction. */
	// tp->pred_flags = 0;
	// inet_csk_schedule_ack(sk);

	// tp->rcv_ooopack += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	seq = DCPIM_SKB_CB(skb)->seq;
	end_seq = DCPIM_SKB_CB(skb)->end_seq;

	// printk("insert to data queue ofo:%d\n", seq);

	p = &dsk->out_of_order_queue.rb_node;
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
		dsk->receiver.inflight_bytes -= (DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
		/* Initial out of order segment, build 1 SACK. */
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
		// tp->ooo_last_skb = skb;
		goto add_sack;
	}
	/* Find place to insert this segment. Handle overlaps on the way. */
	parent = NULL;
	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (before(seq, DCPIM_SKB_CB(skb1)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		if (before(seq, DCPIM_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, DCPIM_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				dcpim_rmem_free_skb(sk, skb);
				dcpim_drop(sk, skb);
				skb = NULL;

				// tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, DCPIM_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				// tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
				old_skbsize = skb->truesize;
				pskb_may_pull(skb, DCPIM_SKB_CB(skb1)->end_seq - DCPIM_SKB_CB(skb)->seq);
				atomic_add(skb->truesize - old_skbsize, &sk->sk_rmem_alloc);
				__skb_pull(skb,  DCPIM_SKB_CB(skb1)->end_seq - DCPIM_SKB_CB(skb)->seq);
				DCPIM_SKB_CB(skb)->seq += DCPIM_SKB_CB(skb1)->end_seq - DCPIM_SKB_CB(skb)->seq;
				seq = DCPIM_SKB_CB(skb)->seq;
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
				dcpim_rmem_free_skb(sk, skb1);
				dcpim_drop(sk, skb1);
				dsk->receiver.inflight_bytes += skb1->len;
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
	dsk->receiver.inflight_bytes -= (DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
merge_right:
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) {
		if (!after(end_seq, DCPIM_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, DCPIM_SKB_CB(skb1)->end_seq)) {
			// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
			// 		 end_seq);
			dsk->receiver.inflight_bytes += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb1)->seq;
			old_skbsize = skb1->truesize;
			pskb_may_pull(skb1, DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb1)->seq);
			atomic_add(skb1->truesize - old_skbsize, &sk->sk_rmem_alloc);
			__skb_pull(skb1,  DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb1)->seq);
			DCPIM_SKB_CB(skb1)->seq += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb1)->seq;
			break;
		}
		rb_erase(&skb1->rbnode, &dsk->out_of_order_queue);
		// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
		// 		 TCP_SKB_CB(skb1)->end_seq);
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		dcpim_rmem_free_skb(sk, skb1);
		dcpim_drop(sk, skb1);
		dsk->receiver.inflight_bytes += skb1->len;

	}
	/* If there is no skb after us, we are the last_skb ! */
	// if (!skb1)
	// 	tp->ooo_last_skb = skb;
add_sack:
	// if (tcp_is_sack(tp))
	dcpim_sack_new_ofo_skb(sk, seq, end_seq);
	return 0;
	// if (skb) {
	// 	tcp_grow_window(sk, skb);
	// 	skb_condense(skb);
	// 	skb_set_owner_r(skb, sk);
	// }
}

static void dcpim_ofo_queue(struct sock *sk)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	// __u32 dsack_high = dcpim->receiver.rcv_nxt;
	bool fragstolen, eaten;
	// bool fin;
	struct sk_buff *skb, *tail;
	struct rb_node *p;

	p = rb_first(&dsk->out_of_order_queue);
	while (p) {
		skb = rb_to_skb(p);
		if (after(DCPIM_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))
			break;

		// if (before(DCPIM_SKB_CB(skb)->seq, dsack_high)) {
		// 	// __u32 dsack = dsack_high;
		// 	// if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
		// 	// 	dsack_high = TCP_SKB_CB(skb)->end_seq;
		// 	// tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		// }
		p = rb_next(p);
		rb_erase(&skb->rbnode, &dsk->out_of_order_queue);

		if (unlikely(!after(DCPIM_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt))) {
			dsk->receiver.inflight_bytes += (DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
			dcpim_rmem_free_skb(sk, skb);
			dcpim_drop(sk, skb);
			continue;
		}
		/* the overlap can happen, so we might need to reduce offset_bytes */
		dsk->receiver.inflight_bytes += (dsk->receiver.rcv_nxt - DCPIM_SKB_CB(skb)->seq);
		tail = skb_peek_tail(&sk->sk_receive_queue);
		eaten = tail && dcpim_try_coalesce(sk, tail, skb, &fragstolen);
		dcpim_rcv_nxt_update(dsk, DCPIM_SKB_CB(skb)->end_seq);
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

void dcpim_data_ready(struct sock *sk)
{
        const struct dcpim_sock *dsk = dcpim_sk(sk);
        int avail = dsk->receiver.rcv_nxt - dsk->receiver.copied_seq;
		// printk("avail:%d sk->sk_rcvlowat:%d\n", avail, sk->sk_rcvlowat);
        if ((avail < sk->sk_rcvlowat) && !sock_flag(sk, SOCK_DONE)) {
        	return;
        }
        sk->sk_data_ready(sk);
}

int dcpim_handle_flow_sync_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	// struct dcpim_flow_sync_hdr *fh;
	struct dcpimhdr *dh;
	struct sock *sk, *child;
	// struct dcpim_message *msg;
	int sdif = inet_sdif(skb);
	// const struct iphdr *iph = ip_hdr(skb);
	bool refcounted = false;
	// struct dcpim_message *msg;
	// if (!pskb_may_pull(skb, sizeof(struct dcpimhdr))) {
	// 	goto drop;		/* No space for header. */
	// }
	dh =  dcpim_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
		// sk = __dcpim4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &dcpim_table);
	// }
	if(sk) {
		bh_lock_sock(sk);
		if(!sock_owned_by_user(sk)) {
			if(sk->sk_state == DCPIM_LISTEN) {
				child = dcpim_conn_request(sk, skb);
				if(child) {
					dsk = dcpim_sk(child);
					if(dh->type == NOTIFICATION_LONG) {
						/* this line needed to change later */
						if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
							hrtimer_start(&dsk->receiver.token_pace_timer, 0, HRTIMER_MODE_REL_PINNED_SOFT);	
							// sock_hold(child);
						}
					} else {
						/* small msg socket */
						child->sk_priority = 7;
					}
					/* add to flow table */
					dcpim_add_mat_tab(&dcpim_epoch, child);
					if(	dcpim_sk(child)->dma_device == NULL && dcpim_enable_ioat)
						dcpim_sk(child)->dma_device = get_free_ioat_dma_device(child);
					/* send flow syn ack back */
					dcpim_xmit_control(construct_syn_ack_pkt(child), child); 
				}
			} else if (sk->sk_state == DCPIM_ESTABLISHED) {
				/* send flow syn ack back */
				dcpim_xmit_control(construct_syn_ack_pkt(sk), sk); 
			}
			kfree_skb(skb);
		} else {
			dcpim_add_backlog(sk, skb, true);
		}
		bh_unlock_sock(sk);

		// /* create short message */
		// if(fh->message_size != UINT_MAX) {
		// 	msg = dcpim_lookup_message(dcpim_rx_messages,  iph->daddr, 
		// 		fh->common.dest, iph->saddr, fh->common.source, fh->message_id);
		// 	if(msg != NULL) {
		// 		goto drop;
		// 	} else {
		// 		msg = dcpim_message_new(dcpim_sk(msg_sock), fh->message_id, fh->message_size);
		// 		if(msg_sock == NULL) {
		// 			msg->hash = dcpim_message_hash(iph->daddr, fh->common.dest, iph->saddr, fh->common.source, fh->message_id);
		// 			msg->flow_sync_skb = skb;
		// 			skb_get(skb);
		// 		}
		// 		dcpim_insert_message(dcpim_rx_messages, msg);
		// 	}
		// }

	} else {
		kfree_skb(skb);
	}
    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}

// ktime_t start, end;
// __u32 backlog_time = 0;
int dcpim_handle_token_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	struct dcpim_token_hdr *th;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	uint32_t old_snd_una = 0;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_token_hdr))) {
		kfree_skb(skb);
		return 0;
	}
	th = dcpim_token_hdr(skb);
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&th->common), th->common.source,
            th->common.dest, sdif, &refcounted);
	if(sk) {
 		dsk = dcpim_sk(sk);
 		bh_lock_sock(sk);
 		skb->sk = sk;
	 	old_snd_una = dsk->sender.snd_una;

 		// if (!sock_owned_by_user(sk)) {
			/* clean rtx queue */
		/* add token */
 		// dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 	// 	/* add sack info */

		// /* start doing transmission (this part may move to different places later)*/
	    if(!sock_owned_by_user(sk)) {
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				if(th->num_sacks > 0)
 					dcpim_get_sack_info(sk, skb);
				sock_rps_save_rxhash(sk, skb);
				if(after(th->rcv_nxt, dsk->sender.snd_una))
					dsk->sender.snd_una = th->rcv_nxt;
				if(after(th->token_nxt, dsk->sender.token_seq))
					dsk->sender.token_seq = th->token_nxt;
				if(dsk->host && dsk->sender.snd_una != old_snd_una)
					atomic_sub((uint32_t)(dsk->sender.snd_una - old_snd_una), &dsk->host->total_unsent_bytes);
				dcpim_write_timer_handler(sk);
				dcpim_clean_rtx_queue(sk);
			}
			kfree_skb(skb);
	    } else {
			dcpim_add_backlog(sk, skb, true);
	 		// test_and_set_bit(DCPIM_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
	 //    if(!sock_owned_by_user(sk) || dsk->num_sacks == 0) {
	 // 		dcpim_write_timer_handler(sk);
	 //    } else {
	 // 		test_and_set_bit(DCPIM_RTX_DEFERRED, &sk->sk_tsq_flags);
	 //    }

        // } else {
        // 	// if(backlog_time % 100 == 0) {
        // 		// end = ktime_get();
        // 		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
        // 		// printk("num of backlog_time:%d\n", backlog_time);
        // 	// }
        //     dcpim_add_backlog(sk, skb, true);
        // }
        bh_unlock_sock(sk);
		// xmit_handle_new_token(&xmit_core_tab, skb);
	} else {
		kfree_skb(skb);
	}
	// kfree_skb(skb);

    if (refcounted) {
        sock_put(sk);
    }
	return 0;
}

int dcpim_handle_ack_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	// struct dcpimhdr *dh;
	struct dcpim_ack_hdr *ah;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	uint32_t old_snd_una = 0;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_ack_hdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	ah = dcpim_ack_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
            ah->common.dest, sdif, &refcounted);
    // }

	if(sk) {
 		bh_lock_sock(sk);
		dsk = dcpim_sk(sk);
		if (!sock_owned_by_user(sk)) {
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				old_snd_una = dsk->sender.snd_una;
				if(after(ah->rcv_nxt, dsk->sender.snd_una))
					dsk->sender.snd_una = ah->rcv_nxt;
				if(dsk->host && dsk->sender.snd_una != old_snd_una)
					atomic_sub((uint32_t)(dsk->sender.snd_una - old_snd_una), &dsk->host->total_unsent_bytes);
				dcpim_clean_rtx_queue(sk);
			}
			kfree_skb(skb);
        } else {
			dcpim_add_backlog(sk, skb, true);
	    }
        bh_unlock_sock(sk);
	   

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);
	} else {
		kfree_skb(skb);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}

int dcpim_handle_syn_ack_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	// struct dcpimhdr *dh;
	struct dcpimhdr *dh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	bool remove_timer = false;
	// uint32_t old_snd_una = 0;
	// if (!pskb_may_pull(skb, sizeof(struct dcpimhdr))) {
	// 	kfree_skb(skb);		/* No space for header. */
	// 	return 0;
	// }
	dh = dcpim_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
    // }
	
	if(sk) {
 		bh_lock_sock(sk);
		dsk = dcpim_sk(sk);
		if (!sock_owned_by_user(sk)) {
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				dsk->sender.syn_ack_recvd = true;
				remove_timer = true;
			}
			kfree_skb(skb);
        } else {
			dcpim_add_backlog(sk, skb, true);
	    }
        bh_unlock_sock(sk);
		if(remove_timer)
			hrtimer_cancel(&dsk->sender.rtx_flow_sync_timer);
		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);
	} else {
		kfree_skb(skb);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}

int dcpim_handle_fin_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	struct dcpimhdr *dh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	// if (!pskb_may_pull(skb, sizeof(struct dcpim_ack_hdr))) {
	// 	kfree_skb(skb);		/* No space for header. */
	// 	return 0;
	// }
	dh = dcpim_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
    // }
	if(sk) {
 		bh_lock_sock(sk);
		dsk = dcpim_sk(sk);
		if (!sock_owned_by_user(sk)) {
			// printk("reach here:%d", __LINE__);
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				dsk->delay_destruct = false;
				dcpim_xmit_control(construct_fin_ack_pkt(sk), sk); 
				dcpim_set_state(sk, DCPIM_CLOSE);
				/* To Do: need to check unhash condition for short flows */
				sk->sk_prot->unhash(sk);
				/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
				if (inet_csk(sk)->icsk_bind_hash) {
					inet_put_port(sk);
				} 
				// dcpim_write_queue_purge(sk);
				sk->sk_data_ready(sk);
			}
	        kfree_skb(skb);
        } else {
            dcpim_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} else {
		/* send fin ack packet */
		dcpim_flip_header(skb, FIN_ACK);
		if(dev_queue_xmit(skb)) {
			WARN_ON_ONCE(true);
		}
			// kfree_skb(skb);
		// printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}

int dcpim_handle_fin_ack_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	// struct inet_sock *inet;
	// struct dcpim_peer *peer;
	// struct iphdr *iph;
	struct dcpimhdr *dh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	// if (!pskb_may_pull(skb, sizeof(struct dcpim_ack_hdr))) {
	// 	kfree_skb(skb);		/* No space for header. */
	// 	return 0;
	// }
	dh = dcpim_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
    // }
	if(sk) {
 		bh_lock_sock(sk);
		dsk = dcpim_sk(sk);
		if (!sock_owned_by_user(sk)) {
			// printk("reach here:%d", __LINE__);
			dsk->delay_destruct = false;
			sk->sk_prot->unhash(sk);
			/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
			if (inet_csk(sk)->icsk_bind_hash) {
				inet_put_port(sk);
			} 
	        kfree_skb(skb);
        } else {
            dcpim_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} else {
		kfree_skb(skb);
		// printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}

static int  dcpim_queue_rcv(struct sock *sk, struct sk_buff *skb,  bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

	/* update inflight bytes */
	/* Note since the overlap might happen, we need not use skb->len, but end_seq - rcv_nxt*/
	dcpim_sk(sk)->receiver.inflight_bytes -= (DCPIM_SKB_CB(skb)->end_seq - dcpim_sk(sk)->receiver.rcv_nxt);
	eaten = (tail &&
		 dcpim_try_coalesce(sk, tail,
				  skb, fragstolen)) ? 1 : 0;
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		// skb_set_owner_r(skb, sk);
	}
	dcpim_rcv_nxt_update(dcpim_sk(sk), DCPIM_SKB_CB(skb)->end_seq);
	return eaten;
}

int dcpim_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	bool fragstolen;
	int eaten;
	int old_skbsize;
	if (DCPIM_SKB_CB(skb)->seq == DCPIM_SKB_CB(skb)->end_seq) {
		dcpim_rmem_free_skb(sk, skb);
		return 0;
	}
	// if(atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf) {
	// 	struct inet_sock *inet = inet_sk(sk);
	//     printk("seq num:%u\n", DCPIM_SKB_CB(skb)->seq);
	//     printk("inet sk dport:%d\n", ntohs(inet->inet_dport));
	//     printk("discard packet due to memory:%d\n", __LINE__);
	// 	sk_drops_add(sk, skb);
	// 	kfree_skb(skb);
	// 	return 0;
	// }
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);

	// skb_dst_drop(skb);
	__skb_pull(skb, (dcpim_hdr(skb)->doff << 2)+ sizeof(struct data_segment));
	// printk("handle packet data queue?:%d\n", DCPIM_SKB_CB(skb)->seq);

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (DCPIM_SKB_CB(skb)->seq == dsk->receiver.rcv_nxt) {
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
		eaten = dcpim_queue_rcv(sk, skb, &fragstolen);

		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {
			dcpim_ofo_queue(sk);
		}

		// 	/* RFC5681. 4.2. SHOULD send immediate ACK, when
		// 	 * gap in queue is filled.
		// 	 */
		// 	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue))
		// 		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		// }

		if (dsk->num_sacks)
			dcpim_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		if (!sock_flag(sk, SOCK_DEAD)) {
			dcpim_data_ready(sk);
		}
		return 0;
	}
	if (!after(DCPIM_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt)) {
		// printk("duplicate drop\n");
		// printk("duplicate seq:%u\n", DCPIM_SKB_CB(skb)->seq);
		dcpim_rmem_free_skb(sk, skb);
		dcpim_drop(sk, skb);
		return 0;
	}

	/* Out of window. F.e. zero window probe. */
	// if (!before(DCPIM_SKB_CB(skb)->seq, dsk->rcv_nxt + tcp_receive_window(dsk)))
	// 	goto out_of_window;

	if (unlikely(before(DCPIM_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt))) {
		/* Partial packet, seq < rcv_next < end_seq; unlikely */
		// tcp_dsack_set(sk, DCPIM_SKB_CB(skb)->seq, dsk->rcv_nxt);


		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		// if (!tcp_receive_window(dsk)) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }
		old_skbsize = skb->truesize;
		// printk("core:%d seq: %u end_seq: %u rcv_nxt:%u skb->truesize:%u\n", raw_smp_processor_id(), DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt, skb->truesize);
		pskb_may_pull(skb, dsk->receiver.rcv_nxt - DCPIM_SKB_CB(skb)->seq);
		atomic_add(skb->truesize - old_skbsize, &sk->sk_rmem_alloc);
		__skb_pull(skb,  dsk->receiver.rcv_nxt - DCPIM_SKB_CB(skb)->seq);
		DCPIM_SKB_CB(skb)->seq = dsk->receiver.rcv_nxt;
		goto queue_and_out;
	}
	dcpim_data_queue_ofo(sk, skb);
	/* check if we can send tokens */
	dcpim_token_timer_defer_handler(sk);
	return 0;
}

bool dcpim_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check)
{
		struct dcpim_sock *dsk = dcpim_sk(sk);
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        // skb_condense(skb);

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
        atomic_add(skb->truesize, &dsk->receiver.backlog_len);

        return false;

 }

/**
 * dcpim_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully.
 */
 ktime_t start,end;
 __u64 total_bytes;
int dcpim_handle_data_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	struct dcpim_data_hdr *dh;
	struct sock *sk;
	struct iphdr *iph;
	int sdif = inet_sdif(skb);

	bool refcounted = false;
	bool discard = false;
	// printk("receive data pkt\n");
	// if(get_random_u32() % 10 <= 0)
	// 	goto drop;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_data_hdr)))
		goto drop;		/* No space for header. */
	dh =  dcpim_data_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&dh->common), dh->common.source,
            dh->common.dest, sdif, &refcounted);
    if(!sk) {
    	goto drop;
	}

	dcpim_v4_fill_cb(skb, iph, dh);
	if(sk) {
		dsk = dcpim_sk(sk);
		iph = ip_hdr(skb);
 		bh_lock_sock(sk);
		// if(raw_smp_processor_id() == 4) {
		// 	printk("receive data pkt seq: %u end_seq: %u rcv_nxt:%u\n", DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(skb)->end_seq, dsk->receiver.rcv_nxt);

		// }
 		/* inflight_bytes for now is best-effort estimation */
        // ret = 0;
		// printk("data seq: %u rcv_nxt:%u \n", DCPIM_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt);
        if (!sock_owned_by_user(sk)) {
			/* current place to set rxhash for RFS/RPS */
			// printk("interrupt core:%d skb->hash:%u\n", raw_smp_processor_id(), skb->hash);
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				sock_rps_save_rxhash(sk, skb);
				dcpim_data_queue(sk, skb);
				WARN_ON_ONCE(dsk->receiver.inflight_bytes < 0);
			} else
				discard = true;
			// dcpim_check_flow_finished_at_receiver(dsk);;
        } else {
        	// printk("add to backlog\n");
            if (dcpim_add_backlog(sk, skb, true)) {
            	discard = true;
				// goto discard_skb;
                // goto discard_and_relse;
            }
        }
        bh_unlock_sock(sk);
	} else {
		discard = true;
	}
	if (discard) {
	    // printk("seq num:%u\n", DCPIM_SKB_CB(skb)->seq);
	    // printk("discard packet:%d\n", __LINE__);
		// sk_drops_add(sk, skb);
		kfree_skb(skb);
	}

    if (refcounted) {
        sock_put(sk);
    }
    return 0;
drop:
    /* Discard frame. */
    kfree_skb(skb);
    return 0;

// discard_and_relse:
//     printk("seq num:%u\n", DCPIM_SKB_CB(skb)->seq);
//     printk("discard packet due to memory:%d\n", __LINE__);
//     sk_drops_add(sk, skb);
//     if (refcounted)
//             sock_put(sk);
//     goto drop;
	// kfree_skb(skb);
}

static bool dcpim_handle_msgid_entry(struct dcpim_message *msg, struct dcpim_sock *dsk) {
	struct dcpim_msgid_entry *entry = NULL, *temp;
	bool append = false;
	if(msg->id < dsk->receiver.rcv_msg_nxt)
		return false;
	else if(msg->id == dsk->receiver.rcv_msg_nxt) {
		dsk->receiver.rcv_msg_nxt += 1;
		goto remove_entry;
	}
	list_for_each_entry(temp, &dsk->receiver.reordered_msgid_list, entry) {
		if(temp->msg_id == msg->id)
			return false;
		if(temp->msg_id < msg->id)
			continue;
		if(temp->msg_id > msg->id) {
			entry = kzalloc(sizeof(struct dcpim_msgid_entry), GFP_ATOMIC);
			entry->msg_id = msg->id;
			list_add_tail(&entry->entry, &temp->entry);
			append = true;
			break;
		}
	}
	if(!append) {
		entry = kzalloc(sizeof(struct dcpim_msgid_entry), GFP_ATOMIC);
		entry->msg_id = msg->id;
		list_add_tail(&entry->entry, &dsk->receiver.reordered_msgid_list);
	}
	return true;
remove_entry:
	list_for_each_entry_safe(entry, temp, &dsk->receiver.reordered_msgid_list, entry) {
		if(entry->msg_id == dsk->receiver.rcv_msg_nxt) {
			dsk->receiver.rcv_msg_nxt += 1;
			list_del_init(&entry->entry);
			kfree(entry);
			continue;
		}
		break;

	}
	return true;
}

/**
 * dcpim_handle_flow_sync_msg_pkt() - Handler for incoming FLOW_SYNC packets of message
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully.
 */
int dcpim_handle_flow_sync_msg_pkt(struct sk_buff *skb) {
	struct dcpim_flow_sync_hdr *fh;
	struct dcpim_message *msg;
	struct sock* sk;
	const struct iphdr *iph = NULL;
	bool free_skb = true, insert = false, success = false, refcounted = false;
	int sdif = inet_sdif(skb);
	s64 num_msgs = 0;
	// struct dcpim_message *msg;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_flow_sync_hdr))) {
		goto drop;		/* No space for header. */
	}
	fh =  dcpim_flow_sync_hdr(skb);
	iph = ip_hdr(skb);
	msg = dcpim_lookup_message(dcpim_rx_messages,  iph->daddr, 
			fh->common.dest, iph->saddr, fh->common.source, fh->message_id);
	if(msg != NULL) {
		dcpim_message_put(msg);
		goto drop;
	}
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&fh->common), fh->common.source,
			fh->common.dest, sdif, &refcounted);
	if(!sk)
		goto drop;
	bh_lock_sock(sk);
	if(sk->sk_state == DCPIM_ESTABLISHED) {
		msg = dcpim_message_new(dcpim_sk(sk), iph->daddr,  fh->common.dest, iph->saddr, fh->common.source, fh->message_id, fh->message_size);
		if(msg == NULL) {
			WARN_ON(true);
			bh_unlock_sock(sk);
			goto drop;
		}
		msg->state = DCPIM_WAIT_FIN_RX;
		success = dcpim_handle_msgid_entry(msg, dcpim_sk(sk));
		if(success) {
			list_add_tail(&msg->table_link, &dcpim_sk(sk)->receiver.unfinished_list);
			dcpim_message_hold(msg);
			num_msgs = atomic64_inc_return(&dcpim_num_rx_msgs);
			hrtimer_start(&msg->fast_rtx_timer, ns_to_ktime(msg->timeout) * num_msgs, 
				HRTIMER_MODE_REL_PINNED_SOFT);
		} else {
			/* transmit fin msg since the msg has already been received as the prior lookup messsage doesn't find the socket */
			dcpim_xmit_control(construct_fin_msg_pkt(sk, fh->message_id), sk);
		}
	}
	bh_unlock_sock(sk);
	if(!success) {
		if(msg != NULL)
			dcpim_message_destroy(msg);
		// kfree(msg);
		goto drop;
	}
	insert = dcpim_insert_message(dcpim_rx_messages, msg);
	if(!insert) {
		WARN_ON_ONCE(true);
		dcpim_message_put(msg);
	}
drop:
    if (refcounted) {
        sock_put(sk);
    }
	if(free_skb)
		kfree_skb(skb);
	return 0;
	// sk = skb_steal_sock(skb);
	// if(!sk) {
}

/**
 * dcpim_handle_data_msg_pkt() - Handler for incoming DATA packets of message
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully.
 */
int dcpim_handle_data_msg_pkt(struct sk_buff *skb) {
	struct dcpim_sock *dsk;
	struct dcpim_message *msg = NULL;
	struct dcpim_data_hdr *dh;
	struct sock *sk;
	struct iphdr *iph;
	// int sdif = inet_sdif(skb);

	bool discard = false;
	bool is_complete = false;
	// success = false, insert = false;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_data_hdr)))
		goto drop;		/* No space for header. */
	dh =  dcpim_data_hdr(skb);
	iph = ip_hdr(skb);
	msg = dcpim_lookup_message(dcpim_rx_messages,  iph->daddr, 
			dh->common.dest, iph->saddr, dh->common.source, dh->message_id);
	dcpim_v4_fill_cb(skb, iph, dh);
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&dh->common), dh->common.source,
	// 	dh->common.dest, sdif, &refcounted);
	// if(dh->flow_sync) {
	// 	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&dh->common), dh->common.source,
	// 		dh->common.dest, sdif, &refcounted);
	// 	if(!sk) {
	// 		goto find_msg;
	// 	}
	// 	msg = dcpim_message_new(NULL, iph->daddr,  dh->common.dest, iph->saddr, dh->common.source, dh->message_id, dh->message_size);
	// 	if(msg == NULL) {
	// 		goto find_msg;
	// 	}
	// 	msg->state = DCPIM_WAIT_FIN_RX;
	// 	bh_lock_sock(sk);
	// 	if(sk->sk_state == DCPIM_ESTABLISHED) {
	// 		success = dcpim_handle_msgid_entry(msg, dcpim_sk(sk));
	// 		if(success) {
	// 			list_add_tail(&msg->table_link, &dcpim_sk(sk)->receiver.unfinished_list);
	// 			dcpim_message_hold(msg);
	// 		}
	// 	}
	// 	bh_unlock_sock(sk);
	// 	if(!success) {
	// 		kfree(msg);
	// 		msg = NULL;
	// 		goto find_msg;
	// 	}
	// 	insert = dcpim_insert_message(dcpim_rx_messages, msg);

	// 	if(unlikely(!insert)) {
	// 		WARN_ON_ONCE(true);
	// 		kfree(msg);
	// 		msg = NULL;
	// 	} else {
	// 		dcpim_message_hold(msg);	
	// 	}
	// } 
// find_msg:
	// if(!msg)
	if(!msg) {
		/* try to retransmit fin pkt if we need to */
		// if(unlikely(dh->flow_sync && sk)) {
		// 	bh_lock_sock(sk);
		// 	if(sk->sk_state == DCPIM_ESTABLISHED)
		// 		dcpim_xmit_control(construct_fin_msg_pkt(sk, dh->message_id), sk);
		// 	bh_unlock_sock(sk);
		// }
		discard = true;
		goto drop;
	}
	spin_lock(&msg->lock);
	if(msg->state == DCPIM_WAIT_FIN_RX) {
		/* skb is handled by receive data; not need to free */
		is_complete = dcpim_message_receive_data(msg, skb);
		if(is_complete) {
			// printk("is complete ");

			// msg->state = DCPIM_WAIT_ACK;
			/* remove message */
			dcpim_remove_message(dcpim_rx_messages, msg, true);
			msg->state = DCPIM_FINISH_RX;
		}
	} else {
		discard = true;
	}
	spin_unlock(&msg->lock);
	if(is_complete) {
		// printk("message fin skb:%p %p\n", fin_skb, fin_skb->dev);
		// fin_skb = construct_fin_msg_pkt(sk, msg->id);
		// dcpim_xmit_control(fin_skb, sk);
		// skb_dump(KERN_WARNING, fin_skb, true);
		// dcpim_message_hold(msg);
		// hrtimer_start(&msg->rtx_timer, msg->timeout , HRTIMER_MODE_REL_PINNED_SOFT);
		// if(dcpim_xmit_control(fin_skb, sk)) {
		// 	WARN_ON_ONCE(true);
		// }
		// msg->fin_skb = NULL;
		/* add to socket */
		atomic64_dec_return(&dcpim_num_rx_msgs);
		hrtimer_cancel(&msg->fast_rtx_timer);
		dsk = msg->dsk;
		sk = (struct sock*)dsk;
		if(sk) {
			// dsk = dcpim_sk(sk);
			bh_lock_sock(sk);
			list_del_init(&msg->table_link);
			dcpim_message_put(msg);
			if(!sock_owned_by_user(sk)) {
				if(sk->sk_state == DCPIM_ESTABLISHED) { 
					/* construct the fin */
					dsk->receiver.num_msgs += 1;
					list_add_tail(&msg->table_link, &dsk->receiver.msg_list);
					dcpim_message_hold(msg);
					sk->sk_data_ready(sk);
				} 
				dcpim_xmit_control(construct_fin_msg_pkt(sk, msg->id), sk);
			} else {
				/* add to backlog and initiate the signal */
				list_add_tail(&msg->table_link, &dsk->receiver.msg_backlog);
				dcpim_message_hold(msg);
				if (!test_and_set_bit(DCPIM_MSG_RX_DEFERRED, &sk->sk_tsq_flags)) {
					sock_hold(sk);
				}
			}			
			bh_unlock_sock(sk);
		}
	}
	dcpim_message_put(msg);
drop:
    // if (refcounted) {
    //     sock_put(sk);
    // }
    /* Discard frame. */
	if(discard)
   		kfree_skb(skb);
    return 0;
}




/**
 * dcpim_handle_fin_msg_pkt() - Handler for incoming fin packets of message
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully.
 */
int dcpim_handle_fin_msg_pkt(struct sk_buff *skb) {
	struct dcpim_fin_hdr *fh;
	struct dcpim_message *msg = NULL;
	struct iphdr *iph;
	struct dcpim_sock *dsk;
	struct sock* sk = NULL;
	bool refcounted = false;
	bool free_skb = true;
	int sdif = inet_sdif(skb);
	// struct dcpim_message *msg;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_fin_hdr))) {
		goto drop;		/* No space for header. */
	}
	iph = ip_hdr(skb);
	fh =  dcpim_fin_hdr(skb);
	if(fh->message_id == -1 ) {
		sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&fh->common), fh->common.source,
			fh->common.dest, sdif, &refcounted);
		dsk = dcpim_sk(sk);
	} else {
		msg = dcpim_lookup_message(dcpim_tx_messages,  iph->daddr, fh->common.dest, iph->saddr, fh->common.source, fh->message_id);
	}
	/* TO DO: change the state of message */
	/* send fin_ack */
	// dcpim_flip_header(skb, FIN_ACK_MSG);
	// if(dev_queue_xmit(skb)) {
	// 	WARN_ON_ONCE(true);
	// }
	if(msg) {
		dcpim_remove_message(dcpim_tx_messages, msg, true);
		dsk = msg->dsk;
		sk = (struct sock*)dsk;
		spin_lock(&msg->lock);
		msg->state = DCPIM_FINISH_TX;
		// dcpim_message_flush_skb(msg);
		spin_unlock(&msg->lock);
	}
	
	if(sk) {
		// dsk = msg->dsk;
		// sk = (struct sock*)dsk;
		bh_lock_sock(sk);
		if(!sock_owned_by_user(sk)) {
			// if(sk->sk_state == DCPIM_ESTABLISHED) {
			if(msg) {
				spin_lock(&msg->lock);
				dcpim_message_flush_skb(msg);
				spin_unlock(&msg->lock);
			}
			/* copied from TCP socket */
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				if(msg) {
					dsk->sender.inflight_msgs -= 1;
				}
				dsk->sender.accmu_rx_msgs = fh->num_msgs;
				smp_mb();
				if (sk->sk_socket && test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) && dsk->sender.inflight_msgs + dsk->sender.accmu_rx_msgs  <= dsk->sender.msg_threshold) {
					sk_stream_write_space(sk);
				}
			}
			// }
		} else {
			if(msg) {
				list_add_tail(&msg->fin_link, &dsk->sender.fin_msg_backlog);
				dcpim_message_hold(msg);
				if (!test_and_set_bit(DCPIM_MSG_TX_DEFERRED, &sk->sk_tsq_flags)) {
					sock_hold(sk);
				}
			}
			dcpim_add_backlog(sk, skb, true);
			free_skb = false;
		}
		bh_unlock_sock(sk);
	}
	if(msg)
		dcpim_message_put(msg);
	if(refcounted)
		sock_put(sk);
	if(free_skb)
		kfree_skb(skb);
	return 0;
drop:
	kfree_skb(skb);
	return 0;
	// sk = skb_steal_sock(skb);
	// if(!sk) {
}

/**
 * dcpim_handle_resync_msg_pkt() - Handler for incoming resync msg packets of message; handling fast retransmission
 * @skb:   resync msg packet
 * 
 * Return: Zero means the function completed successfully.
 */
int dcpim_handle_resync_msg_pkt(struct sk_buff *skb) {
	struct dcpim_resync_msg_hdr *rh;
	struct dcpim_message *msg;
	struct iphdr *iph;
	struct dcpim_sock *dsk;
	struct sock* sk;
	bool remove_msg = false;
	// struct dcpim_message *msg;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_resync_msg_hdr))) {
		goto drop;		/* No space for header. */
	}
	iph = ip_hdr(skb);
	rh =  dcpim_resync_msg_hdr(skb);
	msg = dcpim_lookup_message(dcpim_tx_messages,  iph->daddr, rh->common.dest, iph->saddr, rh->common.source, rh->message_id);
	/* TO DO: change the state of message */
	/* send fin_ack */
	// dcpim_flip_header(skb, FIN_ACK_MSG);
	// if(dev_queue_xmit(skb)) {
	// 	WARN_ON_ONCE(true);
	// }

	if(msg) {
		dsk = msg->dsk;
		sk = (struct sock*)dsk;
		hrtimer_cancel(&msg->rtx_timer);
		bh_lock_sock(sk);
		spin_lock(&msg->lock);
		if (msg->state == DCPIM_WAIT_FIN_TX) {
			/* for now, only retransmit if the socket is still in established state */
			msg->state = DCPIM_WAIT_FOR_MATCHING;
			if(!sock_owned_by_user(sk)) {
				if(sk->sk_state == DCPIM_ESTABLISHED) {
					/* add msg_list to the head of rtx_msg_list */
					list_add(&msg->table_link, &dsk->sender.rtx_msg_list);
					dcpim_message_hold(msg);
					dsk->sender.num_rtx_msgs += 1;
					/* Give one message one channel for doing rtx at one epoch */
					atomic_add(dcpim_epoch.epoch_bytes_per_k, &msg->dsk->host->total_unsent_bytes);
					atomic_add(1, &msg->dsk->host->rtx_msg_size);
					/* wake up socket and participate matcihing for retransmssion */
					// queue_work_on(raw_smp_processor_id(), dcpim_wq, &dsk->rtx_msg_work);
				} else {
					dcpim_message_flush_skb(msg);
					remove_msg = true;
				}
			} else {
				list_add_tail(&msg->table_link, &dsk->sender.rtx_msg_backlog);
				dcpim_message_hold(msg);
				if (!test_and_set_bit(DCPIM_MSG_RTX_DEFERRED, &sk->sk_tsq_flags)) {
					sock_hold(sk);
				}
			}
		} else if (msg->state == DCPIM_WAIT_FIN_RX || msg->state == DCPIM_INIT)
			WARN_ON(true);
		spin_unlock(&msg->lock);
		bh_unlock_sock(sk);
		dcpim_message_put(msg);
		if(remove_msg) {
			dcpim_remove_message(dcpim_tx_messages, msg, true);
		}
	}
	kfree_skb(skb);
	return 0;
drop:
	kfree_skb(skb);
	return 0;
	// sk = skb_steal_sock(skb);
	// if(!sk) {
}

/**
 * dcpim_handle_fin_ack_msg_pkt() - Handler for incoming fin_ack packets of message
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully.
 */
int dcpim_handle_fin_ack_msg_pkt(struct sk_buff *skb) {
	struct dcpim_fin_ack_hdr *fh;
	struct dcpim_message *msg;
	struct iphdr *iph;
	// struct dcpim_message *msg;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_fin_ack_hdr))) {
		goto drop;		/* No space for header. */
	}
	iph = ip_hdr(skb);
	fh =  dcpim_fin_ack_hdr(skb);
	msg = dcpim_lookup_message(dcpim_rx_messages,  iph->daddr, fh->common.dest, iph->saddr, fh->common.source, fh->message_id);
	if(msg) {
		dcpim_remove_message(dcpim_rx_messages, msg, true);
		/* reduce inflight msg size at rx side */
		spin_lock(&msg->lock);
		if(msg->state == DCPIM_WAIT_ACK)
			msg->state = DCPIM_FINISH_RX;
		spin_unlock(&msg->lock);
		dcpim_message_put(msg);
	}
drop:
	kfree_skb(skb);
	return 0;
	// sk = skb_steal_sock(skb);
	// if(!sk) {
}

/* should hold the lock, before calling this function；
 * This function is only called for backlog handling from the release_sock()
 */
int dcpim_v4_do_rcv(struct sock *sk, struct sk_buff *skb) {
	struct dcpimhdr* dh;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	uint32_t old_snd_una = dsk->sender.snd_una;
	dh = dcpim_hdr(skb);
	atomic_sub(skb->truesize, &dsk->receiver.backlog_len);
	/* current place to set rxhash for RFS/RPS */
	// printk("backlog rcv\n");
	if(sk->sk_state == DCPIM_ESTABLISHED) {
		if(dh->type == DATA) {
 			sock_rps_save_rxhash(sk, skb);
			dcpim_data_queue(sk, skb);
			WARN_ON_ONCE(dsk->receiver.inflight_bytes < 0);
			return 0;
			// return __dcpim4_lib_rcv(skb, &dcpim_table, IPPROTO_DCPIM);
		} else if (dh->type == FIN) {
			// printk("reach here:%d", __LINE__);
			dsk->delay_destruct = false;
			dcpim_xmit_control(construct_fin_ack_pkt(sk), sk); 
			dcpim_set_state(sk, DCPIM_CLOSE);
			sk->sk_prot->unhash(sk);
			/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
			if (inet_csk(sk)->icsk_bind_hash) {
				inet_put_port(sk);
			} 
			// dcpim_write_queue_purge(sk);
			// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
			sk->sk_data_ready(sk);
		} else if (dh->type == ACK) {
			struct dcpim_ack_hdr *ah = dcpim_ack_hdr(skb);
			if(after(ah->rcv_nxt,dsk->sender.snd_una))
				dsk->sender.snd_una = ah->rcv_nxt;
			if(dsk->host && dsk->sender.snd_una != old_snd_una)
				atomic_sub((uint32_t)(dsk->sender.snd_una - old_snd_una), &dsk->host->total_unsent_bytes);
			dcpim_clean_rtx_queue(sk);
		} else if (dh->type == TOKEN) {
			/* clean rtx queue */
			struct dcpim_token_hdr *th = dcpim_token_hdr(skb);
 			sock_rps_save_rxhash(sk, skb);
			if(th->num_sacks > 0)
				dcpim_get_sack_info(sk, skb);
			if(after(th->rcv_nxt, dsk->sender.snd_una))
				dsk->sender.snd_una = th->rcv_nxt;
			if(after(th->token_nxt, dsk->sender.token_seq))
				dsk->sender.token_seq = th->token_nxt;
			if(dsk->host && dsk->sender.snd_una != old_snd_una)
				atomic_sub((uint32_t)(dsk->sender.snd_una - old_snd_una), &dsk->host->total_unsent_bytes);
			dcpim_write_timer_handler(sk);
			dcpim_clean_rtx_queue(sk);		
		} else if (dh->type == NOTIFICATION_LONG || dh->type == NOTIFICATION_SHORT) {
			/* send syn ack back */
			dcpim_xmit_control(construct_syn_ack_pkt(sk), sk); 
		} else if (dh->type == SYN_ACK) {
			dsk->sender.syn_ack_recvd = true;
			hrtimer_cancel(&dsk->sender.rtx_flow_sync_timer);
		} else 	if(dh->type == FIN_ACK) {
			/* it is impossible to reach here */
			WARN_ON_ONCE(true);
			dsk->delay_destruct = false;
		} else if (dh->type == FIN_MSG) {
			struct dcpim_fin_hdr *fh = dcpim_fin_hdr(skb);
			dsk->sender.accmu_rx_msgs = fh->num_msgs;
			smp_mb();
			if (sk->sk_socket && test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) && dsk->sender.inflight_msgs + dsk->sender.accmu_rx_msgs <= dsk->sender.msg_threshold) {
				sk_stream_write_space(sk);
			}
		}
	} else if(sk->sk_state == DCPIM_LISTEN) {
		if(dh->type == NOTIFICATION_LONG || dh->type == NOTIFICATION_SHORT) {
			struct sock* child;
			child = dcpim_conn_request(sk, skb);
			if(child) {
				dsk = dcpim_sk(child);
				if(dh->type == NOTIFICATION_LONG) {
					/* this line needed to change later */
					if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
						hrtimer_start(&dsk->receiver.token_pace_timer, 0, HRTIMER_MODE_REL_PINNED_SOFT);	
						// sock_hold(child);
					}
				} else {
					/* small msg socket */
					child->sk_priority = 7;
				}
				dcpim_add_mat_tab(&dcpim_epoch, child);
				if(dcpim_sk(child)->dma_device == NULL && dcpim_enable_ioat)
					dcpim_sk(child)->dma_device = get_free_ioat_dma_device(child);
				/* send syn ack back */
				dcpim_xmit_control(construct_syn_ack_pkt(child), child); 
			}  
			// return __dcpim4_lib_rcv(skb, &dcpim_table, IPPROTO_DCPIM);
		} 
	} else {
		if(dh->type == FIN_ACK || dh->type == FIN) {
			dsk->delay_destruct = false;
			if(dh->type == FIN) {
				dcpim_xmit_control(construct_fin_ack_pkt(sk), sk); 
			} 
			sk->sk_prot->unhash(sk);
			/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
			if (inet_csk(sk)->icsk_bind_hash) {
				inet_put_port(sk);
			} 
		}
	}
	kfree_skb(skb);
	return 0;
}

/* Short message socket handling logic */

/* To Do: Redundancy check of short message for extreme case (Sync packet + flow destroy in hash table race condition) */
