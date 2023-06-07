#define pr_fmt(fmt) "DCPIM: " fmt

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
// #include "net_dcpim.h"
// #include "net_dcpimlite.h"
#include "uapi_linux_dcpim.h"
// struct udp_table dcpim_table __read_mostly;
// EXPORT_SYMBOL(dcpim_table);


long sysctl_dcpim_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_dcpim_mem);

atomic_long_t dcpim_memory_allocated;
EXPORT_SYMBOL(dcpim_memory_allocated);

// struct dcpim_match_tab dcpim_match_table;
// EXPORT_SYMBOL(dcpim_match_table);

struct dcpim_params dcpim_params;
EXPORT_SYMBOL(dcpim_params);

struct dcpim_epoch dcpim_epoch;
EXPORT_SYMBOL(dcpim_epoch);

struct inet_hashinfo dcpim_hashinfo;
EXPORT_SYMBOL(dcpim_hashinfo);

struct workqueue_struct *dcpim_wq;

struct dcpim_message_bucket dcpim_tx_messages[DCPIM_BUCKETS];
struct dcpim_message_bucket dcpim_rx_messages[DCPIM_BUCKETS];

#define MAX_DCPIM_PORTS 65536
#define PORTS_PER_CHAIN (MAX_DCPIM_PORTS / DCPIM_HTABLE_SIZE_MIN)
static inline bool before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)


void dcpim_rbtree_insert(struct rb_root *root, struct sk_buff *skb)
{
        struct rb_node **p = &root->rb_node;
        struct rb_node *parent = NULL;
        struct sk_buff *skb1;

        while (*p) {
                parent = *p;
                skb1 = rb_to_skb(parent);
                if (before(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(skb1)->seq))
                        p = &parent->rb_left;
                else
                        p = &parent->rb_right;
        }
        rb_link_node(&skb->rbnode, parent, p);
        rb_insert_color(&skb->rbnode, root);
}

static void dcpim_rtx_queue_purge(struct sock *sk)
{
	struct rb_node *p = rb_first(&sk->tcp_rtx_queue);

	// dcpim_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		dcpim_rtx_queue_unlink(skb, sk);
		dcpim_wmem_free_skb(sk, skb);
	}
}

static void dcpim_ofo_queue_purge(struct sock *sk)
{
	struct dcpim_sock * dsk = dcpim_sk(sk);
	struct rb_node *p = rb_first(&dsk->out_of_order_queue);

	// dcpim_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		dcpim_ofo_queue_unlink(skb, sk);
		dcpim_rmem_free_skb(sk, skb);
	}
}

void dcpim_write_queue_purge(struct sock *sk)
{
	// struct dcpim_sock *dsk;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
		dcpim_wmem_free_skb(sk, skb);
	}
	dcpim_rtx_queue_purge(sk);
	// skb = sk->sk_tx_skb_cache;
	// if (skb) {
	// 	__kfree_skb(skb);
	// 	sk->sk_tx_skb_cache = NULL;
	// }
	// sk_mem_reclaim(sk);
}

void dcpim_read_queue_purge(struct sock* sk) {
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		dcpim_rmem_free_skb(sk, skb);
	}
	dcpim_ofo_queue_purge(sk);
}

int dcpim_err(struct sk_buff *skb, u32 info)
{
	return 0;
	// return __dcpim4_lib_err(skb, info, &dcpim_table);
}


int sk_wait_ack(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc = 0;
	add_wait_queue(sk_sleep(sk), &wait);
	while(1) {
		if(sk->sk_state == DCPIM_CLOSE)
			break;
		if (signal_pending(current))
			break;
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		rc = sk_wait_event(sk, timeo, sk->sk_state == DCPIM_CLOSE, &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	return rc;
}
EXPORT_SYMBOL(sk_wait_ack);


int dcpim_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len) {
	// DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	// int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	int sent_len = 0;
	long timeo;
	int flags;
	flags = msg->msg_flags;
	if (sk->sk_state != DCPIM_ESTABLISHED) {
		return -ENOTCONN;
	}

	/* the bytes from user larger than the flow size */
	// if (dsk->sender.write_seq >= dsk->total_length) {
	// 	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 	sk_wait_ack(sk, &timeo);
	// 	return -EMSGSIZE;
	// }

	// if (len + dsk->sender.write_seq > dsk->total_length) {
	// 	len = dsk->total_length - dsk->sender.write_seq;
	// }
	if(sk_stream_wspace(sk) <= 0) {
		timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
		sk_stream_wait_memory(sk, &timeo);
	}

	sent_len = dcpim_fill_packets(sk, msg, len);
	if(sent_len < 0)
		return sent_len;
	if(sent_len == 0) {
		timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
		sk_stream_wait_memory(sk, &timeo);
	}
	// if(dsk->total_length < dcpim_params.short_flow_size) {
	// 	struct sk_buff *skb;
	// 	dsk->sender.token_seq = dsk->total_length;
	// 	while((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
	// 		dcpim_xmit_data(skb, dsk, false);
	// 	}
	// }

	// if(sent_len == -ENOMEM) {
	// 	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 	sk_stream_wait_memory(sk, &timeo);
	// }
	/*temporary solution */
	local_bh_disable();
	bh_lock_sock(sk);
	if(!skb_queue_empty(&sk->sk_write_queue)
		&& after(dsk->sender.token_seq, DCPIM_SKB_CB(dcpim_send_head(sk))->end_seq)) {
 		dcpim_write_timer_handler(sk);
	} 
	bh_unlock_sock(sk);
	local_bh_enable();
	return sent_len;
}

static inline bool dcpim_message_memory_free(struct sock* sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	return dsk->sender.inflight_msgs <= dsk->sender.msg_threshold && sk_stream_memory_free(sk);
}
/**
 * dcpim_stream_wait_memory - Wait for more memory for a socket
 * @sk: socket to wait for memory
 * @timeo_p: for how long
 */
int dcpim_stream_wait_memory(struct sock *sk, long *timeo_p)
{
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	if (dcpim_message_memory_free(sk))
		current_timeo = vm_wait = (prandom_u32() % (HZ / 5)) + 2;

	add_wait_queue(sk_sleep(sk), &wait);

	while (1) {
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);

		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
			goto do_error;
		if (!*timeo_p)
			goto do_eagain;
		if (signal_pending(current))
			goto do_interrupted;
		sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		if (dcpim_message_memory_free(sk) && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		sk_wait_event(sk, &current_timeo, sk->sk_err ||
						  (sk->sk_shutdown & SEND_SHUTDOWN) ||
						  (dcpim_message_memory_free(sk) &&
						  !vm_wait), &wait);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}
out:
	remove_wait_queue(sk_sleep(sk), &wait);
	return err;

do_error:
	err = -EPIPE;
	goto out;
do_eagain:
	/* Make sure that whenever EAGAIN is returned, EPOLLOUT event can
	 * be generated later.
	 * When TCP receives ACK packets that make room, tcp_check_space()
	 * only calls tcp_new_space() if SOCK_NOSPACE is set.
	 */
	set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
	err = -EAGAIN;
	goto out;
do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;
}

int dcpim_sendmsg_msg_locked(struct sock *sk, struct msghdr *msg, size_t len) {
	// DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	// int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int sent_len = 0;
	int err = 0;
	long timeo;
	int flags;
	struct dcpim_message *dcpim_msg = dcpim_message_new(dsk, inet->inet_saddr, inet->inet_sport, inet->inet_daddr, inet->inet_dport, dsk->short_message_id, len);

	if(dcpim_msg == NULL) {
		WARN_ON(true);
		return -ENOBUFS;
	}
	flags = msg->msg_flags;
	if (sk->sk_state != DCPIM_ESTABLISHED) {
		return -ENOTCONN;
	}
	/* we allow the actual socket buffer size is one msg size larger than the limit */
	if(dcpim_message_memory_free(sk) <= 0) {
		timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
		err = dcpim_stream_wait_memory(sk, &timeo);
		if(err != 0)
			goto do_error;
	}
	sent_len = dcpim_fill_packets_message(sk, dcpim_msg, msg, len);
	if(sent_len <= 0) {
		dcpim_message_put(dcpim_msg);
		goto sent_done;

	} else if(sent_len != dcpim_msg->total_len) {
		printk("sent len:%d len:%d\n", sent_len, dcpim_msg->total_len);
		dcpim_msg->total_len = sent_len;
		dcpim_msg->remaining_len = sent_len;
		WARN_ON_ONCE(true);
	}
 	dsk->short_message_id++;
	dcpim_msg->state = DCPIM_WAIT_FIN_TX;
	dsk->sender.inflight_msgs++;
	/* add msg into sender_msg_table */
	local_bh_disable();
	if(!dcpim_insert_message(dcpim_tx_messages, dcpim_msg)) {
		WARN_ON(true);
	}
	local_bh_enable();
	/* burst packets of short flows
	 * No need to hold the lock because we just initialize the message.
	 * Flow sync packet currently doesn't 
	 */
	hrtimer_start(&dcpim_msg->rtx_timer, ns_to_ktime(dcpim_msg->timeout) , 
		HRTIMER_MODE_REL_PINNED_SOFT);
	dcpim_xmit_control(construct_flow_sync_msg_pkt(sk, dcpim_msg->id, dcpim_msg->total_len, 0), sk); 
	dcpim_xmit_data_whole_message(dcpim_msg, dsk);
	/* Intiiate hrtimer for retransmission */
	// dcpim_message_hold(dcpim_msg);
sent_done:
	return sent_len;
	// if(sent_len == 0) {
	// 	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 	sk_stream_wait_memory(sk, &timeo);
	// }
	// if(dsk->total_length < dcpim_params.short_flow_size) {
	// 	struct sk_buff *skb;
	// 	dsk->sender.token_seq = dsk->total_length;
	// 	while((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
	// 		dcpim_xmit_data(skb, dsk, false);
	// 	}
	// }

	// if(sent_len == -ENOMEM) {
	// 	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 	sk_stream_wait_memory(sk, &timeo);
	// }
	/*temporary solution */
	// local_bh_disable();
	// bh_lock_sock(sk);
	// if(!skb_queue_empty(&sk->sk_write_queue) && 
	// 	dsk->sender.token_seq >= DCPIM_SKB_CB(dcpim_send_head(sk))->end_seq) {
 	// 	dcpim_write_timer_handler(sk);
	// } 
	// bh_unlock_sock(sk);
	// local_bh_enable();
do_error:
	return sk_stream_error(sk, flags, err);
}

int dcpim_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int ret;
	lock_sock(sk);
	dcpim_rps_record_flow(sk);
	if(sk->sk_priority != 7)
		ret = dcpim_sendmsg_locked(sk, msg, len);
	else 
		/* send short flow message */
		ret = dcpim_sendmsg_msg_locked(sk, msg, len);
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(dcpim_sendmsg);

int dcpim_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	printk(KERN_WARNING "unimplemented sendpage invoked on dcpim socket\n");
	return -ENOSYS;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct dcpim_sock *up = dcpim_sk(sk);
// 	int ret;

// 	if (flags & MSG_SENDPAGE_NOTLAST)
// 		flags |= MSG_MORE;

// 	if (!up->pending) {
// 		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

// 		/* Call dcpim_sendmsg to specify destination address which
// 		 * sendpage interface can't pass.
// 		 * This will succeed only when the socket is connected.
// 		 */
// 		ret = dcpim_sendmsg(sk, &msg, 0);
// 		if (ret < 0)
// 			return ret;
// 	}

// 	lock_sock(sk);

// 	if (unlikely(!up->pending)) {
// 		release_sock(sk);

// 		net_dbg_ratelimited("cork failed\n");
// 		return -EINVAL;
// 	}

// 	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
// 			     page, offset, size, flags);
// 	if (ret == -EOPNOTSUPP) {
// 		release_sock(sk);
// 		return sock_no_sendpage(sk->sk_socket, page, offset,
// 					size, flags);
// 	}
// 	if (ret < 0) {
// 		dcpim_flush_pending_frames(sk);
// 		goto out;
// 	}

// 	up->len += size;
// 	if (!(up->corkflag || (flags&MSG_MORE)))
// 		ret = dcpim_push_pending_frames(sk);
// 	if (!ret)
// 		ret = size;
// out:
// 	release_sock(sk);
// 	return ret;
// }

// #define DCPIM_SKB_IS_STATELESS 0x80000000

// /* all head states (dst, sk, nf conntrack) except skb extensions are
//  * cleared by dcpim_rcv().
//  *
//  * We need to preserve secpath, if present, to eventually process
//  * IP_CMSG_PASSSEC at recvmsg() time.
//  *
//  * Other extensions can be cleared.
//  */
// static bool dcpim_try_make_stateless(struct sk_buff *skb)
// {
// 	if (!skb_has_extensions(skb))
// 		return true;

// 	if (!secpath_exists(skb)) {
// 		skb_ext_reset(skb);
// 		return true;
// 	}

// 	return false;
}

/* fully reclaim rmem/fwd memory allocated for skb */
// static void dcpim_rmem_release(struct sock *sk, int size, int partial,
// 			     bool rx_queue_lock_held)
// {
// 	struct dcpim_sock *up = dcpim_sk(sk);
// 	struct sk_buff_head *sk_queue;
// 	int amt;

// 	if (likely(partial)) {
// 		up->forward_deficit += size;
// 		size = up->forward_deficit;
// 		if (size < (sk->sk_rcvbuf >> 2) &&
// 		    !skb_queue_empty(&up->reader_queue))
// 			return;
// 	} else {
// 		size += up->forward_deficit;
// 	}
// 	up->forward_deficit = 0;

// 	/* acquire the sk_receive_queue for fwd allocated memory scheduling,
// 	 * if the called don't held it already
// 	 */
// 	sk_queue = &sk->sk_receive_queue;
// 	if (!rx_queue_lock_held)
// 		spin_lock(&sk_queue->lock);


// 	sk->sk_forward_alloc += size;
// 	amt = (sk->sk_forward_alloc - partial) & ~(PAGE_SIZE - 1);
// 	sk->sk_forward_alloc -= amt;

// 	if (amt)
// 		__sk_mem_reduce_allocated(sk, amt >> PAGE_SHIFT);

// 	atomic_sub(size, &sk->sk_rmem_alloc);

// 	/* this can save us from acquiring the rx queue lock on next receive */
// 	skb_queue_splice_tail_init(sk_queue, &up->reader_queue);

// 	if (!rx_queue_lock_held)
// 		spin_unlock(&sk_queue->lock);
// }

void dcpim_destruct_sock(struct sock *sk)
{
	struct dcpim_message *temp;
	struct dcpim_msgid_entry *entry = NULL, *etemp;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	/* reclaim completely the forward allocated memory */
	// unsigned int total = 0;
	// struct sk_buff *skb;
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     dcpim_sk(sk)->dcpim_port_hash);
	local_bh_disable();
	list_for_each_entry_safe(entry, etemp, &dsk->receiver.reordered_msgid_list, entry) {
		kfree(entry);
	}
	list_for_each_entry(temp, &dsk->receiver.unfinished_list, table_link) {
		spin_lock(&temp->lock);
		temp->state = DCPIM_FINISH_RX;
		spin_unlock(&temp->lock);
		dcpim_remove_message(dcpim_rx_messages, temp, true);
		dcpim_message_put(temp);
	}
	local_bh_enable();
	/* clean the message*/
	// skb_queue_splice_tail_init(&sk->sk_receive_queue, &dsk->reader_queue);
	// while ((skb = __skb_dequeue(&dsk->reader_queue)) != NULL) {
	// 	total += skb->truesize;
	// 	kfree_skb(skb);
	// }

	// dcpim_rmem_release(sk, total, 0, true);
	/* need to confirm whether we need to reclaim */
	sk_mem_reclaim(sk);
	inet_sock_destruct(sk);
}
EXPORT_SYMBOL_GPL(dcpim_destruct_sock);

int dcpim_init_sock(struct sock *sk)
{
	struct dcpim_sock* dsk = dcpim_sk(sk);
	// dcpim_set_state(sk, DCPIM_CLOSE);
	inet_sk_state_store(sk, DCPIM_CLOSE);
	dsk->core_id = raw_smp_processor_id();
	// next_going_id 
	// printk("remaining tokens:%d\n", dcpim_epoch.remaining_tokens);
	// atomic64_set(&dsk->next_outgoing_id, 1);
	// initialize the ready queue and its lock
	
	WRITE_ONCE(dsk->delay_destruct, true);
	hrtimer_init(&dsk->rtx_fin_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	dsk->rtx_fin_timer.function = dcpim_rtx_fin_timer_handler;
	WRITE_ONCE(dsk->fin_sent_times, 0);
	INIT_WORK(&dsk->rtx_fin_work, rtx_fin_handler);

	sk->sk_destruct = dcpim_destruct_sock;
	dsk->short_message_id = 0;
	WRITE_ONCE(dsk->num_sacks, 0);
	WRITE_ONCE(dsk->sender.num_sacks, 0);
	WRITE_ONCE(dsk->sender.token_seq, 0);
	WRITE_ONCE(dsk->sender.write_seq, 0);
	WRITE_ONCE(dsk->sender.snd_nxt, 0);
	WRITE_ONCE(dsk->sender.snd_una, 0);
	WRITE_ONCE(dsk->sender.remaining_pkts_at_sender, 0);

	WRITE_ONCE(dsk->sender.next_matched_bytes, 0);
	WRITE_ONCE(dsk->sender.grant, NULL);
	WRITE_ONCE(dsk->sender.grant_index, -1);
	
	WRITE_ONCE(dsk->sender.syn_ack_recvd, false);
	WRITE_ONCE(dsk->sender.sync_sent_times, 0);
	atomic_set(&dsk->sender.rtx_msg_bytes, 0);

	hrtimer_init(&dsk->sender.rtx_flow_sync_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	dsk->sender.rtx_flow_sync_timer.function = & dcpim_rtx_sync_timer_handler;
	INIT_LIST_HEAD(&dsk->sender.rtx_msg_list);
	INIT_LIST_HEAD(&dsk->sender.rtx_msg_backlog);
	INIT_WORK(&dsk->sender.rtx_msg_work, dcpim_rtx_msg_handler);
	WRITE_ONCE(dsk->sender.num_rtx_msgs, 0);

	WRITE_ONCE(dsk->sender.inflight_msgs, 0);
	INIT_LIST_HEAD(&dsk->sender.fin_msg_backlog);
	WRITE_ONCE(dsk->sender.msg_threshold, 200);
	INIT_LIST_HEAD(&dsk->match_link);
	INIT_LIST_HEAD(&dsk->entry);
	dsk->host = NULL;
	dsk->in_host_table = false;
	WRITE_ONCE(dsk->receiver.finished_at_receiver, false);
	WRITE_ONCE(dsk->receiver.flow_finish_wait, false);
	WRITE_ONCE(dsk->receiver.rmem_exhausted, 0);
	WRITE_ONCE(dsk->receiver.last_rtx_time, ktime_get());
	WRITE_ONCE(dsk->receiver.latest_token_sent_time, ktime_get());
	WRITE_ONCE(dsk->receiver.copied_seq, 0);
	WRITE_ONCE(dsk->receiver.bytes_received, 0);
	WRITE_ONCE(dsk->receiver.rcv_nxt, 0);
	WRITE_ONCE(dsk->receiver.last_ack, 0);
	WRITE_ONCE(dsk->receiver.priority, 0);
	WRITE_ONCE(dsk->receiver.in_pq, false);
	WRITE_ONCE(dsk->receiver.prev_token_nxt, 0);
	WRITE_ONCE(dsk->receiver.token_nxt, 0);
	WRITE_ONCE(dsk->receiver.max_congestion_win, 5 * dcpim_params.control_pkt_bdp);
	WRITE_ONCE(dsk->receiver.rts, NULL);
	WRITE_ONCE(dsk->receiver.rts_index, -1);
	WRITE_ONCE(dsk->receiver.rcv_msg_nxt, 0);
	INIT_LIST_HEAD(&dsk->receiver.msg_list);
	INIT_LIST_HEAD(&dsk->receiver.msg_backlog);
	
	INIT_LIST_HEAD(&dsk->receiver.reordered_msgid_list);
	INIT_LIST_HEAD(&dsk->receiver.unfinished_list);

	// INIT_LIST_HEAD(&dsk->reciever.);

	/* token batch 64KB */
	WRITE_ONCE(dsk->receiver.token_batch, 62636 * 2);
	atomic_set(&dsk->receiver.backlog_len, 0);
	atomic_set(&dsk->receiver.inflight_bytes, 0);
	atomic_set(&dsk->receiver.rtx_status, 0);
	// atomic_set(&dsk->receiver.matched_bw, 100);
	WRITE_ONCE(sk->sk_max_pacing_rate, 0); // bytes per second
	WRITE_ONCE(dsk->receiver.next_pacing_rate, 0); // bytes per second

	// dsk->start_time = ktime_get();
	hrtimer_init(&dsk->receiver.token_pace_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	dsk->receiver.token_pace_timer.function = &dcpim_xmit_token_handler;
	hrtimer_init(&dsk->receiver.rtx_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	dsk->receiver.rtx_timer.function = & dcpim_rtx_token_handler;
	dsk->receiver.rtx_rcv_nxt = 0;
	
	WRITE_ONCE(sk->sk_sndbuf, dcpim_params.wmem_default);
	WRITE_ONCE(sk->sk_rcvbuf, dcpim_params.rmem_default);
	// sk->sk_tx_skb_cache = NULL;
	/* reuse tcp rtx queue*/
	sk->tcp_rtx_queue = RB_ROOT;
	dsk->out_of_order_queue = RB_ROOT;
	// printk("flow wait at init:%d\n", dsk->receiver.flow_wait);
	return 0;
}
EXPORT_SYMBOL_GPL(dcpim_init_sock);

/*
 *	IOCTL requests applicable to the DCPIM protocol
 */

int dcpim_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	printk(KERN_WARNING "unimplemented ioctl invoked on DCPIM socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL(dcpim_ioctl);

bool dcpim_try_send_token(struct sock *sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	// struct inet_sock *inet = inet_sk(sk);
	uint32_t token_bytes = 0;
	token_bytes = dcpim_token_timer_defer_handler(sk);
	if(token_bytes > 0)
		return true;
	if(token_bytes == 0 && dsk->receiver.rcv_nxt >= dsk->receiver.last_ack + dsk->receiver.token_batch) {
		dcpim_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk); 
		dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	}
	// if(dsk->receiver.rcv_nxt >= dsk->receiver.last_ack + dsk->receiver.token_batch) {
	// 	dcpim_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk, inet->inet_dport); 
	// 	dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	// 	return true;
	// }
	return false;
}

int dcpim_recvmsg_normal(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	struct dcpim_sock *dsk = dcpim_sk(sk);
	int copied = 0;
	// u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	// int inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	// int trigger_tokens = 1;
	struct sk_buff *skb, *last, *tmp;
	// u32 urg_hole = 0;
	// struct scm_timestamping_internal tss;
	// int cmsg_flags;
	// printk("recvmsg: sk->rxhash:%u\n", sk->sk_rxhash);
	// printk("rcvmsg core:%d\n", raw_smp_processor_id());

	dcpim_rps_record_flow(sk);

	// if (unlikely(flags & MSG_ERRQUEUE))
	// 	return inet_recv_error(sk, msg, len, addr_len);
	// printk("start recvmsg \n");
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	// printk("target bytes:%d\n", target);

	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    (sk->sk_state == DCPIM_ESTABLISHED))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = -ENOTCONN;


	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);

	if (sk->sk_state != DCPIM_ESTABLISHED)
		goto out;
	/* Urgent data needs to be handled specially. */
	// if (flags & MSG_OOB)
	// 	goto recv_urg;

	// if (unlikely(tp->repair)) {
	// 	err = -EPERM;
		// if (!(flags & MSG_PEEK))
		// 	goto out;

		// if (tp->repair_queue == TCP_SEND_QUEUE)
		// 	goto recv_sndq;

		// err = -EINVAL;
		// if (tp->repair_queue == TCP_NO_QUEUE)
		// 	goto out;

		/* 'common' recv queue MSG_PEEK-ing */
//	}

	seq = &dsk->receiver.copied_seq;
	// if (flags & MSG_PEEK) {
	// 	peek_seq = dsk->receiver.copied_seq;
	// 	seq = &peek_seq;
	// }

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		// if (tp->urg_data && tp->urg_seq == *seq) {
		// 	if (copied)
		// 		break;
		// 	if (signal_pending(current)) {
		// 		copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
		// 		break;
		// 	}
		// }

		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, DCPIM_SKB_CB(skb)->seq),
				 "DCPIM recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, DCPIM_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt,
				 flags))
				break;

			offset = *seq - DCPIM_SKB_CB(skb)->seq;
			// if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
			// 	pr_err_once("%s: found a SYN, please report !\n", __func__);
			// 	offset--;
			// }
			if (offset < skb->len) {
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
				// __skb_unlink(skb, &sk->sk_receive_queue);

				// kfree_skb(skb);
				// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
			}
			// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			// 	goto found_fin_ok;
			// WARN(!(flags & MSG_PEEK),
			//      "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X\n",
			//      *seq, DCPIM_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt, flags);
		}

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == DCPIM_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == DCPIM_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				// copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		// tcp_cleanup_rbuf(sk, copied);
		// printk("release sock");
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			// printk("call release sock1\n");
			release_sock(sk);
			lock_sock(sk);
		} else {
			dcpim_try_send_token(sk);
			sk_wait_data(sk, &timeo, last);
		}

		// if ((flags & MSG_PEEK) &&
		//     (peek_seq - copied - urg_hole != tp->copied_seq)) {
		// 	net_dbg_ratelimited("TCP(%s:%d): Application bug, race in MSG_PEEK\n",
		// 			    current->comm,
		// 			    task_pid_nr(current));
		// 	peek_seq = dsk->receiver.copied_seq;
		// }
		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;
		// dcpim_try_send_token(sk);

		/* Do we have urgent data here? */
		// if (tp->urg_data) {
		// 	u32 urg_offset = tp->urg_seq - *seq;
		// 	if (urg_offset < used) {
		// 		if (!urg_offset) {
		// 			if (!sock_flag(sk, SOCK_URGINLINE)) {
		// 				WRITE_ONCE(*seq, *seq + 1);
		// 				urg_hole++;
		// 				offset++;
		// 				used--;
		// 				if (!used)
		// 					goto skip_copy;
		// 			}
		// 		} else
		// 			used = urg_offset;
		// 	}
		// }

		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			// printk("copy data done: %d\n", used);
			if (err) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			continue;
		__skb_unlink(skb, &sk->sk_receive_queue);
		atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);

		// if (copied > 3 * trigger_tokens * dsk->receiver.max_gso_data) {
		// 	// dcpim_try_send_token(sk);
		// 	trigger_tokens += 1;
			
		// }
		dcpim_try_send_token(sk);

		// tcp_rcv_space_adjust(sk);

// skip_copy:
		// if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
		// 	tp->urg_data = 0;
		// 	tcp_fast_path_check(sk);
		// }
		// if (used + offset < skb->len)
		// 	continue;

		// if (TCP_SKB_CB(skb)->has_rxtstamp) {
		// 	tcp_update_recv_tstamps(skb, &tss);
		// 	cmsg_flags |= 2;
		// }
		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		// 	goto found_fin_ok;
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		continue;

// found_fin_ok:
		/* Process the FIN. */
		// WRITE_ONCE(*seq, *seq + 1);
		// if (!(flags & MSG_PEEK))
		// 	sk_eat_skb(sk, skb);
		// break;
	} while (len > 0);

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	// tcp_cleanup_rbuf(sk, copied);
	dcpim_try_send_token(sk);
	// if (dsk->receiver.copied_seq == dsk->total_length) {
	// 	printk("call tcp close in the recv msg\n");
	// 	dcpim_set_state(sk, DCPIM_CLOSE);
	// } else {
	// 	// dcpim_try_send_token(sk);
	// }
	release_sock(sk);

	// if (cmsg_flags) {
	// 	if (cmsg_flags & 2)
	// 		tcp_recv_timestamp(msg, sk, &tss);
	// 	if (cmsg_flags & 1) {
	// 		inq = tcp_inq_hint(sk);
	// 		put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
	// 	}
	// }
	// printk("recvmsg\n");
	return copied;

out:
	release_sock(sk);
	return err;

// recv_urg:
// 	err = tcp_recv_urg(sk, msg, len, flags);
// 	goto out;

// recv_sndq:
// 	// err = tcp_peek_sndq(sk, msg, len);
// 	goto out;
}


/**
 * sk_msg_wait_data - wait for message to arrive at message_list
 * @sk:    sock to wait on
 * @timeo: for how long
 *
 * Now socket state including sk->sk_err is changed only under lock,
 * hence we may omit checks after joining wait queue.
 * We check receive queue before schedule() only as optimization;
 * it is very likely that release_sock() added new data.
 */
int sk_msg_wait_data(struct dcpim_sock *dsk, long *timeo)
{
	struct sock* sk = (struct sock*)dsk;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, timeo, !list_empty(&dsk->receiver.msg_list), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return rc;
}

/*
 * 	dcpim_recvmsg_msg for short messages
 * 	Guarantee: 
 */
int dcpim_recvmsg_msg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct dcpim_message *message = NULL;
	int copied = 0;
	// u32 peek_seq;
	u32 seq = 0;
	unsigned long used;
	int err;
	// int inq;
	// int target;		/* Read at least this many bytes */
	long timeo;
	// int trigger_tokens = 1;
	struct sk_buff *skb, *last, *tmp;
	dcpim_rps_record_flow(sk);
	// target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	// printk("target bytes:%d\n", target);

	if (sk_can_busy_loop(sk) && list_empty(&dsk->receiver.msg_list) &&
	    (sk->sk_state == DCPIM_ESTABLISHED))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = -ENOTCONN;
	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);
	/* if sk_state is not established, go to out */
	if (sk->sk_state != DCPIM_ESTABLISHED)
		goto out;
	/* if message list is empty, go to sleep */
	while(list_empty(&dsk->receiver.msg_list)) {
		if (!timeo) {
			err = -EAGAIN;
			goto out;
		}
		if (sock_flag(sk, SOCK_DONE) || sk->sk_shutdown & RCV_SHUTDOWN || sk->sk_state == DCPIM_CLOSE) {
			err = 0;
			goto out;
		}
		if (sk->sk_err) {
			err = sock_error(sk);
			goto out;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto out;
		}
		sk_msg_wait_data(dsk, &timeo);
	}
	message = list_first_entry(&dsk->receiver.msg_list, struct dcpim_message, table_link);
	if(len < message->total_len) {
		err = -ENOBUFS;
		goto out;
	} else {
		list_del(&message->table_link);
	}
	do {
		u32 offset;
		/* Next get a buffer. */
		last = skb_peek_tail(&message->pkt_queue);
		skb_queue_walk_safe(&message->pkt_queue, skb, tmp) {
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(seq, DCPIM_SKB_CB(skb)->seq),
				 "DCPIM short recvmsg seq # bug: copied %X, seq %X, fl %X\n",
				 seq, DCPIM_SKB_CB(skb)->seq, flags))
				break;
			offset = seq - DCPIM_SKB_CB(skb)->seq;
			// if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
			// 	pr_err_once("%s: found a SYN, please report !\n", __func__);
			// 	offset--;
			// }
			if (offset < skb->len) {
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
			}
		}
		break;

found_ok_skb:
		/* Ok so how much can we use? */
		WARN_ON(offset != 0);
		used = skb->len - offset;
		if (len < used)
			used = len;
		err = skb_copy_datagram_msg(skb, offset, msg, used);
		// printk("copy data done: %d\n", used);
		if (err) {
			/* Exception. Bailout! */
			if (!copied)
				copied = -EFAULT;
			break;
		}
		WRITE_ONCE(seq, seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			continue;
		spin_lock_bh(&message->lock);
		__skb_unlink(skb, &message->pkt_queue);
		spin_unlock_bh(&message->lock);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);
		continue;
	} while (len > 0);
	/* To Do: change the state of dcPIM message */
	dcpim_message_put(message);
	release_sock(sk);
	return copied;
out:
	release_sock(sk);
	return err;
}

int dcpim_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	// struct dcpim_sock *dsk = dcpim_sk(sk);
	int ret = 0;
	/* maybe we should change to the locked version later */
	if(sk->sk_priority != 7)
		ret = dcpim_recvmsg_normal(sk, msg, len, nonblock, flags, addr_len);
	else 
		/* recv_msg short flow message */
		ret = dcpim_recvmsg_msg(sk, msg, len, nonblock, flags, addr_len);
	return ret;
}

// int dcpim_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
// {
// 	if (addr_len < sizeof(struct sockaddr_in))
//  		return -EINVAL;

//  	return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
// }
// EXPORT_SYMBOL(dcpim_pre_connect);

int dcpim_disconnect(struct sock *sk, int flags)
{
	printk(KERN_WARNING "unimplemented dcpim_disconnect");
	return 0;
	// struct inet_sock *inet = inet_sk(sk);
 	// /*
 	//  *	1003.1g - break association.
 	//  */
	// printk("call disconnect");
	// if(sk->sk_state == DCPIM_LISTEN)
	// 	inet_csk_listen_stop(sk);
 	// sk->sk_state = DCPIM_CLOSE;
 	// inet->inet_daddr = 0;
 	// inet->inet_dport = 0;
 	// sock_rps_reset_rxhash(sk);
 	// sk->sk_bound_dev_if = 0;
 	// if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK)) {
 	// 	inet_reset_saddr(sk);
 	// 	if (sk->sk_prot->rehash &&
 	// 	    (sk->sk_userlocks & SOCK_BINDPORT_LOCK))
 	// 		sk->sk_prot->rehash(sk);
 	// }

 	// if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
 	// 	sk->sk_prot->unhash(sk);
 	// 	inet->inet_sport = 0;
 	// }
 	// sk_dst_reset(sk);
 	return 0;
}
EXPORT_SYMBOL(dcpim_disconnect);

// int dcpim_v4_early_demux(struct sk_buff *skb)
// {
// 	// struct net *net = dev_net(skb->dev);
// 	// struct in_device *in_dev = NULL;
// 	const struct iphdr *iph;
// 	const struct dcpimhdr *uh;
// 	struct sock *sk = NULL;
// 	// struct dst_entry *dst;
// 	// int dif = skb->dev->ifindex;
// 	int sdif = inet_sdif(skb);
// 	// int ours;

// 	/* validate the packet */
// 	// printk("early demux");
// 	if(skb->pkt_type != PACKET_HOST) {
// 		return 0;
// 	}
// 	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct dcpimhdr)))
// 		return 0;

// 	iph = ip_hdr(skb);
// 	uh = dcpim_hdr(skb);

//     // if (th->doff < sizeof(struct tcphdr) / 4)
//     //             return 0;
//     sk = __dcpim_lookup_established(dev_net(skb->dev), &dcpim_hashinfo,
//                                    iph->saddr, uh->source,
//                                    iph->daddr, ntohs(uh->dest),
//                                    skb->skb_iif, sdif);

//     if (sk) {
//             skb->sk = sk;
//             skb->destructor = sock_edemux;
//             if (sk_fullsock(sk)) {
//                     struct dst_entry *dst = READ_ONCE(sk->sk_rx_dst);

//                     if (dst)
//                             dst = dst_check(dst, 0);
//                     if (dst &&
//                         inet_sk(sk)->rx_dst_ifindex == skb->skb_iif)
//                             skb_dst_set_noref(skb, dst);
//             }
//     }
// 	return 0;
// }

int dcpim_rcv(struct sk_buff *skb)
{
	// printk("receive dcpim rcv\n");
	// skb_dump(KERN_WARNING, skb, false);
	struct dcpimhdr* dh;
	// printk("skb->len:%d\n", skb->len);
	if (!pskb_may_pull(skb, sizeof(struct dcpimhdr)))
		goto drop;		/* No space for header. */
	dh = dcpim_hdr(skb);
	// printk("dh == NULL?: %d\n", dh == NULL);
	// printk("end ref \n");
	if(dh->type == DATA) {
		return dcpim_handle_data_pkt(skb);
		// return __dcpim4_lib_rcv(skb, &dcpim_table, IPPROTO_DCPIM);
	} else if (dh->type == NOTIFICATION) {
		return dcpim_handle_flow_sync_pkt(skb);
	} else if (dh->type == TOKEN) {
		return dcpim_handle_token_pkt(skb);
	} else if (dh->type == FIN) {
		return dcpim_handle_fin_pkt(skb);
	} else if (dh->type == ACK) {
		return dcpim_handle_ack_pkt(skb);
	} else if (dh->type == SYN_ACK) {
		return dcpim_handle_syn_ack_pkt(skb);
	}  else if (dh->type == FIN_ACK) {
		return dcpim_handle_fin_ack_pkt(skb);
	}
	/* belows are for matching */
	else if (dh->type == RTS) {
		return dcpim_handle_rts(skb, &dcpim_epoch);
	} else if (dh->type == GRANT) {
		return dcpim_handle_grant(skb, &dcpim_epoch);
	} else if (dh->type == ACCEPT) {
		return dcpim_handle_accept(skb, &dcpim_epoch);
	}
	/* belows are for short flows */
	else if (dh->type == NOTIFICATION_MSG) {
		return dcpim_handle_flow_sync_msg_pkt(skb);
	} else if (dh->type == DATA_MSG) {
		return dcpim_handle_data_msg_pkt(skb);
	} else if (dh->type == FIN_MSG) {
		return dcpim_handle_fin_msg_pkt(skb);
	} else if (dh->type == FIN_ACK_MSG) {
		return dcpim_handle_fin_ack_msg_pkt(skb);
	} else if (dh->type == RTX_MSG) {
		return dcpim_handle_rtx_msg(skb, &dcpim_epoch);
	}

drop:

	kfree_skb(skb);
	return 0;

	return 0;
	// return __dcpim4_lib_rcv(skb, &dcpim_table, IPPROTO_DCPIM);
}

void dcpim_flush_msgs_handler(struct dcpim_sock *dsk) {
	struct list_head *list, *temp;
	struct dcpim_message *msg;
	/* for now, only add to list if dsk is in established state. */
	list_for_each_safe(list, temp, &dsk->sender.rtx_msg_list) {
		msg = list_entry(list, struct dcpim_message, table_link);
		list_del(&msg->table_link);
		atomic_sub(msg->total_len, &msg->dsk->host->total_unsent_bytes);
		atomic_sub(msg->total_len, &msg->dsk->host->rtx_msg_bytes);
		/* don't check the state since number of locks needed to get are the same here */
		spin_lock_bh(&msg->lock);
		dcpim_message_flush_skb(msg);
		spin_unlock_bh(&msg->lock);
		dcpim_remove_message(dcpim_tx_messages, msg, true);
		dcpim_message_put(msg);
	}
	list_for_each_safe(list, temp, &dsk->receiver.msg_list) {
		msg = list_entry(list, struct dcpim_message, table_link);
		list_del(&msg->table_link);
		/* no need to remove since preivously removed when msg is finished */
		dcpim_message_put(msg);
	}
}

void dcpim_destroy_sock(struct sock *sk)
{
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     dcpim_sk(sk)->dcpim_port_hash);
	struct dcpim_sock *dsk = dcpim_sk(sk);
	// struct inet_sock *inet = inet_sk(sk);
	struct rcv_core_entry *entry = &rcv_core_tab.table[raw_smp_processor_id()];
	/* To Do: flip the order; now the order was a mess */
	lock_sock(sk);
	if(sk->sk_priority != 7) {
		if(dsk->host)
			atomic_sub((uint32_t)(dsk->sender.write_seq - dsk->sender.snd_una), &dsk->host->total_unsent_bytes);
		/* To Do: remove short flow inflight bytes */
	}
	dcpim_flush_msgs_handler(dsk);
	/* delete from flow matching table */
	dcpim_remove_mat_tab(&dcpim_epoch, sk);
	// release_sock(sk);

	// local_bh_disable();
	// bh_lock_sock(sk);
	// dcpim_set_state(sk, DCPIM_CLOSE);
	// bh_unlock_sock(sk);
	// local_bh_enable();

	// lock_sock(sk);
	if(sk->sk_state == DCPIM_LISTEN)
		inet_csk_listen_stop(sk);

	local_bh_disable();
	bh_lock_sock(sk);
	/* need to sync with the matching side's ESTABLISHED_STATE checking */
	dcpim_set_state(sk, DCPIM_CLOSE);
	bh_unlock_sock(sk);
	local_bh_enable();
	
	// hrtimer_cancel(&up->receiver.flow_wait_timer);
	// if(sk->sk_state == DCPIM_ESTABLISHED) {
	if(hrtimer_cancel(&dsk->receiver.token_pace_timer)) {
		printk(" cancel hrtimer at:%d\n", __LINE__);	
		// __sock_put(sk);
	}
	if(hrtimer_cancel(&dsk->receiver.rtx_timer)) {
		printk(" cancel rtx hrtimer at:%d\n", __LINE__);	
		// __sock_put(sk);
	}
	if(hrtimer_cancel(&dsk->sender.rtx_flow_sync_timer)) {
		printk(" cancel rtx hrtimer at:%d\n", __LINE__);	
		// __sock_put(sk);
	}
	dcpim_write_queue_purge(sk);
	dcpim_read_queue_purge(sk);
	// }
	// dcpim_flush_pending_frames(sk);
	release_sock(sk);
	/* cancel the work after release the lock */
	cancel_work_sync(&dsk->sender.rtx_msg_work);
	// printk("sk->sk_wmem_queued:%d\n",sk->sk_wmem_queued);
	spin_lock_bh(&entry->lock);
	// printk("dsk->match_link:%p\n", &up->match_link);
	if(dsk->receiver.in_pq)
		dcpim_pq_delete(&entry->flow_q, &dsk->match_link);
	spin_unlock_bh(&entry->lock);

	printk("refcount sock:%d %p\n", refcount_read(&sk->sk_refcnt), dsk);
	// if (static_branch_unlikely(&dcpim_encap_needed_key)) {
	// 	if (up->encap_type) {
	// 		void (*encap_destroy)(struct sock *sk);
	// 		encap_destroy = READ_ONCE(up->encap_destroy);
	// 		if (encap_destroy)
	// 			encap_destroy(sk);
	// 	}
	// 	if (up->encap_enabled)
	// 		static_branch_dec(&dcpim_encap_needed_key);
	// }
}


int dcpim_setsockopt(struct sock *sk, int level, int optname,
		   sockptr_t optval, unsigned int optlen)
{
	printk(KERN_WARNING "unimplemented setsockopt invoked on DCPIM socket:"
			" level %d, optname %d, optlen %d\n",
			level, optname, optlen);
	return -EINVAL;
	// if (level == SOL_DCPIM)
	// 	return dcpim_lib_setsockopt(sk, level, optname, optval, optlen,
	// 				  dcpim_push_pending_frames);
	// return ip_setsockopt(sk, level, optname, optval, optlen);
}

// #ifdef CONFIG_COMPAT
// int compat_dcpim_setsockopt(struct sock *sk, int level, int optname,
// 			  char __user *optval, unsigned int optlen)
// {
// 	if (level == SOL_DCPIM)
// 		return dcpim_lib_setsockopt(sk, level, optname, optval, optlen,
// 					  dcpim_push_pending_frames);
// 	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
// }
// #endif

int dcpim_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on DCPIM socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
	// struct dcpim_sock *up = dcpim_sk(sk);
	// int val, len;

	// if (get_user(len, optlen))
	// 	return -EFAULT;

	// len = min_t(unsigned int, len, sizeof(int));

	// if (len < 0)
	// 	return -EINVAL;

	// switch (optname) {
	// case DCPIM_CORK:
	// 	val = up->corkflag;
	// 	break;

	// case DCPIM_ENCAP:
	// 	val = up->encap_type;
	// 	break;

	// case DCPIM_NO_CHECK6_TX:
	// 	val = up->no_check6_tx;
	// 	break;

	// case DCPIM_NO_CHECK6_RX:
	// 	val = up->no_check6_rx;
	// 	break;

	// case DCPIM_SEGMENT:
	// 	val = up->gso_size;
	// 	break;
	// default:
	// 	return -ENOPROTOOPT;
	// }

	// if (put_user(len, optlen))
	// 	return -EFAULT;
	// if (copy_to_user(optval, &val, len))
	// 	return -EFAULT;
	// return 0;
}
EXPORT_SYMBOL(dcpim_lib_getsockopt);

int dcpim_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on DCPIM socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
}

__poll_t dcpim_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	printk(KERN_WARNING "unimplemented poll invoked on DCPIM socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL(dcpim_poll);

int dcpim_abort(struct sock *sk, int err)
{
	printk(KERN_WARNING "unimplemented abort invoked on DCPIM socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(dcpim_abort);


// static void __dcpim_sysctl_init(struct net *net)
// {
// 	net->ipv4.sysctl_udp_rmem_min = SK_MEM_QUANTUM;
// 	net->ipv4.sysctl_udp_wmem_min = SK_MEM_QUANTUM;

// #ifdef CONFIG_NET_L3_MASTER_DEV
// 	net->ipv4.sysctl_udp_l3mdev_accept = 0;
// #endif
// }

// static int __net_init dcpim_sysctl_init(struct net *net)
// {
// 	__dcpim_sysctl_init(net);
// 	return 0;
// }

// static struct pernet_operations __net_initdata dcpim_sysctl_ops = {
// 	.init	= dcpim_sysctl_init,
// };

void __init dcpim_init(void)
{
	unsigned long limit;
	// unsigned int i;

	printk("try to add dcpim table \n");
	printk("dcpim sock size:%ld\n", sizeof(struct dcpim_sock));
	printk("tcp sock size:%ld\n", sizeof(struct tcp_sock));

	dcpim_hashtable_init(&dcpim_hashinfo, 0);

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_dcpim_mem[0] = limit / 4 * 3;
	sysctl_dcpim_mem[1] = limit;
	sysctl_dcpim_mem[2] = sysctl_dcpim_mem[0] * 2;

	// __dcpim_sysctl_init(&init_net);
	/* 16 spinlocks per cpu */
	// dcpim_busylocks_log = ilog2(nr_cpu_ids) + 4;
	// dcpim_busylocks = kmalloc(sizeof(spinlock_t) << dcpim_busylocks_log,
	// 			GFP_KERNEL);
	// if (!dcpim_busylocks)
	// 	panic("DCPIM: failed to alloc dcpim_busylocks\n");
	// for (i = 0; i < (1U << dcpim_busylocks_log); i++)
	// 	spin_lock_init(dcpim_busylocks + i);
	// if (register_pernet_subsys(&dcpim_sysctl_ops)) 
	// 	panic("DCPIM: failed to init sysctl parameters.\n");

	printk("DCPIM init complete\n");

}

void dcpim_destroy() {
	printk("try to destroy peer table\n");
	printk("try to destroy dcpim socket table\n");
	dcpim_hashtable_destroy(&dcpim_hashinfo);
	// kfree(dcpim_busylocks);
}
