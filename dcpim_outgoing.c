// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		DATACENTER ADMISSION CONTROL PROTOCOL(DCPIM) 
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 */

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
 #include "net_dcpim.h"
// #include "net_dcpimlite.h"
#include "uapi_linux_dcpim.h"
#include "dcpim_impl.h"


#define DCPIM_DEFERRED_ALL (DCPIMF_TSQ_DEFERRED |		\
			  DCPIMF_CLEAN_TIMER_DEFERRED |	\
			  DCPIMF_TOKEN_TIMER_DEFERRED |	\
			  DCPIMF_RMEM_CHECK_DEFERRED | \
			  DCPIMF_RTX_DEFERRED | \
			  DCPIMF_WAIT_DEFERRED)

/* Insert buff after skb on the write or rtx queue of sk.  */
static void dcpim_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum dcpim_queue dcpim_queue)
{
	if (dcpim_queue == DCPIM_FRAG_IN_WRITE_QUEUE)
		skb_append(skb, buff,&sk->sk_write_queue);
	else
		dcpim_rbtree_insert(&sk->tcp_rtx_queue, buff);
}


/* Initialize GSO segments for a packet. */
static void dcpim_set_skb_gso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	// if (skb->len <= mss_now) {
	// 	/* Avoid the costly divide in the normal
	// 	 * non-TSO case.
	// 	 */
	// 	tcp_skb_pcount_set(skb, 1);
	// 	TCP_SKB_CB(skb)->tcp_gso_size = 0;
	// } else {
	// 	tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
	// 	TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	// }
	if(skb->len >= mss_now) {
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// WARN_ON(skb->len != DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);

	}
}

struct sk_buff *dcpim_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule)
{
	struct sk_buff *skb;
	/* The DCPIM header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	// if (unlikely(tcp_under_memory_pressure(sk)))
	// 	sk_mem_reclaim_partial(sk);

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);
	if (likely(skb)) {
		// bool mem_scheduled;

		// if (force_schedule) {
		// 	mem_scheduled = true;
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// } else {
		// 	mem_scheduled = sk_wmem_schedule(sk, skb->truesize);
		// }
		// if (likely(mem_scheduled)) {
		// 	skb_reserve(skb, sk->sk_prot->max_header);
		// 	/*
		// 	 * Make sure that we have exactly size bytes
		// 	 * available to the caller, no more, no less.
		// 	 */
		// 	skb->reserved_tailroom = skb->end - skb->tail - size;
		// 	INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		// 	return skb;
		// }
		// __kfree_skb(skb);
		skb_reserve(skb, sk->sk_prot->max_header);
		skb->reserved_tailroom = skb->end - skb->tail - size;
		skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));

		return skb;
	} 
	// else {
	// 	sk->sk_prot->enter_memory_pressure(sk);
	// 	sk_stream_moderate_sndbuf(sk);
	// }
	// __kfree_skb(skb);
	return NULL;
}

/* assume hold bh_sock_lock */
int dcpim_fragment(struct sock *sk, enum dcpim_queue dcpim_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	// struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	// int max_pkt_data;
	// int old_factor;
	long limit;
	int nlen;
	// u8 flags;



	if (len == 0)
		return -EINVAL;
	if (len >= skb->len)
		return -EINVAL;

	/* dcpim_sendmsg() can overshoot sk_wmem_queued by one full size skb.
	 * We need some allowance to not penalize applications setting small
	 * SO_SNDBUF values.
	 * Also allow first and last skb in retransmit queue to be split.
	 */
	limit = sk->sk_sndbuf + 2 * SKB_TRUESIZE(GSO_MAX_SIZE);
	if (unlikely((sk->sk_wmem_queued >> 1) > limit &&
		     dcpim_queue != DCPIM_FRAG_IN_WRITE_QUEUE &&
		     skb != dcpim_rtx_queue_head(sk) &&
		     skb != dcpim_rtx_queue_tail(sk))) {
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWQUEUETOOBIG);
		return -ENOMEM;
	}

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = dcpim_stream_alloc_skb(sk, skb->len - len, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */
	skb_copy_decrypted(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	// sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len;
	buff->truesize += nlen;
	skb->truesize -= nlen;
	printk("do fragment\n");
	printk("new buff seq:%u\n", DCPIM_SKB_CB(skb)->seq + len);
	/* Correct the sequence numbers. */
	DCPIM_SKB_CB(buff)->seq = DCPIM_SKB_CB(skb)->seq + len;
	DCPIM_SKB_CB(buff)->end_seq = DCPIM_SKB_CB(skb)->end_seq;
	DCPIM_SKB_CB(skb)->end_seq = DCPIM_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	// flags = DCPIM_SKB_CB(skb)->tcp_flags;
	// DCPIM_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	// DCPIM_SKB_CB(buff)->tcp_flags = flags;
	// DCPIM_SKB_CB(buff)->sacked = DCPIM_SKB_CB(skb)->sacked;
	// tcp_skb_fragment_eor(skb, buff);
	skb_split(skb, buff, len);

	buff->ip_summed = CHECKSUM_PARTIAL;

	// buff->tstamp = skb->tstamp;
	// tcp_fragment_tstamp(skb, buff);

	// old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	dcpim_set_skb_gso_segs(skb, mss_now);
	dcpim_set_skb_gso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	// TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	// if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
	// 	int diff = old_factor - tcp_skb_pcount(skb) -
	// 		tcp_skb_pcount(buff);

	// 	if (diff)
	// 		tcp_adjust_pcount(sk, skb, diff);
	// }

	/* Link BUFF into the send queue. */
	// __skb_header_release(buff);

	dcpim_insert_write_queue_after(skb, buff, sk, dcpim_queue);
	// if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
	// 	list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}

/**
 * dcpim_fill_packets_message() - Create one or more packets and fill them with
 * data from user space, and link them to the corresponding message.
 * @sk:   socket which invokes the sendmsg.
 * @dcpim_msg:   Short message that holds the created packets.
 * @msg:         Address of the user-space source buffer.
 * @len:         Number of bytes of user data.
 * 
 * Return:   Return the length (bytes) that has been moved to the kernel space
 *           from user space, or a negative errno if there was an error. 
 */
int dcpim_fill_packets_message(struct sock* sk, struct dcpim_message *dcpim_msg,
		struct msghdr *msg, size_t len)
{
	int bytes_left, sent_len = 0;
	uint32_t write_seq = 0;
	struct sk_buff *skb;
	// struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	// struct sk_buff **last_link;
	struct dst_entry *dst;
	// struct dcpim_sock* dsk = dcpim_sk(sk);
	/* check socket has enough space */
	if (unlikely(len == 0)) {
		err = -EINVAL;
		goto error;
	}

	dst = sk_dst_get(sk);
	if(dst == NULL) {
		printk("dst is NULL\n");
		return -ENOTCONN;
	}
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	bytes_left = len;


	if (len <= max_pkt_data ) {
		max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = dst->dev->gso_max_size;
		if (gso_size > dcpim_params.bdp)
			gso_size = dcpim_params.bdp;
		// if(gso_size > dcpim_params.gso_size)
		// 	gso_size = dcpim_params.gso_size;
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct dcpim_data_hdr);
			WARN_ON(max_pkt_data < 0);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
	}
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	// ktime_t start, end;
	// start = ktime_get();
	for (; bytes_left > 0; ) {
		// struct dcpim_data_hdr *h;
		struct data_segment *seg;
		int available;
		int current_len = 0;
		 // last_pkt_length;
		
		/* The sizeof(void*) creates extra space for dcpim_next_skb. */
		skb = dcpim_stream_alloc_skb(sk, gso_size, GFP_KERNEL, true);
		/* this is a temp solution; will remove after adding split buffer mechanism */
		if (unlikely(!skb)) {
			// goto finish;
			err = -ENOMEM;
			goto error;
		}
		if ((max_gso_data > bytes_left)) {
			// if(!sk->sk_tx_skb_cache)
			// 	sk->sk_tx_skb_cache = skb;
			// else
			kfree_skb(skb);
			break;
		}
		available = max_gso_data;
		current_len = available > bytes_left? bytes_left : available;
		// h->message_id = 256;
		WRITE_ONCE(DCPIM_SKB_CB(skb)->seq, write_seq + len - bytes_left);
		WRITE_ONCE(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(skb)->seq + current_len);
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */
		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left + write_seq);

			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			if (!copy_from_iter_full(skb_put(skb, seg_size),
					seg_size, &msg->msg_iter)) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			available -= seg_size;
		} while ((available > 0) && (bytes_left > 0));
		sent_len += current_len;
		dcpim_set_skb_gso_segs(skb, max_pkt_data + sizeof(struct data_segment));
		dcpim_add_write_queue_tail(sk, skb);
	}
	WRITE_ONCE(write_seq, write_seq + sent_len);
	return sent_len;
	
error:
	return err;
}

/**
 * dcpim_fill_packets() - Create one or more packets and fill them with
 * data from user space.
 * @sk:      Socket that performs data copy.
 * @msg:     Address of the user-space source buffer.
 * @len:     Number of bytes of user data.
 * 
 * Return:   Return the length (bytes) that has been moved to the kernel space
 *           from user space, or a negative errno if there was an error. 
 */
int dcpim_fill_packets(struct sock *sk,
		struct msghdr *msg, size_t len)
{
	int bytes_left, sent_len = 0;
	struct sk_buff *skb;
	// struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	// struct sk_buff **last_link;
	struct dst_entry *dst;
	struct dcpim_sock* dsk = dcpim_sk(sk);
	/* check socket has enough space */
	if (unlikely(len == 0)) {
		err = -EINVAL;
		goto error;
	}

	dst = sk_dst_get(sk);
	if(dst == NULL) {
		printk("dst is NULL\n");
		return -ENOTCONN;
	}
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	bytes_left = len;


	if (len <= max_pkt_data ) {
		max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = dst->dev->gso_max_size;
		if (gso_size > dcpim_params.bdp)
			gso_size = dcpim_params.bdp;
		// if(gso_size > dcpim_params.gso_size)
		// 	gso_size = dcpim_params.gso_size;
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct dcpim_data_hdr);
			WARN_ON(max_pkt_data < 0);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
		/* Round unscheduled bytes *up* to an even number of gsos. */
		// unsched = rtt_bytes + max_gso_data - 1;
		// unsched -= unsched % max_gso_data;
		// if (unsched > sent_len)
		// 	unsched = sent_len;
	}
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	// ktime_t start, end;
	// start = ktime_get();
	for (; bytes_left > 0; ) {
		// struct dcpim_data_hdr *h;
		struct data_segment *seg;
		int available;
		int current_len = 0;
		 // last_pkt_length;
		
		/* The sizeof(void*) creates extra space for dcpim_next_skb. */
		skb = dcpim_stream_alloc_skb(sk, gso_size, GFP_KERNEL, true);
		// if(sk->sk_tx_skb_cache != NULL) {
		// 	skb = sk->sk_tx_skb_cache;
		// 	sk->sk_tx_skb_cache = NULL;
		// } else {
		// 	skb = alloc_skb(gso_size, GFP_KERNEL);
		// }
		// skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
		/* this is a temp solution; will remove after adding split buffer mechanism */
		if (unlikely(!skb)) {
			// goto finish;
			err = -ENOMEM;
			goto error;
		}
		if (skb->truesize > sk_stream_wspace(sk) || (max_gso_data > bytes_left)) {
			// if(!sk->sk_tx_skb_cache)
			// 	sk->sk_tx_skb_cache = skb;
			// else
			kfree_skb(skb);
			break;
		}

		// if ((bytes_left > max_pkt_data)
		// 		&& (max_gso_data > max_pkt_data)) {
		// 	skb_shinfo(skb)->gso_size = max_pkt_data;
		// 	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// }
		// skb_shinfo(skb)->gso_segs = 0;

		// skb_reserve(skb, sizeof(struct iphdr));
		// skb_reset_transport_header(skb);
		// h = (struct dcpim_data_hdr *) skb_put(skb, sizeof(*h));
		available = max_gso_data;
		current_len = available > bytes_left? bytes_left : available;
		// h->message_id = 256;
		WRITE_ONCE(DCPIM_SKB_CB(skb)->seq, dsk->sender.write_seq + len - bytes_left);
		WRITE_ONCE(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(skb)->seq + current_len);
		// if (!copy_from_iter_full(skb_put(skb, current_len),
		// 		current_len, &msg->msg_iter)) {
		// 	err = -EFAULT;
		// 	kfree_skb(skb);
		// 	goto error;
		// }
		// skb_shinfo(skb)->gso_segs += current_len / max_pkt_data;
		// if (current_len % max_pkt_data)
		// 	skb_shinfo(skb)->gso_segs += 1;
		// bytes_left -= current_len;
		// h->common.seq = 200;
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */

		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left + dsk->sender.write_seq);

			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			if (!copy_from_iter_full(skb_put(skb, seg_size),
					seg_size, &msg->msg_iter)) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			// printk("seg size: %d\n", seg_size);
			// printk("offset: %d\n",  ntohl(seg->offset));
			// buffer += seg_size;
			// (skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
			// h->common.len = htons(ntohs(h->common.len) + sizeof(*seg));
		} while ((available > 0) && (bytes_left > 0));
		sent_len += current_len;
		// h->incoming = htonl(((len - bytes_left) > unsched) ?
		// 		(len - bytes_left) : unsched);
		
		/* Make sure that the last segment won't result in a
		 * packet that's too small.
		 */


		// last_pkt_length = htonl(seg->segment_length) + sizeof(*h);
		// if (unlikely(last_pkt_length < DCPIM_HEADER_MAX_SIZE)){
		// 	skb_put(skb, DCPIM_HEADER_MAX_SIZE - last_pkt_length);
		// }
		// *last_link = skb;
		// last_link = dcpim_next_skb(skb);
		// *last_link = NULL;
		dcpim_set_skb_gso_segs(skb, max_pkt_data + sizeof(struct data_segment));
		dcpim_add_write_queue_tail(sk, skb);
		sk_wmem_queued_add(sk, skb->truesize);

		// sk_mem_charge(sk, skb->truesize);
	}
		// end = ktime_get();

		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
	// if (!sent_len) {
	// 	printk("total len:%ld\n", len);
	// 	printk("sent length:%d\n", sent_len);
	// 	printk("(sk_stream_wspace(sk):%d\n", (sk_stream_wspace(sk)));
	// }
// finish:
	WRITE_ONCE(dsk->sender.write_seq, dsk->sender.write_seq + sent_len);
	return sent_len;
	
error:
	// dcpim_free_skbs(first);
	return err;
}

/**
 * dcpim_release_cb - dcpim release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void dcpim_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & DCPIM_DEFERRED_ALL))
			return;
		nflags = flags & ~DCPIM_DEFERRED_ALL;
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
	// sock_release_ownership(sk);

	/* First check read memory */
	// if (flags & DCPIMF_RMEM_CHECK_DEFERRED) {
	// 	dcpim_rem_check_handler(sk);
	// }

	// if (flags & DCPIMF_CLEAN_TIMER_DEFERRED) {
	// 	dcpim_clean_rtx_queue(sk);
	// 	// __sock_put(sk);
	// }
	if (flags & DCPIMF_TOKEN_TIMER_DEFERRED) {
		dcpim_token_timer_defer_handler(sk);
		__sock_put(sk);
	}
	// if (flags & DCPIMF_RTX_DEFERRED) {
	// 	dcpim_write_timer_handler(sk);
	// }
	// if (flags & DCPIMF_WAIT_DEFERRED) {
	// 	dcpim_flow_wait_handler(sk);
	// }

	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(dcpim_release_cb);


struct sk_buff* __construct_control_skb(struct sock* sk, int size) {

	struct sk_buff *skb;
	if(!size)
		size = DCPIM_HEADER_MAX_SIZE;
	skb = alloc_skb(size, GFP_ATOMIC);
	skb->sk = sk;
	// int extra_bytes;
	if (unlikely(!skb))
		return NULL;
	skb_reserve(skb, DCPIM_HEADER_MAX_SIZE);
	skb_reset_transport_header(skb);

	// h = (struct dcpim_hdr *) skb_put(skb, length);
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
	uint32_t message_size, __u64 start_time) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_flow_sync_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_flow_sync_hdr *) skb_put(skb, sizeof(struct dcpim_flow_sync_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_flow_sync_hdr));
	dh->type = NOTIFICATION;
	fh->message_id = message_id;
	fh->message_size = message_size;
	fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority,
	 __u32 prev_token_nxt, __u32 token_nxt, bool handle_rtx) {
	// int extra_bytes = 0;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff* skb = __construct_control_skb(sk, DCPIM_HEADER_MAX_SIZE
		 + dsk->num_sacks * sizeof(struct dcpim_sack_block_wire));
	struct dcpim_token_hdr* fh;
	struct dcpimhdr* dh;
	struct dcpim_sack_block_wire *sack;
	int i = 0;
	bool manual_end_point = true;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_token_hdr *) skb_put(skb, sizeof(struct dcpim_token_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_token_hdr));
	dh->type = TOKEN;
	fh->priority = priority;
	fh->rcv_nxt = dsk->receiver.rcv_nxt;
	fh->token_nxt = token_nxt;
	fh->num_sacks = 0;
	// printk("TOKEN: new grant next:%u\n", fh->grant_nxt);
	// printk("prev_grant_nxt:%u\n", prev_grant_nxt);
	// printk("new rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	// printk("copied seq:%u\n", dsk->receiver.copied_seq);
	if(handle_rtx && dsk->receiver.rcv_nxt < prev_token_nxt) {
		printk("rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
		while(i < dsk->num_sacks) {
			__u32 start_seq = dsk->selective_acks[i].start_seq;
			__u32 end_seq = dsk->selective_acks[i].end_seq;

			if(start_seq > prev_token_nxt)
				goto next;
			if(end_seq > prev_token_nxt) {
				end_seq = prev_token_nxt;
				manual_end_point = false;
			}

			sack = (struct dcpim_sack_block_wire*) skb_put(skb, sizeof(struct dcpim_sack_block_wire));
			sack->start_seq = htonl(start_seq);
			printk("start seq:%u\n", start_seq);
			printk("end seq:%u\n", end_seq);

			sack->end_seq = htonl(end_seq);
			fh->num_sacks++;
		next:
			i++;
		}
		if(manual_end_point) {
			sack = (struct dcpim_sack_block_wire*) skb_put(skb, sizeof(struct dcpim_sack_block_wire));
			sack->start_seq = htonl(prev_token_nxt);
			sack->end_seq = htonl(prev_token_nxt);
			printk("sack start seq:%u\n", prev_token_nxt);
			fh->num_sacks++;
		}

	}

	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_ack_hdr* ah;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	ah = (struct dcpim_ack_hdr *) skb_put(skb, sizeof(struct dcpim_ack_hdr));
	dh = (struct dcpimhdr*) (&ah->common);
	dh->len = htons(sizeof(struct dcpim_ack_hdr));
	dh->type = ACK;
	ah->rcv_nxt = rcv_nxt;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_pkt(struct sock* sk) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	dh = (struct dcpimhdr*) skb_put(skb, sizeof(struct dcpimhdr));
	dh->len = htons(sizeof(struct dcpimhdr));
	dh->type = FIN;
	// fh->message_id = message_id;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_rts_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_rts_hdr *) skb_put(skb, sizeof(struct dcpim_rts_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_rts_hdr));
	dh->type = RTS;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz, bool prompt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_grant_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_grant_hdr *) skb_put(skb, sizeof(struct dcpim_grant_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_grant_hdr));
	dh->type = GRANT;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->prompt = prompt;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_accept_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_accept_hdr *) skb_put(skb, sizeof(struct dcpim_accept_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_accept_hdr));
	dh->type = ACCEPT;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}
/**
 * dcpim_xmit_control() - Send a control packet to the other end of an RPC.
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
// int dcpim_xmit_control(enum dcpim_packet_type type, struct sk_buff *skb,
// 	size_t len, struct flowi4 *fl4)
// {
// 	struct sock *sk = skb->sk;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct dcpim_header *dh = dcpim_hdr(skb);
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
// 	return __dcpim_xmit_control(contents, length, rpc->peer, rpc->hsk);
// }


void dcpim_retransmit(struct sock* sk) {
	struct dcpim_sock* dsk = dcpim_sk(sk);
	// struct dcpim_sack_block *sp;
	struct sk_buff *skb;
	int start_seq, end_seq, mss_now, mtu, i;
	struct dst_entry *dst;
	dst = sk_dst_get(sk);
	mtu = dst_mtu(dst);
	mss_now = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	/* last sack is the fake sack [prev_grant_next, prev_grant_next) */
	skb = skb_rb_first(&sk->tcp_rtx_queue);
	for (i = 0; i < dsk->num_sacks; i++) {
		if(!skb)
			break;
		if(i == 0) {
			start_seq = dsk->sender.snd_una;
		} else {
			start_seq = dsk->selective_acks[i - 1].end_seq;
		}
		end_seq = dsk->selective_acks[i].start_seq;

		while(skb) {
			if(!before(start_seq, DCPIM_SKB_CB(skb)->end_seq)) {
				goto go_to_next;
			}
			if(!after(end_seq, DCPIM_SKB_CB(skb)->seq)) {
				break;
			}
			/* split the skb buffer; after split, end sequence of skb will change */
			if(after(start_seq, DCPIM_SKB_CB(skb)->seq)) {
				/* move the start seq forward to the start of a MSS packet */
				int seg = (start_seq - DCPIM_SKB_CB(skb)->seq + 1) / mss_now;
				int ret = dcpim_fragment(sk, DCPIM_FRAG_IN_RTX_QUEUE, skb,
				 seg * (mss_now + sizeof(struct data_segment)), mss_now  + sizeof(struct data_segment), GFP_ATOMIC);
				/* move forward after the split */
				if(!ret)
					skb = skb_rb_next(skb);
			}
			if(before(end_seq, DCPIM_SKB_CB(skb)->end_seq)) {
				/* split the skb buffer; Round up this time */
				int seg = DIV_ROUND_UP((end_seq - DCPIM_SKB_CB(skb)->seq), mss_now);
				dcpim_fragment(sk, DCPIM_FRAG_IN_RTX_QUEUE, skb,
				 seg * (mss_now + sizeof(struct data_segment)), mss_now  + sizeof(struct data_segment), GFP_ATOMIC);		
			}
			dcpim_retransmit_data(skb, dcpim_sk(sk));
go_to_next:
			skb = skb_rb_next(skb);
		}


	}	
	dsk->num_sacks = 0;
}
/**
 * __dcpim_xmit_control() - Lower-level version of dcpim_xmit_control: sends
 * a control packet.
 * @skb:	   Packet payload
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int dcpim_xmit_control(struct sk_buff* skb, struct sock* sk)
{
	// struct dcpim_hdr *h;
	int result;
	struct dcpimhdr* dh;
	struct inet_sock *inet = inet_sk(sk);
	// struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = dcpim_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = inet->inet_dport;
	dh->check = 0;
	dh->doff = (sizeof(struct dcpimhdr)) << 2;
	// inet->tos = IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL;
	skb->sk = sk;
	// dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, __sk_dst_get(sk));
	// skb_get(skb);
	result = __ip_queue_xmit(sk, skb, &inet->cork.fl, IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL);
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
		// if (refcount_read(&skb->users) > 1)
		// 	printk(KERN_NOTICE "ip_queue_xmit didn't free "
		// 			"DCPIM control packet after error\n");
	}
	// kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 *
 */
void dcpim_xmit_data(struct sk_buff* skb, struct dcpim_sock* dsk, bool free_token)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb))) 
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, free_token);
	/* change the state of queue and metadata*/

	// dcpim_unlink_write_queue(oskb, sk);
	dcpim_rbtree_insert(&sk->tcp_rtx_queue, oskb);
	WRITE_ONCE(dsk->sender.snd_nxt, DCPIM_SKB_CB(oskb)->end_seq);
	// sk_wmem_queued_add(sk, -skb->truesize);

	// if (!skb_queue_empty(&sk->sk_write_queue)) {
	// 	struct sk_buff *skb = dcpim_send_head(sk);
	// 	WRITE_ONCE(dsk->sender.snd_nxt, DCPIM_SKB_CB(skb)->end_seq);
	// 	__dcpim_xmit_data(skb, dsk);
	// }
	// while (msg->next_packet) {
	// 	// int priority = TOS_1;
	// 	struct sk_buff *skb = msg->next_packet;
	// 	// struct dcpim_sock* dsk = msg->dsk;
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
	// 	msg->next_packet = *dcpim_next_skb(skb);
		
	// 	skb_get(skb);
	// 	__dcpim_xmit_data(skb, dsk);
	// 	force = false;
	// }
}

/** dcpim_xmit_data_message - send skb of a short message
 * 
 */
void dcpim_xmit_data_message(struct sk_buff* skb, struct dcpim_sock* dsk, bool free_token)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb))) 
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, free_token);
}

/** dcpim_xmit_data_message - send the whole short message. Assume caller holds the lock.
 * 
 */
void dcpim_xmit_data_whole_message(struct dcpim_message* msg, struct dcpim_sock* dsk, bool free_token)
{
	struct sk_buff* skb;
	skb_queue_walk(&msg->pkt_queue, skb) {
		dcpim_xmit_data_message(skb, dsk, free_token);
	}
}

void dcpim_retransmit_data(struct sk_buff* skb, struct dcpim_sock* dsk)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb)))
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, 0);
}

/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __dcpim_xmit_data(struct sk_buff *skb, struct dcpim_sock* dsk, bool free_token)
{
	int err;
	__u8 tos;
	// struct dcpim_data_hder *h = (struct dcpim_data_hder *)
	// 		skb_transport_header(skb);
	struct sock* sk = (struct sock*)dsk;
	struct inet_sock *inet = inet_sk(sk);
	struct dcpim_data_hdr *h;
	// struct dcpimhdr* dh;

	// dh = dcpim_hdr(skb);

	// dh->source = inet->inet_sport;

	// dh->dest = dport;

	// inet->tos = TOS_1;

	// set_priority(skb, rpc->hsk, priority);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	if(free_token) 
		tos = IPTOS_LOWDELAY | IPTOS_PREC_INTERNETCONTROL;
	else 
		tos = IPTOS_THROUGHPUT | IPTOS_PREC_IMMEDIATE;
	skb_push(skb, sizeof(struct dcpim_data_hdr) - sizeof(struct data_segment));
	skb_reset_transport_header(skb);
	h = (struct dcpim_data_hdr *)
				skb_transport_header(skb);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, peer->dst);
	skb->sk = sk;
	skb_dst_set(skb, __sk_dst_get(sk));
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct dcpimhdr, check);
	h->common.source = inet->inet_sport;
	h->common.dest = inet->inet_dport;
	// h->common.len = htons(DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
	// h->common.seq = htonl(DCPIM_SKB_CB(skb)->seq);
	h->common.type = DATA;
	h->free_token = free_token;
	dcpim_set_doff(h);
	
	skb_set_hash_from_sk(skb, sk);

	// h->common.seq = htonl(200);
	err = __ip_queue_xmit(sk, skb, &inet->cork.fl, tos);
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
					"DCPIM data packet after error\n");
			kfree_skb(skb);
		}
	}
	// INC_METRIC(packets_sent[0], 1);
}

/* Called with bottom-half processing disabled.
   assuming hold the socket lock */
int dcpim_write_timer_handler(struct sock *sk)
{    
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff *skb;
	int sent_bytes = 0;
	if(dsk->num_sacks > 0) {
		// printk("retransmit\n");
		dcpim_retransmit(sk);
	}
	while((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
		if (dsk->sender.token_seq - DCPIM_SKB_CB(skb)->end_seq <= sk->sk_sndbuf) {
			dcpim_xmit_data(skb, dsk, false);
			sent_bytes += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
		} else {
			skb_queue_head(&sk->sk_write_queue, skb);
			break;
		}
		/* To Do: grant_nxt might be somewhere in the middle of seq and end_seq; need to split skb to do the transmission */
	}
	return sent_bytes;
}


uint32_t dcpim_xmit_token(struct dcpim_sock* dsk, uint32_t token_bytes) {
	// struct inet_sock *inet = inet_sk((struct sock*)dsk);
	struct sock *sk = (struct sock*)dsk;
	if(token_bytes == 0) {
		return token_bytes;
	}
	dsk->receiver.prev_token_nxt = dsk->receiver.token_nxt;
	dsk->receiver.token_nxt += token_bytes; 
	dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	atomic_add(token_bytes, &dsk->receiver.inflight_bytes);
	dcpim_xmit_control(construct_token_pkt((struct sock*)dsk, 3, dsk->receiver.prev_token_nxt, dsk->receiver.token_nxt, false),
	 	sk);
	return token_bytes;
	
}

int dcpim_token_timer_defer_handler(struct sock *sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	uint32_t matched_bw = atomic_read(&dsk->receiver.matched_bw);
	uint32_t token_bytes = dcpim_avail_token_space((struct sock*)dsk);
	if(sk->sk_state != DCPIM_ESTABLISHED)
		return 0;
	if(matched_bw == 0)
		return 0;
	if(token_bytes < dsk->receiver.token_batch)
		return 0;
	token_bytes = dcpim_xmit_token(dsk, token_bytes);
	if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
		hrtimer_start(&dsk->receiver.token_pace_timer,
			ns_to_ktime(token_bytes * 8 / matched_bw), HRTIMER_MODE_REL_PINNED_SOFT);
	}
	return token_bytes;
}

/* hrtimer may fire twice for some reaons; need to check what happens later. */
enum hrtimer_restart dcpim_xmit_token_handler(struct hrtimer *timer) {

	struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, receiver.token_pace_timer);
	struct sock* sk = (struct sock *)dsk;
	uint32_t matched_bw = atomic_read(&dsk->receiver.matched_bw);
	uint32_t token_bytes = 0;

	if(matched_bw == 0)
		goto put_sock;
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		token_bytes = dcpim_avail_token_space((struct sock*)dsk);
		if(token_bytes >= dsk->receiver.token_batch) {
			dcpim_xmit_token(dsk, token_bytes);
			hrtimer_forward_now(timer, ns_to_ktime(token_bytes * 8 / matched_bw));
			bh_unlock_sock(sk);
			/* still need to sock_hold */
			return HRTIMER_RESTART;
		}	
	} else {
		/* delegate our work to dcpim_release_cb() */
		// WARN_ON(sk->sk_state == DCPIM_CLOSE);
		if (!test_and_set_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
			sock_hold(sk);
		}

	}
	bh_unlock_sock(sk);
put_sock:
	// sock_put(sk);
	return HRTIMER_NORESTART;
}