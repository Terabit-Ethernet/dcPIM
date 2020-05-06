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
// #include "net_dcacp.h"
// #include "net_dcacplite.h"
#include "uapi_linux_dcacp.h"
// struct udp_table dcacp_table __read_mostly;
// EXPORT_SYMBOL(dcacp_table);

struct dcacp_peertab dcacp_peers_table;
EXPORT_SYMBOL(dcacp_peers_table);

long sysctl_dcacp_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_dcacp_mem);

atomic_long_t dcacp_memory_allocated;
EXPORT_SYMBOL(dcacp_memory_allocated);

struct dcacp_match_tab dcacp_match_table;
EXPORT_SYMBOL(dcacp_match_table);

struct dcacp_params dcacp_params;
EXPORT_SYMBOL(dcacp_params);

struct dcacp_epoch dcacp_epoch;
EXPORT_SYMBOL(dcacp_epoch);

struct inet_hashinfo dcacp_hashinfo;
EXPORT_SYMBOL(dcacp_hashinfo);
#define MAX_DCACP_PORTS 65536
#define PORTS_PER_CHAIN (MAX_DCACP_PORTS / DCACP_HTABLE_SIZE_MIN)


void dcacp_rbtree_insert(struct rb_root *root, struct sk_buff *skb)
{
        struct rb_node **p = &root->rb_node;
        struct rb_node *parent = NULL;
        struct sk_buff *skb1;

        while (*p) {
                parent = *p;
                skb1 = rb_to_skb(parent);
                if (before(DCACP_SKB_CB(skb)->seq, DCACP_SKB_CB(skb1)->seq))
                        p = &parent->rb_left;
                else
                        p = &parent->rb_right;
        }
        rb_link_node(&skb->rbnode, parent, p);
        rb_insert_color(&skb->rbnode, root);
}

static void dcacp_rtx_queue_purge(struct sock *sk)
{
	struct rb_node *p = rb_first(&sk->tcp_rtx_queue);

	// dcacp_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		dcacp_rtx_queue_unlink(skb, sk);
		dcacp_wmem_free_skb(sk, skb);
	}
}

static void dcacp_ofo_queue_purge(struct sock *sk)
{
	struct dcacp_sock * dsk = dcacp_sk(sk);
	struct rb_node *p = rb_first(&dsk->out_of_order_queue);

	// dcacp_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		dcacp_ofo_queue_unlink(skb, sk);
		dcacp_rmem_free_skb(sk, skb);
	}
}

void dcacp_write_queue_purge(struct sock *sk)
{
	// struct dcacp_sock *dsk;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
		dcacp_wmem_free_skb(sk, skb);
	}
	dcacp_rtx_queue_purge(sk);
	skb = sk->sk_tx_skb_cache;
	if (skb) {
		__kfree_skb(skb);
		sk->sk_tx_skb_cache = NULL;
	}
	// sk_mem_reclaim(sk);
}

void dcacp_read_queue_purge(struct sock* sk) {
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		dcacp_rmem_free_skb(sk, skb);
	}
	dcacp_ofo_queue_purge(sk);
}

DEFINE_STATIC_KEY_FALSE(dcacp_encap_needed_key);
void dcacp_encap_enable(void)
{
	static_branch_inc(&dcacp_encap_needed_key);
}
EXPORT_SYMBOL(dcacp_encap_enable);

int dcacp_err(struct sk_buff *skb, u32 info)
{
	return 0;
	// return __dcacp4_lib_err(skb, info, &dcacp_table);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
void dcacp_flush_pending_frames(struct sock *sk)
{
	struct dcacp_sock *up = dcacp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}
EXPORT_SYMBOL(dcacp_flush_pending_frames);

/**
 * 	dcacp4_hwcsum  -  handle outgoing HW checksumming
 * 	@skb: 	sk_buff containing the filled-in DCACP header
 * 	        (checksum field must be zeroed out)
 *	@src:	source IP address
 *	@dst:	destination IP address
 */
void dcacp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst)
{
	struct dcacphdr *uh = dcacp_hdr(skb);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int hlen = len;
	__wsum csum = 0;

	if (!skb_has_frag_list(skb)) {
		/*
		 * Only one fragment on the socket.
		 */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct dcacphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len,
					       IPPROTO_DCACP, 0);
	} else {
		struct sk_buff *frags;

		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		skb_walk_frags(skb, frags) {
			csum = csum_add(csum, frags->csum);
			hlen -= frags->len;
		}

		csum = skb_checksum(skb, offset, hlen, csum);
		skb->ip_summed = CHECKSUM_NONE;

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_DCACP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}
EXPORT_SYMBOL_GPL(dcacp4_hwcsum);

/* Function to set DCACP checksum for an IPv4 DCACP packet. This is intended
 * for the simple case like when setting the checksum for a DCACP tunnel.
 */
void dcacp_set_csum(bool nocheck, struct sk_buff *skb,
		  __be32 saddr, __be32 daddr, int len)
{
	struct dcacphdr *uh = dcacp_hdr(skb);

	if (nocheck) {
		uh->check = 0;
	} else if (skb_is_gso(skb)) {
		uh->check = ~dcacp_v4_check(len, saddr, daddr, 0);
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		uh->check = 0;
		uh->check = dcacp_v4_check(len, saddr, daddr, lco_csum(skb));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct dcacphdr, check);
		uh->check = ~dcacp_v4_check(len, saddr, daddr, 0);
	}
}
EXPORT_SYMBOL(dcacp_set_csum);

static int dcacp_send_skb(struct sk_buff *skb, struct flowi4 *fl4,
			struct inet_cork *cork, enum dcacp_packet_type type)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct dcacp_data_hdr *uh;
	int err = 0;
	// int is_dcacplite = IS_DCACPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int datalen = len - sizeof(*uh);
	// __wsum csum = 0;

	/*
	 * Create a DCACP header
	 */

	uh = dcacp_data_hdr(skb);
	uh->common.source = inet->inet_sport;
	uh->common.dest = fl4->fl4_dport;
	uh->common.len = htons(len);
	uh->common.check = 0;
	uh->common.type = type;

	if (cork->gso_size) {
		const int hlen = skb_network_header_len(skb) +
				 sizeof(struct dcacp_data_hdr);
		printk("try to do gso \n");
		if (hlen + cork->gso_size > cork->fragsize) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (skb->len > cork->gso_size * DCACP_MAX_SEGMENTS) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (sk->sk_no_check_tx) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (skb->ip_summed != CHECKSUM_PARTIAL ||
		    dst_xfrm(skb_dst(skb))) {
			kfree_skb(skb);
			return -EIO;
		}

		if (datalen > cork->gso_size) {
			skb_shinfo(skb)->gso_size = cork->gso_size;
			skb_shinfo(skb)->gso_type = SKB_GSO_DCACP_L4;
			skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(datalen,
								 cork->gso_size);
		}
		// goto csum_partial;
	}

// 	if (is_dcacplite)  				 /*     DCACP-Lite      */
// 		csum = dcacplite_csum(skb);

// 	else if (sk->sk_no_check_tx) {			 /* DCACP csum off */

// 		skb->ip_summed = CHECKSUM_NONE;
// 		goto send;

// 	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* DCACP hardware csum */
// csum_partial:

// 		dcacp4_hwcsum(skb, fl4->saddr, fl4->daddr);
// 		goto send;

// 	} else
// 		csum = dcacp_csum(skb);
// 	/* add protocol-dependent pseudo-header */
// 	uh->common.check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
// 				      sk->sk_protocol, csum);
// 	if (uh->common.check == 0)
// 		uh->common.check = CSUM_MANGLED_0;

// send:
	// printk("size of data pkt header: %d\n", sizeof(struct dcacp_data_hdr));
	err = ip_send_skb(sock_net(sk), skb);
	// if (err) {
	// 	if (err == -ENOBUFS && !inet->recverr) {
	// 		UDP_INC_STATS(sock_net(sk),
	// 			      UDP_MIB_SNDBUFERRORS, is_dcacplite);
	// 		err = 0;
	// 	}
	// } else
	// 	UDP_INC_STATS(sock_net(sk),
	// 		      UDP_MIB_OUTDATAGRAMS, is_dcacplite);
	return err;
}

/*
 * Push out all pending data as one DCACP datagram. Socket is locked.
 */
int dcacp_push_pending_frames(struct sock *sk)
{
	struct dcacp_sock  *up = dcacp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	struct sk_buff *skb;
	int err = 0;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		goto out;

	err = dcacp_send_skb(skb, fl4, &inet->cork.base, DATA);

out:
	up->len = 0;
	up->pending = 0;
	return err;
}
EXPORT_SYMBOL(dcacp_push_pending_frames);

static int __dcacp_cmsg_send(struct cmsghdr *cmsg, u16 *gso_size)
{
	switch (cmsg->cmsg_type) {
	case DCACP_SEGMENT:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(__u16)))
			return -EINVAL;
		*gso_size = *(__u16 *)CMSG_DATA(cmsg);
		return 0;
	default:
		return -EINVAL;
	}
}

int dcacp_cmsg_send(struct sock *sk, struct msghdr *msg, u16 *gso_size)
{
	struct cmsghdr *cmsg;
	bool need_ip = false;
	int err;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_DCACP) {
			need_ip = true;
			continue;
		}

		err = __dcacp_cmsg_send(cmsg, gso_size);
		if (err)
			return err;
	}

	return need_ip;
}
EXPORT_SYMBOL_GPL(dcacp_cmsg_send);

int sk_wait_ack(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc = 0;
	add_wait_queue(sk_sleep(sk), &wait);
	while(1) {
		if(sk->sk_state == TCP_CLOSE)
			break;
		if (signal_pending(current))
			break;
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		rc = sk_wait_event(sk, timeo, sk->sk_state == TCP_CLOSE, &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	return rc;
}
EXPORT_SYMBOL(sk_wait_ack);


int dcacp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len) {
	// DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	// int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	struct dcacp_sock *dsk = dcacp_sk(sk);
	int sent_len = 0;
	long timeo;
	int err, flags;

	flags = msg->msg_flags;
	if (sk->sk_state != DCACP_SENDER) {
		return -ENOTCONN;
	}

	/* the bytes from user larger than the flow size */
	if (dsk->sender.write_seq >= dsk->total_length) {
		timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
		sk_wait_ack(sk, &timeo);
		return -EMSGSIZE;
	}

	if (len + dsk->sender.write_seq > dsk->total_length) {
		len = dsk->total_length - dsk->sender.write_seq;
	}
	if(sk_stream_wspace(sk) <= 0) {
		timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
		sk_stream_wait_memory(sk, &timeo);
	}

	sent_len = dcacp_fill_packets(sk, msg, len);
	if(sent_len < 0)
		return sent_len;
	if(dsk->total_length < dcacp_params.short_flow_size) {
		struct sk_buff *skb;
		dsk->grant_nxt = dsk->total_length;
		while((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
			dcacp_xmit_data(skb, dsk, false);
		}
	}

	// if(sent_len == -ENOMEM) {
	// 	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 	sk_stream_wait_memory(sk, &timeo);
	// }
	/*temporary solution */
	local_bh_disable();
	bh_lock_sock(sk);
	if(!skb_queue_empty(&sk->sk_write_queue) && 
		dsk->grant_nxt >= DCACP_SKB_CB(dcacp_send_head(sk))->end_seq) {
 		dcacp_write_timer_handler(sk);
	} 
	bh_unlock_sock(sk);
	local_bh_enable();
	return sent_len;
}

int dcacp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int ret;
	lock_sock(sk);
	ret = dcacp_sendmsg_locked(sk, msg, len);
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(dcacp_sendmsg);

int dcacp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct dcacp_sock *up = dcacp_sk(sk);
	int ret;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	if (!up->pending) {
		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

		/* Call dcacp_sendmsg to specify destination address which
		 * sendpage interface can't pass.
		 * This will succeed only when the socket is connected.
		 */
		ret = dcacp_sendmsg(sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		net_dbg_ratelimited("cork failed\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
			     page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		dcacp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = dcacp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

#define DCACP_SKB_IS_STATELESS 0x80000000

/* all head states (dst, sk, nf conntrack) except skb extensions are
 * cleared by dcacp_rcv().
 *
 * We need to preserve secpath, if present, to eventually process
 * IP_CMSG_PASSSEC at recvmsg() time.
 *
 * Other extensions can be cleared.
 */
static bool dcacp_try_make_stateless(struct sk_buff *skb)
{
	if (!skb_has_extensions(skb))
		return true;

	if (!secpath_exists(skb)) {
		skb_ext_reset(skb);
		return true;
	}

	return false;
}

static void dcacp_set_dev_scratch(struct sk_buff *skb)
{
	struct dcacp_dev_scratch *scratch = dcacp_skb_scratch(skb);

	BUILD_BUG_ON(sizeof(struct dcacp_dev_scratch) > sizeof(long));
	scratch->_tsize_state = skb->truesize;
#if BITS_PER_LONG == 64
	scratch->len = skb->len;
	scratch->csum_unnecessary = !!skb_csum_unnecessary(skb);
	scratch->is_linear = !skb_is_nonlinear(skb);
#endif
	if (dcacp_try_make_stateless(skb))
		scratch->_tsize_state |= DCACP_SKB_IS_STATELESS;
}

static void dcacp_skb_csum_unnecessary_set(struct sk_buff *skb)
{
	/* We come here after dcacp_lib_checksum_complete() returned 0.
	 * This means that __skb_checksum_complete() might have
	 * set skb->csum_valid to 1.
	 * On 64bit platforms, we can set csum_unnecessary
	 * to true, but only if the skb is not shared.
	 */
#if BITS_PER_LONG == 64
	if (!skb_shared(skb))
		dcacp_skb_scratch(skb)->csum_unnecessary = true;
#endif
}

static bool dcacp_skb_has_head_state(struct sk_buff *skb)
{
	return !(dcacp_skb_scratch(skb)->_tsize_state & DCACP_SKB_IS_STATELESS);
}

/* fully reclaim rmem/fwd memory allocated for skb */
static void dcacp_rmem_release(struct sock *sk, int size, int partial,
			     bool rx_queue_lock_held)
{
	struct dcacp_sock *up = dcacp_sk(sk);
	struct sk_buff_head *sk_queue;
	int amt;

	if (likely(partial)) {
		up->forward_deficit += size;
		size = up->forward_deficit;
		if (size < (sk->sk_rcvbuf >> 2) &&
		    !skb_queue_empty(&up->reader_queue))
			return;
	} else {
		size += up->forward_deficit;
	}
	up->forward_deficit = 0;

	/* acquire the sk_receive_queue for fwd allocated memory scheduling,
	 * if the called don't held it already
	 */
	sk_queue = &sk->sk_receive_queue;
	if (!rx_queue_lock_held)
		spin_lock(&sk_queue->lock);


	sk->sk_forward_alloc += size;
	amt = (sk->sk_forward_alloc - partial) & ~(SK_MEM_QUANTUM - 1);
	sk->sk_forward_alloc -= amt;

	if (amt)
		__sk_mem_reduce_allocated(sk, amt >> SK_MEM_QUANTUM_SHIFT);

	atomic_sub(size, &sk->sk_rmem_alloc);

	/* this can save us from acquiring the rx queue lock on next receive */
	skb_queue_splice_tail_init(sk_queue, &up->reader_queue);

	if (!rx_queue_lock_held)
		spin_unlock(&sk_queue->lock);
}


/* Idea of busylocks is to let producers grab an extra spinlock
 * to relieve pressure on the receive_queue spinlock shared by consumer.
 * Under flood, this means that only one producer can be in line
 * trying to acquire the receive_queue spinlock.
 * These busylock can be allocated on a per cpu manner, instead of a
 * per socket one (that would consume a cache line per socket)
 */
static int dcacp_busylocks_log __read_mostly;
static spinlock_t *dcacp_busylocks __read_mostly;

static spinlock_t *busylock_acquire(void *ptr)
{
	spinlock_t *busy;

	busy = dcacp_busylocks + hash_ptr(ptr, dcacp_busylocks_log);
	spin_lock(busy);
	return busy;
}

static void busylock_release(spinlock_t *busy)
{
	if (busy)
		spin_unlock(busy);
}

int __dcacp_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff_head *list = &sk->sk_receive_queue;
	int rmem, delta, amt, err = -ENOMEM;
	spinlock_t *busy = NULL;
	int size;
	/* try to avoid the costly atomic add/sub pair when the receive
	 * queue is full; always allow at least a packet
	 */
	rmem = atomic_read(&sk->sk_rmem_alloc);
	if (rmem > sk->sk_rcvbuf)
		goto drop;

	/* Under mem pressure, it might be helpful to help dcacp_recvmsg()
	 * having linear skbs :
	 * - Reduce memory overhead and thus increase receive queue capacity
	 * - Less cache line misses at copyout() time
	 * - Less work at consume_skb() (less alien page frag freeing)
	 */
	if (rmem > (sk->sk_rcvbuf >> 1)) {
		skb_condense(skb);

		busy = busylock_acquire(sk);
	}
	size = skb->truesize;
	dcacp_set_dev_scratch(skb);

	/* we drop only if the receive buf is full and the receive
	 * queue contains some other skb
	 */
	rmem = atomic_add_return(size, &sk->sk_rmem_alloc);
	if (rmem > (size + (unsigned int)sk->sk_rcvbuf))
		goto uncharge_drop;

	spin_lock(&list->lock);
	if (size >= sk->sk_forward_alloc) {
		amt = sk_mem_pages(size);
		delta = amt << SK_MEM_QUANTUM_SHIFT;
		if (!__sk_mem_raise_allocated(sk, delta, amt, SK_MEM_RECV)) {
			err = -ENOBUFS;
			spin_unlock(&list->lock);
			goto uncharge_drop;
		}

		sk->sk_forward_alloc += delta;
	}

	sk->sk_forward_alloc -= size;

	/* no need to setup a destructor, we will explicitly release the
	 * forward allocated memory on dequeue
	 */
	sock_skb_set_dropcount(sk, skb);

	__skb_queue_tail(list, skb);
	spin_unlock(&list->lock);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk);

	busylock_release(busy);
	return 0;

uncharge_drop:
	printk("uncharge_drop\n");
	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);

drop:
	// printk("packet is being dropped\n");
	atomic_inc(&sk->sk_drops);
	busylock_release(busy);
	return err;
}
EXPORT_SYMBOL_GPL(__dcacp_enqueue_schedule_skb);

void dcacp_destruct_sock(struct sock *sk)
{

	/* reclaim completely the forward allocated memory */
	unsigned int total = 0;
	// struct sk_buff *skb;
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     dcacp_sk(sk)->dcacp_port_hash);
	printk("call destruct sock \n");
	/* clean the message*/
	// skb_queue_splice_tail_init(&sk->sk_receive_queue, &dsk->reader_queue);
	// while ((skb = __skb_dequeue(&dsk->reader_queue)) != NULL) {
	// 	total += skb->truesize;
	// 	kfree_skb(skb);
	// }

	dcacp_rmem_release(sk, total, 0, true);
	inet_sock_destruct(sk);
}
EXPORT_SYMBOL_GPL(dcacp_destruct_sock);

int dcacp_init_sock(struct sock *sk)
{
	struct dcacp_sock* dsk = dcacp_sk(sk);
	dcacp_set_state(sk, TCP_CLOSE);
	skb_queue_head_init(&dcacp_sk(sk)->reader_queue);
	dsk->peer = NULL;
	printk("init sock\n");
	// next_going_id 
	atomic64_set(&dsk->next_outgoing_id, 1);
	// initialize the ready queue and its lock
	sk->sk_destruct = dcacp_destruct_sock;
	dsk->unsolved = 0;
	WRITE_ONCE(dsk->num_sacks, 0);
	WRITE_ONCE(dsk->grant_nxt, 0);
	WRITE_ONCE(dsk->prev_grant_nxt, 0);
	INIT_LIST_HEAD(&dsk->match_link);
	WRITE_ONCE(dsk->sender.write_seq, 0);
	WRITE_ONCE(dsk->sender.snd_nxt, 0);
	WRITE_ONCE(dsk->sender.snd_una, 0);

	WRITE_ONCE(dsk->receiver.free_flow, false);
	WRITE_ONCE(dsk->receiver.rcv_nxt, 0);
	WRITE_ONCE(dsk->receiver.copied_seq, 0);
	WRITE_ONCE(dsk->receiver.grant_batch, 0);
	WRITE_ONCE(dsk->receiver.finished_at_receiver, false);
	WRITE_ONCE(dsk->receiver.rmem_exhausted, 0);
	hrtimer_init(&dsk->receiver.flow_wait_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	dsk->receiver.flow_wait_timer.function = &dcacp_flow_wait_event;

	WRITE_ONCE(sk->sk_sndbuf, dcacp_params.wmem_default);
	WRITE_ONCE(sk->sk_rcvbuf, dcacp_params.rmem_default);
	kfree_skb(sk->sk_tx_skb_cache);
	sk->sk_tx_skb_cache = NULL;
	/* reuse tcp rtx queue*/
	sk->tcp_rtx_queue = RB_ROOT;
	dsk->out_of_order_queue = RB_ROOT;
	return 0;
}
EXPORT_SYMBOL_GPL(dcacp_init_sock);

void skb_consume_dcacp(struct sock *sk, struct sk_buff *skb, int len)
{
	if (unlikely(READ_ONCE(sk->sk_peek_off) >= 0)) {
		bool slow = lock_sock_fast(sk);

		sk_peek_offset_bwd(sk, len);
		unlock_sock_fast(sk, slow);
	}

	if (!skb_unref(skb))
		return;

	/* In the more common cases we cleared the head states previously,
	 * see __dcacp_queue_rcv_skb().
	 */
	if (unlikely(dcacp_skb_has_head_state(skb)))
		skb_release_head_state(skb);
	__consume_stateless_skb(skb);
}
EXPORT_SYMBOL_GPL(skb_consume_dcacp);

static struct sk_buff *__first_packet_length(struct sock *sk,
					     struct sk_buff_head *rcvq,
					     int *total)
{
	struct sk_buff *skb;

	while ((skb = skb_peek(rcvq)) != NULL) {
		if (dcacp_lib_checksum_complete(skb)) {
			// __UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS,
			// 		IS_DCACPLITE(sk));
			// __UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS,
			// 		IS_DCACPLITE(sk));
			atomic_inc(&sk->sk_drops);
			__skb_unlink(skb, rcvq);
			*total += skb->truesize;
			kfree_skb(skb);
		} else {
			dcacp_skb_csum_unnecessary_set(skb);
			break;
		}
	}
	return skb;
}

/**
 *	first_packet_length	- return length of first packet in receive queue
 *	@sk: socket
 *
 *	Drops all bad checksum frames, until a valid one is found.
 *	Returns the length of found skb, or -1 if none is found.
 */
static int first_packet_length(struct sock *sk)
{
	struct sk_buff_head *rcvq = &dcacp_sk(sk)->reader_queue;
	struct sk_buff_head *sk_queue = &sk->sk_receive_queue;
	struct sk_buff *skb;
	int total = 0;
	int res;

	spin_lock_bh(&rcvq->lock);
	skb = __first_packet_length(sk, rcvq, &total);
	if (!skb && !skb_queue_empty_lockless(sk_queue)) {
		spin_lock(&sk_queue->lock);
		skb_queue_splice_tail_init(sk_queue, rcvq);
		spin_unlock(&sk_queue->lock);

		skb = __first_packet_length(sk, rcvq, &total);
	}
	res = skb ? skb->len : -1;
	if (total)
		dcacp_rmem_release(sk, total, 1, false);
	spin_unlock_bh(&rcvq->lock);
	return res;
}

/*
 *	IOCTL requests applicable to the DCACP protocol
 */

int dcacp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = sk_wmem_alloc_get(sk);

		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		int amount = max_t(int, 0, first_packet_length(sk));

		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}
EXPORT_SYMBOL(dcacp_ioctl);


/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int dcacp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{

	struct dcacp_sock *dsk = dcacp_sk(sk);
	int copied = 0;
	// u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	// int inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last, *tmp;
	// u32 urg_hole = 0;
	// struct scm_timestamping_internal tss;
	// int cmsg_flags;

	// if (unlikely(flags & MSG_ERRQUEUE))
	// 	return inet_recv_error(sk, msg, len, addr_len);
	// printk("start recvmsg \n");
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	// printk("target bytes:%d\n", target);

	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    (sk->sk_state == DCACP_RECEIVER))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);

	err = -ENOTCONN;


	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);

	if (sk->sk_state != DCACP_RECEIVER)
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
			if (WARN(before(*seq, DCACP_SKB_CB(skb)->seq),
				 "DCACP recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, DCACP_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt,
				 flags))
				break;

			offset = *seq - DCACP_SKB_CB(skb)->seq;
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
			//      *seq, DCACP_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt, flags);
		}

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
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

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
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

		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			release_sock(sk);
			lock_sock(sk);
		} else {
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
	if (dsk->receiver.copied_seq == dsk->total_length) {
		printk("call tcp close in the recv msg\n");
		dcacp_set_state(sk, TCP_CLOSE);
	}
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
	// printk("recvmsg err\n");
	release_sock(sk);
	return err;

// recv_urg:
// 	err = tcp_recv_urg(sk, msg, len, flags);
// 	goto out;

// recv_sndq:
// 	// err = tcp_peek_sndq(sk, msg, len);
// 	goto out;
}

int dcacp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	/* This check is replicated from __ip4_datagram_connect() and
	 * intended to prevent BPF program called below from accessing bytes
	 * that are out of the bound specified by user in addr_len.
	 */
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
}
EXPORT_SYMBOL(dcacp_pre_connect);

int __dcacp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */

	sk->sk_state = TCP_CLOSE;
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sock_rps_reset_rxhash(sk);
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK)) {
		inet_reset_saddr(sk);
		if (sk->sk_prot->rehash &&
		    (sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			sk->sk_prot->rehash(sk);
	}

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->inet_sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}
EXPORT_SYMBOL(__dcacp_disconnect);

int dcacp_disconnect(struct sock *sk, int flags)
{
	lock_sock(sk);
	__dcacp_disconnect(sk, flags);
	release_sock(sk);
	return 0;
}
EXPORT_SYMBOL(dcacp_disconnect);


static inline int dcacp4_csum_init(struct sk_buff *skb, struct dcacphdr *uh,
				 int proto)
{
	int err;

	DCACP_SKB_CB(skb)->partial_cov = 0;
	DCACP_SKB_CB(skb)->cscov = skb->len;

	// if (proto == IPPROTO_DCACPLITE) {
	// 	err = dcacplite_checksum_init(skb, uh);
	// 	if (err)
	// 		return err;

	// 	if (DCACP_SKB_CB(skb)->partial_cov) {
	// 		skb->csum = inet_compute_pseudo(skb, proto);
	// 		return 0;
	// 	}
	// }

	/* Note, we are only interested in != 0 or == 0, thus the
	 * force to int.
	 */
	// struct iphdr* iph = ip_hdr(skb);
	// printk("uh checksum: %u\n", uh->check);
	// printk("uh proto: %d\n", proto);
	// printk("skb len: %d\n", skb->len);
	// printk("skb->ip_summed == CHECKSUM_COMPLETE: %d\n", skb->ip_summed == CHECKSUM_COMPLETE);
	// printk("!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len, proto, skb->csum): %d\n",
	// 	!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len, proto, skb->csum));
	err = (__force int)skb_checksum_init_zero_check(skb, proto, uh->check,
							inet_compute_pseudo);
	// printk("error is err:%d\n", __LINE__);

	if (err)
		return err;

	if (skb->ip_summed == CHECKSUM_COMPLETE && !skb->csum_valid) {
		/* If SW calculated the value, we know it's bad */
		if (skb->csum_complete_sw)
			return 1;

		/* HW says the value is bad. Let's validate that.
		 * skb->csum is no longer the full packet checksum,
		 * so don't treat it as such.
		 */
		skb_checksum_complete_unset(skb);
	}

	return 0;
}

/* wrapper for dcacp_queue_rcv_skb tacking care of csum conversion and
 * return code conversion for ip layer consumption
 */
// static int dcacp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb,
// 			       struct dcacphdr *uh)
// {
// 	int ret;
// 	if (inet_get_convert_csum(sk) && uh->check && !IS_DCACPLITE(sk))
// 		skb_checksum_try_convert(skb, IPPROTO_DCACP, inet_compute_pseudo);

// 	ret = dcacp_queue_rcv_skb(sk, skb);

// 	/* a return value > 0 means to resubmit the input, but
// 	 * it wants the return to be -protocol, or 0
// 	 */
// 	if (ret > 0)
// 		return -ret;
// 	return 0;
// }

/*
 *	All we need to do is get the socket, and then do a checksum.
 */

// int __dcacp4_lib_rcv(struct sk_buff *skb, struct udp_table *dcacptable,
// 		   int proto)
// {
// 	struct sock *sk;
// 	struct dcacphdr *uh;
// 	struct dcacp_data_hdr *dh;

// 	struct dcacp_message_in *msg;
// 	struct message_hslot* slot;
// 	unsigned short ulen;
// 	struct rtable *rt = skb_rtable(skb);
// 	__be32 saddr, daddr;
// 	struct net *net = dev_net(skb->dev);

// 	/*
// 	 *  Validate the packet.
// 	 */
// 	if (!pskb_may_pull(skb, sizeof(struct dcacp_data_hdr)))
// 		goto drop;		/* No space for header. */

// 	uh   = dcacp_hdr(skb);
// 	dh = dcacp_data_hdr(skb);
// 	ulen = ntohs(uh->len);
// 	saddr = ip_hdr(skb)->saddr;
// 	daddr = ip_hdr(skb)->daddr;
// 	if (ulen > skb->len)
// 		goto short_packet;

// 	if (proto == IPPROTO_DCACP) {
// 		/* DCACP validates ulen. */
// 		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
// 			goto short_packet;
// 		uh = dcacp_hdr(skb);
// 	}
// 	// printk("saddr: %u\n LINE: %d", saddr, __LINE__);
// 	// if (dcacp4_csum_init(skb, uh, proto))
// 	// 	goto csum_error;
// 	// printk("reach skb:%d\n", __LINE__);
// 	sk = skb_steal_sock(skb);

// 	if (sk) {
// 		struct dst_entry *dst = skb_dst(skb);
// 		int ret;
// 		slot = dcacp_message_in_bucket(dcacp_sk(sk), dh->message_id);
// 		spin_lock_bh(&slot->lock);
// 		msg = get_dcacp_message_in(dcacp_sk(sk), saddr, dh->common.source, dh->message_id);

// 		dcacp_message_in_finish(msg);
// 		spin_unlock_bh(&slot->lock);
// 		if (unlikely(sk->sk_rx_dst != dst))
// 			dcacp_sk_rx_dst_set(sk, dst);

// 		ret = dcacp_unicast_rcv_skb(sk, skb, uh);
// 		sock_put(sk);
// 		return ret;
// 	}

// 	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
// 		return __dcacp4_lib_mcast_deliver(net, skb, uh,
// 						saddr, daddr, dcacptable, proto);

// 	sk = __dcacp4_lib_lookup_skb(skb, uh->source, uh->dest, dcacptable);
// 	if (sk) {
// 		slot = dcacp_message_in_bucket(dcacp_sk(sk), dh->message_id);
// 		spin_lock_bh(&slot->lock);
// 		msg = get_dcacp_message_in(dcacp_sk(sk), saddr, dh->common.source, dh->message_id);
// 		dcacp_message_in_finish(msg);
// 		spin_unlock_bh(&slot->lock);
// 		return dcacp_unicast_rcv_skb(sk, skb, uh);
// 	}

// 	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
// 		goto drop;
// 	nf_reset_ct(skb);

// 	/* No socket. Drop packet silently, if checksum is wrong */
// 	// if (dcacp_lib_checksum_complete(skb))
// 	// 	goto csum_error;

// 	__UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_DCACPLITE);
// 	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

// 	/*
// 	 * Hmm.  We got an DCACP packet to a port to which we
// 	 * don't wanna listen.  Ignore it.
// 	 */
// 	kfree_skb(skb);
// 	return 0;

// short_packet:
// 	// printk("short packet\n");

// 	net_dbg_ratelimited("DCACP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
// 			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
// 			    &saddr, ntohs(uh->source),
// 			    ulen, skb->len,
// 			    &daddr, ntohs(uh->dest));
// 	goto drop;

// // csum_error:
// // 	/*
// // 	 * RFC1122: OK.  Discards the bad packet silently (as far as
// // 	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
// // 	 */
// // 	printk("checksum error\n");
// // 	printk("DCACP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
// // 			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
// // 			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
// // 			    ulen);
// // 	net_dbg_ratelimited("DCACP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
// // 			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
// // 			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
// // 			    ulen);
// // 	__UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_DCACPLITE);
// drop:
// 	printk("packet is dropped\n");
// 	__UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_DCACPLITE);
// 	kfree_skb(skb);
// 	return 0;
// }

/* We can only early demux multicast if there is a single matching socket.
 * If more than one socket found returns NULL
 */
// static struct sock *__dcacp4_lib_mcast_demux_lookup(struct net *net,
// 						  __be16 loc_port, __be32 loc_addr,
// 						  __be16 rmt_port, __be32 rmt_addr,
// 						  int dif, int sdif)
// {
// 	struct sock *sk, *result;
// 	unsigned short hnum = ntohs(loc_port);
// 	unsigned int slot = dcacp_hashfn(net, hnum, dcacp_table.mask);
// 	struct udp_hslot *hslot = &dcacp_table.hash[slot];

// 	/* Do not bother scanning a too big list */
// 	if (hslot->count > 10)
// 		return NULL;

// 	result = NULL;
// 	sk_for_each_rcu(sk, &hslot->head) {
// 		if (__dcacp_is_mcast_sock(net, sk, loc_port, loc_addr,
// 					rmt_port, rmt_addr, dif, sdif, hnum)) {
// 			if (result)
// 				return NULL;
// 			result = sk;
// 		}
// 	}

// 	return result;
// }

/* For unicast we should only early demux connected sockets or we can
 * break forwarding setups.  The chains here can be long so only check
 * if the first socket is an exact match and if not move on.
 */
// static struct sock *__dcacp4_lib_demux_lookup(struct net *net,
// 					    __be16 loc_port, __be32 loc_addr,
// 					    __be16 rmt_port, __be32 rmt_addr,
// 					    int dif, int sdif)
// {
// 	unsigned short hnum = ntohs(loc_port);
// 	unsigned int hash2 = ipv4_portaddr_hash(net, loc_addr, hnum);
// 	unsigned int slot2 = hash2 & dcacp_table.mask;
// 	struct udp_hslot *hslot2 = &dcacp_table.hash2[slot2];
// 	INET_ADDR_COOKIE(acookie, rmt_addr, loc_addr);
// 	const __portpair ports = INET_COMBINED_PORTS(rmt_port, hnum);
// 	struct sock *sk;

// 	dcacp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
// 		if (INET_MATCH(sk, net, acookie, rmt_addr,
// 			       loc_addr, ports, dif, sdif))
// 			return sk;
// 		/* Only check first socket in chain */
// 		break;
// 	}
// 	return NULL;
// }

int dcacp_v4_early_demux(struct sk_buff *skb)
{
	// struct net *net = dev_net(skb->dev);
	// struct in_device *in_dev = NULL;
	const struct iphdr *iph;
	const struct dcacphdr *uh;
	struct sock *sk = NULL;
	// struct dst_entry *dst;
	// int dif = skb->dev->ifindex;
	int sdif = inet_sdif(skb);
	// int ours;

	/* validate the packet */
	// printk("early demux");
	if(skb->pkt_type != PACKET_HOST) {
		return 0;
	}
	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct dcacphdr)))
		return 0;

	iph = ip_hdr(skb);
	uh = dcacp_hdr(skb);

    // if (th->doff < sizeof(struct tcphdr) / 4)
    //             return 0;
    sk = __dcacp_lookup_established(dev_net(skb->dev), &dcacp_hashinfo,
                                   iph->saddr, uh->source,
                                   iph->daddr, ntohs(uh->dest),
                                   skb->skb_iif, sdif);

    if (sk) {
            skb->sk = sk;
            skb->destructor = sock_edemux;
            if (sk_fullsock(sk)) {
                    struct dst_entry *dst = READ_ONCE(sk->sk_rx_dst);

                    if (dst)
                            dst = dst_check(dst, 0);
                    if (dst &&
                        inet_sk(sk)->rx_dst_ifindex == skb->skb_iif)
                            skb_dst_set_noref(skb, dst);
            }
    }
	return 0;
}


int dcacp_rcv(struct sk_buff *skb)
{
	// printk("receive dcacp rcv\n");
	// skb_dump(KERN_WARNING, skb, false);
	struct dcacphdr* dh;
	// printk("skb->len:%d\n", skb->len);
	if (!pskb_may_pull(skb, sizeof(struct dcacphdr)))
		goto drop;		/* No space for header. */
	dh = dcacp_hdr(skb);
	// printk("dh == NULL?: %d\n", dh == NULL);
	// printk("receive pkt: %d\n", dh->type);
	// printk("end ref \n");
	if(dh->type == DATA) {
		return dcacp_handle_data_pkt(skb);
		// return __dcacp4_lib_rcv(skb, &dcacp_table, IPPROTO_DCACP);
	} else if (dh->type == NOTIFICATION) {
		return dcacp_handle_flow_sync_pkt(skb);
	} else if (dh->type == TOKEN) {
		return dcacp_handle_token_pkt(skb);
	} else if (dh->type == ACK) {
		return dcacp_handle_ack_pkt(skb);
	} else if (dh->type == RTS) {
		return dcacp_handle_rts(skb, &dcacp_match_table, &dcacp_epoch);
	} else if (dh->type == GRANT) {
		return dcacp_handle_grant(skb, &dcacp_match_table, &dcacp_epoch);
	} else if (dh->type == ACCEPT) {
		return dcacp_handle_accept(skb, &dcacp_match_table, &dcacp_epoch);
	}


drop:

	kfree_skb(skb);
	return 0;

	return 0;
	// return __dcacp4_lib_rcv(skb, &dcacp_table, IPPROTO_DCACP);
}

void dcacp_destroy_sock(struct sock *sk)
{
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     dcacp_sk(sk)->dcacp_port_hash);
	struct dcacp_sock *up = dcacp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	local_bh_disable();
	bh_lock_sock(sk);
	hrtimer_cancel(&up->receiver.flow_wait_timer);
	if(sk->sk_state == DCACP_SENDER || sk->sk_state == DCACP_RECEIVER) {
		printk("send ack pkt\n");
		dcacp_xmit_control(construct_ack_pkt(sk, 0), up->peer, sk, inet->inet_dport); 
	}
	dcacp_set_state(sk, TCP_CLOSE);
	// dcacp_flush_pending_frames(sk);
	dcacp_write_queue_purge(sk);
	dcacp_read_queue_purge(sk);
	bh_unlock_sock(sk);
	local_bh_enable();

	printk("sk->sk_wmem_queued:%d\n",sk->sk_wmem_queued);
	spin_lock_bh(&dcacp_epoch.lock);
	dcacp_pq_delete(&dcacp_epoch.flow_q, &up->match_link);
	spin_unlock_bh(&dcacp_epoch.lock);
	if (static_branch_unlikely(&dcacp_encap_needed_key)) {
		if (up->encap_type) {
			void (*encap_destroy)(struct sock *sk);
			encap_destroy = READ_ONCE(up->encap_destroy);
			if (encap_destroy)
				encap_destroy(sk);
		}
		if (up->encap_enabled)
			static_branch_dec(&dcacp_encap_needed_key);
	}
}

/*
 *	Socket option code for DCACP
 */
int dcacp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct dcacp_sock *up = dcacp_sk(sk);
	int val, valbool;
	int err = 0;
	// int is_dcacplite = IS_DCACPLITE(sk);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	valbool = val ? 1 : 0;

	switch (optname) {
	case DCACP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			push_pending_frames(sk);
			release_sock(sk);
		}
		break;

	case DCACP_ENCAP:
		switch (val) {
		case 0:
#ifdef CONFIG_XFRM
		case DCACP_ENCAP_ESPINDCACP:
		case DCACP_ENCAP_ESPINDCACP_NON_IKE:
			up->encap_rcv = xfrm4_udp_encap_rcv;
#endif
			/* FALLTHROUGH */
		case DCACP_ENCAP_L2TPINDCACP:
			up->encap_type = val;
			lock_sock(sk);
			udp_tunnel_encap_enable(sk->sk_socket);
			release_sock(sk);
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	case DCACP_NO_CHECK6_TX:
		up->no_check6_tx = valbool;
		break;

	case DCACP_NO_CHECK6_RX:
		up->no_check6_rx = valbool;
		break;

	case DCACP_SEGMENT:
		if (val < 0 || val > USHRT_MAX)
			return -EINVAL;
		up->gso_size = val;
		break;

	case DCACP_GRO:
		lock_sock(sk);
		if (valbool)
			udp_tunnel_encap_enable(sk->sk_socket);
		up->gro_enabled = valbool;
		release_sock(sk);
		break;

	/*
	 * 	DCACP-Lite's partial checksum coverage (RFC 3828).
	 */
	/* The sender sets actual checksum coverage length via this option.
	 * The case coverage > packet length is handled by send module. */
	case DCACPLITE_SEND_CSCOV:
		// if (!is_dcacplite)          Disable the option on DCACP sockets 
		// 	return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcslen = val;
		up->pcflag |= DCACPLITE_SEND_CC;
		break;

	/* The receiver specifies a minimum checksum coverage value. To make
	 * sense, this should be set to at least 8 (as done below). If zero is
	 * used, this again means full checksum coverage.                     */
	case DCACPLITE_RECV_CSCOV:
		// if (!is_dcacplite)          Disable the option on DCACP sockets 
		// 	return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values.       */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcrlen = val;
		up->pcflag |= DCACPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}
EXPORT_SYMBOL(dcacp_lib_setsockopt);

int dcacp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen)
{
	if (level == SOL_DCACP)
		return dcacp_lib_setsockopt(sk, level, optname, optval, optlen,
					  dcacp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_dcacp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level == SOL_DCACP)
		return dcacp_lib_setsockopt(sk, level, optname, optval, optlen,
					  dcacp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int dcacp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct dcacp_sock *up = dcacp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case DCACP_CORK:
		val = up->corkflag;
		break;

	case DCACP_ENCAP:
		val = up->encap_type;
		break;

	case DCACP_NO_CHECK6_TX:
		val = up->no_check6_tx;
		break;

	case DCACP_NO_CHECK6_RX:
		val = up->no_check6_rx;
		break;

	case DCACP_SEGMENT:
		val = up->gso_size;
		break;

	/* The following two cannot be changed on DCACP sockets, the return is
	 * always 0 (which corresponds to the full checksum coverage of DCACP). */
	case DCACPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case DCACPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(dcacp_lib_getsockopt);

int dcacp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_DCACP)
		return dcacp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_dcacp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_DCACP)
		return dcacp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * 	dcacp_poll - wait for a DCACP event.
 *	@file - file struct
 *	@sock - socket
 *	@wait - poll table
 *
 *	This is same as datagram poll, except for the special case of
 *	blocking sockets. If application is using a blocking fd
 *	and a packet with checksum error is in the queue;
 *	then it could get return from select indicating data available
 *	but then block when reading it. Add special case code
 *	to work around these arguably broken applications.
 */
__poll_t dcacp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	__poll_t mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;

	if (!skb_queue_empty_lockless(&dcacp_sk(sk)->reader_queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	/* Check for false positives due to checksum errors */
	if ((mask & EPOLLRDNORM) && !(file->f_flags & O_NONBLOCK) &&
	    !(sk->sk_shutdown & RCV_SHUTDOWN) && first_packet_length(sk) == -1)
		mask &= ~(EPOLLIN | EPOLLRDNORM);

	return mask;

}
EXPORT_SYMBOL(dcacp_poll);

int dcacp_abort(struct sock *sk, int err)
{
	lock_sock(sk);

	sk->sk_err = err;
	sk->sk_error_report(sk);
	__dcacp_disconnect(sk, 0);

	release_sock(sk);

	return 0;
}
EXPORT_SYMBOL_GPL(dcacp_abort);

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

// static struct sock *dcacp_get_first(struct seq_file *seq, int start)
// {
// 	struct sock *sk;
// 	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
// 	struct dcacp_iter_state *state = seq->private;
// 	struct net *net = seq_file_net(seq);

// 	for (state->bucket = start; state->bucket <= afinfo->dcacp_table->mask;
// 	     ++state->bucket) {
// 		struct udp_hslot *hslot = &afinfo->dcacp_table->hash[state->bucket];

// 		if (hlist_empty(&hslot->head))
// 			continue;

// 		spin_lock_bh(&hslot->lock);
// 		sk_for_each(sk, &hslot->head) {
// 			if (!net_eq(sock_net(sk), net))
// 				continue;
// 			if (sk->sk_family == afinfo->family)
// 				goto found;
// 		}
// 		spin_unlock_bh(&hslot->lock);
// 	}
// 	sk = NULL;
// found:
// 	return sk;
// }

// static struct sock *dcacp_get_next(struct seq_file *seq, struct sock *sk)
// {
// 	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
// 	struct dcacp_iter_state *state = seq->private;
// 	struct net *net = seq_file_net(seq);

// 	do {
// 		sk = sk_next(sk);
// 	} while (sk && (!net_eq(sock_net(sk), net) || sk->sk_family != afinfo->family));

// 	if (!sk) {
// 		if (state->bucket <= afinfo->dcacp_table->mask)
// 			spin_unlock_bh(&afinfo->dcacp_table->hash[state->bucket].lock);
// 		return dcacp_get_first(seq, state->bucket + 1);
// 	}
// 	return sk;
// }

// static struct sock *dcacp_get_idx(struct seq_file *seq, loff_t pos)
// {
// 	struct sock *sk = dcacp_get_first(seq, 0);

// 	if (sk)
// 		while (pos && (sk = dcacp_get_next(seq, sk)) != NULL)
// 			--pos;
// 	return pos ? NULL : sk;
// }

// void *dcacp_seq_start(struct seq_file *seq, loff_t *pos)
// {
// 	struct dcacp_iter_state *state = seq->private;
// 	state->bucket = MAX_DCACP_PORTS;

// 	return *pos ? dcacp_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
// }
// EXPORT_SYMBOL(dcacp_seq_start);

// void *dcacp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
// {
// 	struct sock *sk;

// 	if (v == SEQ_START_TOKEN)
// 		sk = dcacp_get_idx(seq, 0);
// 	else
// 		sk = dcacp_get_next(seq, v);

// 	++*pos;
// 	return sk;
// }
// EXPORT_SYMBOL(dcacp_seq_next);

// void dcacp_seq_stop(struct seq_file *seq, void *v)
// {
// 	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
// 	struct dcacp_iter_state *state = seq->private;

// 	if (state->bucket <= afinfo->dcacp_table->mask)
// 		spin_unlock_bh(&afinfo->dcacp_table->hash[state->bucket].lock);
// }
// EXPORT_SYMBOL(dcacp_seq_stop);

/* ------------------------------------------------------------------------ */
static void dcacp4_format_sock(struct sock *sp, struct seq_file *f,
		int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr;
	__be32 src  = inet->inet_rcv_saddr;
	__u16 destp	  = ntohs(inet->inet_dport);
	__u16 srcp	  = ntohs(inet->inet_sport);

	seq_printf(f, "%5d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u",
		bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		dcacp_rqueue_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sp)),
		0, sock_i_ino(sp),
		refcount_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops));
}

int dcacp4_seq_show(struct seq_file *seq, void *v)
{
	seq_setwidth(seq, 127);
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode ref pointer drops");
	else {
		struct dcacp_iter_state *state = seq->private;

		dcacp4_format_sock(v, seq, state->bucket);
	}
	seq_pad(seq, '\n');
	return 0;
}

// const struct seq_operations dcacp_seq_ops = {
// 	.start		= dcacp_seq_start,
// 	.next		= dcacp_seq_next,
// 	.stop		= dcacp_seq_stop,
// 	.show		= dcacp4_seq_show,
// };
// EXPORT_SYMBOL(dcacp_seq_ops);

// static struct dcacp_seq_afinfo dcacp4_seq_afinfo = {
// 	.family		= AF_INET,
// 	// .dcacp_table	= &dcacp_table,
// };

// static int __net_init dcacp4_proc_init_net(struct net *net)
// {
// 	if (!proc_create_net_data("dcacp", 0444, net->proc_net, &dcacp_seq_ops,
// 			sizeof(struct dcacp_iter_state), &dcacp4_seq_afinfo))
// 		return -ENOMEM;
// 	return 0;
// }

// static void __net_exit dcacp4_proc_exit_net(struct net *net)
// {
// 	remove_proc_entry("dcacp", net->proc_net);
// }

// static struct pernet_operations dcacp4_net_ops = {
// 	.init = dcacp4_proc_init_net,
// 	.exit = dcacp4_proc_exit_net,
// };

// int __init dcacp4_proc_init(void)
// {
// 	return register_pernet_subsys(&dcacp4_net_ops);
// }

// void dcacp4_proc_exit(void)
// {
// 	unregister_pernet_subsys(&dcacp4_net_ops);
// }
#endif /* CONFIG_PROC_FS */

void* allocate_hash_table(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit) {
	unsigned long long max = high_limit;
	unsigned long log2qty, size;
	void *table = NULL;
	gfp_t gfp_flags;
	numentries = roundup_pow_of_two(numentries);

	max = min(max, 0x80000000ULL);

	if (numentries < low_limit)
		numentries = low_limit;
	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);
	gfp_flags = (flags & HASH_ZERO) ? GFP_ATOMIC | __GFP_ZERO : GFP_ATOMIC;

	size = bucketsize << log2qty;

	table = vmalloc(size);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	pr_info("%s hash table entries: %ld (order: %d, %lu bytes, %s)\n",
		tablename, 1UL << log2qty, ilog2(size) - PAGE_SHIFT, size,
		"vmalloc");

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}

// static __initdata unsigned long uhash_entries;
// static int __init set_uhash_entries(char *str)
// {
// 	ssize_t ret;

// 	if (!str)
// 		return 0;

// 	ret = kstrtoul(str, 0, &uhash_entries);
// 	if (ret)
// 		return 0;

// 	if (uhash_entries && uhash_entries < DCACP_HTABLE_SIZE_MIN)
// 		uhash_entries = DCACP_HTABLE_SIZE_MIN;
// 	return 1;
// }
// __setup("uhash_entries=", set_uhash_entries);

// void __init dcacp_table_init(struct udp_table *table, const char *name)
// {
// 	unsigned int i;
// 	table->hash = allocate_hash_table(name,
// 					      2 * sizeof(struct udp_hslot),
// 					      uhash_entries,
// 					      21, /* one slot per 2 MB */
// 					      0,
// 					      &table->log,
// 					      &table->mask,
// 					      DCACP_HTABLE_SIZE_MIN,
// 					      64 * 1024);
// 	table->hash2 = table->hash + (table->mask + 1);
// 	for (i = 0; i <= table->mask; i++) {
// 		INIT_HLIST_HEAD(&table->hash[i].head);
// 		table->hash[i].count = 0;
// 		spin_lock_init(&table->hash[i].lock);
// 	}
// 	for (i = 0; i <= table->mask; i++) {
// 		INIT_HLIST_HEAD(&table->hash2[i].head);
// 		table->hash2[i].count = 0;
// 		spin_lock_init(&table->hash2[i].lock);
// 	}
// }

u32 dcacp_flow_hashrnd(void)
{
	static u32 hashrnd __read_mostly;

	net_get_random_once(&hashrnd, sizeof(hashrnd));

	return hashrnd;
}
EXPORT_SYMBOL(dcacp_flow_hashrnd);

static void __dcacp_sysctl_init(struct net *net)
{
	net->ipv4.sysctl_udp_rmem_min = SK_MEM_QUANTUM;
	net->ipv4.sysctl_udp_wmem_min = SK_MEM_QUANTUM;

#ifdef CONFIG_NET_L3_MASTER_DEV
	net->ipv4.sysctl_udp_l3mdev_accept = 0;
#endif
}

static int __net_init dcacp_sysctl_init(struct net *net)
{
	__dcacp_sysctl_init(net);
	return 0;
}

static struct pernet_operations __net_initdata dcacp_sysctl_ops = {
	.init	= dcacp_sysctl_init,
};

void __init dcacp_init(void)
{
	unsigned long limit;
	unsigned int i;

	printk("try to add dcacp table \n");

	dcacp_hashtable_init(&dcacp_hashinfo, 0);

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_dcacp_mem[0] = limit / 4 * 3;
	sysctl_dcacp_mem[1] = limit;
	sysctl_dcacp_mem[2] = sysctl_dcacp_mem[0] * 2;

	__dcacp_sysctl_init(&init_net);
	/* 16 spinlocks per cpu */
	dcacp_busylocks_log = ilog2(nr_cpu_ids) + 4;
	dcacp_busylocks = kmalloc(sizeof(spinlock_t) << dcacp_busylocks_log,
				GFP_KERNEL);
	if (!dcacp_busylocks)
		panic("DCACP: failed to alloc dcacp_busylocks\n");
	for (i = 0; i < (1U << dcacp_busylocks_log); i++)
		spin_lock_init(dcacp_busylocks + i);
	if (register_pernet_subsys(&dcacp_sysctl_ops)) 
		panic("DCACP: failed to init sysctl parameters.\n");

	dcacp_peertab_init(&dcacp_peers_table);
	printk("DCACP init complete\n");

}

void dcacp_destroy() {
	printk("try to destroy peer table\n");
	dcacp_peertab_destroy(&dcacp_peers_table);
	printk("try to destroy dcacp socket table\n");
	dcacp_hashtable_destroy(&dcacp_hashinfo);
	kfree(dcacp_busylocks);
}