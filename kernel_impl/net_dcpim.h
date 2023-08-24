/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCPIM module.
 *
 * Version:	@(#)dcpim.h	1.0.2	05/07/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 *		Alan Cox	: Turned on dcpim checksums. I don't want to
 *				  chase 'memory corruption' bugs that aren't!
 */
#ifndef _DCPIM_H
#define _DCPIM_H

#include <linux/list.h>
#include <linux/bug.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/gro.h>
#include <net/xfrm.h>
#include <linux/ipv6.h>
#include <linux/seq_file.h>
#include <linux/poll.h>

#include "linux_dcpim.h"

#define DCPIM_NUM_SACKS 16
enum dcpim_queue {
	DCPIM_FRAG_IN_WRITE_QUEUE,
	DCPIM_FRAG_IN_RTX_QUEUE,
};

/**
 *	struct dcpim_skb_cb  -  DCPIM(-Lite) private variables
 *
 *	@header:      private variables used by IPv4/IPv6
 *	@cscov:       checksum coverage length (DCPIM-Lite only)
 *	@partial_cov: if set indicates partial csum coverage
 */
struct dcpim_skb_cb {
	__u32 seq; /* Starting sequence number	*/
	__u32		end_seq;	/* SEQ + datalen	*/

	union {
		struct inet_skb_parm	h4;
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_skb_parm	h6;
#endif
	} header;
	__u16		cscov;
	__u8		partial_cov;
};
#define DCPIM_SKB_CB(__skb)	((struct dcpim_skb_cb *)((__skb)->cb))

/* return flow control window */
static inline uint32_t dcpim_space(const struct sock *sk)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	uint32_t flow_control_window = READ_ONCE(sk->sk_rcvbuf) - (dsk->receiver.inflight_bytes) 
		- atomic_read(&sk->sk_rmem_alloc);
	return flow_control_window > sk->sk_rcvbuf ? 0 : flow_control_window;
}

static inline uint32_t dcpim_congestion_space(const struct sock *sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	uint32_t congestion_window = dsk->receiver.max_congestion_win - (dsk->receiver.inflight_bytes);
	return congestion_window > dsk->receiver.max_congestion_win ? 0 : congestion_window; 
}

static inline uint32_t dcpim_avail_token_space(const struct sock *sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	uint32_t flow_control_win = dcpim_space(sk);
	uint32_t congestion_win = dcpim_congestion_space(sk);
	uint32_t token_space = 0;
	if(congestion_win > flow_control_win)
		token_space = flow_control_win;
	else
		token_space = congestion_win;
	return token_space > dsk->receiver.token_batch ? dsk->receiver.token_batch : token_space;
 
}

static inline void dcpim_rps_record_flow(const struct sock *sk)
{
	struct dcpim_sock *dsk = dcpim_sk(sk);
	dsk->core_id = raw_smp_processor_id();
	// printk("dsk->core_id:%u\n", dsk->core_id);
#ifdef CONFIG_RPS
	if (static_branch_unlikely(&rfs_needed)) {
		/* Reading sk->sk_rxhash might incur an expensive cache line
		 * miss.
		 *
		 * DCPIM_RECEIVER | DCPIM_SENDER does cover almost all states where RFS
		 * might be useful, and is cheaper [1] than testing :
		 *	IPv4: inet_sk(sk)->inet_daddr
		 * 	IPv6: ipv6_addr_any(&sk->sk_v6_daddr)
		 * OR	an additional socket flag
		 * [1] : sk_state and sk_prot are in the same cache line.
		 */
		if (sk->sk_state == DCPIM_ESTABLISHED) {
			// printk("rfs:rxhash:%u\n", sk->sk_rxhash);
			sock_rps_record_flow_hash(sk->sk_rxhash);
		}
	}
#endif
}

/**
 * dcpim_next_skb() - Compute address of DCPIM's private link field in @skb.
 * @skb:     Socket buffer containing private link field.
 * 
 * DCPIM needs to keep a list of buffers in a message, but it can't use the
 * links built into sk_buffs because DCPIM wants to retain its list even
 * after sending the packet, and the built-in links get used during sending.
 * Thus we allocate extra space at the very end of the packet's data
 * area to hold a forward pointer for a list.
 */
static inline struct sk_buff **dcpim_next_skb(struct sk_buff *skb)
{
	return (struct sk_buff **) (skb_end_pointer(skb) - sizeof(char*));
}

/**
 * dcpim_free_skbs() - Free all of the skbs in a list.
 * @head:    First in a list of socket buffers linked through dcpim_next_skb.
 */
static inline void dcpim_free_skbs(struct sk_buff *head)
{
        while (head) {
                struct sk_buff *next = *dcpim_next_skb(head);
                kfree_skb(head);
                head = next;
        }
}
// /**
//  *	struct dcpim_hslot - DCPIM hash slot
//  *
//  *	@head:	head of list of sockets
//  *	@count:	number of sockets in 'head' list
//  *	@lock:	spinlock protecting changes to head/count
//  */
// struct dcpim_hslot {
// 	struct hlist_head	head;
// 	int			count;
// 	spinlock_t		lock;
// } __attribute__((aligned(2 * sizeof(long))));

// /**
//  *	struct dcpim_table - DCPIM table
//  *
//  *	@hash:	hash table, sockets are hashed on (local port)
//  *	@hash2:	hash table, sockets are hashed on (local port, local address)
//  *	@mask:	number of slots in hash tables, minus 1
//  *	@log:	log2(number of slots in hash table)
//  */
// struct dcpim_table {
// 	struct dcpim_hslot	*hash;
// 	struct dcpim_hslot	*hash2;
// 	unsigned int		mask;
// 	unsigned int		log;
// };

static inline bool inet_exact_dif_match(struct net *net, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_NET_L3_MASTER_DEV)
	if (!net->ipv4.sysctl_tcp_l3mdev_accept &&
	    skb && ipv4_l3mdev_skb(IPCB(skb)->flags))
		return true;
#endif
	return false;
}
/* DCPIM write queue and rtx queue management. Copied from TCP */
void dcpim_rbtree_insert(struct rb_root *root, struct sk_buff *skb);

static inline struct sk_buff *dcpim_rtx_queue_head(const struct sock *sk)
{
	return skb_rb_first(&sk->tcp_rtx_queue);
}

static inline struct sk_buff *dcpim_rtx_queue_tail(const struct sock *sk)
{
	return skb_rb_last(&sk->tcp_rtx_queue);
}

static inline void dcpim_rtx_queue_unlink(struct sk_buff *skb, struct sock *sk)
{
	// tcp_skb_tsorted_anchor_cleanup(skb);
	rb_erase(&skb->rbnode, &sk->tcp_rtx_queue);
}

static inline void dcpim_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sk_wmem_queued_add(sk, -skb->truesize);
	// sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

static inline void dcpim_rtx_queue_unlink_and_free(struct sk_buff *skb, struct sock *sk)
{
	// list_del(&skb->tcp_tsorted_anchor);
	dcpim_rtx_queue_unlink(skb, sk);
	dcpim_wmem_free_skb(sk, skb);
}

/* DCPIM compartor */
//static inline bool before(__u32 seq1, __u32 seq2)
//{
//        return (__s32)(seq1-seq2) < 0;
//}

// #define after(seq2, seq1) 	before(seq1, seq2)

static inline struct sk_buff *dcpim_write_queue_head(const struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline struct sk_buff *dcpim_write_queue_tail(const struct sock *sk)
{
	return skb_peek_tail(&sk->sk_write_queue);
}

#define dcpim_for_write_queue_from_safe(skb, tmp, sk)			\
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)

static inline struct sk_buff *dcpim_send_head(const struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline bool dcpim_skb_is_last(const struct sock *sk,
				   const struct sk_buff *skb)
{
	return skb_queue_is_last(&sk->sk_write_queue, skb);
}

/**
 * tcp_write_queue_empty - test if any payload (or FIN) is available in write queue
 * @sk: socket
 *
 * Since the write queue can have a temporary empty skb in it,
 * we must not use "return skb_queue_empty(&sk->sk_write_queue)"
 */
static inline bool dcpim_write_queue_empty(const struct sock *sk)
{
	const struct dcpim_sock *dp = dcpim_sk(sk);

	return dp->sender.write_seq == dp->sender.snd_nxt;
}

static inline bool dcpim_rtx_queue_empty(const struct sock *sk)
{
	return RB_EMPTY_ROOT(&sk->tcp_rtx_queue);
}

static inline bool dcpim_rtx_and_write_queues_empty(const struct sock *sk)
{
	return dcpim_rtx_queue_empty(sk) && dcpim_write_queue_empty(sk);
}

static inline void dcpim_add_write_queue_tail(struct sock *sk, struct sk_buff *skb)
{
	skb_queue_tail(&sk->sk_write_queue, skb);

	// /* Queue it, remembering where we must start sending. */
	// if (sk->sk_write_queue.next == skb)
	// 	tcp_chrono_start(sk, TCP_CHRONO_BUSY);
}

/* Insert new before skb on the write queue of sk.  */
// static inline void dcpim_insert_write_queue_before(struct sk_buff *new,
// 						  struct sk_buff *skb,
// 						  struct sock *sk)
// {
// 	__skb_queue_before(&sk->sk_write_queue, skb, new);
// }

static inline void dcpim_unlink_write_queue(struct sk_buff *skb, struct sock *sk)
{
	// tcp_skb_tsorted_anchor_cleanup(skb);
	__skb_unlink(skb, &sk->sk_write_queue);
}

static inline void dcpim_ofo_queue_unlink(struct sk_buff *skb, struct sock *sk)
{
	// tcp_skb_tsorted_anchor_cleanup(skb);
	rb_erase(&skb->rbnode, &(dcpim_sk(sk))->out_of_order_queue);
}

static inline void dcpim_rmem_free_skb(struct sock *sk, struct sk_buff *skb) {
	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	__kfree_skb(skb);
}

// extern struct udp_table dcpim_table;
// void dcpim_table_init(struct udp_table *, const char *);
// static inline struct dcpim_hslot *dcpim_hashslot(struct dcpim_table *table,
// 					     struct net *net, unsigned int num)
// {
// 	return &table->hash[dcpim_hashfn(net, num, table->mask)];
// }
// /*
//  * For secondary hash, net_hash_mix() is performed before calling
//  * dcpim_hashslot2(), this explains difference with dcpim_hashslot()
//  */
// static inline struct dcpim_hslot *dcpim_hashslot2(struct dcpim_table *table,
// 					      unsigned int hash)
// {
// 	return &table->hash2[hash & table->mask];
// }

// extern struct proto dcpim_prot;

extern atomic_long_t dcpim_memory_allocated;

/* sysctl variables for dcpim */
extern long sysctl_dcpim_mem[3];
// extern int sysctl_dcpim_rmem_min;
// extern int sysctl_dcpim_wmem_min;

// struct sk_buff;

/*
 *	Generic checksumming routines for DCPIM(-Lite) v4 and v6
 */
static inline __sum16 __dcpim_lib_checksum_complete(struct sk_buff *skb)
{
	return (DCPIM_SKB_CB(skb)->cscov == skb->len ?
		__skb_checksum_complete(skb) :
		__skb_checksum_complete_head(skb, DCPIM_SKB_CB(skb)->cscov));
}

static inline int dcpim_lib_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__dcpim_lib_checksum_complete(skb);
}

// /**
//  * 	dcpim_csum_outgoing  -  compute DCPIMv4/v6 checksum over fragments
//  * 	@sk: 	socket we are writing to
//  * 	@skb: 	sk_buff containing the filled-in DCPIM header
//  * 	        (checksum field must be zeroed out)
//  */
// static inline __wsum dcpim_csum_outgoing(struct sock *sk, struct sk_buff *skb)
// {
// 	__wsum csum = csum_partial(skb_transport_header(skb),
// 				   sizeof(struct dcpimhdr), 0);
// 	skb_queue_walk(&sk->sk_write_queue, skb) {
// 		csum = csum_add(csum, skb->csum);
// 	}
// 	return csum;
// }

static inline __wsum dcpim_csum(struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct dcpim_data_hdr), skb->csum);

	for (skb = skb_shinfo(skb)->frag_list; skb; skb = skb->next) {
		csum = csum_add(csum, skb->csum);
	}
	return csum;
}

static inline __sum16 dcpim_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_DCPIM, base);
}

void dcpim_set_csum(bool nocheck, struct sk_buff *skb,
		  __be32 saddr, __be32 daddr, int len);

static inline void dcpim_csum_pull_header(struct sk_buff *skb)
{
	if (!skb->csum_valid && skb->ip_summed == CHECKSUM_NONE)
		skb->csum = csum_partial(skb->data, sizeof(struct dcpim_data_hdr),
					 skb->csum);
	skb_pull_rcsum(skb, sizeof(struct dcpim_data_hdr));
	DCPIM_SKB_CB(skb)->cscov -= sizeof(struct dcpim_data_hdr);
}

typedef struct sock *(*dcpim_lookup_t)(struct sk_buff *skb, __be16 sport,
				     __be16 dport);

struct sk_buff *dcpim_gro_receive(struct list_head *head, struct sk_buff *skb);
int dcpim_gro_complete(struct sk_buff *skb, int dhoff);

struct sk_buff *__dcpim_gso_segment(struct sk_buff *gso_skb,
				  netdev_features_t features);

static inline struct dcpimhdr *dcpim_gro_dcpimhdr(struct sk_buff *skb)
{
	struct dcpimhdr *uh;
	unsigned int hlen, off;

	off  = skb_gro_offset(skb);
	hlen = off + sizeof(*uh);
	uh   = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen))
		uh = skb_gro_header_slow(skb, hlen, off);

	return uh;
}



// void dcpim_lib_rehash(struct sock *sk, u16 new_hash);

static inline void dcpim_lib_close(struct sock *sk, long timeout)
{
	// sk_common_release(sk);
	if (sk->sk_prot->destroy)
		sk->sk_prot->destroy(sk);

	/*
	 * Observation: when sk_common_release is called, processes have
	 * no access to socket. But net still has.
	 * Step one, detach it from networking:
	 *
	 * A. Remove from hash tables.
	 */

	// sk->sk_prot->unhash(sk);

	/*
	 * In this point socket cannot receive new packets, but it is possible
	 * that some packets are in flight because some CPU runs receiver and
	 * did hash table lookup before we unhashed socket. They will achieve
	 * receive queue and will be purged by socket destructor.
	 *
	 * Also we still have packets pending on receive queue and probably,
	 * our own packets waiting in device queues. sock_destroy will drain
	 * receive queue, but transmitted packets will delay socket destruction
	 * until the last reference will be released.
	 */

	sock_orphan(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	sock_put(sk);
}


// u32 dcpim_flow_hashrnd(void);

// static inline __be16 dcpim_flow_src_port(struct net *net, struct sk_buff *skb,
// 				       int min, int max, bool use_eth)
// {
// 	u32 hash;

// 	if (min >= max) {
// 		/* Use default range */
// 		inet_get_local_port_range(net, &min, &max);
// 	}

// 	hash = skb_get_hash(skb);
// 	if (unlikely(!hash)) {
// 		if (use_eth) {
// 			/* Can't find a normal hash, caller has indicated an
// 			 * Ethernet packet so use that to compute a hash.
// 			 */
// 			hash = jhash(skb->data, 2 * ETH_ALEN,
// 				     (__force u32) skb->protocol);
// 		} else {
// 			/* Can't derive any sort of hash for the packet, set
// 			 * to some consistent random value.
// 			 */
// 			hash = dcpim_flow_hashrnd();
// 		}
// 	}

// 	/* Since this is being sent on the wire obfuscate hash a bit
// 	 * to minimize possbility that any useful information to an
// 	 * attacker is leaked. Only upper 16 bits are relevant in the
// 	 * computation for 16 bit port value.
// 	 */
// 	hash ^= hash << 16;

// 	return htons((((u64) hash * (max - min)) >> 32) + min);
// }


// static inline int dcpim_rqueue_get(struct sock *sk)
// {
// 	return sk_rmem_alloc_get(sk) - READ_ONCE(dcpim_sk(sk)->forward_deficit);
// }

static inline bool dcpim_sk_bound_dev_eq(struct net *net, int bound_dev_if,
				       int dif, int sdif)
{
#if IS_ENABLED(CONFIG_NET_L3_MASTER_DEV)
	return inet_bound_dev_eq(!!net->ipv4.sysctl_udp_l3mdev_accept,
				 bound_dev_if, dif, sdif);
#else
	return inet_bound_dev_eq(true, bound_dev_if, dif, sdif);
#endif
}

// /* net/ipv4/dcpim.c */
void dcpim_destruct_sock(struct sock *sk);
void skb_consume_dcpim(struct sock *sk, struct sk_buff *skb, int len);
// int __dcpim_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb);
// void dcpim_skb_destructor(struct sock *sk, struct sk_buff *skb);
// struct sk_buff *__skb_recv_dcpim(struct sock *sk, unsigned int flags,
// 			       int noblock, int *off, int *err);
// static inline struct sk_buff *skb_recv_dcpim(struct sock *sk, unsigned int flags,
// 					   int noblock, int *err)
// {
// 	int off = 0;

// 	return __skb_recv_dcpim(sk, flags, noblock, &off, err);
// }

int dcpim_v4_early_demux(struct sk_buff *skb);
bool dcpim_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst);
// int dcpim_get_port(struct sock *sk, unsigned short snum,
// 		 int (*saddr_cmp)(const struct sock *,
// 				  const struct sock *));
int dcpim_err(struct sk_buff *, u32);
int dcpim_abort(struct sock *sk, int err);
int dcpim_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int dcpim_push_pending_frames(struct sock *sk);
// void dcpim_flush_pending_frames(struct sock *sk);
// int dcpim_cmsg_send(struct sock *sk, struct msghdr *msg, u16 *gso_size);
// void dcpim4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);
int dcpim_rcv(struct sk_buff *skb);
int dcpim_ioctl(struct sock *sk, int cmd, unsigned long arg);
int dcpim_init_sock(struct sock *sk);
int dcpim_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// int __dcpim_disconnect(struct sock *sk, int flags);
int dcpim_disconnect(struct sock *sk, int flags);
// __poll_t dcpim_poll(struct file *file, struct socket *sock, poll_table *wait);
// struct sk_buff *skb_dcpim_tunnel_segment(struct sk_buff *skb,
// 				       netdev_features_t features,
// 				       bool is_ipv6);
int dcpim_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen);
int dcpim_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *));
int dcpimv4_offload_init(void);
int dcpimv4_offload_end(void);
void dcpim_init(void);

void dcpim_destroy(void);
#endif	/* _DCPIM_H */
