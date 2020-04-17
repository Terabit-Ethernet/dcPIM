/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCACP module.
 *
 * Version:	@(#)dcacp.h	1.0.2	05/07/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 *		Alan Cox	: Turned on dcacp checksums. I don't want to
 *				  chase 'memory corruption' bugs that aren't!
 */
#ifndef _DCACP_H
#define _DCACP_H

#include <linux/list.h>
#include <linux/bug.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <linux/seq_file.h>
#include <linux/poll.h>

#include "linux_dcacp.h"

#define TOS_7 0xE0
#define TOS_6 0xC0
#define TOS_5 0xA0
#define TOS_4 0x80
#define TOS_3 0x60
#define TOS_2 0x40
#define TOS_1 0x20
#define TOS_0 0x00

/**
 *	struct dcacp_skb_cb  -  DCACP(-Lite) private variables
 *
 *	@header:      private variables used by IPv4/IPv6
 *	@cscov:       checksum coverage length (DCACP-Lite only)
 *	@partial_cov: if set indicates partial csum coverage
 */
struct dcacp_skb_cb {
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
#define DCACP_SKB_CB(__skb)	((struct dcacp_skb_cb *)((__skb)->cb))

/**
 * dcacp_next_skb() - Compute address of DCACP's private link field in @skb.
 * @skb:     Socket buffer containing private link field.
 * 
 * DCACP needs to keep a list of buffers in a message, but it can't use the
 * links built into sk_buffs because DCACP wants to retain its list even
 * after sending the packet, and the built-in links get used during sending.
 * Thus we allocate extra space at the very end of the packet's data
 * area to hold a forward pointer for a list.
 */
static inline struct sk_buff **dcacp_next_skb(struct sk_buff *skb)
{
	return (struct sk_buff **) (skb_end_pointer(skb) - sizeof(char*));
}

/**
 * dcacp_free_skbs() - Free all of the skbs in a list.
 * @head:    First in a list of socket buffers linked through dcacp_next_skb.
 */
static inline void dcacp_free_skbs(struct sk_buff *head)
{
        while (head) {
                struct sk_buff *next = *dcacp_next_skb(head);
                kfree_skb(head);
                head = next;
        }
}
// /**
//  *	struct dcacp_hslot - DCACP hash slot
//  *
//  *	@head:	head of list of sockets
//  *	@count:	number of sockets in 'head' list
//  *	@lock:	spinlock protecting changes to head/count
//  */
// struct dcacp_hslot {
// 	struct hlist_head	head;
// 	int			count;
// 	spinlock_t		lock;
// } __attribute__((aligned(2 * sizeof(long))));

// /**
//  *	struct dcacp_table - DCACP table
//  *
//  *	@hash:	hash table, sockets are hashed on (local port)
//  *	@hash2:	hash table, sockets are hashed on (local port, local address)
//  *	@mask:	number of slots in hash tables, minus 1
//  *	@log:	log2(number of slots in hash table)
//  */
// struct dcacp_table {
// 	struct dcacp_hslot	*hash;
// 	struct dcacp_hslot	*hash2;
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
/* DCACP write queue and rtx queue management. Copied from TCP */
void dcacp_rbtree_insert(struct rb_root *root, struct sk_buff *skb);

static inline struct sk_buff *dcacp_rtx_queue_head(const struct sock *sk)
{
	return skb_rb_first(&sk->tcp_rtx_queue);
}

static inline struct sk_buff *dcacp_rtx_queue_tail(const struct sock *sk)
{
	return skb_rb_last(&sk->tcp_rtx_queue);
}

static inline void dcacp_rtx_queue_unlink(struct sk_buff *skb, struct sock *sk)
{
	// tcp_skb_tsorted_anchor_cleanup(skb);
	rb_erase(&skb->rbnode, &sk->tcp_rtx_queue);
}

static inline void dcacp_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk_wmem_queued_add(sk, -skb->truesize);
	sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

static inline void dcacp_rtx_queue_unlink_and_free(struct sk_buff *skb, struct sock *sk)
{
	// list_del(&skb->tcp_tsorted_anchor);
	dcacp_rtx_queue_unlink(skb, sk);
	dcacp_wmem_free_skb(sk, skb);
}

/* DCACP compartor */
static inline bool before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

static inline struct sk_buff *dcacp_write_queue_head(const struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline struct sk_buff *dcacp_write_queue_tail(const struct sock *sk)
{
	return skb_peek_tail(&sk->sk_write_queue);
}

#define dcacp_for_write_queue_from_safe(skb, tmp, sk)			\
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)

static inline struct sk_buff *dcacp_send_head(const struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline bool dcacp_skb_is_last(const struct sock *sk,
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
static inline bool dcacp_write_queue_empty(const struct sock *sk)
{
	const struct dcacp_sock *dp = dcacp_sk(sk);

	return dp->sender.write_seq == dp->sender.snd_nxt;
}

static inline bool dcacp_rtx_queue_empty(const struct sock *sk)
{
	return RB_EMPTY_ROOT(&sk->tcp_rtx_queue);
}

static inline bool dcacp_rtx_and_write_queues_empty(const struct sock *sk)
{
	return dcacp_rtx_queue_empty(sk) && dcacp_write_queue_empty(sk);
}

static inline void dcacp_add_write_queue_tail(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&sk->sk_write_queue, skb);

	// /* Queue it, remembering where we must start sending. */
	// if (sk->sk_write_queue.next == skb)
	// 	tcp_chrono_start(sk, TCP_CHRONO_BUSY);
}

/* Insert new before skb on the write queue of sk.  */
static inline void dcacp_insert_write_queue_before(struct sk_buff *new,
						  struct sk_buff *skb,
						  struct sock *sk)
{
	__skb_queue_before(&sk->sk_write_queue, skb, new);
}

static inline void dcacp_unlink_write_queue(struct sk_buff *skb, struct sock *sk)
{
	// tcp_skb_tsorted_anchor_cleanup(skb);
	__skb_unlink(skb, &sk->sk_write_queue);
}



extern struct udp_table dcacp_table;
void dcacp_table_init(struct udp_table *, const char *);
// static inline struct dcacp_hslot *dcacp_hashslot(struct dcacp_table *table,
// 					     struct net *net, unsigned int num)
// {
// 	return &table->hash[dcacp_hashfn(net, num, table->mask)];
// }
// /*
//  * For secondary hash, net_hash_mix() is performed before calling
//  * dcacp_hashslot2(), this explains difference with dcacp_hashslot()
//  */
// static inline struct dcacp_hslot *dcacp_hashslot2(struct dcacp_table *table,
// 					      unsigned int hash)
// {
// 	return &table->hash2[hash & table->mask];
// }

// extern struct proto dcacp_prot;

extern atomic_long_t dcacp_memory_allocated;

/* sysctl variables for dcacp */
extern long sysctl_dcacp_mem[3];
// extern int sysctl_dcacp_rmem_min;
// extern int sysctl_dcacp_wmem_min;

// struct sk_buff;

/*
 *	Generic checksumming routines for DCACP(-Lite) v4 and v6
 */
static inline __sum16 __dcacp_lib_checksum_complete(struct sk_buff *skb)
{
	return (DCACP_SKB_CB(skb)->cscov == skb->len ?
		__skb_checksum_complete(skb) :
		__skb_checksum_complete_head(skb, DCACP_SKB_CB(skb)->cscov));
}

static inline int dcacp_lib_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__dcacp_lib_checksum_complete(skb);
}

// /**
//  * 	dcacp_csum_outgoing  -  compute DCACPv4/v6 checksum over fragments
//  * 	@sk: 	socket we are writing to
//  * 	@skb: 	sk_buff containing the filled-in DCACP header
//  * 	        (checksum field must be zeroed out)
//  */
// static inline __wsum dcacp_csum_outgoing(struct sock *sk, struct sk_buff *skb)
// {
// 	__wsum csum = csum_partial(skb_transport_header(skb),
// 				   sizeof(struct dcacphdr), 0);
// 	skb_queue_walk(&sk->sk_write_queue, skb) {
// 		csum = csum_add(csum, skb->csum);
// 	}
// 	return csum;
// }

static inline __wsum dcacp_csum(struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct dcacp_data_hdr), skb->csum);

	for (skb = skb_shinfo(skb)->frag_list; skb; skb = skb->next) {
		csum = csum_add(csum, skb->csum);
	}
	return csum;
}

static inline __sum16 dcacp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_DCACP, base);
}

void dcacp_set_csum(bool nocheck, struct sk_buff *skb,
		  __be32 saddr, __be32 daddr, int len);

static inline void dcacp_csum_pull_header(struct sk_buff *skb)
{
	if (!skb->csum_valid && skb->ip_summed == CHECKSUM_NONE)
		skb->csum = csum_partial(skb->data, sizeof(struct dcacp_data_hdr),
					 skb->csum);
	skb_pull_rcsum(skb, sizeof(struct dcacp_data_hdr));
	DCACP_SKB_CB(skb)->cscov -= sizeof(struct dcacp_data_hdr);
}

typedef struct sock *(*dcacp_lookup_t)(struct sk_buff *skb, __be16 sport,
				     __be16 dport);

struct sk_buff *dcacp_gro_receive(struct list_head *head, struct sk_buff *skb,
				struct dcacphdr *uh, struct sock *sk);
int dcacp_gro_complete(struct sk_buff *skb, int nhoff, dcacp_lookup_t lookup);

struct sk_buff *__dcacp_gso_segment(struct sk_buff *gso_skb,
				  netdev_features_t features);

static inline struct dcacphdr *dcacp_gro_dcacphdr(struct sk_buff *skb)
{
	struct dcacphdr *uh;
	unsigned int hlen, off;

	off  = skb_gro_offset(skb);
	hlen = off + sizeof(*uh);
	uh   = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen))
		uh = skb_gro_header_slow(skb, hlen, off);

	return uh;
}



// void dcacp_lib_rehash(struct sock *sk, u16 new_hash);

static inline void dcacp_lib_close(struct sock *sk, long timeout)
{
	printk("call socket close\n");
	sk_common_release(sk);
}


// u32 dcacp_flow_hashrnd(void);

// static inline __be16 dcacp_flow_src_port(struct net *net, struct sk_buff *skb,
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
// 			hash = dcacp_flow_hashrnd();
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

/*
 * Save and compile IPv4 options, return a pointer to it
 */

static inline struct ip_options_rcu *dcacp_v4_save_options(struct net *net,
							 struct sk_buff *skb)
{
	const struct ip_options *opt = &DCACP_SKB_CB(skb)->header.h4.opt;
	struct ip_options_rcu *dopt = NULL;
	if (opt->optlen) {
		int opt_size = sizeof(*dopt) + opt->optlen;

		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt && __ip_options_echo(net, &dopt->opt, skb, opt)) {
			kfree(dopt);
			dopt = NULL;
		}
	}
	return dopt;
}

static inline int dcacp_rqueue_get(struct sock *sk)
{
	return sk_rmem_alloc_get(sk) - READ_ONCE(dcacp_sk(sk)->forward_deficit);
}

static inline bool dcacp_sk_bound_dev_eq(struct net *net, int bound_dev_if,
				       int dif, int sdif)
{
#if IS_ENABLED(CONFIG_NET_L3_MASTER_DEV)
	return inet_bound_dev_eq(!!net->ipv4.sysctl_udp_l3mdev_accept,
				 bound_dev_if, dif, sdif);
#else
	return inet_bound_dev_eq(true, bound_dev_if, dif, sdif);
#endif
}

// /* net/ipv4/dcacp.c */
void dcacp_destruct_sock(struct sock *sk);
void skb_consume_dcacp(struct sock *sk, struct sk_buff *skb, int len);
// int __dcacp_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb);
// void dcacp_skb_destructor(struct sock *sk, struct sk_buff *skb);
// struct sk_buff *__skb_recv_dcacp(struct sock *sk, unsigned int flags,
// 			       int noblock, int *off, int *err);
// static inline struct sk_buff *skb_recv_dcacp(struct sock *sk, unsigned int flags,
// 					   int noblock, int *err)
// {
// 	int off = 0;

// 	return __skb_recv_dcacp(sk, flags, noblock, &off, err);
// }

int dcacp_v4_early_demux(struct sk_buff *skb);
bool dcacp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst);
// int dcacp_get_port(struct sock *sk, unsigned short snum,
// 		 int (*saddr_cmp)(const struct sock *,
// 				  const struct sock *));
int dcacp_err(struct sk_buff *, u32);
int dcacp_abort(struct sock *sk, int err);
int dcacp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int dcacp_push_pending_frames(struct sock *sk);
void dcacp_flush_pending_frames(struct sock *sk);
int dcacp_cmsg_send(struct sock *sk, struct msghdr *msg, u16 *gso_size);
void dcacp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);
int dcacp_rcv(struct sk_buff *skb);
int dcacp_ioctl(struct sock *sk, int cmd, unsigned long arg);
int dcacp_init_sock(struct sock *sk);
int dcacp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int __dcacp_disconnect(struct sock *sk, int flags);
int dcacp_disconnect(struct sock *sk, int flags);
// __poll_t dcacp_poll(struct file *file, struct socket *sock, poll_table *wait);
// struct sk_buff *skb_dcacp_tunnel_segment(struct sk_buff *skb,
// 				       netdev_features_t features,
// 				       bool is_ipv6);
int dcacp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen);
int dcacp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *));
struct sock *dcacp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			     __be32 daddr, __be16 dport, int dif);
struct sock *__dcacp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			       __be32 daddr, __be16 dport, int dif, int sdif,
			       struct udp_table *tbl, struct sk_buff *skb);
struct sock *dcacp4_lib_lookup_skb(struct sk_buff *skb,
				 __be16 sport, __be16 dport);
// struct sock *dcacp6_lib_lookup(struct net *net,
// 			     const struct in6_addr *saddr, __be16 sport,
// 			     const struct in6_addr *daddr, __be16 dport,
// 			     int dif);
// struct sock *__dcacp6_lib_lookup(struct net *net,
// 			       const struct in6_addr *saddr, __be16 sport,
// 			       const struct in6_addr *daddr, __be16 dport,
// 			       int dif, int sdif, struct dcacp_table *tbl,
// 			       struct sk_buff *skb);
// struct sock *dcacp6_lib_lookup_skb(struct sk_buff *skb,
// 				 __be16 sport, __be16 dport);

/* DCACP uses skb->dev_scratch to cache as much information as possible and avoid
 * possibly multiple cache miss on dequeue()
 */
struct dcacp_dev_scratch {
	/* skb->truesize and the stateless bit are embedded in a single field;
	 * do not use a bitfield since the compiler emits better/smaller code
	 * this way
	 */
	u32 _tsize_state;

#if BITS_PER_LONG == 64
	/* len and the bit needed to compute skb_csum_unnecessary
	 * will be on cold cache lines at recvmsg time.
	 * skb->len can be stored on 16 bits since the dcacp header has been
	 * already validated and pulled.
	 */
	u16 len;
	bool is_linear;
	bool csum_unnecessary;
#endif
};

static inline struct dcacp_dev_scratch *dcacp_skb_scratch(struct sk_buff *skb)
{
	return (struct dcacp_dev_scratch *)&skb->dev_scratch;
}

#if BITS_PER_LONG == 64
static inline unsigned int dcacp_skb_len(struct sk_buff *skb)
{
	return dcacp_skb_scratch(skb)->len;
}

static inline bool dcacp_skb_csum_unnecessary(struct sk_buff *skb)
{
	return true;
	// return dcacp_skb_scratch(skb)->csum_unnecessary;
}

static inline bool dcacp_skb_is_linear(struct sk_buff *skb)
{
	return dcacp_skb_scratch(skb)->is_linear;
}

#else
static inline unsigned int dcacp_skb_len(struct sk_buff *skb)
{
	return skb->len;
}

static inline bool dcacp_skb_csum_unnecessary(struct sk_buff *skb)
{
	return skb_csum_unnecessary(skb);
}

static inline bool dcacp_skb_is_linear(struct sk_buff *skb)
{
	return !skb_is_nonlinear(skb);
}
#endif

// static inline int copy_linear_skb(struct sk_buff *skb, int len, int off,
// 				  struct iov_iter *to)
// {
// 	int n;

// 	n = copy_to_iter(skb->data + off, len, to);
// 	if (n == len)
// 		return 0;

// 	iov_iter_revert(to, n);
// 	return -EFAULT;
// }

/*
 * 	SNMP statistics for UDP and UDP-Lite
 */
#define UDP_INC_STATS(net, field, is_udplite)		      do { \
	if (is_udplite) SNMP_INC_STATS((net)->mib.udplite_statistics, field);       \
	else		SNMP_INC_STATS((net)->mib.udp_statistics, field);  }  while(0)
#define __UDP_INC_STATS(net, field, is_udplite) 	      do { \
	if (is_udplite) __SNMP_INC_STATS((net)->mib.udplite_statistics, field);         \
	else		__SNMP_INC_STATS((net)->mib.udp_statistics, field);    }  while(0)

#define __UDP6_INC_STATS(net, field, is_udplite)	    do { \
	if (is_udplite) __SNMP_INC_STATS((net)->mib.udplite_stats_in6, field);\
	else		__SNMP_INC_STATS((net)->mib.udp_stats_in6, field);  \
} while(0)
#define UDP6_INC_STATS(net, field, __lite)		    do { \
	if (__lite) SNMP_INC_STATS((net)->mib.udplite_stats_in6, field);  \
	else	    SNMP_INC_STATS((net)->mib.udp_stats_in6, field);      \
} while(0)

#if IS_ENABLED(CONFIG_IPV6)
#define __UDPX_MIB(sk, ipv4)						\
({									\
	ipv4 ? (IS_UDPLITE(sk) ? sock_net(sk)->mib.udplite_statistics :	\
				 sock_net(sk)->mib.udp_statistics) :	\
		(IS_UDPLITE(sk) ? sock_net(sk)->mib.udplite_stats_in6 :	\
				 sock_net(sk)->mib.udp_stats_in6);	\
})
#else
#define __UDPX_MIB(sk, ipv4)						\
({									\
	IS_UDPLITE(sk) ? sock_net(sk)->mib.udplite_statistics :		\
			 sock_net(sk)->mib.udp_statistics;		\
})
#endif

#define __UDPX_INC_STATS(sk, field) \
	__SNMP_INC_STATS(__UDPX_MIB(sk, (sk)->sk_family == AF_INET), field)

#ifdef CONFIG_PROC_FS
struct dcacp_seq_afinfo {
	sa_family_t			family;
	struct udp_table		*dcacp_table;
};

struct dcacp_iter_state {
	struct seq_net_private  p;
	int			bucket;
};

void *dcacp_seq_start(struct seq_file *seq, loff_t *pos);
void *dcacp_seq_next(struct seq_file *seq, void *v, loff_t *pos);
void dcacp_seq_stop(struct seq_file *seq, void *v);

extern const struct seq_operations dcacp_seq_ops;
extern const struct seq_operations dcacp6_seq_ops;

int dcacp4_proc_init(void);
void dcacp4_proc_exit(void);
#endif /* CONFIG_PROC_FS */

int dcacpv4_offload_init(void);
int dcacpv4_offload_end(void);
void dcacp_init(void);

void dcacp_destroy(void);
DECLARE_STATIC_KEY_FALSE(dcacp_encap_needed_key);
void dcacp_encap_enable(void);
#if IS_ENABLED(CONFIG_IPV6)
DECLARE_STATIC_KEY_FALSE(dcacpv6_encap_needed_key);
void dcacpv6_encap_enable(void);
#endif

static inline struct sk_buff *dcacp_rcv_segment(struct sock *sk,
					      struct sk_buff *skb, bool ipv4)
{
	netdev_features_t features = NETIF_F_SG;
	struct sk_buff *segs;

	/* Avoid csum recalculation by skb_segment unless userspace explicitly
	 * asks for the final checksum values
	 */
	if (!inet_get_convert_csum(sk))
		features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;

	/* DCACP segmentation expects packets of type CHECKSUM_PARTIAL or
	 * CHECKSUM_NONE in __dcacp_gso_segment. DCACP GRO indeed builds partial
	 * packets in dcacp_gro_complete_segment. As does DCACP GSO, verified by
	 * dcacp_send_skb. But when those packets are looped in dev_loopback_xmit
	 * their ip_summed is set to CHECKSUM_UNNECESSARY. Reset in this
	 * specific case, where PARTIAL is both correct and required.
	 */
	if (skb->pkt_type == PACKET_LOOPBACK)
		skb->ip_summed = CHECKSUM_PARTIAL;

	/* the GSO CB lays after the DCACP one, no need to save and restore any
	 * CB fragment
	 */
	segs = __skb_gso_segment(skb, features, false);
	if (IS_ERR_OR_NULL(segs)) {
		int segs_nr = skb_shinfo(skb)->gso_segs;

		atomic_add(segs_nr, &sk->sk_drops);
		SNMP_ADD_STATS(__UDPX_MIB(sk, ipv4), UDP_MIB_INERRORS, segs_nr);
		kfree_skb(skb);
		return NULL;
	}

	consume_skb(skb);
	return segs;
}

#endif	/* _DCACP_H */
