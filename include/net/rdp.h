/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the RDP module.
 *
 * Version:	@(#)rdp.h	1.0.2	05/07/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 *		Alan Cox	: Turned on rdp checksums. I don't want to
 *				  chase 'memory corruption' bugs that aren't!
 */
#ifndef _RDP_H
#define _RDP_H

#include <linux/list.h>
#include <linux/bug.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <linux/seq_file.h>
#include <linux/poll.h>

/**
 *	struct rdp_skb_cb  -  RDP(-Lite) private variables
 *
 *	@header:      private variables used by IPv4/IPv6
 *	@cscov:       checksum coverage length (RDP-Lite only)
 *	@partial_cov: if set indicates partial csum coverage
 */
struct rdp_skb_cb {
	union {
		struct inet_skb_parm	h4;
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_skb_parm	h6;
#endif
	} header;
	__u16		cscov;
	__u8		partial_cov;
};
#define RDP_SKB_CB(__skb)	((struct rdp_skb_cb *)((__skb)->cb))

/**
 *	struct rdp_hslot - RDP hash slot
 *
 *	@head:	head of list of sockets
 *	@count:	number of sockets in 'head' list
 *	@lock:	spinlock protecting changes to head/count
 */
struct rdp_hslot {
	struct hlist_head	head;
	int			count;
	spinlock_t		lock;
} __attribute__((aligned(2 * sizeof(long))));

/**
 *	struct rdp_table - RDP table
 *
 *	@hash:	hash table, sockets are hashed on (local port)
 *	@hash2:	hash table, sockets are hashed on (local port, local address)
 *	@mask:	number of slots in hash tables, minus 1
 *	@log:	log2(number of slots in hash table)
 */
struct rdp_table {
	struct rdp_hslot	*hash;
	struct rdp_hslot	*hash2;
	unsigned int		mask;
	unsigned int		log;
};
extern struct rdp_table rdp_table;
void rdp_table_init(struct rdp_table *, const char *);
static inline struct rdp_hslot *rdp_hashslot(struct rdp_table *table,
					     struct net *net, unsigned int num)
{
	return &table->hash[rdp_hashfn(net, num, table->mask)];
}
/*
 * For secondary hash, net_hash_mix() is performed before calling
 * rdp_hashslot2(), this explains difference with rdp_hashslot()
 */
static inline struct rdp_hslot *rdp_hashslot2(struct rdp_table *table,
					      unsigned int hash)
{
	return &table->hash2[hash & table->mask];
}

extern struct proto rdp_prot;

extern atomic_long_t rdp_memory_allocated;

/* sysctl variables for rdp */
extern long sysctl_rdp_mem[3];
extern int sysctl_rdp_rmem_min;
extern int sysctl_rdp_wmem_min;

struct sk_buff;

/*
 *	Generic checksumming routines for RDP(-Lite) v4 and v6
 */
static inline __sum16 __rdp_lib_checksum_complete(struct sk_buff *skb)
{
	return (RDP_SKB_CB(skb)->cscov == skb->len ?
		__skb_checksum_complete(skb) :
		__skb_checksum_complete_head(skb, RDP_SKB_CB(skb)->cscov));
}

static inline int rdp_lib_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__rdp_lib_checksum_complete(skb);
}

/**
 * 	rdp_csum_outgoing  -  compute RDPv4/v6 checksum over fragments
 * 	@sk: 	socket we are writing to
 * 	@skb: 	sk_buff containing the filled-in RDP header
 * 	        (checksum field must be zeroed out)
 */
static inline __wsum rdp_csum_outgoing(struct sock *sk, struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct rdphdr), 0);
	skb_queue_walk(&sk->sk_write_queue, skb) {
		csum = csum_add(csum, skb->csum);
	}
	return csum;
}

static inline __wsum rdp_csum(struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct rdphdr), skb->csum);

	for (skb = skb_shinfo(skb)->frag_list; skb; skb = skb->next) {
		csum = csum_add(csum, skb->csum);
	}
	return csum;
}

static inline __sum16 rdp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcprdp_magic(saddr, daddr, len, IPPROTO_RDP, base);
}

void rdp_set_csum(bool nocheck, struct sk_buff *skb,
		  __be32 saddr, __be32 daddr, int len);

static inline void rdp_csum_pull_header(struct sk_buff *skb)
{
	if (!skb->csum_valid && skb->ip_summed == CHECKSUM_NONE)
		skb->csum = csum_partial(skb->data, sizeof(struct rdphdr),
					 skb->csum);
	skb_pull_rcsum(skb, sizeof(struct rdphdr));
	RDP_SKB_CB(skb)->cscov -= sizeof(struct rdphdr);
}

typedef struct sock *(*rdp_lookup_t)(struct sk_buff *skb, __be16 sport,
				     __be16 dport);

struct sk_buff *rdp_gro_receive(struct list_head *head, struct sk_buff *skb,
				struct rdphdr *uh, rdp_lookup_t lookup);
int rdp_gro_complete(struct sk_buff *skb, int nhoff, rdp_lookup_t lookup);

struct sk_buff *__rdp_gso_segment(struct sk_buff *gso_skb,
				  netdev_features_t features);

static inline struct rdphdr *rdp_gro_rdphdr(struct sk_buff *skb)
{
	struct rdphdr *uh;
	unsigned int hlen, off;

	off  = skb_gro_offset(skb);
	hlen = off + sizeof(*uh);
	uh   = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen))
		uh = skb_gro_header_slow(skb, hlen, off);

	return uh;
}

/* hash routines shared between RDPv4/6 and RDP-Litev4/6 */
static inline int rdp_lib_hash(struct sock *sk)
{
	BUG();
	return 0;
}

void rdp_lib_unhash(struct sock *sk);
void rdp_lib_rehash(struct sock *sk, u16 new_hash);

static inline void rdp_lib_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

int rdp_lib_get_port(struct sock *sk, unsigned short snum,
		     unsigned int hash2_nulladdr);

u32 rdp_flow_hashrnd(void);

static inline __be16 rdp_flow_src_port(struct net *net, struct sk_buff *skb,
				       int min, int max, bool use_eth)
{
	u32 hash;

	if (min >= max) {
		/* Use default range */
		inet_get_local_port_range(net, &min, &max);
	}

	hash = skb_get_hash(skb);
	if (unlikely(!hash)) {
		if (use_eth) {
			/* Can't find a normal hash, caller has indicated an
			 * Ethernet packet so use that to compute a hash.
			 */
			hash = jhash(skb->data, 2 * ETH_ALEN,
				     (__force u32) skb->protocol);
		} else {
			/* Can't derive any sort of hash for the packet, set
			 * to some consistent random value.
			 */
			hash = rdp_flow_hashrnd();
		}
	}

	/* Since this is being sent on the wire obfuscate hash a bit
	 * to minimize possbility that any useful information to an
	 * attacker is leaked. Only upper 16 bits are relevant in the
	 * computation for 16 bit port value.
	 */
	hash ^= hash << 16;

	return htons((((u64) hash * (max - min)) >> 32) + min);
}

static inline int rdp_rqueue_get(struct sock *sk)
{
	return sk_rmem_alloc_get(sk) - READ_ONCE(rdp_sk(sk)->forward_deficit);
}

static inline bool rdp_sk_bound_dev_eq(struct net *net, int bound_dev_if,
				       int dif, int sdif)
{
#if IS_ENABLED(CONFIG_NET_L3_MASTER_DEV)
	return inet_bound_dev_eq(!!net->ipv4.sysctl_rdp_l3mdev_accept,
				 bound_dev_if, dif, sdif);
#else
	return inet_bound_dev_eq(true, bound_dev_if, dif, sdif);
#endif
}

/* net/ipv4/rdp.c */
void rdp_destruct_sock(struct sock *sk);
void skb_consume_rdp(struct sock *sk, struct sk_buff *skb, int len);
int __rdp_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb);
void rdp_skb_destructor(struct sock *sk, struct sk_buff *skb);
struct sk_buff *__skb_recv_rdp(struct sock *sk, unsigned int flags,
			       int noblock, int *off, int *err);
static inline struct sk_buff *skb_recv_rdp(struct sock *sk, unsigned int flags,
					   int noblock, int *err)
{
	int off = 0;

	return __skb_recv_rdp(sk, flags, noblock, &off, err);
}

int rdp_v4_early_demux(struct sk_buff *skb);
bool rdp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst);
int rdp_get_port(struct sock *sk, unsigned short snum,
		 int (*saddr_cmp)(const struct sock *,
				  const struct sock *));
int rdp_err(struct sk_buff *, u32);
int rdp_abort(struct sock *sk, int err);
int rdp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int rdp_push_pending_frames(struct sock *sk);
void rdp_flush_pending_frames(struct sock *sk);
int rdp_cmsg_send(struct sock *sk, struct msghdr *msg, u16 *gso_size);
void rdp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);
int rdp_rcv(struct sk_buff *skb);
int rdp_ioctl(struct sock *sk, int cmd, unsigned long arg);
int rdp_init_sock(struct sock *sk);
int rdp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int __rdp_disconnect(struct sock *sk, int flags);
int rdp_disconnect(struct sock *sk, int flags);
__poll_t rdp_poll(struct file *file, struct socket *sock, poll_table *wait);
struct sk_buff *skb_rdp_tunnel_segment(struct sk_buff *skb,
				       netdev_features_t features,
				       bool is_ipv6);
int rdp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen);
int rdp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *));
struct sock *rdp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			     __be32 daddr, __be16 dport, int dif);
struct sock *__rdp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			       __be32 daddr, __be16 dport, int dif, int sdif,
			       struct rdp_table *tbl, struct sk_buff *skb);
struct sock *rdp4_lib_lookup_skb(struct sk_buff *skb,
				 __be16 sport, __be16 dport);
struct sock *rdp6_lib_lookup(struct net *net,
			     const struct in6_addr *saddr, __be16 sport,
			     const struct in6_addr *daddr, __be16 dport,
			     int dif);
struct sock *__rdp6_lib_lookup(struct net *net,
			       const struct in6_addr *saddr, __be16 sport,
			       const struct in6_addr *daddr, __be16 dport,
			       int dif, int sdif, struct rdp_table *tbl,
			       struct sk_buff *skb);
struct sock *rdp6_lib_lookup_skb(struct sk_buff *skb,
				 __be16 sport, __be16 dport);

/* RDP uses skb->dev_scratch to cache as much information as possible and avoid
 * possibly multiple cache miss on dequeue()
 */
struct rdp_dev_scratch {
	/* skb->truesize and the stateless bit are embedded in a single field;
	 * do not use a bitfield since the compiler emits better/smaller code
	 * this way
	 */
	u32 _tsize_state;

#if BITS_PER_LONG == 64
	/* len and the bit needed to compute skb_csum_unnecessary
	 * will be on cold cache lines at recvmsg time.
	 * skb->len can be stored on 16 bits since the rdp header has been
	 * already validated and pulled.
	 */
	u16 len;
	bool is_linear;
	bool csum_unnecessary;
#endif
};

static inline struct rdp_dev_scratch *rdp_skb_scratch(struct sk_buff *skb)
{
	return (struct rdp_dev_scratch *)&skb->dev_scratch;
}

#if BITS_PER_LONG == 64
static inline unsigned int rdp_skb_len(struct sk_buff *skb)
{
	return rdp_skb_scratch(skb)->len;
}

static inline bool rdp_skb_csum_unnecessary(struct sk_buff *skb)
{
	return rdp_skb_scratch(skb)->csum_unnecessary;
}

static inline bool rdp_skb_is_linear(struct sk_buff *skb)
{
	return rdp_skb_scratch(skb)->is_linear;
}

#else
static inline unsigned int rdp_skb_len(struct sk_buff *skb)
{
	return skb->len;
}

static inline bool rdp_skb_csum_unnecessary(struct sk_buff *skb)
{
	return skb_csum_unnecessary(skb);
}

static inline bool rdp_skb_is_linear(struct sk_buff *skb)
{
	return !skb_is_nonlinear(skb);
}
#endif

static inline int copy_linear_skb(struct sk_buff *skb, int len, int off,
				  struct iov_iter *to)
{
	int n;

	n = copy_to_iter(skb->data + off, len, to);
	if (n == len)
		return 0;

	iov_iter_revert(to, n);
	return -EFAULT;
}

/*
 * 	SNMP statistics for RDP and RDP-Lite
 */
#define RDP_INC_STATS(net, field, is_rdplite)		      do { \
	if (is_rdplite) SNMP_INC_STATS((net)->mib.rdplite_statistics, field);       \
	else		SNMP_INC_STATS((net)->mib.rdp_statistics, field);  }  while(0)
#define __RDP_INC_STATS(net, field, is_rdplite) 	      do { \
	if (is_rdplite) __SNMP_INC_STATS((net)->mib.rdplite_statistics, field);         \
	else		__SNMP_INC_STATS((net)->mib.rdp_statistics, field);    }  while(0)

#define __RDP6_INC_STATS(net, field, is_rdplite)	    do { \
	if (is_rdplite) __SNMP_INC_STATS((net)->mib.rdplite_stats_in6, field);\
	else		__SNMP_INC_STATS((net)->mib.rdp_stats_in6, field);  \
} while(0)
#define RDP6_INC_STATS(net, field, __lite)		    do { \
	if (__lite) SNMP_INC_STATS((net)->mib.rdplite_stats_in6, field);  \
	else	    SNMP_INC_STATS((net)->mib.rdp_stats_in6, field);      \
} while(0)

#if IS_ENABLED(CONFIG_IPV6)
#define __RDPX_MIB(sk, ipv4)						\
({									\
	ipv4 ? (IS_RDPLITE(sk) ? sock_net(sk)->mib.rdplite_statistics :	\
				 sock_net(sk)->mib.rdp_statistics) :	\
		(IS_RDPLITE(sk) ? sock_net(sk)->mib.rdplite_stats_in6 :	\
				 sock_net(sk)->mib.rdp_stats_in6);	\
})
#else
#define __RDPX_MIB(sk, ipv4)						\
({									\
	IS_RDPLITE(sk) ? sock_net(sk)->mib.rdplite_statistics :		\
			 sock_net(sk)->mib.rdp_statistics;		\
})
#endif

#define __RDPX_INC_STATS(sk, field) \
	__SNMP_INC_STATS(__RDPX_MIB(sk, (sk)->sk_family == AF_INET), field)

#ifdef CONFIG_PROC_FS
struct rdp_seq_afinfo {
	sa_family_t			family;
	struct rdp_table		*rdp_table;
};

struct rdp_iter_state {
	struct seq_net_private  p;
	int			bucket;
};

void *rdp_seq_start(struct seq_file *seq, loff_t *pos);
void *rdp_seq_next(struct seq_file *seq, void *v, loff_t *pos);
void rdp_seq_stop(struct seq_file *seq, void *v);

extern const struct seq_operations rdp_seq_ops;
extern const struct seq_operations rdp6_seq_ops;

int rdp4_proc_init(void);
void rdp4_proc_exit(void);
#endif /* CONFIG_PROC_FS */

int rdpv4_offload_init(void);

void rdp_init(void);

DECLARE_STATIC_KEY_FALSE(rdp_encap_needed_key);
void rdp_encap_enable(void);
#if IS_ENABLED(CONFIG_IPV6)
DECLARE_STATIC_KEY_FALSE(rdpv6_encap_needed_key);
void rdpv6_encap_enable(void);
#endif

static inline struct sk_buff *rdp_rcv_segment(struct sock *sk,
					      struct sk_buff *skb, bool ipv4)
{
	netdev_features_t features = NETIF_F_SG;
	struct sk_buff *segs;

	/* Avoid csum recalculation by skb_segment unless userspace explicitly
	 * asks for the final checksum values
	 */
	if (!inet_get_convert_csum(sk))
		features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;

	/* the GSO CB lays after the RDP one, no need to save and restore any
	 * CB fragment
	 */
	segs = __skb_gso_segment(skb, features, false);
	if (IS_ERR_OR_NULL(segs)) {
		int segs_nr = skb_shinfo(skb)->gso_segs;

		atomic_add(segs_nr, &sk->sk_drops);
		SNMP_ADD_STATS(__RDPX_MIB(sk, ipv4), RDP_MIB_INERRORS, segs_nr);
		kfree_skb(skb);
		return NULL;
	}

	consume_skb(skb);
	return segs;
}

#endif	/* _RDP_H */
