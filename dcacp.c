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
struct udp_table dcacp_table __read_mostly;
EXPORT_SYMBOL(dcacp_table);

struct dcacp_peertab dcacp_peers_table;
EXPORT_SYMBOL(dcacp_peers_table);

long sysctl_dcacp_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_dcacp_mem);

atomic_long_t dcacp_memory_allocated;
EXPORT_SYMBOL(dcacp_memory_allocated);

#define MAX_DCACP_PORTS 65536
#define PORTS_PER_CHAIN (MAX_DCACP_PORTS / DCACP_HTABLE_SIZE_MIN)

static int dcacp_lib_lport_inuse(struct net *net, __u16 num,
			       const struct udp_hslot *hslot,
			       unsigned long *bitmap,
			       struct sock *sk, unsigned int log)
{
	struct sock *sk2;
	kuid_t uid = sock_i_uid(sk);

	sk_for_each(sk2, &hslot->head) {
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (bitmap || dcacp_sk(sk2)->dcacp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    inet_rcv_saddr_equal(sk, sk2, true)) {
			if (sk2->sk_reuseport && sk->sk_reuseport &&
			    !rcu_access_pointer(sk->sk_reuseport_cb) &&
			    uid_eq(uid, sock_i_uid(sk2))) {
				if (!bitmap)
					return 0;
			} else {
				if (!bitmap)
					return 1;
				__set_bit(dcacp_sk(sk2)->dcacp_port_hash >> log,
					  bitmap);
			}
		}
	}
	return 0;
}

/*
 * Note: we still hold spinlock of primary hash chain, so no other writer
 * can insert/delete a socket with local_port == num
 */
static int dcacp_lib_lport_inuse2(struct net *net, __u16 num,
				struct udp_hslot *hslot2,
				struct sock *sk)
{
	struct sock *sk2;
	kuid_t uid = sock_i_uid(sk);
	int res = 0;

	spin_lock(&hslot2->lock);
	dcacp_portaddr_for_each_entry(sk2, &hslot2->head) {
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (dcacp_sk(sk2)->dcacp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    inet_rcv_saddr_equal(sk, sk2, true)) {
			if (sk2->sk_reuseport && sk->sk_reuseport &&
			    !rcu_access_pointer(sk->sk_reuseport_cb) &&
			    uid_eq(uid, sock_i_uid(sk2))) {
				res = 0;
			} else {
				res = 1;
			}
			break;
		}
	}
	spin_unlock(&hslot2->lock);
	return res;
}

static int dcacp_reuseport_add_sock(struct sock *sk, struct udp_hslot *hslot)
{
	struct net *net = sock_net(sk);
	kuid_t uid = sock_i_uid(sk);
	struct sock *sk2;

	sk_for_each(sk2, &hslot->head) {
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    sk2->sk_family == sk->sk_family &&
		    ipv6_only_sock(sk2) == ipv6_only_sock(sk) &&
		    (dcacp_sk(sk2)->dcacp_port_hash == dcacp_sk(sk)->dcacp_port_hash) &&
		    (sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    sk2->sk_reuseport && uid_eq(uid, sock_i_uid(sk2)) &&
		    inet_rcv_saddr_equal(sk, sk2, false)) {
			return reuseport_add_sock(sk, sk2,
						  inet_rcv_saddr_any(sk));
		}
	}

	return reuseport_alloc(sk, inet_rcv_saddr_any(sk));
}

/**
 *  dcacp_lib_get_port  -  DCACP/-Lite port lookup for IPv4 and IPv6
 *
 *  @sk:          socket struct in question
 *  @snum:        port number to look up
 *  @hash2_nulladdr: AF-dependent hash value in secondary hash chains,
 *                   with NULL address
 */
int dcacp_lib_get_port(struct sock *sk, unsigned short snum,
		     unsigned int hash2_nulladdr)
{
	struct udp_hslot *hslot, *hslot2;
	struct udp_table *dcacptable = sk->sk_prot->h.udp_table;
	int    error = 1;
	struct net *net = sock_net(sk);

	if (!snum) {
		int low, high, remaining;
		unsigned int rand;
		unsigned short first, last;
		DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);

		inet_get_local_port_range(net, &low, &high);
		remaining = (high - low) + 1;

		rand = prandom_u32();
		first = reciprocal_scale(rand, remaining) + low;
		/*
		 * force rand to be an odd multiple of DCACP_HTABLE_SIZE
		 */
		rand = (rand | 1) * (dcacptable->mask + 1);
		last = first + dcacptable->mask + 1;
		do {
			hslot = udp_hashslot(dcacptable, net, first);
			bitmap_zero(bitmap, PORTS_PER_CHAIN);
			spin_lock_bh(&hslot->lock);
			dcacp_lib_lport_inuse(net, snum, hslot, bitmap, sk,
					    dcacptable->log);

			snum = first;
			/*
			 * Iterate on all possible values of snum for this hash.
			 * Using steps of an odd multiple of DCACP_HTABLE_SIZE
			 * give us randomization and full range coverage.
			 */
			do {
				if (low <= snum && snum <= high &&
				    !test_bit(snum >> dcacptable->log, bitmap) &&
				    !inet_is_local_reserved_port(net, snum))
					goto found;
				snum += rand;
			} while (snum != first);
			spin_unlock_bh(&hslot->lock);
			cond_resched();
		} while (++first != last);
		goto fail;
	} else {
		hslot = udp_hashslot(dcacptable, net, snum);
		spin_lock_bh(&hslot->lock);
		if (hslot->count > 10) {
			int exist;
			unsigned int slot2 = dcacp_sk(sk)->dcacp_portaddr_hash ^ snum;

			slot2          &= dcacptable->mask;
			hash2_nulladdr &= dcacptable->mask;

			hslot2 = udp_hashslot2(dcacptable, slot2);
			if (hslot->count < hslot2->count)
				goto scan_primary_hash;

			exist = dcacp_lib_lport_inuse2(net, snum, hslot2, sk);
			if (!exist && (hash2_nulladdr != slot2)) {
				hslot2 = udp_hashslot2(dcacptable, hash2_nulladdr);
				exist = dcacp_lib_lport_inuse2(net, snum, hslot2,
							     sk);
			}
			if (exist)
				goto fail_unlock;
			else
				goto found;
		}
scan_primary_hash:
		if (dcacp_lib_lport_inuse(net, snum, hslot, NULL, sk, 0))
			goto fail_unlock;
	}
found:
	inet_sk(sk)->inet_num = snum;
	dcacp_sk(sk)->dcacp_port_hash = snum;
	dcacp_sk(sk)->dcacp_portaddr_hash ^= snum;
	if (sk_unhashed(sk)) {
		if (sk->sk_reuseport &&
		    dcacp_reuseport_add_sock(sk, hslot)) {
			inet_sk(sk)->inet_num = 0;
			dcacp_sk(sk)->dcacp_port_hash = 0;
			dcacp_sk(sk)->dcacp_portaddr_hash ^= snum;
			goto fail_unlock;
		}

		sk_add_node_rcu(sk, &hslot->head);
		hslot->count++;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

		hslot2 = udp_hashslot2(dcacptable, dcacp_sk(sk)->dcacp_portaddr_hash);
		spin_lock(&hslot2->lock);
		if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
		    sk->sk_family == AF_INET6)
			hlist_add_tail_rcu(&dcacp_sk(sk)->dcacp_portaddr_node,
					   &hslot2->head);
		else
			hlist_add_head_rcu(&dcacp_sk(sk)->dcacp_portaddr_node,
					   &hslot2->head);
		hslot2->count++;
		spin_unlock(&hslot2->lock);
	}
	sock_set_flag(sk, SOCK_RCU_FREE);
	error = 0;
fail_unlock:
	spin_unlock_bh(&hslot->lock);
fail:
	return error;
}
EXPORT_SYMBOL(dcacp_lib_get_port);

int dcacp_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		ipv4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		ipv4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	dcacp_sk(sk)->dcacp_portaddr_hash = hash2_partial;
	return dcacp_lib_get_port(sk, snum, hash2_nulladdr);
}

static int compute_score(struct sock *sk, struct net *net,
			 __be32 saddr, __be16 sport,
			 __be32 daddr, unsigned short hnum,
			 int dif, int sdif)
{
	int score;
	struct inet_sock *inet;
	bool dev_match;

	if (!net_eq(sock_net(sk), net) ||
	    dcacp_sk(sk)->dcacp_port_hash != hnum ||
	    ipv6_only_sock(sk))
		return -1;

	if (sk->sk_rcv_saddr != daddr)
		return -1;

	score = (sk->sk_family == PF_INET) ? 2 : 1;

	inet = inet_sk(sk);
	if (inet->inet_daddr) {
		if (inet->inet_daddr != saddr)
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)
			return -1;
		score += 4;
	}

	dev_match = dcacp_sk_bound_dev_eq(net, sk->sk_bound_dev_if,
					dif, sdif);
	if (!dev_match)
		return -1;
	score += 4;

	if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id())
		score++;
	return score;
}

static u32 dcacp_ehashfn(const struct net *net, const __be32 laddr,
		       const __u16 lport, const __be32 faddr,
		       const __be16 fport)
{
	static u32 dcacp_ehash_secret __read_mostly;

	net_get_random_once(&dcacp_ehash_secret, sizeof(dcacp_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      dcacp_ehash_secret + net_hash_mix(net));
}

/* called with rcu_read_lock() */
static struct sock *dcacp4_lib_lookup2(struct net *net,
				     __be32 saddr, __be16 sport,
				     __be32 daddr, unsigned int hnum,
				     int dif, int sdif,
				     struct udp_hslot *hslot2,
				     struct sk_buff *skb)
{
	struct sock *sk, *result;
	int score, badness;
	u32 hash = 0;

	result = NULL;
	badness = 0;
	dcacp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
		score = compute_score(sk, net, saddr, sport,
				      daddr, hnum, dif, sdif);
		if (score > badness) {
			if (sk->sk_reuseport &&
			    sk->sk_state != TCP_ESTABLISHED) {
				hash = dcacp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				result = reuseport_select_sock(sk, hash, skb,
							sizeof(struct dcacphdr));
				if (result && !reuseport_has_conns(sk, false))
					return result;
			}
			badness = score;
			result = sk;
		}
	}
	return result;
}

/* DCACP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
struct sock *__dcacp4_lib_lookup(struct net *net, __be32 saddr,
		__be16 sport, __be32 daddr, __be16 dport, int dif,
		int sdif, struct udp_table *dcacptable, struct sk_buff *skb)
{
	struct sock *result;
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2;
	struct udp_hslot *hslot2;

	hash2 = ipv4_portaddr_hash(net, daddr, hnum);
	slot2 = hash2 & dcacptable->mask;
	hslot2 = &dcacptable->hash2[slot2];

	result = dcacp4_lib_lookup2(net, saddr, sport,
				  daddr, hnum, dif, sdif,
				  hslot2, skb);
	if (!result) {
		hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
		slot2 = hash2 & dcacptable->mask;
		hslot2 = &dcacptable->hash2[slot2];

		result = dcacp4_lib_lookup2(net, saddr, sport,
					  htonl(INADDR_ANY), hnum, dif, sdif,
					  hslot2, skb);
	}
	if (IS_ERR(result))
		return NULL;
	return result;
}
EXPORT_SYMBOL_GPL(__dcacp4_lib_lookup);

static inline struct sock *__dcacp4_lib_lookup_skb(struct sk_buff *skb,
						 __be16 sport, __be16 dport,
						 struct udp_table *dcacptable)
{
	const struct iphdr *iph = ip_hdr(skb);

	return __dcacp4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
				 iph->daddr, dport, inet_iif(skb),
				 inet_sdif(skb), dcacptable, skb);
}

struct sock *dcacp4_lib_lookup_skb(struct sk_buff *skb,
				 __be16 sport, __be16 dport)
{
	const struct iphdr *iph = ip_hdr(skb);

	return __dcacp4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
				 iph->daddr, dport, inet_iif(skb),
				 inet_sdif(skb), &dcacp_table, NULL);
}
EXPORT_SYMBOL_GPL(dcacp4_lib_lookup_skb);

/* Must be called under rcu_read_lock().
 * Does increment socket refcount.
 */
#if IS_ENABLED(CONFIG_NF_TPROXY_IPV4) || IS_ENABLED(CONFIG_NF_SOCKET_IPV4)
struct sock *dcacp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			     __be32 daddr, __be16 dport, int dif)
{
	struct sock *sk;

	sk = __dcacp4_lib_lookup(net, saddr, sport, daddr, dport,
			       dif, 0, &dcacp_table, NULL);
	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	return sk;
}
EXPORT_SYMBOL_GPL(dcacp4_lib_lookup);
#endif

static inline bool __dcacp_is_mcast_sock(struct net *net, struct sock *sk,
				       __be16 loc_port, __be32 loc_addr,
				       __be16 rmt_port, __be32 rmt_addr,
				       int dif, int sdif, unsigned short hnum)
{
	struct inet_sock *inet = inet_sk(sk);

	if (!net_eq(sock_net(sk), net) ||
	    dcacp_sk(sk)->dcacp_port_hash != hnum ||
	    (inet->inet_daddr && inet->inet_daddr != rmt_addr) ||
	    (inet->inet_dport != rmt_port && inet->inet_dport) ||
	    (inet->inet_rcv_saddr && inet->inet_rcv_saddr != loc_addr) ||
	    ipv6_only_sock(sk) ||
	    !dcacp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif))
		return false;
	if (!ip_mc_sf_allow(sk, loc_addr, rmt_addr, dif, sdif))
		return false;
	return true;
}

DEFINE_STATIC_KEY_FALSE(dcacp_encap_needed_key);
void dcacp_encap_enable(void)
{
	static_branch_inc(&dcacp_encap_needed_key);
}
EXPORT_SYMBOL(dcacp_encap_enable);

/* Handler for tunnels with arbitrary destination ports: no socket lookup, go
 * through error handlers in encapsulations looking for a match.
 */
static int __dcacp4_lib_err_encap_no_sk(struct sk_buff *skb, u32 info)
{
	int i;

	for (i = 0; i < MAX_IPTUN_ENCAP_OPS; i++) {
		int (*handler)(struct sk_buff *skb, u32 info);
		const struct ip_tunnel_encap_ops *encap;

		encap = rcu_dereference(iptun_encaps[i]);
		if (!encap)
			continue;
		handler = encap->err_handler;
		if (handler && !handler(skb, info))
			return 0;
	}

	return -ENOENT;
}

/* Try to match ICMP errors to DCACP tunnels by looking up a socket without
 * reversing source and destination port: this will match tunnels that force the
 * same destination port on both endpoints (e.g. VXLAN, GENEVE). Note that
 * lwtunnels might actually break this assumption by being configured with
 * different destination ports on endpoints, in this case we won't be able to
 * trace ICMP messages back to them.
 *
 * If this doesn't match any socket, probe tunnels with arbitrary destination
 * ports (e.g. FoU, GUE): there, the receiving socket is useless, as the port
 * we've sent packets to won't necessarily match the local destination port.
 *
 * Then ask the tunnel implementation to match the error against a valid
 * association.
 *
 * Return an error if we can't find a match, the socket if we need further
 * processing, zero otherwise.
 */
static struct sock *__dcacp4_lib_err_encap(struct net *net,
					 const struct iphdr *iph,
					 struct dcacphdr *uh,
					 struct udp_table *dcacptable,
					 struct sk_buff *skb, u32 info)
{
	int network_offset, transport_offset;
	struct sock *sk;

	network_offset = skb_network_offset(skb);
	transport_offset = skb_transport_offset(skb);

	/* Network header needs to point to the outer IPv4 header inside ICMP */
	skb_reset_network_header(skb);

	/* Transport header needs to point to the DCACP header */
	skb_set_transport_header(skb, iph->ihl << 2);

	sk = __dcacp4_lib_lookup(net, iph->daddr, uh->source,
			       iph->saddr, uh->dest, skb->dev->ifindex, 0,
			       dcacptable, NULL);
	if (sk) {
		int (*lookup)(struct sock *sk, struct sk_buff *skb);
		struct dcacp_sock *up = dcacp_sk(sk);

		lookup = READ_ONCE(up->encap_err_lookup);
		if (!lookup || lookup(sk, skb))
			sk = NULL;
	}

	if (!sk)
		sk = ERR_PTR(__dcacp4_lib_err_encap_no_sk(skb, info));

	skb_set_transport_header(skb, transport_offset);
	skb_set_network_header(skb, network_offset);

	return sk;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the dcacp header.  We need
 * to find the appropriate port.
 */

int __dcacp4_lib_err(struct sk_buff *skb, u32 info, struct udp_table *dcacptable)
{
	struct inet_sock *inet;
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct dcacphdr *uh = (struct dcacphdr *)(skb->data+(iph->ihl<<2));
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	bool tunnel = false;
	struct sock *sk;
	int harderr;
	int err;
	struct net *net = dev_net(skb->dev);

	sk = __dcacp4_lib_lookup(net, iph->daddr, uh->dest,
			       iph->saddr, uh->source, skb->dev->ifindex,
			       inet_sdif(skb), dcacptable, NULL);
	if (!sk) {
		/* No socket for error: try tunnels before discarding */
		sk = ERR_PTR(-ENOENT);
		if (static_branch_unlikely(&dcacp_encap_needed_key)) {
			sk = __dcacp4_lib_err_encap(net, iph, uh, dcacptable, skb,
						  info);
			if (!sk)
				return 0;
		}

		if (IS_ERR(sk)) {
			__ICMP_INC_STATS(net, ICMP_MIB_INERRORS);
			return PTR_ERR(sk);
		}

		tunnel = true;
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			ipv4_sk_update_pmtu(skb, sk, info);
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	case ICMP_REDIRECT:
		ipv4_sk_redirect(skb, sk);
		goto out;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per
	 *	4.1.3.3.
	 */
	if (tunnel) {
		/* ...not for tunnels though: we don't have a sending socket */
		goto out;
	}
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8 *)(uh+1));

	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	return 0;
}

int dcacp_err(struct sk_buff *skb, u32 info)
{
	return __dcacp4_lib_err(skb, info, &dcacp_table);
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
			struct inet_cork *cork, enum dcacp_packet_type type, struct dcacp_message_out* mesg)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct dcacp_data_hdr *uh;
	int err = 0;
	int is_dcacplite = IS_DCACPLITE(sk);
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

	if(mesg != NULL) {
		uh->message_id = mesg->id;
		// uh->data_seq_no = 0;
	}
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
		if (skb->ip_summed != CHECKSUM_PARTIAL || is_dcacplite ||
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
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_SNDBUFERRORS, is_dcacplite);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_OUTDATAGRAMS, is_dcacplite);
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

	err = dcacp_send_skb(skb, fl4, &inet->cork.base, DATA, NULL);

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

int dcacp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct dcacp_sock *up = dcacp_sk(sk);
	struct dcacp_peer* peer;
	struct dcacp_message_out* mesg;
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_dcacplite = IS_DCACPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;
	struct message_hslot *slot;

	// printk_once("dcacp sendmsg");
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	getfrag = is_dcacplite ? dcacplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct dcacp_data_hdr);

	/*
	 *	Get and verify the address.
	 */
	if (usin) {
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}

	ipcm_init_sk(&ipc, inet);
	ipc.gso_size = up->gso_size;

	if (msg->msg_controllen) {
		err = dcacp_cmsg_send(sk, msg, &ipc.gso_size);
		if (err > 0)
			err = ip_cmsg_send(sk, msg, &ipc,
					   sk->sk_family == AF_INET6);
		if (unlikely(err < 0)) {
			kfree(ipc.opt);
			return err;
		}
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	if (cgroup_bpf_enabled && !connected) {
		// To Do: may need to change in future
		err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk,
					    (struct sockaddr *)usin, &ipc.addr);
		if (err)
			goto out_free;
		if (usin) {
			if (usin->sin_port == 0) {
				/* BPF program set invalid port. Reject it. */
				err = -EINVAL;
				goto out_free;
			}
			daddr = usin->sin_addr.s_addr;
			dport = usin->sin_port;
		}
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr) {
			err = -EINVAL;
			goto out_free;
		}
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif) {
		ipc.oif = inet->uc_index;
	} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
		/* oif is set, packet is to local broadcast and
		 * and uc_index is set. oif is most likely set
		 * by sk_bound_dev_if. If uc_index != oif check if the
		 * oif is an L3 master and uc_index is an L3 slave.
		 * If so, we want to allow the send using the uc_index.
		 */
		if (ipc.oif != inet->uc_index &&
		    ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
							      inet->uc_index)) {
			ipc.oif = inet->uc_index;
		}
	}

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;

		flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport,
				   sk->sk_uid);

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		struct inet_cork cork;

		// skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
		// 		  sizeof(struct dcacp_data_hdr), &ipc, &rt,
		// 		  &cork, msg->msg_flags);
		peer =  dcacp_peer_find(&dcacp_peers_table, daddr, inet);
		skb = dcacp_fill_packets(peer, msg, len);
		mesg = dcacp_message_out_init(peer, up, skb, 
		atomic64_fetch_add(1, &up->next_outgoing_id), len, dport);
		/* transmit the flow sync packet */
		printk("try to send notification pkt\n");
		printk("saddr:%hu\n", saddr);
		slot = dcacp_message_out_bucket(up, mesg->id);
		dcacp_xmit_control(construct_flow_sync_pkt(up, mesg->id, len, 0), peer, up, mesg->dport); 

		printk("socket address: %p LINE:%d\n", up,  __LINE__);

		spin_lock_bh(&slot->lock);
		add_dcacp_message_out(up, mesg);
		// skb_get(skb);

		spin_unlock_bh(&slot->lock);
		// err = PTR_ERR(skb);
		dcacp_xmit_data(mesg, true);
		err = 0;
		// if (!IS_ERR_OR_NULL(skb))
		// 	err = dcacp_send_skb(skb, fl4, &cork, DATA, mesg);
		// printk("err:%d\n", err);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited("socket already corked\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
			     sizeof(struct dcacphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		dcacp_flush_pending_frames(sk);
	else if (!corkreq)
		err = dcacp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	ip_rt_put(rt);
out_free:
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_SNDBUFERRORS, is_dcacplite);
	}
	return err;

do_confirm:
	if (msg->msg_flags & MSG_PROBE)
		dst_confirm_neigh(&rt->dst, &fl4->daddr);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
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

static int dcacp_skb_truesize(struct sk_buff *skb)
{
	return dcacp_skb_scratch(skb)->_tsize_state & ~DCACP_SKB_IS_STATELESS;
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

/* Note: called with reader_queue.lock held.
 * Instead of using skb->truesize here, find a copy of it in skb->dev_scratch
 * This avoids a cache line miss while receive_queue lock is held.
 * Look at __dcacp_enqueue_schedule_skb() to find where this copy is done.
 */
void dcacp_skb_destructor(struct sock *sk, struct sk_buff *skb)
{
	prefetch(&skb->data);
	dcacp_rmem_release(sk, dcacp_skb_truesize(skb), 1, false);
}
EXPORT_SYMBOL(dcacp_skb_destructor);

/* as above, but the caller held the rx queue lock, too */
static void dcacp_skb_dtor_locked(struct sock *sk, struct sk_buff *skb)
{
	prefetch(&skb->data);
	dcacp_rmem_release(sk, dcacp_skb_truesize(skb), 1, true);
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
	struct dcacp_sock *dsk = dcacp_sk(sk);
	struct dcacp_message_out *out;
	struct dcacp_message_in* in;
	struct hlist_node *n;
	unsigned int total = 0;
	struct sk_buff *skb;
	int i;
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     dcacp_sk(sk)->dcacp_port_hash);
	printk("call destruct sock \n");
	for (i = 0; i < DCACP_MESSAGE_BUCKETS; i++) {
		struct message_hslot *slot = &dsk->mesg_out_table[i];
		spin_lock_bh(&slot->lock);
		hlist_for_each_entry_safe(out, n, &slot->head, sk_table_link) {
			dcacp_message_out_destroy(out);
		}
		spin_unlock_bh(&slot->lock);
		slot->count = 0;
	}
	for (i = 0; i < DCACP_MESSAGE_BUCKETS; i++) {
		struct message_hslot *slot = &dsk->mesg_in_table[i];
		spin_lock_bh(&slot->lock);
		hlist_for_each_entry_safe(in, n, &slot->head, sk_table_link) {
			dcacp_message_in_destroy(in);
		}
		spin_unlock_bh(&slot->lock);
		slot->count = 0;
	}
	kfree(dsk->mesg_out_table);
	kfree(dsk->mesg_in_table);
	skb_queue_splice_tail_init(&sk->sk_receive_queue, &dsk->reader_queue);
	while ((skb = __skb_dequeue(&dsk->reader_queue)) != NULL) {
		total += skb->truesize;
		kfree_skb(skb);
	}
	dcacp_rmem_release(sk, total, 0, true);

	inet_sock_destruct(sk);
}
EXPORT_SYMBOL_GPL(dcacp_destruct_sock);

int dcacp_init_sock(struct sock *sk)
{
	struct dcacp_sock* dsk = dcacp_sk(sk);
	int i;
	skb_queue_head_init(&dcacp_sk(sk)->reader_queue);
	dsk->mesg_out_table = kmalloc(sizeof(struct message_hslot) * DCACP_MESSAGE_BUCKETS, GFP_KERNEL);
	dsk->mesg_in_table = kmalloc(sizeof(struct message_hslot) * DCACP_MESSAGE_BUCKETS, GFP_KERNEL);
	for (i = 0; i < DCACP_MESSAGE_BUCKETS; i++) {
		struct message_hslot *slot = &dsk->mesg_in_table[i];
		spin_lock_init(&slot->lock);
		INIT_HLIST_HEAD(&slot->head);
		slot->count = 0;
	}
	for (i = 0; i < DCACP_MESSAGE_BUCKETS; i++) {
		struct message_hslot *slot = &dsk->mesg_out_table[i];
		spin_lock_init(&slot->lock);
		INIT_HLIST_HEAD(&slot->head);
		slot->count = 0;
	}
	// next_going_id 
	atomic64_set(&dsk->next_outgoing_id, 1);
	// initialize the ready queue and its lock
	spin_lock_init(&dsk->ready_queue_lock);
	INIT_LIST_HEAD(&dsk->ready_message_queue);
	spin_lock_init(&dsk->waiting_thread_queue_lock);
	INIT_LIST_HEAD(&dsk->waiting_thread_queue);
	sk->sk_destruct = dcacp_destruct_sock;
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
			__UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS,
					IS_DCACPLITE(sk));
			__UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS,
					IS_DCACPLITE(sk));
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


struct sk_buff *__skb_recv_dcacp(struct sock *sk, unsigned int flags,
			       int noblock, int *off, int *err)
{
	struct sk_buff_head *sk_queue = &sk->sk_receive_queue;
	struct sk_buff_head *queue;
	struct sk_buff *last;
	long timeo;
	int error;

	queue = &dcacp_sk(sk)->reader_queue;
	flags |= noblock ? MSG_DONTWAIT : 0;
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	do {
		struct sk_buff *skb;

		error = sock_error(sk);
		if (error)
			break;

		error = -EAGAIN;
		do {
			spin_lock_bh(&queue->lock);
			skb = __skb_try_recv_from_queue(sk, queue, flags,
							dcacp_skb_destructor,
							off, err, &last);
			if (skb) {
				spin_unlock_bh(&queue->lock);
				return skb;
			}

			if (skb_queue_empty_lockless(sk_queue)) {
				spin_unlock_bh(&queue->lock);
				goto busy_check;
			}

			/* refill the reader queue and walk it again
			 * keep both queues locked to avoid re-acquiring
			 * the sk_receive_queue lock if fwd memory scheduling
			 * is needed.
			 */
			spin_lock(&sk_queue->lock);
			skb_queue_splice_tail_init(sk_queue, queue);

			skb = __skb_try_recv_from_queue(sk, queue, flags,
							dcacp_skb_dtor_locked,
							off, err, &last);
			spin_unlock(&sk_queue->lock);
			spin_unlock_bh(&queue->lock);
			if (skb)
				return skb;

busy_check:
			if (!sk_can_busy_loop(sk))
				break;

			sk_busy_loop(sk, flags & MSG_DONTWAIT);
		} while (!skb_queue_empty_lockless(sk_queue));

		/* sk_queue is empty, reader_queue may contain peeked packets */
	} while (timeo &&
		 !__skb_wait_for_more_packets(sk, &sk->sk_receive_queue,
					      &error, &timeo,
					      (struct sk_buff *)sk_queue));

	*err = error;
	return NULL;
}
EXPORT_SYMBOL(__skb_recv_dcacp);

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int dcacp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len)
{
	// struct inet_sock *inet = inet_sk(sk);
	struct dcacp_message_in* mesg;
	struct message_hslot *slot;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct sk_buff *skb;
	int err;
	// unsigned int ulen, copied;
	// int off, peeking = flags & MSG_PEEK;
	// int is_dcacplite = IS_DCACPLITE(sk);
	// bool checksum_valid = false;

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len, addr_len);

// try_again:
	mesg = dcacp_wait_for_message(dcacp_sk(sk), flags, &err);
	if(!mesg) {
		return err;
	}
	err = dcacp_message_in_copy_data(mesg, &msg->msg_iter, len);
	skb = skb_peek(&mesg->packets);
	// off = sk_peek_offset(sk, flags);
	// skb = __skb_recv_dcacp(sk, flags, noblock, &off, &err);
	// if (!skb)
		// return err;

	// ulen = dcacp_skb_len(skb);
	// copied = len;
	// if (copied > ulen - off)
	// 	copied = ulen - off;
	// else if (copied < ulen)
	// 	msg->msg_flags |= MSG_TRUNC;

	// /*
	//  * If checksum is needed at all, try to do it while copying the
	//  * data.  If the data is truncated, or if we only want a partial
	//  * coverage checksum (DCACP-Lite), do it before the copy.
	//  */

	// if (copied < ulen || peeking ||
	//     (is_dcacplite && DCACP_SKB_CB(skb)->partial_cov)) {
	// 	checksum_valid =dcacp_skb_csum_unnecessary(skb) ||
	// 			!__dcacp_lib_checksum_complete(skb);
	// 	if (!checksum_valid)
	// 		goto csum_copy_err;
	// }

	// if (checksum_valid || dcacp_skb_csum_unnecessary(skb)) {
	// 	if (dcacp_skb_is_linear(skb))
	// 		err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
	// 	else
	// 		err = skb_copy_datagram_msg(skb, off, msg, copied);
	// } else {
	// 	err = skb_copy_and_csum_datagram_msg(skb, off, msg);

	// 	if (err == -EINVAL)
	// 		goto csum_copy_err;
	// }

	// if (unlikely(err)) {
	// 	if (!peeking) {
	// 		atomic_inc(&sk->sk_drops);
	// 		UDP_INC_STATS(sock_net(sk),
	// 			      UDP_MIB_INERRORS, is_dcacplite);
	// 	}
	// 	kfree_skb(skb);
	// 	return err;
	// }

	// if (!peeking)
	// 	UDP_INC_STATS(sock_net(sk),
	// 		      UDP_MIB_INDATAGRAMS, is_dcacplite);

	// sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (sin && skb) {
		sin->sin_family = AF_INET;
		sin->sin_port = dcacp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);

		if (cgroup_bpf_enabled)
			BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk,
							(struct sockaddr *)sin);
	}

	slot = dcacp_message_in_bucket(dcacp_sk(sk), mesg->id);
	spin_lock_bh(&slot->lock);
	dcacp_message_in_finish(mesg);
	spin_unlock_bh(&slot->lock);
	return err;
// 	if (dcacp_sk(sk)->gro_enabled)
// 		dcacp_cmsg_recv(msg, sk, skb);
// 	if (inet->cmsg_flags)
// 		ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct dcacphdr), off);

// 	err = copied;
// 	if (flags & MSG_TRUNC)
// 		err = ulen;

// 	skb_consume_dcacp(sk, skb, peeking ? -err : err);
// 	return err;

// csum_copy_err:
// 	if (!__sk_queue_drop_skb(sk, &dcacp_sk(sk)->reader_queue, skb, flags,
// 				 dcacp_skb_destructor)) {
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_dcacplite);
// 		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_dcacplite);
// 	}
// 	printk("copy error:%d\n", __LINE__);
// 	kfree_skb(skb);

// 	/* starting over for a new packet, but check if we need to yield */
// 	cond_resched();
// 	msg->msg_flags &= ~MSG_TRUNC;
// 	goto try_again;
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

void dcacp_lib_unhash(struct sock *sk)
{
	if (sk_hashed(sk)) {
		struct udp_table *dcacptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2;

		hslot  = udp_hashslot(dcacptable, sock_net(sk),
				      dcacp_sk(sk)->dcacp_port_hash);
		hslot2 = udp_hashslot2(dcacptable, dcacp_sk(sk)->dcacp_portaddr_hash);

		spin_lock_bh(&hslot->lock);
		if (rcu_access_pointer(sk->sk_reuseport_cb))
			reuseport_detach_sock(sk);
		if (sk_del_node_init_rcu(sk)) {
			hslot->count--;
			inet_sk(sk)->inet_num = 0;
			sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

			spin_lock(&hslot2->lock);
			hlist_del_init_rcu(&dcacp_sk(sk)->dcacp_portaddr_node);
			hslot2->count--;
			spin_unlock(&hslot2->lock);
		}
		spin_unlock_bh(&hslot->lock);
	}
}
EXPORT_SYMBOL(dcacp_lib_unhash);

/*
 * inet_rcv_saddr was changed, we must rehash secondary hash
 */
void dcacp_lib_rehash(struct sock *sk, u16 newhash)
{
	if (sk_hashed(sk)) {
		struct udp_table *dcacptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2, *nhslot2;

		hslot2 = udp_hashslot2(dcacptable, dcacp_sk(sk)->dcacp_portaddr_hash);
		nhslot2 = udp_hashslot2(dcacptable, newhash);
		dcacp_sk(sk)->dcacp_portaddr_hash = newhash;

		if (hslot2 != nhslot2 ||
		    rcu_access_pointer(sk->sk_reuseport_cb)) {
			hslot = udp_hashslot(dcacptable, sock_net(sk),
					     dcacp_sk(sk)->dcacp_port_hash);
			/* we must lock primary chain too */
			spin_lock_bh(&hslot->lock);
			if (rcu_access_pointer(sk->sk_reuseport_cb))
				reuseport_detach_sock(sk);

			if (hslot2 != nhslot2) {
				spin_lock(&hslot2->lock);
				hlist_del_init_rcu(&dcacp_sk(sk)->dcacp_portaddr_node);
				hslot2->count--;
				spin_unlock(&hslot2->lock);

				spin_lock(&nhslot2->lock);
				hlist_add_head_rcu(&dcacp_sk(sk)->dcacp_portaddr_node,
							 &nhslot2->head);
				nhslot2->count++;
				spin_unlock(&nhslot2->lock);
			}

			spin_unlock_bh(&hslot->lock);
		}
	}
}
EXPORT_SYMBOL(dcacp_lib_rehash);

void dcacp_v4_rehash(struct sock *sk)
{
	u16 new_hash = ipv4_portaddr_hash(sock_net(sk),
					  inet_sk(sk)->inet_rcv_saddr,
					  inet_sk(sk)->inet_num);
	dcacp_lib_rehash(sk, new_hash);
}

static int __dcacp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		sk_incoming_cpu_update(sk);
	} else {
		sk_mark_napi_id_once(sk, skb);
	}

	rc = __dcacp_enqueue_schedule_skb(sk, skb);
	if (rc < 0) {
		int is_dcacplite = IS_DCACPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					is_dcacplite);
		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_dcacplite);
		kfree_skb(skb);
		// trace_udp_fail_queue_rcv_skb(rc, sk);
		return -1;
	}

	return 0;
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "dcacp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
static int dcacp_queue_rcv_one_skb(struct sock *sk, struct sk_buff *skb)
{
	struct dcacp_sock *up = dcacp_sk(sk);
	int is_dcacplite = IS_DCACPLITE(sk);

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset_ct(skb);

	if (static_branch_unlikely(&dcacp_encap_needed_key) && up->encap_type) {
		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
		 * This is an encapsulation socket so pass the skb to
		 * the socket's dcacp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the DCACP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to DCACP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let DCACP handle it */
		encap_rcv = READ_ONCE(up->encap_rcv);
		if (encap_rcv) {
			int ret;

			/* Verify checksum before giving to encap */
			// if (dcacp_lib_checksum_complete(skb))
			// 	goto csum_error;

			ret = encap_rcv(sk, skb);
			if (ret <= 0) {
				__UDP_INC_STATS(sock_net(sk),
						UDP_MIB_INDATAGRAMS,
						is_dcacplite);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a DCACP Packet */
	}

	/*
	 * 	DCACP-Lite specific tests, ignored on DCACP sockets
	 */
	if ((is_dcacplite & DCACPLITE_RECV_CC)  &&  DCACP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			net_dbg_ratelimited("DCACPLite: partial coverage %d while full coverage %d requested\n",
					    DCACP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (DCACP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			net_dbg_ratelimited("DCACPLite: coverage %d too small, need min %d\n",
					    DCACP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	prefetch(&sk->sk_rmem_alloc);
	// if (rcu_access_pointer(sk->sk_filter) &&
	//     dcacp_lib_checksum_complete(skb))
	// 		goto csum_error;

	if (sk_filter_trim_cap(sk, skb, sizeof(struct dcacphdr)))
		goto drop;

	dcacp_csum_pull_header(skb);

	ipv4_pktinfo_prepare(sk, skb);
	return __dcacp_queue_rcv_skb(sk, skb);

// csum_error:
// 	__UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_dcacplite);
drop:
	__UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_dcacplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}

static int dcacp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff *next, *segs;
	int ret;

	if (likely(!dcacp_unexpected_gso(sk, skb)))
		return dcacp_queue_rcv_one_skb(sk, skb);

	BUILD_BUG_ON(sizeof(struct dcacp_skb_cb) > SKB_SGO_CB_OFFSET);
	__skb_push(skb, -skb_mac_offset(skb));
	segs = dcacp_rcv_segment(sk, skb, true);
	skb_list_walk_safe(segs, skb, next) {
		__skb_pull(skb, skb_transport_offset(skb));
		ret = dcacp_queue_rcv_one_skb(sk, skb);
		if (ret > 0)
			ip_protocol_deliver_rcu(dev_net(skb->dev), skb, -ret);
	}
	return 0;
}

/* For TCP sockets, sk_rx_dst is protected by socket lock
 * For DCACP, we use xchg() to guard against concurrent changes.
 */
bool dcacp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old;

	if (dst_hold_safe(dst)) {
		old = xchg(&sk->sk_rx_dst, dst);
		dst_release(old);
		return old != dst;
	}
	return false;
}
EXPORT_SYMBOL(dcacp_sk_rx_dst_set);

/*
 *	Multicasts and broadcasts go to each listener.
 *
 *	Note: called only from the BH handler context.
 */
static int __dcacp4_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
				    struct dcacphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct udp_table *dcacptable,
				    int proto)
{
	struct sock *sk, *first = NULL;
	unsigned short hnum = ntohs(uh->dest);
	struct udp_hslot *hslot = udp_hashslot(dcacptable, net, hnum);
	unsigned int hash2 = 0, hash2_any = 0, use_hash2 = (hslot->count > 10);
	unsigned int offset = offsetof(typeof(*sk), sk_node);
	int dif = skb->dev->ifindex;
	int sdif = inet_sdif(skb);
	struct hlist_node *node;
	struct sk_buff *nskb;

	if (use_hash2) {
		hash2_any = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum) &
			    dcacptable->mask;
		hash2 = ipv4_portaddr_hash(net, daddr, hnum) & dcacptable->mask;
start_lookup:
		hslot = &dcacptable->hash2[hash2];
		offset = offsetof(typeof(*sk), __sk_common.skc_portaddr_node);
	}

	sk_for_each_entry_offset_rcu(sk, node, &hslot->head, offset) {
		if (!__dcacp_is_mcast_sock(net, sk, uh->dest, daddr,
					 uh->source, saddr, dif, sdif, hnum))
			continue;

		if (!first) {
			first = sk;
			continue;
		}
		nskb = skb_clone(skb, GFP_ATOMIC);

		if (unlikely(!nskb)) {
			atomic_inc(&sk->sk_drops);
			__UDP_INC_STATS(net, UDP_MIB_RCVBUFERRORS,
					IS_DCACPLITE(sk));
			__UDP_INC_STATS(net, UDP_MIB_INERRORS,
					IS_DCACPLITE(sk));
			continue;
		}
		if (dcacp_queue_rcv_skb(sk, nskb) > 0)
			consume_skb(nskb);
	}

	/* Also lookup *:port if we are using hash2 and haven't done so yet. */
	if (use_hash2 && hash2 != hash2_any) {
		hash2 = hash2_any;
		goto start_lookup;
	}

	if (first) {
		if (dcacp_queue_rcv_skb(first, skb) > 0)
			consume_skb(skb);
	} else {
		kfree_skb(skb);
		__UDP_INC_STATS(net, UDP_MIB_IGNOREDMULTI,
				proto == IPPROTO_DCACPLITE);
	}
	return 0;
}

/* Initialize DCACP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires checksumming packet body,
 * including DCACP header and folding it to skb->csum.
 */
static inline int dcacp4_csum_init(struct sk_buff *skb, struct dcacphdr *uh,
				 int proto)
{
	int err;

	DCACP_SKB_CB(skb)->partial_cov = 0;
	DCACP_SKB_CB(skb)->cscov = skb->len;

	if (proto == IPPROTO_DCACPLITE) {
		err = dcacplite_checksum_init(skb, uh);
		if (err)
			return err;

		if (DCACP_SKB_CB(skb)->partial_cov) {
			skb->csum = inet_compute_pseudo(skb, proto);
			return 0;
		}
	}

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
static int dcacp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb,
			       struct dcacphdr *uh)
{
	int ret;
	if (inet_get_convert_csum(sk) && uh->check && !IS_DCACPLITE(sk))
		skb_checksum_try_convert(skb, IPPROTO_DCACP, inet_compute_pseudo);

	ret = dcacp_queue_rcv_skb(sk, skb);

	/* a return value > 0 means to resubmit the input, but
	 * it wants the return to be -protocol, or 0
	 */
	if (ret > 0)
		return -ret;
	return 0;
}

/*
 *	All we need to do is get the socket, and then do a checksum.
 */

int __dcacp4_lib_rcv(struct sk_buff *skb, struct udp_table *dcacptable,
		   int proto)
{
	struct sock *sk;
	struct dcacphdr *uh;
	struct dcacp_data_hdr *dh;

	struct dcacp_message_in *msg;
	struct message_hslot* slot;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct dcacp_data_hdr)))
		goto drop;		/* No space for header. */

	uh   = dcacp_hdr(skb);
	dh = dcacp_data_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_DCACP) {
		/* DCACP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = dcacp_hdr(skb);
	}
	// printk("saddr: %u\n LINE: %d", saddr, __LINE__);
	// if (dcacp4_csum_init(skb, uh, proto))
	// 	goto csum_error;
	// printk("reach skb:%d\n", __LINE__);
	sk = skb_steal_sock(skb);

	if (sk) {
		struct dst_entry *dst = skb_dst(skb);
		int ret;
		slot = dcacp_message_in_bucket(dcacp_sk(sk), dh->message_id);
		spin_lock_bh(&slot->lock);
		msg = get_dcacp_message_in(dcacp_sk(sk), saddr, dh->common.source, dh->message_id);

		dcacp_message_in_finish(msg);
		spin_unlock_bh(&slot->lock);
		if (unlikely(sk->sk_rx_dst != dst))
			dcacp_sk_rx_dst_set(sk, dst);

		ret = dcacp_unicast_rcv_skb(sk, skb, uh);
		sock_put(sk);
		return ret;
	}

	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __dcacp4_lib_mcast_deliver(net, skb, uh,
						saddr, daddr, dcacptable, proto);

	sk = __dcacp4_lib_lookup_skb(skb, uh->source, uh->dest, dcacptable);
	if (sk) {
		slot = dcacp_message_in_bucket(dcacp_sk(sk), dh->message_id);
		spin_lock_bh(&slot->lock);
		msg = get_dcacp_message_in(dcacp_sk(sk), saddr, dh->common.source, dh->message_id);
		dcacp_message_in_finish(msg);
		spin_unlock_bh(&slot->lock);
		return dcacp_unicast_rcv_skb(sk, skb, uh);
	}

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset_ct(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	// if (dcacp_lib_checksum_complete(skb))
	// 	goto csum_error;

	__UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_DCACPLITE);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an DCACP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	// printk("short packet\n");

	net_dbg_ratelimited("DCACP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
			    &saddr, ntohs(uh->source),
			    ulen, skb->len,
			    &daddr, ntohs(uh->dest));
	goto drop;

// csum_error:
// 	/*
// 	 * RFC1122: OK.  Discards the bad packet silently (as far as
// 	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
// 	 */
// 	printk("checksum error\n");
// 	printk("DCACP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
// 			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
// 			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
// 			    ulen);
// 	net_dbg_ratelimited("DCACP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
// 			    proto == IPPROTO_DCACPLITE ? "Lite" : "",
// 			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
// 			    ulen);
// 	__UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_DCACPLITE);
drop:
	printk("packet is dropped\n");
	__UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_DCACPLITE);
	kfree_skb(skb);
	return 0;
}

/* We can only early demux multicast if there is a single matching socket.
 * If more than one socket found returns NULL
 */
static struct sock *__dcacp4_lib_mcast_demux_lookup(struct net *net,
						  __be16 loc_port, __be32 loc_addr,
						  __be16 rmt_port, __be32 rmt_addr,
						  int dif, int sdif)
{
	struct sock *sk, *result;
	unsigned short hnum = ntohs(loc_port);
	unsigned int slot = dcacp_hashfn(net, hnum, dcacp_table.mask);
	struct udp_hslot *hslot = &dcacp_table.hash[slot];

	/* Do not bother scanning a too big list */
	if (hslot->count > 10)
		return NULL;

	result = NULL;
	sk_for_each_rcu(sk, &hslot->head) {
		if (__dcacp_is_mcast_sock(net, sk, loc_port, loc_addr,
					rmt_port, rmt_addr, dif, sdif, hnum)) {
			if (result)
				return NULL;
			result = sk;
		}
	}

	return result;
}

/* For unicast we should only early demux connected sockets or we can
 * break forwarding setups.  The chains here can be long so only check
 * if the first socket is an exact match and if not move on.
 */
static struct sock *__dcacp4_lib_demux_lookup(struct net *net,
					    __be16 loc_port, __be32 loc_addr,
					    __be16 rmt_port, __be32 rmt_addr,
					    int dif, int sdif)
{
	unsigned short hnum = ntohs(loc_port);
	unsigned int hash2 = ipv4_portaddr_hash(net, loc_addr, hnum);
	unsigned int slot2 = hash2 & dcacp_table.mask;
	struct udp_hslot *hslot2 = &dcacp_table.hash2[slot2];
	INET_ADDR_COOKIE(acookie, rmt_addr, loc_addr);
	const __portpair ports = INET_COMBINED_PORTS(rmt_port, hnum);
	struct sock *sk;

	dcacp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
		if (INET_MATCH(sk, net, acookie, rmt_addr,
			       loc_addr, ports, dif, sdif))
			return sk;
		/* Only check first socket in chain */
		break;
	}
	return NULL;
}

int dcacp_v4_early_demux(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct in_device *in_dev = NULL;
	const struct iphdr *iph;
	const struct dcacphdr *uh;
	struct sock *sk = NULL;
	struct dst_entry *dst;
	int dif = skb->dev->ifindex;
	int sdif = inet_sdif(skb);
	int ours;

	/* validate the packet */
	printk("early demux");
	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct dcacphdr)))
		return 0;

	iph = ip_hdr(skb);
	uh = dcacp_hdr(skb);

	if (skb->pkt_type == PACKET_MULTICAST) {
		in_dev = __in_dev_get_rcu(skb->dev);

		if (!in_dev)
			return 0;

		ours = ip_check_mc_rcu(in_dev, iph->daddr, iph->saddr,
				       iph->protocol);
		if (!ours)
			return 0;

		sk = __dcacp4_lib_mcast_demux_lookup(net, uh->dest, iph->daddr,
						   uh->source, iph->saddr,
						   dif, sdif);
	} else if (skb->pkt_type == PACKET_HOST) {
		sk = __dcacp4_lib_demux_lookup(net, uh->dest, iph->daddr,
					     uh->source, iph->saddr, dif, sdif);
	}

	if (!sk || !refcount_inc_not_zero(&sk->sk_refcnt))
		return 0;

	skb->sk = sk;
	skb->destructor = sock_efree;
	dst = READ_ONCE(sk->sk_rx_dst);

	if (dst)
		dst = dst_check(dst, 0);
	if (dst) {
		u32 itag = 0;

		/* set noref for now.
		 * any place which wants to hold dst has to call
		 * dst_hold_safe()
		 */
		skb_dst_set_noref(skb, dst);

		/* for unconnected multicast sockets we need to validate
		 * the source on each packet
		 */
		if (!inet_sk(sk)->inet_daddr && in_dev)
			return ip_mc_validate_source(skb, iph->daddr,
						     iph->saddr, iph->tos,
						     skb->dev, in_dev, &itag);
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
	}


drop:
	printk("drop packet:\n");

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
	bool slow = lock_sock_fast(sk);
	dcacp_flush_pending_frames(sk);
	unlock_sock_fast(sk, slow);
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
	int is_dcacplite = IS_DCACPLITE(sk);

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
		if (!is_dcacplite)         /* Disable the option on DCACP sockets */
			return -ENOPROTOOPT;
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
		if (!is_dcacplite)         /* Disable the option on DCACP sockets */
			return -ENOPROTOOPT;
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
	if (level == SOL_DCACP  ||  level == SOL_DCACPLITE)
		return dcacp_lib_setsockopt(sk, level, optname, optval, optlen,
					  dcacp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_dcacp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level == SOL_DCACP  ||  level == SOL_DCACPLITE)
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
	if (level == SOL_DCACP  ||  level == SOL_DCACPLITE)
		return dcacp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_dcacp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_DCACP  ||  level == SOL_DCACPLITE)
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

static struct sock *dcacp_get_first(struct seq_file *seq, int start)
{
	struct sock *sk;
	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
	struct dcacp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	for (state->bucket = start; state->bucket <= afinfo->dcacp_table->mask;
	     ++state->bucket) {
		struct udp_hslot *hslot = &afinfo->dcacp_table->hash[state->bucket];

		if (hlist_empty(&hslot->head))
			continue;

		spin_lock_bh(&hslot->lock);
		sk_for_each(sk, &hslot->head) {
			if (!net_eq(sock_net(sk), net))
				continue;
			if (sk->sk_family == afinfo->family)
				goto found;
		}
		spin_unlock_bh(&hslot->lock);
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *dcacp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
	struct dcacp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	do {
		sk = sk_next(sk);
	} while (sk && (!net_eq(sock_net(sk), net) || sk->sk_family != afinfo->family));

	if (!sk) {
		if (state->bucket <= afinfo->dcacp_table->mask)
			spin_unlock_bh(&afinfo->dcacp_table->hash[state->bucket].lock);
		return dcacp_get_first(seq, state->bucket + 1);
	}
	return sk;
}

static struct sock *dcacp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = dcacp_get_first(seq, 0);

	if (sk)
		while (pos && (sk = dcacp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

void *dcacp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct dcacp_iter_state *state = seq->private;
	state->bucket = MAX_DCACP_PORTS;

	return *pos ? dcacp_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL(dcacp_seq_start);

void *dcacp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = dcacp_get_idx(seq, 0);
	else
		sk = dcacp_get_next(seq, v);

	++*pos;
	return sk;
}
EXPORT_SYMBOL(dcacp_seq_next);

void dcacp_seq_stop(struct seq_file *seq, void *v)
{
	struct dcacp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
	struct dcacp_iter_state *state = seq->private;

	if (state->bucket <= afinfo->dcacp_table->mask)
		spin_unlock_bh(&afinfo->dcacp_table->hash[state->bucket].lock);
}
EXPORT_SYMBOL(dcacp_seq_stop);

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

const struct seq_operations dcacp_seq_ops = {
	.start		= dcacp_seq_start,
	.next		= dcacp_seq_next,
	.stop		= dcacp_seq_stop,
	.show		= dcacp4_seq_show,
};
EXPORT_SYMBOL(dcacp_seq_ops);

static struct dcacp_seq_afinfo dcacp4_seq_afinfo = {
	.family		= AF_INET,
	.dcacp_table	= &dcacp_table,
};

static int __net_init dcacp4_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("dcacp", 0444, net->proc_net, &dcacp_seq_ops,
			sizeof(struct dcacp_iter_state), &dcacp4_seq_afinfo))
		return -ENOMEM;
	return 0;
}

static void __net_exit dcacp4_proc_exit_net(struct net *net)
{
	remove_proc_entry("dcacp", net->proc_net);
}

static struct pernet_operations dcacp4_net_ops = {
	.init = dcacp4_proc_init_net,
	.exit = dcacp4_proc_exit_net,
};

int __init dcacp4_proc_init(void)
{
	return register_pernet_subsys(&dcacp4_net_ops);
}

void dcacp4_proc_exit(void)
{
	unregister_pernet_subsys(&dcacp4_net_ops);
}
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

static __initdata unsigned long uhash_entries;
static int __init set_uhash_entries(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtoul(str, 0, &uhash_entries);
	if (ret)
		return 0;

	if (uhash_entries && uhash_entries < DCACP_HTABLE_SIZE_MIN)
		uhash_entries = DCACP_HTABLE_SIZE_MIN;
	return 1;
}
__setup("uhash_entries=", set_uhash_entries);

void __init dcacp_table_init(struct udp_table *table, const char *name)
{
	unsigned int i;
	table->hash = allocate_hash_table(name,
					      2 * sizeof(struct udp_hslot),
					      uhash_entries,
					      21, /* one slot per 2 MB */
					      0,
					      &table->log,
					      &table->mask,
					      DCACP_HTABLE_SIZE_MIN,
					      64 * 1024);
	table->hash2 = table->hash + (table->mask + 1);
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash[i].head);
		table->hash[i].count = 0;
		spin_lock_init(&table->hash[i].lock);
	}
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash2[i].head);
		table->hash2[i].count = 0;
		spin_lock_init(&table->hash2[i].lock);
	}
}

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

	dcacp_table_init(&dcacp_table, "DCACP");

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
void dcacp_table_destroy(struct udp_table *table) {
	struct sock *sk;
	struct hlist_node *tmp;
	int i = 0;
	for (i = 0; i <= table->mask; i++) {
		spin_lock(&table->hash[i].lock);
		sk_for_each_safe(sk, tmp, &table->hash[i].head) {
			struct udp_hslot *hslot2;
			hslot2 = udp_hashslot2(table, dcacp_sk(sk)->dcacp_portaddr_hash);
			if (rcu_access_pointer(sk->sk_reuseport_cb))
				reuseport_detach_sock(sk);
			if (sk_del_node_init_rcu(sk)) {
				table->hash[i].count--;
				inet_sk(sk)->inet_num = 0;
				sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

				spin_lock(&hslot2->lock);
				hlist_del_init_rcu(&dcacp_sk(sk)->dcacp_portaddr_node);
				hslot2->count--;
				spin_unlock(&hslot2->lock);
			}
			// need to consult Jaehyun what is the right way to clean socket
			dcacp_destroy_sock(sk);
			dcacp_destruct_sock(sk);
			kfree(sk);
		}
		spin_unlock(&table->hash[i].lock);
	}
	for (i = 0; i <= table->mask; i++) {
		spin_lock(&table->hash2[i].lock);
		sk_for_each_safe(sk, tmp, &table->hash[i].head) {
			if (rcu_access_pointer(sk->sk_reuseport_cb))
				reuseport_detach_sock(sk);
			inet_sk(sk)->inet_num = 0;
			sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
			hlist_del_init_rcu(&dcacp_sk(sk)->dcacp_portaddr_node);
			table->hash2[i].count--;

			dcacp_destroy_sock(sk);
			dcacp_destruct_sock(sk);
			kfree(sk);
		}
		spin_unlock(&table->hash2[i].lock);
	}
	vfree(table->hash);

	// vfree(table->hash2);
}
void dcacp_destroy() {
	dcacp_peertab_destroy(&dcacp_peers_table);
	dcacp_table_destroy(&dcacp_table);
	kfree(dcacp_busylocks);
}