// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPV4 GSO/GRO offload support
 *	Linux INET implementation
 *
 *	DCACPv4 GSO support
 */

#include <linux/skbuff.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "net_dcacp.h"

struct sk_buff *dcacp_gso_segment(struct sk_buff *skb,
				netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	// unsigned int sum_truesize = 0;
	struct dcacphdr *dh;
	// struct dcacp_data_hdr *data_hdr;
	unsigned int dhlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int mss;
	unsigned int datalen;
	// struct sk_buff *gso_skb = skb;
	// __sum16 newcheck;
	// bool ooo_okay, copy_destructor;
	dh = dcacp_hdr(skb);
	dhlen = dh->doff / 4;
	if (dh->type != DATA) {
		goto out;
	}
	if (dhlen < sizeof(*dh)) {
		goto out;
	}


	if (!pskb_may_pull(skb, dhlen))
		goto out;

	oldlen = (u16)~skb->len;
	datalen = ntohs(dh->len);
	__skb_pull(skb, dhlen);
	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}
	// copy_destructor = gso_skb->destructor == tcp_wfree;
	// ooo_okay = gso_skb->ooo_okay;
	/* All segments but the first should have ooo_okay cleared */
	// skb->ooo_okay = 0;

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	/* Only first segment might have ooo_okay set */
	// segs->ooo_okay = ooo_okay;

	/* GSO partial and frag_list segmentation only requires splitting
	 * the frame into an MSS multiple and possibly a remainder, both
	 * cases return a GSO skb. So update the mss now.
	 */
	if (skb_is_gso(segs))
		mss *= skb_shinfo(segs)->gso_segs;
	delta = htonl(oldlen + (dhlen + mss));

	skb = segs;
	dh = dcacp_hdr(skb);
	seq = ntohl(dh->seq);

	// if (unlikely(skb_shinfo(gso_skb)->tx_flags & SKBTX_SW_TSTAMP))
	// 	tcp_gso_tstamp(segs, skb_shinfo(gso_skb)->tskey, seq, mss);

	// newcheck = ~csum_fold((__force __wsum)((__force u32)th->check +
	// 				       (__force u32)delta));


	while (skb->next) {
		// th->fin = th->psh = 0;
		// th->check = newcheck;

		// if (skb->ip_summed == CHECKSUM_PARTIAL)
		// 	gso_reset_checksum(skb, ~th->check);
		// else
		// 	th->check = gso_make_checksum(skb, ~th->check);

		seq += mss;
		dh->len = htons(mss);
		datalen -= mss;
		// if (copy_destructor) {
		// 	skb->destructor = gso_skb->destructor;
		// 	// skb->sk = gso_skb->sk;
		// 	// sum_truesize += skb->truesize;
		// }
		skb = skb->next;
		dh = dcacp_hdr(skb);

		dh->seq = htonl(seq);
		// th->cwr = 0;

	}

	/* Following permits TCP Small Queues to work well with GSO :
	 * The callback to TCP stack will be called at the time last frag
	 * is freed at TX completion, and not right now when gso_skb
	 * is freed by GSO engine
	 */
	// if (copy_destructor) {
	// 	int delta;

	// 	swap(gso_skb->sk, skb->sk);
	// 	swap(gso_skb->destructor, skb->destructor);
	// 	sum_truesize += skb->truesize;
	// 	delta = sum_truesize - gso_skb->truesize;
	// 	 In some pathological cases, delta can be negative.
	// 	 * We need to either use refcount_add() or refcount_sub_and_test()
		 
	// 	if (likely(delta >= 0))
	// 		refcount_add(delta, &skb->sk->sk_wmem_alloc);
	// 	else
	// 		WARN_ON_ONCE(refcount_sub_and_test(-delta, &skb->sk->sk_wmem_alloc));
	// }

	// delta = htonl(oldlen + (skb_tail_pointer(skb) -
	// 			skb_transport_header(skb)) +
	// 	      skb->data_len);
	// th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
	// 			(__force u32)delta));
	// if (skb->ip_summed == CHECKSUM_PARTIAL)
	// 	gso_reset_checksum(skb, ~th->check);
	// else
	// 	th->check = gso_make_checksum(skb, ~th->check);
	dh->len = htons(datalen);

out:
	return segs;
}

static struct sk_buff *dcacp4_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_DCACP))
		return ERR_PTR(-EINVAL);

	if (!pskb_may_pull(skb, sizeof(struct dcacphdr)))
		return ERR_PTR(-EINVAL);

	// if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
	// 	const struct iphdr *iph = ip_hdr(skb);
	// 	struct tcphdr *th = tcp_hdr(skb);

	// 	 Set up checksum pseudo header, usually expect stack to
	// 	 * have done this already.
		 

	// 	th->check = 0;
	// 	skb->ip_summed = CHECKSUM_PARTIAL;
	// 	__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
	// }
	return dcacp_gso_segment(skb, features);
}



#define DCACP_GRO_CNT_MAX 64
static struct sk_buff *dcacp_gro_receive_segment(struct list_head *head,
					       struct sk_buff *skb)
{
	struct dcacphdr *uh = dcacp_hdr(skb);
	struct sk_buff *pp = NULL;
	struct dcacphdr *uh2;
	struct sk_buff *p;
	unsigned int ulen;
	int ret = 0;


	/* requires non zero csum, for symmetry with GSO */
	if (!uh->check) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	/* Do not deal with padded or malicious packets, sorry ! */
	ulen = ntohs(uh->len);
	if (ulen <= sizeof(*uh) || ulen != skb_gro_len(skb)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}
	/* pull encapsulating dcacp header */
	skb_gro_pull(skb, sizeof(struct dcacphdr));

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = dcacp_hdr(p);

		/* Match ports only, as csum is always non zero */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		if (NAPI_GRO_CB(skb)->is_flist != NAPI_GRO_CB(p)->is_flist) {
			NAPI_GRO_CB(skb)->flush = 1;
			return p;
		}

		/* Terminate the flow on len mismatch or if it grow "too much".
		 * Under small packet flood GRO count could elsewhere grow a lot
		 * leading to excessive truesize values.
		 * On len mismatch merge the first packet shorter than gso_size,
		 * otherwise complete the GRO packet.
		 */
		if (ulen > ntohs(uh2->len)) {
			pp = p;
		} else {
			if (NAPI_GRO_CB(skb)->is_flist) {
				if (!pskb_may_pull(skb, skb_gro_offset(skb))) {
					NAPI_GRO_CB(skb)->flush = 1;
					return NULL;
				}
				if ((skb->ip_summed != p->ip_summed) ||
				    (skb->csum_level != p->csum_level)) {
					NAPI_GRO_CB(skb)->flush = 1;
					return NULL;
				}
				ret = skb_gro_receive_list(p, skb);
			} else {
				skb_gro_postpull_rcsum(skb, uh,
						       sizeof(struct dcacphdr));

				ret = skb_gro_receive(p, skb);
			}
		}

		if (ret || ulen != ntohs(uh2->len) ||
		    NAPI_GRO_CB(p)->count >= DCACP_GRO_CNT_MAX)
			pp = p;

		return pp;
	}

	/* mismatch, but we never need to flush */
	return NULL;
}

// struct sk_buff *dcacp_gro_receive(struct list_head *head, struct sk_buff *skb,
// 				struct dcacphdr *uh, struct sock *sk)
// {
// 	struct sk_buff *pp = NULL;
// 	struct sk_buff *p;
// 	struct dcacphdr *uh2;
// 	unsigned int off = skb_gro_offset(skb);
// 	int flush = 1;

// 	if (skb->dev->features & NETIF_F_GRO_FRAGLIST)
// 		NAPI_GRO_CB(skb)->is_flist = sk ? !dcacp_sk(sk)->gro_enabled: 1;

// 	if ((sk && dcacp_sk(sk)->gro_enabled) || NAPI_GRO_CB(skb)->is_flist) {
// 		pp = call_gro_receive(dcacp_gro_receive_segment, head, skb);
// 		return pp;
// 	}

// 	if (!sk || NAPI_GRO_CB(skb)->encap_mark ||
// 	    (skb->ip_summed != CHECKSUM_PARTIAL &&
// 	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
// 	     !NAPI_GRO_CB(skb)->csum_valid) ||
// 	    !dcacp_sk(sk)->gro_receive)
// 		goto out;

// 	/* mark that this skb passed once through the tunnel gro layer */
// 	NAPI_GRO_CB(skb)->encap_mark = 1;

// 	flush = 0;

// 	list_for_each_entry(p, head, list) {
// 		if (!NAPI_GRO_CB(p)->same_flow)
// 			continue;

// 		uh2 = (struct dcacphdr   *)(p->data + off);

// 		/* Match ports and either checksums are either both zero
// 		 * or nonzero.
// 		 */
// 		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
// 		    (!uh->check ^ !uh2->check)) {
// 			NAPI_GRO_CB(p)->same_flow = 0;
// 			continue;
// 		}
// 	}

// 	skb_gro_pull(skb, sizeof(struct dcacphdr)); /* pull encapsulating dcacp header */
// 	skb_gro_postpull_rcsum(skb, uh, sizeof(struct dcacphdr));
// 	pp = call_gro_receive_sk(dcacp_sk(sk)->gro_receive, sk, head, skb);

// out:
// 	skb_gro_flush_final(skb, pp, flush);
// 	return pp;
// }
// EXPORT_SYMBOL(dcacp_gro_receive);

// INDIRECT_CALLABLE_SCOPE
// struct sk_buff *dcacp4_gro_receive(struct list_head *head, struct sk_buff *skb)
// {
// 	struct dcacphdr *uh = dcacp_gro_dcacphdr(skb);
// 	struct sk_buff *pp;
// 	struct sock *sk;

// 	if (unlikely(!uh))
// 		goto flush;

// 	/* Don't bother verifying checksum if we're going to flush anyway. */
// 	if (NAPI_GRO_CB(skb)->flush)
// 		goto skip;

// 	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_DCACP, uh->check,
// 						 inet_gro_compute_pseudo))
// 		goto flush;
// 	else if (uh->check)
// 		skb_gro_checksum_try_convert(skb, IPPROTO_DCACP,
// 					     inet_gro_compute_pseudo);
// skip:
// 	NAPI_GRO_CB(skb)->is_ipv6 = 0;
// 	rcu_read_lock();
// 	sk = static_branch_unlikely(&dcacp_encap_needed_key) ? dcacp4_lib_lookup_skb(skb, uh->source, uh->dest) : NULL;
// 	pp = dcacp_gro_receive(head, skb, uh, sk);
// 	rcu_read_unlock();
// 	return pp;

// flush:
// 	NAPI_GRO_CB(skb)->flush = 1;
// 	return NULL;
// }

// static int dcacp_gro_complete_segment(struct sk_buff *skb)
// {
// 	struct dcacphdr *uh = dcacp_hdr(skb);

// 	skb->csum_start = (unsigned char *)uh - skb->head;
// 	skb->csum_offset = offsetof(struct dcacphdr, check);
// 	skb->ip_summed = CHECKSUM_PARTIAL;

// 	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
// 	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;
// 	return 0;
// }

// int dcacp_gro_complete(struct sk_buff *skb, int nhoff,
// 		     dcacp_lookup_t lookup)
// {
// 	__be16 newlen = htons(skb->len - nhoff);
// 	struct dcacphdr *uh = (struct dcacphdr *)(skb->data + nhoff);
// 	int err = -ENOSYS;
// 	struct sock *sk;

// 	uh->len = newlen;

// 	rcu_read_lock();
// 	sk = INDIRECT_CALL_INET(lookup, udp6_lib_lookup_skb,
// 				dcacp4_lib_lookup_skb, skb, uh->source, uh->dest);
// 	if (sk && dcacp_sk(sk)->gro_complete) {
// 		skb_shinfo(skb)->gso_type = uh->check ? SKB_GSO_UDP_TUNNEL_CSUM
// 					: SKB_GSO_UDP_TUNNEL;

// 		/* Set encapsulation before calling into inner gro_complete()
// 		 * functions to make them set up the inner offsets.
// 		 */
// 		skb->encapsulation = 1;
// 		err = dcacp_sk(sk)->gro_complete(sk, skb,
// 				nhoff + sizeof(struct dcacphdr));
// 	} else {
// 		err = dcacp_gro_complete_segment(skb);
// 	}
// 	rcu_read_unlock();

// 	if (skb->remcsum_offload)
// 		skb_shinfo(skb)->gso_type |= SKB_GSO_TUNNEL_REMCSUM;

// 	return err;
// }
// EXPORT_SYMBOL(dcacp_gro_complete);

// INDIRECT_CALLABLE_SCOPE int dcacp4_gro_complete(struct sk_buff *skb, int nhoff)
// {
// 	const struct iphdr *iph = ip_hdr(skb);
// 	struct dcacphdr *uh = (struct dcacphdr *)(skb->data + nhoff);
// 	printk("dcacp gro complete\n");
// 	if (NAPI_GRO_CB(skb)->is_flist) {
// 		uh->len = htons(skb->len - nhoff);

// 		skb_shinfo(skb)->gso_type |= (SKB_GSO_FRAGLIST|SKB_GSO_UDP_L4);
// 		skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

// 		if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
// 			if (skb->csum_level < SKB_MAX_CSUM_LEVEL)
// 				skb->csum_level++;
// 		} else {
// 			skb->ip_summed = CHECKSUM_UNNECESSARY;
// 			skb->csum_level = 0;
// 		}

// 		return 0;
// 	}

// 	if (uh->check)
// 		uh->check = ~dcacp_v4_check(skb->len - nhoff, iph->saddr,
// 					  iph->daddr, 0);

// 	return dcacp_gro_complete(skb, nhoff, dcacp4_lib_lookup_skb);
// }

static const struct net_offload dcacpv4_offload = {
	.callbacks = {
		.gso_segment = dcacp4_gso_segment,
		// .gro_receive  =	dcacp4_gro_receive,
		// .gro_complete =	dcacp4_gro_complete,
	},
};

int __init dcacpv4_offload_init(void)
{
	return inet_add_offload(&dcacpv4_offload, IPPROTO_DCACP);
}

int dcacpv4_offload_end(void)
{
        return inet_del_offload(&dcacpv4_offload, IPPROTO_DCACP);
}
