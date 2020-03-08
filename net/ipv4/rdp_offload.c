// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPV4 GSO/GRO offload support
 *	Linux INET implementation
 *
 *	RDPv4 GSO support
 */

#include <linux/skbuff.h>
#include <net/rdp.h>
#include <net/protocol.h>
#include <net/inet_common.h>

static struct sk_buff *__skb_rdp_tunnel_segment(struct sk_buff *skb,
	netdev_features_t features,
	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
					     netdev_features_t features),
	__be16 new_protocol, bool is_ipv6)
{
	int tnl_hlen = skb_inner_mac_header(skb) - skb_transport_header(skb);
	bool remcsum, need_csum, offload_csum, gso_partial;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct rdphdr *uh = rdp_hdr(skb);
	u16 mac_offset = skb->mac_header;
	__be16 protocol = skb->protocol;
	u16 mac_len = skb->mac_len;
	int rdp_offset, outer_hlen;
	__wsum partial;
	bool need_ipsec;

	if (unlikely(!pskb_may_pull(skb, tnl_hlen)))
		goto out;

	/* Adjust partial header checksum to negate old length.
	 * We cannot rely on the value contained in uh->len as it is
	 * possible that the actual value exceeds the boundaries of the
	 * 16 bit length field due to the header being added outside of an
	 * IP or IPv6 frame that was already limited to 64K - 1.
	 */
	if (skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL)
		partial = (__force __wsum)uh->len;
	else
		partial = (__force __wsum)htonl(skb->len);
	partial = csum_sub(csum_unfold(uh->check), partial);

	/* setup inner skb. */
	skb->encapsulation = 0;
	SKB_GSO_CB(skb)->encap_level = 0;
	__skb_pull(skb, tnl_hlen);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb_inner_network_offset(skb));
	skb->mac_len = skb_inner_network_offset(skb);
	skb->protocol = new_protocol;

	need_csum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_RDP_TUNNEL_CSUM);
	skb->encap_hdr_csum = need_csum;

	remcsum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_TUNNEL_REMCSUM);
	skb->remcsum_offload = remcsum;

	need_ipsec = skb_dst(skb) && dst_xfrm(skb_dst(skb));
	/* Try to offload checksum if possible */
	offload_csum = !!(need_csum &&
			  !need_ipsec &&
			  (skb->dev->features &
			   (is_ipv6 ? (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM) :
				      (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM))));

	features &= skb->dev->hw_enc_features;

	/* The only checksum offload we care about from here on out is the
	 * outer one so strip the existing checksum feature flags and
	 * instead set the flag based on our outer checksum offload value.
	 */
	if (remcsum) {
		features &= ~NETIF_F_CSUM_MASK;
		if (!need_csum || offload_csum)
			features |= NETIF_F_HW_CSUM;
	}

	/* segment inner packet. */
	segs = gso_inner_segment(skb, features);
	if (IS_ERR_OR_NULL(segs)) {
		skb_gso_error_unwind(skb, protocol, tnl_hlen, mac_offset,
				     mac_len);
		goto out;
	}

	gso_partial = !!(skb_shinfo(segs)->gso_type & SKB_GSO_PARTIAL);

	outer_hlen = skb_tnl_header_len(skb);
	rdp_offset = outer_hlen - tnl_hlen;
	skb = segs;
	do {
		unsigned int len;

		if (remcsum)
			skb->ip_summed = CHECKSUM_NONE;

		/* Set up inner headers if we are offloading inner checksum */
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			skb_reset_inner_headers(skb);
			skb->encapsulation = 1;
		}

		skb->mac_len = mac_len;
		skb->protocol = protocol;

		__skb_push(skb, outer_hlen);
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, mac_len);
		skb_set_transport_header(skb, rdp_offset);
		len = skb->len - rdp_offset;
		uh = rdp_hdr(skb);

		/* If we are only performing partial GSO the inner header
		 * will be using a length value equal to only one MSS sized
		 * segment instead of the entire frame.
		 */
		if (gso_partial && skb_is_gso(skb)) {
			uh->len = htons(skb_shinfo(skb)->gso_size +
					SKB_GSO_CB(skb)->data_offset +
					skb->head - (unsigned char *)uh);
		} else {
			uh->len = htons(len);
		}

		if (!need_csum)
			continue;

		uh->check = ~csum_fold(csum_add(partial,
				       (__force __wsum)htonl(len)));

		if (skb->encapsulation || !offload_csum) {
			uh->check = gso_make_checksum(skb, ~uh->check);
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		} else {
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct rdphdr, check);
		}
	} while ((skb = skb->next));
out:
	return segs;
}

struct sk_buff *skb_rdp_tunnel_segment(struct sk_buff *skb,
				       netdev_features_t features,
				       bool is_ipv6)
{
	__be16 protocol = skb->protocol;
	const struct net_offload **offloads;
	const struct net_offload *ops;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
					     netdev_features_t features);

	rcu_read_lock();

	switch (skb->inner_protocol_type) {
	case ENCAP_TYPE_ETHER:
		protocol = skb->inner_protocol;
		gso_inner_segment = skb_mac_gso_segment;
		break;
	case ENCAP_TYPE_IPPROTO:
		offloads = is_ipv6 ? inet6_offloads : inet_offloads;
		ops = rcu_dereference(offloads[skb->inner_ipproto]);
		if (!ops || !ops->callbacks.gso_segment)
			goto out_unlock;
		gso_inner_segment = ops->callbacks.gso_segment;
		break;
	default:
		goto out_unlock;
	}

	segs = __skb_rdp_tunnel_segment(skb, features, gso_inner_segment,
					protocol, is_ipv6);

out_unlock:
	rcu_read_unlock();

	return segs;
}
EXPORT_SYMBOL(skb_rdp_tunnel_segment);

struct sk_buff *__rdp_gso_segment(struct sk_buff *gso_skb,
				  netdev_features_t features)
{
	struct sock *sk = gso_skb->sk;
	unsigned int sum_truesize = 0;
	struct sk_buff *segs, *seg;
	struct rdphdr *uh;
	unsigned int mss;
	bool copy_dtor;
	__sum16 check;
	__be16 newlen;

	mss = skb_shinfo(gso_skb)->gso_size;
	if (gso_skb->len <= sizeof(*uh) + mss)
		return ERR_PTR(-EINVAL);

	skb_pull(gso_skb, sizeof(*uh));

	/* clear destructor to avoid skb_segment assigning it to tail */
	copy_dtor = gso_skb->destructor == sock_wfree;
	if (copy_dtor)
		gso_skb->destructor = NULL;

	segs = skb_segment(gso_skb, features);
	if (IS_ERR_OR_NULL(segs)) {
		if (copy_dtor)
			gso_skb->destructor = sock_wfree;
		return segs;
	}

	/* GSO partial and frag_list segmentation only requires splitting
	 * the frame into an MSS multiple and possibly a remainder, both
	 * cases return a GSO skb. So update the mss now.
	 */
	if (skb_is_gso(segs))
		mss *= skb_shinfo(segs)->gso_segs;

	seg = segs;
	uh = rdp_hdr(seg);

	/* preserve TX timestamp flags and TS key for first segment */
	skb_shinfo(seg)->tskey = skb_shinfo(gso_skb)->tskey;
	skb_shinfo(seg)->tx_flags |=
			(skb_shinfo(gso_skb)->tx_flags & SKBTX_ANY_TSTAMP);

	/* compute checksum adjustment based on old length versus new */
	newlen = htons(sizeof(*uh) + mss);
	check = csum16_add(csum16_sub(uh->check, uh->len), newlen);

	for (;;) {
		if (copy_dtor) {
			seg->destructor = sock_wfree;
			seg->sk = sk;
			sum_truesize += seg->truesize;
		}

		if (!seg->next)
			break;

		uh->len = newlen;
		uh->check = check;

		if (seg->ip_summed == CHECKSUM_PARTIAL)
			gso_reset_checksum(seg, ~check);
		else
			uh->check = gso_make_checksum(seg, ~check) ? :
				    CSUM_MANGLED_0;

		seg = seg->next;
		uh = rdp_hdr(seg);
	}

	/* last packet can be partial gso_size, account for that in checksum */
	newlen = htons(skb_tail_pointer(seg) - skb_transport_header(seg) +
		       seg->data_len);
	check = csum16_add(csum16_sub(uh->check, uh->len), newlen);

	uh->len = newlen;
	uh->check = check;

	if (seg->ip_summed == CHECKSUM_PARTIAL)
		gso_reset_checksum(seg, ~check);
	else
		uh->check = gso_make_checksum(seg, ~check) ? : CSUM_MANGLED_0;

	/* update refcount for the packet */
	if (copy_dtor) {
		int delta = sum_truesize - gso_skb->truesize;

		/* In some pathological cases, delta can be negative.
		 * We need to either use refcount_add() or refcount_sub_and_test()
		 */
		if (likely(delta >= 0))
			refcount_add(delta, &sk->sk_wmem_alloc);
		else
			WARN_ON_ONCE(refcount_sub_and_test(-delta, &sk->sk_wmem_alloc));
	}
	return segs;
}
EXPORT_SYMBOL_GPL(__rdp_gso_segment);

static struct sk_buff *rdp4_ufo_fragment(struct sk_buff *skb,
					 netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	unsigned int mss;
	__wsum csum;
	struct rdphdr *uh;
	struct iphdr *iph;

	if (skb->encapsulation &&
	    (skb_shinfo(skb)->gso_type &
	     (SKB_GSO_RDP_TUNNEL|SKB_GSO_RDP_TUNNEL_CSUM))) {
		segs = skb_rdp_tunnel_segment(skb, features, false);
		goto out;
	}

	if (!(skb_shinfo(skb)->gso_type & (SKB_GSO_RDP | SKB_GSO_RDP_L4)))
		goto out;

	if (!pskb_may_pull(skb, sizeof(struct rdphdr)))
		goto out;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_RDP_L4)
		return __rdp_gso_segment(skb, features);

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	/* Do software UFO. Complete and fill in the RDP checksum as
	 * HW cannot do checksum of RDP packets sent as multiple
	 * IP fragments.
	 */

	uh = rdp_hdr(skb);
	iph = ip_hdr(skb);

	uh->check = 0;
	csum = skb_checksum(skb, 0, skb->len, 0);
	uh->check = rdp_v4_check(skb->len, iph->saddr, iph->daddr, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* If there is no outer header we can fake a checksum offload
	 * due to the fact that we have already done the checksum in
	 * software prior to segmenting the frame.
	 */
	if (!skb->encap_hdr_csum)
		features |= NETIF_F_HW_CSUM;

	/* Fragment the skb. IP headers of the fragments are updated in
	 * inet_gso_segment()
	 */
	segs = skb_segment(skb, features);
out:
	return segs;
}

#define RDP_GRO_CNT_MAX 64
static struct sk_buff *rdp_gro_receive_segment(struct list_head *head,
					       struct sk_buff *skb)
{
	struct rdphdr *uh = rdp_hdr(skb);
	struct sk_buff *pp = NULL;
	struct rdphdr *uh2;
	struct sk_buff *p;
	unsigned int ulen;

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
	/* pull encapsulating rdp header */
	skb_gro_pull(skb, sizeof(struct rdphdr));
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct rdphdr));

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = rdp_hdr(p);

		/* Match ports only, as csum is always non zero */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* Terminate the flow on len mismatch or if it grow "too much".
		 * Under small packet flood GRO count could elsewhere grow a lot
		 * leading to excessive truesize values.
		 * On len mismatch merge the first packet shorter than gso_size,
		 * otherwise complete the GRO packet.
		 */
		if (ulen > ntohs(uh2->len) || skb_gro_receive(p, skb) ||
		    ulen != ntohs(uh2->len) ||
		    NAPI_GRO_CB(p)->count >= RDP_GRO_CNT_MAX)
			pp = p;

		return pp;
	}

	/* mismatch, but we never need to flush */
	return NULL;
}

INDIRECT_CALLABLE_DECLARE(struct sock *rdp6_lib_lookup_skb(struct sk_buff *skb,
						   __be16 sport, __be16 dport));
struct sk_buff *rdp_gro_receive(struct list_head *head, struct sk_buff *skb,
				struct rdphdr *uh, rdp_lookup_t lookup)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct rdphdr *uh2;
	unsigned int off = skb_gro_offset(skb);
	int flush = 1;
	struct sock *sk;

	rcu_read_lock();
	sk = INDIRECT_CALL_INET(lookup, rdp6_lib_lookup_skb,
				rdp4_lib_lookup_skb, skb, uh->source, uh->dest);
	if (!sk)
		goto out_unlock;

	if (rdp_sk(sk)->gro_enabled) {
		pp = call_gro_receive(rdp_gro_receive_segment, head, skb);
		rcu_read_unlock();
		return pp;
	}

	if (NAPI_GRO_CB(skb)->encap_mark ||
	    (skb->ip_summed != CHECKSUM_PARTIAL &&
	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
	     !NAPI_GRO_CB(skb)->csum_valid) ||
	    !rdp_sk(sk)->gro_receive)
		goto out_unlock;

	/* mark that this skb passed once through the tunnel gro layer */
	NAPI_GRO_CB(skb)->encap_mark = 1;

	flush = 0;

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = (struct rdphdr   *)(p->data + off);

		/* Match ports and either checksums are either both zero
		 * or nonzero.
		 */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
		    (!uh->check ^ !uh2->check)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	skb_gro_pull(skb, sizeof(struct rdphdr)); /* pull encapsulating rdp header */
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct rdphdr));
	pp = call_gro_receive_sk(rdp_sk(sk)->gro_receive, sk, head, skb);

out_unlock:
	rcu_read_unlock();
	skb_gro_flush_final(skb, pp, flush);
	return pp;
}
EXPORT_SYMBOL(rdp_gro_receive);

INDIRECT_CALLABLE_SCOPE
struct sk_buff *rdp4_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	struct rdphdr *uh = rdp_gro_rdphdr(skb);

	if (unlikely(!uh) || !static_branch_unlikely(&rdp_encap_needed_key))
		goto flush;

	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_RDP, uh->check,
						 inet_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		skb_gro_checksum_try_convert(skb, IPPROTO_RDP, uh->check,
					     inet_gro_compute_pseudo);
skip:
	NAPI_GRO_CB(skb)->is_ipv6 = 0;
	return rdp_gro_receive(head, skb, uh, rdp4_lib_lookup_skb);

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

static int rdp_gro_complete_segment(struct sk_buff *skb)
{
	struct rdphdr *uh = rdp_hdr(skb);

	skb->csum_start = (unsigned char *)uh - skb->head;
	skb->csum_offset = offsetof(struct rdphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
	skb_shinfo(skb)->gso_type |= SKB_GSO_RDP_L4;
	return 0;
}

int rdp_gro_complete(struct sk_buff *skb, int nhoff,
		     rdp_lookup_t lookup)
{
	__be16 newlen = htons(skb->len - nhoff);
	struct rdphdr *uh = (struct rdphdr *)(skb->data + nhoff);
	int err = -ENOSYS;
	struct sock *sk;

	uh->len = newlen;

	rcu_read_lock();
	sk = INDIRECT_CALL_INET(lookup, rdp6_lib_lookup_skb,
				rdp4_lib_lookup_skb, skb, uh->source, uh->dest);
	if (sk && rdp_sk(sk)->gro_enabled) {
		err = rdp_gro_complete_segment(skb);
	} else if (sk && rdp_sk(sk)->gro_complete) {
		skb_shinfo(skb)->gso_type = uh->check ? SKB_GSO_RDP_TUNNEL_CSUM
					: SKB_GSO_RDP_TUNNEL;

		/* Set encapsulation before calling into inner gro_complete()
		 * functions to make them set up the inner offsets.
		 */
		skb->encapsulation = 1;
		err = rdp_sk(sk)->gro_complete(sk, skb,
				nhoff + sizeof(struct rdphdr));
	}
	rcu_read_unlock();

	if (skb->remcsum_offload)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TUNNEL_REMCSUM;

	return err;
}
EXPORT_SYMBOL(rdp_gro_complete);

INDIRECT_CALLABLE_SCOPE int rdp4_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rdphdr *uh = (struct rdphdr *)(skb->data + nhoff);

	if (uh->check)
		uh->check = ~rdp_v4_check(skb->len - nhoff, iph->saddr,
					  iph->daddr, 0);

	return rdp_gro_complete(skb, nhoff, rdp4_lib_lookup_skb);
}

static const struct net_offload rdpv4_offload = {
	.callbacks = {
		.gso_segment = rdp4_ufo_fragment,
		.gro_receive  =	rdp4_gro_receive,
		.gro_complete =	rdp4_gro_complete,
	},
};

int __init rdpv4_offload_init(void)
{
	return inet_add_offload(&rdpv4_offload, IPPROTO_RDP);
}
