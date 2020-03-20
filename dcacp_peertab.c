/* Copyright (c) 2019-2020, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file manages dcacp_peertab objects and is responsible for creating
 * and deleting dcacp_peer objects.
 */

#include "dcacp_impl.h"

/**
 * dcacp_peertab_init() - Constructor for dcacp_peertabs.
 * @peertab:  The object to initialize; previous contents are discarded.
 * 
 * Return:    0 in the normal case, or a negative errno if there was a problem.
 */
int dcacp_peertab_init(struct dcacp_peertab *peertab)
{
	/* Note: when we return, the object must be initialized so it's
	 * safe to call dcacp_peertab_destroy, even if this function returns
	 * an error.
	 */
	int i;
	spin_lock_init(&peertab->write_lock);
	peertab->buckets = (struct hlist_head *) vmalloc(
			DCACP_PEERTAB_BUCKETS * sizeof(*peertab->buckets));
	if (!peertab->buckets)
		return -ENOMEM;
	for (i = 0; i < DCACP_PEERTAB_BUCKETS; i++) {
		INIT_HLIST_HEAD(&peertab->buckets[i]);
	}
	return 0;
}

/**
 * dcacp_peertab_destroy() - Destructor for dcacp_peertabs. After this
 * function returns, it is unsafe to use any results from previous calls
 * to dcacp_peer_find, since all existing dcacp_peer objects will have been
 * destroyed.
 * @peertab:  The table to destroy.
 */
void dcacp_peertab_destroy(struct dcacp_peertab *peertab)
{
	int i;
	struct dcacp_peer *peer;
	struct hlist_node *next;
	if (!peertab->buckets)
		return;
	
	for (i = 0; i < DCACP_PEERTAB_BUCKETS; i++) {
		hlist_for_each_entry_safe(peer, next, &peertab->buckets[i],
				peertab_links) {
			dst_release(peer->dst);
			kfree(peer);
		}
	}
	vfree(peertab->buckets);
}

/**
 * dcacp_peer_find() - Returns the peer associated with a given host; creates
 * a new dcacp_peer if one doesn't already exist.
 * @peertab:    Peer table in which to perform lookup.
 * @addr:       IPV4 address of the desired host.
 * @inet:       Socket that will be used for sending packets.
 * 
 * Return:      The peer associated with @addr, or a negative errno if an
 *              error occurred. The caller can retain this pointer
 *              indefinitely: peer entries are never deleted except in
 *              dcacp_peertab_destroy.
 */
struct dcacp_peer *dcacp_peer_find(struct dcacp_peertab *peertab, __be32 addr,
	struct inet_sock *inet)
{
	/* Note: this function uses RCU operators to ensure safety even
	 * if a concurrent call is adding a new entry.
	 */
	struct dcacp_peer *peer;
	struct rtable *rt;
	__u32 bucket = hash_32(addr, DCACP_PEERTAB_BUCKET_BITS);
	hlist_for_each_entry_rcu(peer, &peertab->buckets[bucket],
			peertab_links) {
		if (peer->addr == addr) {
			return peer;
		}
		// INC_METRIC(peer_hash_links, 1);
	}
	
	/* No existing entry; create a new one.
	 * 
	 * Note: after we acquire the lock, we have to check again to
	 * make sure the entry still doesn't exist after grabbing
	 * the lock (it might have been created by a concurrent invocation
	 * of this function). */
	spin_lock_bh(&peertab->write_lock);
	hlist_for_each_entry_rcu(peer, &peertab->buckets[bucket],
			peertab_links) {
		if (peer->addr == addr)
			goto done;
	}
	peer = kmalloc(sizeof(*peer), GFP_ATOMIC);
	if (!peer) {
		peer = (struct dcacp_peer *) ERR_PTR(-ENOMEM);
		// INC_METRIC(peer_kmalloc_errors, 1);
		goto done;
	}
	peer->addr = addr;
	flowi4_init_output(&peer->flow.u.ip4, inet->sk.sk_bound_dev_if,
			inet->sk.sk_mark, inet->tos, RT_SCOPE_UNIVERSE,
			inet->sk.sk_protocol, 0, addr, inet->inet_saddr,
			0, 0, inet->sk.sk_uid);
	security_sk_classify_flow(&inet->sk, &peer->flow);
	rt = ip_route_output_flow(sock_net(&inet->sk), &peer->flow.u.ip4,
			&inet->sk);
	if (IS_ERR(rt)) {
		kfree(peer);
		peer = (struct dcacp_peer *) PTR_ERR(rt);
		// INC_METRIC(peer_route_errors, 1);
		goto done;
	}
	peer->dst = &rt->dst;
	// peer->unsched_cutoffs[DCACP_MAX_PRIORITIES-1] = 0;
	// peer->unsched_cutoffs[DCACP_MAX_PRIORITIES-2] = INT_MAX;
	// peer->cutoff_version = 0;
	// peer->last_update_jiffies = 0;
	// peer->last_resend_tick = 0;
	hlist_add_head_rcu(&peer->peertab_links, &peertab->buckets[bucket]);
	// INC_METRIC(peer_new_entries, 1);
	
    done:
	spin_unlock_bh(&peertab->write_lock);
	return peer;
}

/**
 * dcacp_peer_unsched_priority() - Returns the priority level to use for
 * unscheduled packets of a message.
 * @dcacp:     Overall data about the Homa protocol implementation.
 * @peer:     The destination of the message.
 * @length:   Number of bytes in the message.
 * 
 * Return:    A priority level.
 */
// int dcacp_unsched_priority(struct dcacp *dcacp, struct dcacp_peer *peer,
// 		int length)
// {
// 	int i;
// 	for (i = dcacp->num_priorities-1; ; i--) {
// 		if (peer->unsched_cutoffs[i] >= length)
// 			return i;
// 	}
// 	/* Can't ever get here */
// }

/**
 * dcacp_peer_set_cutoffs() - Set the cutoffs for unscheduled priorities in
 * a peer object. This is a convenience function used primarily by unit tests.
 * @peer:   Homa_peer object whose cutoffs should be set.
 * @c0:     Largest message size that will use priority 0. 
 * @c1:     Largest message size that will use priority 1.
 * @c2:     Largest message size that will use priority 2.
 * @c3:     Largest message size that will use priority 3.
 * @c4:     Largest message size that will use priority 4.
 * @c5:     Largest message size that will use priority 5.
 * @c6:     Largest message size that will use priority 6.
 * @c7:     Largest message size that will use priority 7.
 */
// void dcacp_peer_set_cutoffs(struct dcacp_peer *peer, int c0, int c1, int c2,
// 		int c3, int c4, int c5, int c6, int c7)
// {
// 	peer->unsched_cutoffs[0] = c0;
// 	peer->unsched_cutoffs[1] = c1;
// 	peer->unsched_cutoffs[2] = c2;
// 	peer->unsched_cutoffs[3] = c3;
// 	peer->unsched_cutoffs[4] = c4;
// 	peer->unsched_cutoffs[5] = c5;
// 	peer->unsched_cutoffs[6] = c6;
// 	peer->unsched_cutoffs[7] = c7;
// }