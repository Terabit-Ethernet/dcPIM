// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * rdp_diag.c	Module for monitoring RDP transport protocols sockets.
 *
 * Authors:	Pavel Emelyanov, <xemul@parallels.com>
 */


#include <linux/module.h>
#include <linux/inet_diag.h>
#include <linux/rdp.h>
#include <net/rdp.h>
#include <net/rdplite.h>
#include <linux/sock_diag.h>

static int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct netlink_callback *cb,
			const struct inet_diag_req_v2 *req,
			struct nlattr *bc, bool net_admin)
{
	if (!inet_diag_bc_sk(bc, sk))
		return 0;

	return inet_sk_diag_fill(sk, NULL, skb, req,
			sk_user_ns(NETLINK_CB(cb->skb).sk),
			NETLINK_CB(cb->skb).portid,
			cb->nlh->nlmsg_seq, NLM_F_MULTI, cb->nlh, net_admin);
}

static int rdp_dump_one(struct rdp_table *tbl, struct sk_buff *in_skb,
			const struct nlmsghdr *nlh,
			const struct inet_diag_req_v2 *req)
{
	int err = -EINVAL;
	struct sock *sk = NULL;
	struct sk_buff *rep;
	struct net *net = sock_net(in_skb->sk);

	rcu_read_lock();
	if (req->sdiag_family == AF_INET)
		/* src and dst are swapped for historical reasons */
		sk = __rdp4_lib_lookup(net,
				req->id.idiag_src[0], req->id.idiag_sport,
				req->id.idiag_dst[0], req->id.idiag_dport,
				req->id.idiag_if, 0, tbl, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	else if (req->sdiag_family == AF_INET6)
		sk = __rdp6_lib_lookup(net,
				(struct in6_addr *)req->id.idiag_src,
				req->id.idiag_sport,
				(struct in6_addr *)req->id.idiag_dst,
				req->id.idiag_dport,
				req->id.idiag_if, 0, tbl, NULL);
#endif
	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	rcu_read_unlock();
	err = -ENOENT;
	if (!sk)
		goto out_nosk;

	err = sock_diag_check_cookie(sk, req->id.idiag_cookie);
	if (err)
		goto out;

	err = -ENOMEM;
	rep = nlmsg_new(sizeof(struct inet_diag_msg) +
			sizeof(struct inet_diag_meminfo) + 64,
			GFP_KERNEL);
	if (!rep)
		goto out;

	err = inet_sk_diag_fill(sk, NULL, rep, req,
			   sk_user_ns(NETLINK_CB(in_skb).sk),
			   NETLINK_CB(in_skb).portid,
			   nlh->nlmsg_seq, 0, nlh,
			   netlink_net_capable(in_skb, CAP_NET_ADMIN));
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(rep);
		goto out;
	}
	err = netlink_unicast(net->diag_nlsk, rep, NETLINK_CB(in_skb).portid,
			      MSG_DONTWAIT);
	if (err > 0)
		err = 0;
out:
	if (sk)
		sock_put(sk);
out_nosk:
	return err;
}

static void rdp_dump(struct rdp_table *table, struct sk_buff *skb,
		     struct netlink_callback *cb,
		     const struct inet_diag_req_v2 *r, struct nlattr *bc)
{
	bool net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	struct net *net = sock_net(skb->sk);
	int num, s_num, slot, s_slot;

	s_slot = cb->args[0];
	num = s_num = cb->args[1];

	for (slot = s_slot; slot <= table->mask; s_num = 0, slot++) {
		struct rdp_hslot *hslot = &table->hash[slot];
		struct sock *sk;

		num = 0;

		if (hlist_empty(&hslot->head))
			continue;

		spin_lock_bh(&hslot->lock);
		sk_for_each(sk, &hslot->head) {
			struct inet_sock *inet = inet_sk(sk);

			if (!net_eq(sock_net(sk), net))
				continue;
			if (num < s_num)
				goto next;
			if (!(r->idiag_states & (1 << sk->sk_state)))
				goto next;
			if (r->sdiag_family != AF_UNSPEC &&
					sk->sk_family != r->sdiag_family)
				goto next;
			if (r->id.idiag_sport != inet->inet_sport &&
			    r->id.idiag_sport)
				goto next;
			if (r->id.idiag_dport != inet->inet_dport &&
			    r->id.idiag_dport)
				goto next;

			if (sk_diag_dump(sk, skb, cb, r, bc, net_admin) < 0) {
				spin_unlock_bh(&hslot->lock);
				goto done;
			}
next:
			num++;
		}
		spin_unlock_bh(&hslot->lock);
	}
done:
	cb->args[0] = slot;
	cb->args[1] = num;
}

static void rdp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct inet_diag_req_v2 *r, struct nlattr *bc)
{
	rdp_dump(&rdp_table, skb, cb, r, bc);
}

static int rdp_diag_dump_one(struct sk_buff *in_skb, const struct nlmsghdr *nlh,
			     const struct inet_diag_req_v2 *req)
{
	return rdp_dump_one(&rdp_table, in_skb, nlh, req);
}

static void rdp_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
		void *info)
{
	r->idiag_rqueue = rdp_rqueue_get(sk);
	r->idiag_wqueue = sk_wmem_alloc_get(sk);
}

#ifdef CONFIG_INET_DIAG_DESTROY
static int __rdp_diag_destroy(struct sk_buff *in_skb,
			      const struct inet_diag_req_v2 *req,
			      struct rdp_table *tbl)
{
	struct net *net = sock_net(in_skb->sk);
	struct sock *sk;
	int err;

	rcu_read_lock();

	if (req->sdiag_family == AF_INET)
		sk = __rdp4_lib_lookup(net,
				req->id.idiag_dst[0], req->id.idiag_dport,
				req->id.idiag_src[0], req->id.idiag_sport,
				req->id.idiag_if, 0, tbl, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	else if (req->sdiag_family == AF_INET6) {
		if (ipv6_addr_v4mapped((struct in6_addr *)req->id.idiag_dst) &&
		    ipv6_addr_v4mapped((struct in6_addr *)req->id.idiag_src))
			sk = __rdp4_lib_lookup(net,
					req->id.idiag_dst[3], req->id.idiag_dport,
					req->id.idiag_src[3], req->id.idiag_sport,
					req->id.idiag_if, 0, tbl, NULL);

		else
			sk = __rdp6_lib_lookup(net,
					(struct in6_addr *)req->id.idiag_dst,
					req->id.idiag_dport,
					(struct in6_addr *)req->id.idiag_src,
					req->id.idiag_sport,
					req->id.idiag_if, 0, tbl, NULL);
	}
#endif
	else {
		rcu_read_unlock();
		return -EINVAL;
	}

	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;

	rcu_read_unlock();

	if (!sk)
		return -ENOENT;

	if (sock_diag_check_cookie(sk, req->id.idiag_cookie)) {
		sock_put(sk);
		return -ENOENT;
	}

	err = sock_diag_destroy(sk, ECONNABORTED);

	sock_put(sk);

	return err;
}

static int rdp_diag_destroy(struct sk_buff *in_skb,
			    const struct inet_diag_req_v2 *req)
{
	return __rdp_diag_destroy(in_skb, req, &rdp_table);
}

static int rdplite_diag_destroy(struct sk_buff *in_skb,
				const struct inet_diag_req_v2 *req)
{
	return __rdp_diag_destroy(in_skb, req, &rdplite_table);
}

#endif

static const struct inet_diag_handler rdp_diag_handler = {
	.dump		 = rdp_diag_dump,
	.dump_one	 = rdp_diag_dump_one,
	.idiag_get_info  = rdp_diag_get_info,
	.idiag_type	 = IPPROTO_RDP,
	.idiag_info_size = 0,
#ifdef CONFIG_INET_DIAG_DESTROY
	.destroy	 = rdp_diag_destroy,
#endif
};

static void rdplite_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			      const struct inet_diag_req_v2 *r,
			      struct nlattr *bc)
{
	rdp_dump(&rdplite_table, skb, cb, r, bc);
}

static int rdplite_diag_dump_one(struct sk_buff *in_skb, const struct nlmsghdr *nlh,
				 const struct inet_diag_req_v2 *req)
{
	return rdp_dump_one(&rdplite_table, in_skb, nlh, req);
}

static const struct inet_diag_handler rdplite_diag_handler = {
	.dump		 = rdplite_diag_dump,
	.dump_one	 = rdplite_diag_dump_one,
	.idiag_get_info  = rdp_diag_get_info,
	.idiag_type	 = IPPROTO_RDPLITE,
	.idiag_info_size = 0,
#ifdef CONFIG_INET_DIAG_DESTROY
	.destroy	 = rdplite_diag_destroy,
#endif
};

static int __init rdp_diag_init(void)
{
	int err;

	err = inet_diag_register(&rdp_diag_handler);
	if (err)
		goto out;
	err = inet_diag_register(&rdplite_diag_handler);
	if (err)
		goto out_lite;
out:
	return err;
out_lite:
	inet_diag_unregister(&rdp_diag_handler);
	goto out;
}

static void __exit rdp_diag_exit(void)
{
	inet_diag_unregister(&rdplite_diag_handler);
	inet_diag_unregister(&rdp_diag_handler);
}

module_init(rdp_diag_init);
module_exit(rdp_diag_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-17 /* AF_INET - IPPROTO_RDP */);
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-136 /* AF_INET - IPPROTO_RDPLITE */);
