// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  RDPLITE     An implementation of the RDP-Lite protocol (RFC 3828).
 *
 *  Authors:    Gerrit Renker       <gerrit@erg.abdn.ac.uk>
 *
 *  Changes:
 *  Fixes:
 */

#define pr_fmt(fmt) "RDPLite: " fmt

#include <linux/export.h>
#include <linux/proc_fs.h>
#include "rdp_impl.h"

struct rdp_table 	rdplite_table __read_mostly;
EXPORT_SYMBOL(rdplite_table);

static int rdplite_rcv(struct sk_buff *skb)
{
	return __rdp4_lib_rcv(skb, &rdplite_table, IPPROTO_RDPLITE);
}

static int rdplite_err(struct sk_buff *skb, u32 info)
{
	return __rdp4_lib_err(skb, info, &rdplite_table);
}

static const struct net_protocol rdplite_protocol = {
	.handler	= rdplite_rcv,
	.err_handler	= rdplite_err,
	.no_policy	= 1,
	.netns_ok	= 1,
};

struct proto 	rdplite_prot = {
	.name		   = "RDP-Lite",
	.owner		   = THIS_MODULE,
	.close		   = rdp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = rdp_disconnect,
	.ioctl		   = rdp_ioctl,
	.init		   = rdplite_sk_init,
	.destroy	   = rdp_destroy_sock,
	.setsockopt	   = rdp_setsockopt,
	.getsockopt	   = rdp_getsockopt,
	.sendmsg	   = rdp_sendmsg,
	.recvmsg	   = rdp_recvmsg,
	.sendpage	   = rdp_sendpage,
	.hash		   = rdp_lib_hash,
	.unhash		   = rdp_lib_unhash,
	.rehash		   = rdp_v4_rehash,
	.get_port	   = rdp_v4_get_port,
	.memory_allocated  = &rdp_memory_allocated,
	.sysctl_mem	   = sysctl_rdp_mem,
	.obj_size	   = sizeof(struct rdp_sock),
	.h.rdp_table	   = &rdplite_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_rdp_setsockopt,
	.compat_getsockopt = compat_rdp_getsockopt,
#endif
};
EXPORT_SYMBOL(rdplite_prot);

static struct inet_protosw rdplite4_protosw = {
	.type		=  SOCK_DGRAM,
	.protocol	=  IPPROTO_RDPLITE,
	.prot		=  &rdplite_prot,
	.ops		=  &inet_dgram_ops,
	.flags		=  INET_PROTOSW_PERMANENT,
};

#ifdef CONFIG_PROC_FS
static struct rdp_seq_afinfo rdplite4_seq_afinfo = {
	.family		= AF_INET,
	.rdp_table 	= &rdplite_table,
};

static int __net_init rdplite4_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("rdplite", 0444, net->proc_net, &rdp_seq_ops,
			sizeof(struct rdp_iter_state), &rdplite4_seq_afinfo))
		return -ENOMEM;
	return 0;
}

static void __net_exit rdplite4_proc_exit_net(struct net *net)
{
	remove_proc_entry("rdplite", net->proc_net);
}

static struct pernet_operations rdplite4_net_ops = {
	.init = rdplite4_proc_init_net,
	.exit = rdplite4_proc_exit_net,
};

static __init int rdplite4_proc_init(void)
{
	return register_pernet_subsys(&rdplite4_net_ops);
}
#else
static inline int rdplite4_proc_init(void)
{
	return 0;
}
#endif

void __init rdplite4_register(void)
{
	rdp_table_init(&rdplite_table, "RDP-Lite");
	if (proto_register(&rdplite_prot, 1))
		goto out_register_err;

	if (inet_add_protocol(&rdplite_protocol, IPPROTO_RDPLITE) < 0)
		goto out_unregister_proto;

	inet_register_protosw(&rdplite4_protosw);

	if (rdplite4_proc_init())
		pr_err("%s: Cannot register /proc!\n", __func__);
	return;

out_unregister_proto:
	proto_unregister(&rdplite_prot);
out_register_err:
	pr_crit("%s: Cannot add RDP-Lite protocol\n", __func__);
}
