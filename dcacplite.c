// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  DCACPLITE     An implementation of the DCACP-Lite protocol (RFC 3828).
 *
 *  Authors:    Gerrit Renker       <gerrit@erg.abdn.ac.uk>
 *
 *  Changes:
 *  Fixes:
 */

#define pr_fmt(fmt) "DCACPLite: " fmt

#include <linux/export.h>
#include <linux/proc_fs.h>
#include "dcacp_impl.h"

#define IPPROTO_DCACPLITE 19

struct udp_table 	dcacplite_table __read_mostly;
EXPORT_SYMBOL(dcacplite_table);

static int dcacplite_rcv(struct sk_buff *skb)
{
	return __dcacp4_lib_rcv(skb, &dcacplite_table, IPPROTO_DCACPLITE);
}

static int dcacplite_err(struct sk_buff *skb, u32 info)
{
	return __dcacp4_lib_err(skb, info, &dcacplite_table);
}

static const struct net_protocol dcacplite_protocol = {
	.handler	= dcacplite_rcv,
	.err_handler	= dcacplite_err,
	.no_policy	= 1,
	.netns_ok	= 1,
};

struct proto 	dcacplite_prot = {
	.name		   = "DCACP-Lite",
	.owner		   = THIS_MODULE,
	.close		   = dcacp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = dcacp_disconnect,
	.ioctl		   = dcacp_ioctl,
	.init		   = dcacplite_sk_init,
	.destroy	   = dcacp_destroy_sock,
	.setsockopt	   = dcacp_setsockopt,
	.getsockopt	   = dcacp_getsockopt,
	.sendmsg	   = dcacp_sendmsg,
	.recvmsg	   = dcacp_recvmsg,
	.sendpage	   = dcacp_sendpage,
	.hash		   = dcacp_lib_hash,
	.unhash		   = dcacp_lib_unhash,
	.rehash		   = dcacp_v4_rehash,
	.get_port	   = dcacp_v4_get_port,
	.memory_allocated  = &dcacp_memory_allocated,
	.sysctl_mem	   = sysctl_dcacp_mem,
	.obj_size	   = sizeof(struct dcacp_sock),
	.h.udp_table	   = &dcacplite_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_dcacp_setsockopt,
	.compat_getsockopt = compat_dcacp_getsockopt,
#endif
};
EXPORT_SYMBOL(dcacplite_prot);

static struct inet_protosw dcacplite4_protosw = {
	.type		=  SOCK_DGRAM,
	.protocol	=  IPPROTO_DCACPLITE,
	.prot		=  &dcacplite_prot,
	.ops		=  &inet_dgram_ops,
	.flags		=  INET_PROTOSW_REUSE,
};

#ifdef CONFIG_PROC_FS
static struct dcacp_seq_afinfo dcacplite4_seq_afinfo = {
	.family		= AF_INET,
	.dcacp_table 	= &dcacplite_table,
};

static int __net_init dcacplite4_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("dcacplite", 0444, net->proc_net, &dcacp_seq_ops,
			sizeof(struct dcacp_iter_state), &dcacplite4_seq_afinfo))
		return -ENOMEM;
	return 0;
}

static void __net_exit dcacplite4_proc_exit_net(struct net *net)
{
	remove_proc_entry("dcacplite", net->proc_net);
}

static struct pernet_operations dcacplite4_net_ops = {
	.init = dcacplite4_proc_init_net,
	.exit = dcacplite4_proc_exit_net,
};

static __init int dcacplite4_proc_init(void)
{
	return register_pernet_subsys(&dcacplite4_net_ops);
}
#else
static inline int dcacplite4_proc_init(void)
{
	return 0;
}
#endif

void __init dcacplite4_register(void)
{
	dcacp_table_init(&dcacplite_table, "DCACP-Lite");
	if (proto_register(&dcacplite_prot, 1))
		goto out_register_err;

	if (inet_add_protocol(&dcacplite_protocol, IPPROTO_DCACPLITE) < 0)
		goto out_unregister_proto;

	inet_register_protosw(&dcacplite4_protosw);

	if (dcacplite4_proc_init())
		pr_err("%s: Cannot register /proc!\n", __func__);
	return;

out_unregister_proto:
	proto_unregister(&dcacplite_prot);
out_register_err:
	pr_crit("%s: Cannot add DCACP-Lite protocol\n", __func__);
}
