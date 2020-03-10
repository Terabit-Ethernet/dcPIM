/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DCACP4_IMPL_H
#define _DCACP4_IMPL_H
#include <net/dcacp.h>
#include <net/dcacplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>

int __dcacp4_lib_rcv(struct sk_buff *, struct dcacp_table *, int);
int __dcacp4_lib_err(struct sk_buff *, u32, struct dcacp_table *);

int dcacp_v4_get_port(struct sock *sk, unsigned short snum);
void dcacp_v4_rehash(struct sock *sk);

int dcacp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen);
int dcacp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
int compat_dcacp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen);
int compat_dcacp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);
#endif
int dcacp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len);
int dcacp_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		 int flags);
void dcacp_destroy_sock(struct sock *sk);

#ifdef CONFIG_PROC_FS
int dcacp4_seq_show(struct seq_file *seq, void *v);
#endif
#endif	/* _DCACP4_IMPL_H */
