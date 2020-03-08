/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RDP4_IMPL_H
#define _RDP4_IMPL_H
#include <net/rdp.h>
#include <net/rdplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>

int __rdp4_lib_rcv(struct sk_buff *, struct rdp_table *, int);
int __rdp4_lib_err(struct sk_buff *, u32, struct rdp_table *);

int rdp_v4_get_port(struct sock *sk, unsigned short snum);
void rdp_v4_rehash(struct sock *sk);

int rdp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen);
int rdp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
int compat_rdp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen);
int compat_rdp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);
#endif
int rdp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len);
int rdp_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		 int flags);
void rdp_destroy_sock(struct sock *sk);

#ifdef CONFIG_PROC_FS
int rdp4_seq_show(struct seq_file *seq, void *v);
#endif
#endif	/* _RDP4_IMPL_H */
