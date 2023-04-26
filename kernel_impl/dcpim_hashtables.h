/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 * Authors:	Lotsa people, from code originally in tcp
 */

#ifndef _DCPIM_HASHTABLES_H
#define _DCPIM_HASHTABLES_H


#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

// #include <net/inet_connection_sock.h>
// #include <net/inet_sock.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/netns/hash.h>

#include <linux/refcount.h>
#include <asm/byteorder.h>
#include <net/inet_hashtables.h>

void dcpim_hashtable_init(struct inet_hashinfo* hashinfo, unsigned long thash_entries);
void dcpim_hashtable_destroy(struct inet_hashinfo* hashinfo);
#endif /* _DCPIM_HASHTABLES_H */
