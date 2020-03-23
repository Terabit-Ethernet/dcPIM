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
 #include "net_dcacp.h"
// #include "net_dcacplite.h"
#include "uapi_linux_dcacp.h"
#include "dcacp_impl.h"



struct dcacp_message_out* dcacp_message_out_init(struct dcacp_peer *peer, 
	struct dcacp_sock *sock, struct sk_buff* skb, __u64 message_id, int message_size, int dport) {
	struct dcacp_message_out *msg;
	msg = (struct dcacp_message_out *) kmalloc(sizeof(*msg), GFP_KERNEL);
	if (unlikely(!msg))
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&msg->lock);
	msg->dport = dport;
	msg->id = message_id;
	msg->dsk = sock;
    msg->peer = peer;
    msg->packets = skb;
    msg->num_skbs = 1;
    msg->total_length = message_size;

    msg->total_bytes_sent = 0;

	/** @priority: Priority level to include in future GRANTS. */

    msg->remaining_pkts_at_sender = 0;

	/* DCACP metric */
    msg->first_byte_send_time = 0;

    msg->start_time= 0;
    msg->finish_time = 0;
    msg->latest_data_pkt_sent_time = 0;

	// int priority;
    return msg;

}

void dcacp_message_out_destroy(struct dcacp_message_out *msgout)
{
	// struct sk_buff *skb, *next;
	if (msgout->total_length < 0)
		return;
	kfree_skb(msgout->packets);
	delete_dcacp_message_out(msgout->dsk, msgout);
	// for (skb = msgout->packets; skb !=  NULL; skb = next) {
	// 	next = *dcacp_next_skb(skb);
	// 	kfree_skb(skb);
	// }
	msgout->packets = NULL;
	kfree(msgout);
}

struct dcacp_message_in* dcacp_message_in_init(struct dcacp_peer *peer, 
	struct dcacp_sock *sock, __u64 message_id, int message_size, int sport) {
	
	struct dcacp_message_in *msg;
	msg = (struct dcacp_message_in *) kmalloc(sizeof(*msg), GFP_KERNEL);
	if (unlikely(!msg))
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&msg->lock);
	skb_queue_head_init(&msg->packets);

	msg->dport = sport;
	msg->id = message_id;
    msg->peer = peer;
    msg->num_skbs = 0;
    msg->total_length = message_size;

    msg->received_bytes = 0;
    msg->received_count = 0;
    msg->recv_till = 0;

	// int priority;

    msg->flow_sync_received = false;
 	msg->finished_at_receiver= false;
    msg->last_token_data_seq_sent = -1;

    msg->token_count = 0;
    // will change later
    msg->token_goal = message_size / 1460;
    msg->largest_token_seq_received = -1;
    msg->largest_token_data_seq_received = -1;
	/* DCACP metric */
    msg->latest_token_sent_time = 0;
    msg->first_byte_receive_time = 0;

    return msg;
}

void dcacp_message_in_destroy(struct dcacp_message_in *msg)
{

	struct sk_buff *skb, *next;
	// struct sk_buff *skb, *next;
	if (msg->total_length < 0)
		return;
	skb_queue_walk_safe(&msg->packets, skb, next)
		kfree_skb(skb);
	__skb_queue_head_init(&msg->packets);
	msg->total_length = -1;

	delete_dcacp_message_in(msg->dsk, msg);

	kfree(msg);
	// for (skb = msgout->packets; skb !=  NULL; skb = next) {
	// 	next = *dcacp_next_skb(skb);
	// 	kfree_skb(skb);
	// }
}