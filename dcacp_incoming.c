
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

extern struct dcacp_peertab dcacp_peers_table;


static inline struct sock *__dcacp4_lib_lookup_skb(struct sk_buff *skb,
						 __be16 sport, __be16 dport,
						 struct udp_table *dcacptable)
{
	const struct iphdr *iph = ip_hdr(skb);

	return __dcacp4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
				 iph->daddr, dport, inet_iif(skb),
				 inet_sdif(skb), dcacptable, skb);
}

int dcacp_handle_flow_sync_pkt(struct sk_buff *skb) {
	struct dcacp_sock *dsk;
	struct inet_sock *inet;
	struct dcacp_message_in *msg;
	struct dcacp_peer *peer;
	struct iphdr *iph;
	struct message_hslot* slot;
	struct dcacp_flow_sync_hdr *fh;
	struct sock *sk;
	if (!pskb_may_pull(skb, sizeof(struct dcacp_flow_sync_hdr)))
		goto drop;		/* No space for header. */
	fh =  dcacp_flow_sync_hdr(skb);
	sk = skb_steal_sock(skb);
	if(!sk) {
		sk = __dcacp4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &dcacp_table);
	}
	if(sk) {
		dsk = dcacp_sk(sk);
		inet = inet_sk(sk);
		iph = ip_hdr(skb);

		peer = dcacp_peer_find(&dcacp_peers_table, iph->saddr, inet);
		msg = dcacp_message_in_init(peer, dsk, fh->message_id, fh->message_size, fh->common.source);
		slot = dcacp_message_in_bucket(dsk, fh->message_id);
		spin_lock_bh(&slot->lock);
		add_dcacp_message_in(dsk, msg);
		spin_unlock_bh(&slot->lock);
		// printk("receive notification pkt\n");
		// printk("msg address: %p LINE:%d\n", msg, __LINE__);
		// printk("fh->message_id:%d\n", msg->id);
		// printk("fh->message_size:%d\n", msg->total_length);
		// printk("source port: %u\n", fh->common.source);
		// printk("dest port: %u\n", fh->common.dest);
		// printk("socket is NULL?: %d\n", sk == NULL);
	}


drop:
	kfree_skb(skb);

	return 0;
}

int dcacp_handle_token_pkt(struct sk_buff *skb) {
	printk("receive token pkt\n");
	kfree_skb(skb);

	return 0;
}

int dcacp_handle_ack_pkt(struct sk_buff *skb) {
	struct dcacp_sock *dsk;
	// struct inet_sock *inet;
	struct dcacp_message_out *msg;
	// struct dcacp_peer *peer;
	// struct iphdr *iph;
	struct message_hslot* slot;
	struct dcacp_ack_hdr *ah = dcacp_ack_hdr(skb);
	struct sock *sk = skb_steal_sock(skb);
	printk("receive ack pkt\n");
	printk("source port: %d\n", ah->common.source);
	printk("dst port: %d\n", ah->common.dest);

	if(!sk) {
		sk = __dcacp4_lib_lookup_skb(skb, ah->common.source, ah->common.dest, &dcacp_table);
	}
	if(sk) {
		dsk = dcacp_sk(sk);
		printk("socket address: %p LINE:%d\n", dsk,  __LINE__);
		slot = dcacp_message_out_bucket(dsk, ah->message_id);
		spin_lock_bh(&slot->lock);
		msg = get_dcacp_message_out(dsk, ah->message_id);
		dcacp_message_out_destroy(msg);
		spin_unlock_bh(&slot->lock);
	} else {
		printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

	kfree_skb(skb);

	return 0;
}

/**
 * dcacp_message_in_copy_data() - Extract the data from an incoming message
 * and copy it to buffer(s) in user space.
 * @msgin:      The message whose data should be extracted.
 * @iter:       Describes the available buffer space at user-level; message
 *              data gets copied here.
 * @max_bytes:  Total amount of space available via iter.
 * 
 * Return:      The number of bytes copied, or a negative errno.
 */
int dcacp_message_in_copy_data(struct dcacp_message_in *msg,
		struct iov_iter *iter, int max_bytes)
{
	struct sk_buff *skb;
	int offset;
	int err;
	int remaining = max_bytes;
	
	/* Do the right thing even if packets have overlapping ranges.
	 * In practice, this shouldn't ever be necessary.
	 */
	offset = 0;
	skb_queue_walk(&msg->packets, skb) {
		struct dcacp_data_hdr *h = (struct dcacp_data_hdr *) skb->data;
		int this_offset = ntohl(h->seg.offset);
		int data_in_packet;
		int this_size = msg->total_length - offset;
		
		data_in_packet = skb->len - sizeof(struct dcacp_data_hdr);
		if (this_size > data_in_packet) {
			this_size = data_in_packet;
		}
		if (offset > this_offset) {
			this_size -= (offset - this_offset);
		}
		if (this_size > remaining) {
			this_size =  remaining;
		}
		err = skb_copy_datagram_iter(skb,
				sizeof(*h) + (offset - this_offset),
				iter, this_size);
		if (err) {
			return err;
		}
		remaining -= this_size;
		offset += this_size;
		if (remaining == 0) {
			break;
		}
	}
	return max_bytes - remaining;
}

/**
 * @dcacp_wait_for_message() - Wait for an appropriate incoming message.
 * @hsk:     Socket where messages will arrive.
 * @flags:   Flags parameter from dcacp_recv; see manual entry for details.
 * @id:      If non-zero, then a response message will not be returned
 *           unless its RPC id matches this.
 *
 * Return:   Pointer to an RPC that matches @flags and @id, or a negative
 *           errno value. The RPC will be locked; the caller must unlock.
 */
struct dcacp_message_in *dcacp_wait_for_message(struct dcacp_sock *dsk, unsigned flags, int *err)
{
	struct dcacp_message_in *msg = NULL;
	int error = 0;
	struct sock* sk = (struct sock*) dsk;
	// struct dcacp_rpc *result = NULL;
	// struct dcacp_interest interest;
	// int sock_locked = 0;
	
	/* Normally this loop only gets executed once, but we may have
	 * to start again if a "found" RPC gets deleted from underneath us.
	 */
	while (1) {

		error = sock_error((struct sock*)dsk);
		if (error) {
			break;
		}
		spin_lock_bh(&dsk->ready_queue_lock);
		do{
			if(!list_empty(&dsk->ready_message_queue)) {
				msg = list_first_entry(&dsk->ready_message_queue, struct dcacp_message_in, ready_link);
				list_del_init(&dsk->ready_message_queue);
				spin_unlock_bh(&dsk->ready_queue_lock);
				return msg;
			}
			spin_unlock_bh(&dsk->ready_queue_lock);
			if (!sk_can_busy_loop(sk))
				break;
			sk_busy_loop(sk, flags & MSG_DONTWAIT);
			// get the lock first before chekcing list empty
 		    spin_lock_bh(&dsk->ready_queue_lock);
		} while(!list_empty(&dsk->ready_message_queue));
		/* Now it's time to sleep. */
		set_current_state(TASK_INTERRUPTIBLE);
		// if (!atomic_long_read(&interest.id) && !hsk->shutdown) {
			// __u64 start = get_cycles();
		schedule();
			// INC_METRIC(blocked_cycles, get_cycles() - start);
		// }
		__set_current_state(TASK_RUNNING);
	}

	*err = error;
	return NULL;
}

/**
 * @dcacp_msg_ready: This function is called when the input message for
 * an RPC becomes complete. It marks the RPC as READY and either notifies
 * a waiting reader or queues the RPC.
 * @rpc:                RPC that now has a complete input message;
 *                      must be locked. The caller must also have
 *                      locked the socket for this RPC.
 */
void dcacp_msg_ready(struct dcacp_message_in *msg)
{

// 	struct homa_interest *interest;
	struct sock *sk;
	
// 	rpc->state = RPC_READY;
	
// 	/* First, see if someone is interested in this RPC specifically.
// 	 */
// 	if (rpc->interest) {
// 		interest = rpc->interest;
// 		goto handoff;
// 	}
	
// 	/* Second, check the interest list for this type of RPC. */
// 	if (rpc->is_client) {
// 		interest = list_first_entry_or_null(
// 				&rpc->hsk->response_interests,
// 				struct homa_interest, response_links);
// 		if (interest)
// 			goto handoff;
		list_add_tail(&msg->ready_link, &msg->dsk->ready_message_queue);
// 	} else {
// 		interest = list_first_entry_or_null(
// 				&rpc->hsk->request_interests,
// 				struct homa_interest, request_links);
// 		if (interest)
// 			goto handoff;
// 		list_add_tail(&rpc->ready_links, &rpc->hsk->ready_requests);
// 	}
	
// 	 If we get here, no-one is waiting for the RPC, so it has been
// 	 * queued.
	 
	
	/* Notify the poll mechanism. */
	sk = (struct sock *) msg->dsk;
	sk->sk_data_ready(sk);
	return;
	
// handoff:
// 	/* We found a waiting thread. Wakeup the thread and cleanup its
// 	 * interest info, so it won't have to acquire the socket lock
// 	 * again.
// 	 */
// 	homa_interest_set(interest, rpc);
// 	if (interest->reg_rpc) {
// 		interest->reg_rpc->interest = NULL;
// 		interest->reg_rpc = NULL;
// 	}
// 	if (interest->request_links.next != LIST_POISON1) {
// 		list_del(&interest->request_links);
// 		interest->request_links.next = LIST_POISON1;
// 	}
// 	if (interest->response_links.next != LIST_POISON1) {
// 		list_del(&interest->response_links);
// 		interest->response_links.next = LIST_POISON1;
// 	}
// 	wake_up_process(interest->thread);
}

/**
 * dcacp_add_packet() - Add an incoming packet to the contents of a
 * partially received message.
 * @msgin: Overall information about the incoming message.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to msgin (because
 *         it provides no new data).
 */
void dcacp_add_packet(struct dcacp_message_in *msg, struct sk_buff *skb)
{
	struct dcacp_data_hdr *h = dcacp_data_hdr(skb);
	int offset = ntohl(h->seg.offset);
	int data_bytes = ntohl(h->seg.segment_length);
	struct sk_buff *skb2;
	
	/* Any data from the packet with offset less than this is
	 * of no value.*/
	int floor = 0;
	
	/* Any data with offset >= this is useless. */
	int ceiling = msg->total_length;
	
	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&msg->packets, skb2) {
		struct dcacp_data_hdr *h2 = dcacp_data_hdr(skb2);
		int offset2 = ntohl(h2->seg.offset);
		int data_bytes2 = skb2->len - sizeof(struct dcacp_data_hdr);
		if (offset2 < offset) {
			floor = offset2 + data_bytes2;
			break;
		}
		ceiling = offset2;
	} 
		
	/* New packet goes right after skb2 (which may refer to the header).
	 * Packets shouldn't overlap in byte ranges, but the code below
	 * assumes they might, so it computes how many non-overlapping bytes
	 * are contributed by the new packet.
	 */
	if (unlikely(floor < offset)) {
		floor = offset;
	}
	if (ceiling > offset + data_bytes) {
		ceiling = offset + data_bytes;
	}
	if (floor >= ceiling) {
		/* This packet is redundant. */
//		char buffer[100];
//		printk(KERN_NOTICE "redundant DCACP packet: %s\n",
//			dcacp_print_packet(skb, buffer, sizeof(buffer)));
		// INC_METRIC(redundant_packets, 1);
		kfree_skb(skb);
		return;
	}
	__skb_insert(skb, skb2, skb2->next, &msg->packets);
	msg->received_bytes += (ceiling - floor);
	msg->num_skbs++;
}

/**
 * dcacp_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
int dcacp_handle_data_pkt(struct sk_buff *skb)
{
	struct dcacp_sock *dsk;
	struct dcacp_data_hdr *dh;
	struct sock *sk;
	struct message_hslot* slot;
	struct iphdr *iph;
	struct dcacp_message_in *msg = NULL;
	if (!pskb_may_pull(skb, sizeof(struct dcacp_data_hdr)))
		goto drop;		/* No space for header. */
	dh =  dcacp_data_hdr(skb);
	sk = skb_steal_sock(skb);
	if(!sk) {
		sk = __dcacp4_lib_lookup_skb(skb, dh->common.source, dh->common.dest, &dcacp_table);
	}
	if(sk) {
		dsk = dcacp_sk(sk);
		iph = ip_hdr(skb);

		slot = dcacp_message_in_bucket(dsk, dh->message_id);
		spin_lock_bh(&slot->lock);
		msg = get_dcacp_message_in(dsk, iph->saddr, dh->common.source, dh->message_id);
		spin_unlock_bh(&slot->lock);
		if(!msg)
			goto drop;
	// struct dcacp *dcacp = rpc->hsk->dcacp;
	// struct dcacp_data_hdr *h = dcacp_data_hdr(skb);
	// int incoming = ntohl(h->incoming);
	
	// tt_record4("incoming data packet, id %llu, port %d, offset %d/%d",
	// 		h->common.id,
	// 		rpc->is_client ? rpc->hsk->client_port
	// 		: rpc->hsk->server_port,
	// 		ntohl(h->seg.offset), ntohl(h->message_length));

	// if (rpc->state != RPC_INCOMING) {
	// 	if (unlikely(!rpc->is_client || (rpc->state == RPC_READY))) {
	// 		kfree_skb(skb);
	// 		return 0;			
	// 	}
	// 	dcacp_message_in_init(&rpc->msgin, ntohl(h->message_length),
	// 			incoming);
	// 	INC_METRIC(responses_received, 1);
	// 	rpc->state = RPC_INCOMING;
	// } else {
	// 	if (incoming > rpc->msgin.incoming) {
	// 		if (incoming > rpc->msgin.total_length)
	// 			rpc->msgin.incoming = rpc->msgin.total_length;
	// 		else
	// 			rpc->msgin.incoming = incoming;
	// 	}
	// }
		dcacp_add_packet(msg, skb);
	// if (rpc->msgin.scheduled)
	// 	dcacp_check_grantable(dcacp, rpc);
	// if (rpc->active_links.next == LIST_POISON1) {
	// 	/* This is the first packet of a server RPC, so we have to
	// 	 * add the RPC to @hsk->active_rpcs. We do it here, rather
	// 	 * than in dcacp_rpc_new_server, so we can acquire the socket
	// 	 * lock just once to both add the RPC to active_rpcs and
	// 	 * also add the RPC to the ready list, if appropriate.
	// 	 */
	// 	INC_METRIC(requests_received, 1);
	// 	dcacp_sock_lock(rpc->hsk, "dcacp_data_pkt (first)");
	// 	if (rpc->hsk->shutdown) {
	// 		/* Unsafe to add new RPCs to a socket after shutdown
	// 		 * has begun; destroy the new RPC.
	// 		 */
	// 		dcacp_message_in_destroy(&rpc->msgin);
	// 		dcacp_sock_unlock(rpc->hsk);
	// 		dcacp_rpc_unlock(rpc);
	// 		kfree(rpc);
	// 		return 1;
	// 	}
			
	// 	list_add_tail_rcu(&rpc->active_links, &rpc->hsk->active_rpcs);
	// 	if (rpc->msgin.bytes_remaining == 0)
	// 		dcacp_rpc_ready(rpc);
	// 	dcacp_sock_unlock(rpc->hsk);
	// } else {
		if (msg->received_bytes == msg->total_length) {
			spin_lock_bh(&msg->dsk->ready_queue_lock);
			dcacp_msg_ready(msg);
			spin_unlock_bh(&msg->dsk->ready_queue_lock);
		}
	// }
	// if (ntohs(h->cutoff_version) != dcacp->cutoff_version) {
	// 	 The sender has out-of-date cutoffs. Note: we may need
	// 	 * to resend CUTOFFS packets if one gets lost, but we don't
	// 	 * want to send multiple CUTOFFS packets when a stream of
	// 	 * packets arrives with stale cutoff_versions. Thus, we
	// 	 * don't send CUTOFFS unless there is a version mismatch
	// 	 * *and* it is been a while since the previous CUTOFFS
	// 	 * packet.
		 
	// 	if (jiffies != rpc->peer->last_update_jiffies) {
	// 		struct cutoffs_header h2;
	// 		int i;
			
	// 		for (i = 0; i < dcacp_MAX_PRIORITIES; i++) {
	// 			h2.unsched_cutoffs[i] =
	// 					htonl(dcacp->unsched_cutoffs[i]);
	// 		}
	// 		h2.cutoff_version = htons(dcacp->cutoff_version);
	// 		dcacp_xmit_control(CUTOFFS, &h2, sizeof(h2), rpc);
	// 		rpc->peer->last_update_jiffies = jiffies;
	// 	}
	// }
	}
drop:
	kfree_skb(skb);
	return 0;
}
