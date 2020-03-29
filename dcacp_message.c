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

/**
 * dcacp_fill_packets() - Create one or more packets and fill them with
 * data from user space.
 * @homa:    Overall data about the DCACP protocol implementation.
 * @peer:    Peer to which the packets will be sent (needed for things like
 *           the MTU).
 * @from:    Address of the user-space source buffer.
 * @len:     Number of bytes of user data.
 * 
 * Return:   Address of the first packet in a list of packets linked through
 *           dcacp_next_skb, or a negative errno if there was an error. No
 *           fields are set in the packet headers except for type, incoming,
 *           offset, and length information. dcacp_message_out_init will fill
 *           in the other fields.
 */
struct sk_buff *dcacp_fill_packets(struct dcacp_peer *peer,
		struct msghdr *msg, size_t len)
{
	/* Note: this function is separate from dcacp_message_out_init
	 * because it must be invoked without holding an RPC lock, and
	 * dcacp_message_out_init must sometimes be called with the lock
	 * held.
	 */
	int bytes_left, unsched;
	struct sk_buff *skb;
	struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data, rtt_bytes;
	struct sk_buff **last_link;
	rtt_bytes = 10000;
	if (unlikely((len > DCACP_MAX_MESSAGE_LENGTH) || (len == 0))) {
		err = -EINVAL;
		goto error;
	}
	
	mtu = dst_mtu(peer->dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcacp_data_hdr);
	if (len <= max_pkt_data) {
		unsched = max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = peer->dst->dev->gso_max_size;
		// if (gso_size > homa->max_gso_size)
		// 	gso_size = homa->max_gso_size;
		
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct dcacp_data_hdr);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
		
		/* Round unscheduled bytes *up* to an even number of gsos. */
		unsched = rtt_bytes + max_gso_data - 1;
		unsched -= unsched % max_gso_data;
		if (unsched > len)
			unsched = len;
	}
	
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	for (bytes_left = len, last_link = &first; bytes_left > 0; ) {
		struct dcacp_data_hdr *h;
		struct data_segment *seg;
		int available, last_pkt_length;
		
		/* The sizeof(void*) creates extra space for dcacp_next_skb. */
		skb = alloc_skb(gso_size + sizeof(void*),
				GFP_KERNEL);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto error;
		}
		if ((bytes_left > max_pkt_data)
				&& (max_gso_data > max_pkt_data)) {
			// printk("unlikely is triggered:%d\n", __LINE__);
			skb_shinfo(skb)->gso_size = sizeof(struct data_segment)
					+ max_pkt_data;
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		}
		skb_shinfo(skb)->gso_segs = 0;
			
		skb_reserve(skb, sizeof(struct iphdr));
		skb_reset_transport_header(skb);
		h = (struct dcacp_data_hdr *) skb_put(skb,
				sizeof(*h) - sizeof(struct data_segment));
		h->common.type = DATA;
		available = max_gso_data;
		h->common.len = available > bytes_left? htonl(bytes_left) :htonl(available);
		
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */
		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left);
			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			if (!copy_from_iter_full(skb_put(skb, seg_size),
					seg_size, &msg->msg_iter)) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			// printk("seg size: %d\n", seg_size);
			// printk("offset: %d\n",  ntohl(seg->offset));
			// buffer += seg_size;
			(skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
		} while ((available > 0) && (bytes_left > 0));
		// h->incoming = htonl(((len - bytes_left) > unsched) ?
		// 		(len - bytes_left) : unsched);
		
		/* Make sure that the last segment won't result in a
		 * packet that's too small.
		 */
		last_pkt_length = htonl(seg->segment_length) + sizeof(*h);
		if (unlikely(last_pkt_length < DCACP_HEADER_MAX_SIZE))
			skb_put(skb, DCACP_HEADER_MAX_SIZE - last_pkt_length);
		*last_link = skb;
		last_link = dcacp_next_skb(skb);
		*last_link = NULL;
	}
	return first;
	
    error:
	dcacp_free_skbs(first);
	return ERR_PTR(err);
}


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
    msg->next_packet = skb;
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

	/* Must scan the packets to fill in header fields that weren't
	 * known when the packets were allocated.
	 */
	while (skb) {
		struct dcacp_data_hdr *h = (struct dcacp_data_hdr *)
				skb_transport_header(skb);
		msg->num_skbs++;
		h->common.source = inet_sk((struct sock*)sock)->inet_sport;
		h->common.dest =dport;
		dcacp_set_doff(h);
		h->message_id = msg->id;
		// printk("doffset: %d\n", h->common.doff);
		// h->message_length = htonl(len);
		// h->cutoff_version = rpc->peer->cutoff_version;
		// h->retransmit = 0;
		skb = *dcacp_next_skb(skb);
	}
	// int priority;
    return msg;

}

void dcacp_message_out_destroy(struct dcacp_message_out *msgout)
{
	// struct sk_buff *skb, *next;
	if(msgout == NULL)
		return;
	if (msgout->total_length < 0)
		return;
	spin_lock_bh(&msgout->lock);
	dcacp_free_skbs(msgout->packets);
	// kfree_skb(msgout->packets);
	delete_dcacp_message_out(msgout->dsk, msgout);
	// printk("call destroy message out in function \n");

	// for (skb = msgout->packets; skb !=  NULL; skb = next) {
	// 	next = *dcacp_next_skb(skb);
	// 	kfree_skb(skb);
	// }
	msgout->packets = NULL;
	spin_unlock_bh(&msgout->lock);

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
	INIT_LIST_HEAD(&msg->ready_link);

	msg->dport = sport;
	msg->dsk = sock;
	msg->id = message_id;
    msg->peer = peer;
    msg->num_skbs = 0;
    msg->total_length = message_size;
    msg->is_ready = false;

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
	if(msg == NULL)
		return;
	if (msg->total_length < 0)
		return;
	spin_lock_bh(&msg->lock);

	// delete_dcacp_message_in(msg->dsk, msg);

	skb_queue_walk_safe(&msg->packets, skb, next) {
		// printk("try to fee one packet skb\n");
		kfree_skb(skb);
	}
	__skb_queue_head_init(&msg->packets);
	msg->total_length = -1;
	// printk("call destroy message in function \n");

	spin_unlock_bh(&msg->lock);

	kfree(msg);
	// for (skb = msgout->packets; skb !=  NULL; skb = next) {
	// 	next = *dcacp_next_skb(skb);
	// 	kfree_skb(skb);
	// }
}

void dcacp_message_in_finish(struct dcacp_message_in *msg) {
	struct message_hslot *slot;
	if(msg == NULL)
		return;
	// send an ack packet to the sender
	// printk("transmit the ack packet \n");
	// printk("message id:%llu\n", msg->id);
	// printk("dsk address: %p LINE:%d\n", msg->dsk, __LINE__);
	slot = dcacp_message_in_bucket(msg->dsk, msg->id);
	spin_lock_bh(&slot->lock);
	delete_dcacp_message_in(msg->dsk, msg);
	spin_unlock_bh(&slot->lock);
	dcacp_message_in_destroy(msg);
	// printk("finish transmitting \n");

	// deete message
	// slot = dcacp_message_in_bucket(msg->dsk, msg->id);
	// spin_lock_bh(&slot->lock);
	// dcacp_message_in_destroy(msg);
	// printk("end destroy\n");
	// spin_unlock_bh(&slot->lock);
}