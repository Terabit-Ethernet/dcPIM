#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/etherdevice.h>
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
#include "dcpim_impl.h"
#include <net/sock_reuseport.h>
#include <net/sock.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_dcpim.h"
 #include "net_dcpim.h"
// #include "net_dcpimlite.h"
#include "uapi_linux_dcpim.h"
#include "dcpim_impl.h"


#define DCPIM_DEFERRED_ALL (DCPIMF_TOKEN_TIMER_DEFERRED |	\
			  DCPIMF_RTX_FLOW_SYNC_DEFERRED |	\
			  DCPIMF_MSG_RX_DEFERRED | \
			  DCPIMF_MSG_TX_DEFERRED | \
			  DCPIMF_MSG_RTX_DEFERRED)

static inline bool before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)


/* Insert buff after skb on the write or rtx queue of sk.  */
static void dcpim_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum dcpim_queue dcpim_queue)
{
	if (dcpim_queue == DCPIM_FRAG_IN_WRITE_QUEUE)
		skb_append(skb, buff,&sk->sk_write_queue);
	else
		dcpim_rbtree_insert(&sk->tcp_rtx_queue, buff);
}

void dcpim_fill_dcpim_header(struct sk_buff *skb, __be16 sport, __be16 dport) {
	struct dcpimhdr* dh;
	dh = dcpim_hdr(skb);
	dh->source = sport;
	dh->dest = dport;
	dh->check = 0;
	dh->doff = (sizeof(struct dcpimhdr)) >> 2;
}

void dcpim_swap_dcpim_header(struct sk_buff *skb) {
	struct dcpimhdr* dh;
	__be16 temp;
	dh = dcpim_hdr(skb);
	temp = dh->source;
	dh->source = dh->dest;
	dh->dest = temp;
}

void dcpim_fill_ip_header(struct sk_buff *skb, __be32 saddr, __be32 daddr) {
    struct iphdr* iph;
    skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos =  iph->tos | 4;
    iph->tot_len= htons(skb->len); 
    iph->frag_off = 0; 
    iph->ttl = 64;
    // iph->protocol = IPPROTO_DCPIM;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = saddr;
    iph->daddr = daddr;
	ip_send_check(iph);
    skb->pkt_type = PACKET_OUTGOING;
	skb->no_fcs = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
}

void dcpim_swap_ip_header(struct sk_buff *skb) {
    struct iphdr* iph = ip_hdr(skb);
	__be32 temp;
	temp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = temp;
    iph->protocol = IPPROTO_TCP;
	iph->frag_off = 0;
	iph->id = 0;
	/* mask to identify it is dcPIM packet; hacky!! */
	iph->tos = iph->tos | 4;
	ip_send_check(iph);
    skb->pkt_type = PACKET_OUTGOING;
	skb->no_fcs = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
}

void dcpim_fill_dst_entry(struct sock *sk, struct sk_buff *skb, struct flowi *fl) {
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	rt = skb_rtable(skb);
	if (rt)
		goto finish;

	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (!rt) {
		__be32 daddr;
		WARN_ON(true);
		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ip_route_output_ports(net, fl4, sk,
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   RT_CONN_FLAGS_TOS(sk, inet_sk(sk)->tos),
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto finish;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);
finish:
	rcu_read_unlock();
}

void dcpim_fill_eth_header(struct sk_buff *skb, const void *saddr, const void *daddr) {
    struct ethhdr* eth;
    eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));
	skb_reset_mac_header(skb);
    skb->protocol = eth->h_proto = htons(ETH_P_IP);
    ether_addr_copy(eth->h_source, saddr);
    ether_addr_copy(eth->h_dest, daddr);
	skb->dev = dev_get_by_name(&init_net, "ens2f0");
}

void dcpim_swap_eth_header(struct sk_buff *skb) {
	unsigned char	temp[ETH_ALEN];
    struct ethhdr* eth = eth_hdr(skb);
    // skb->protocol = eth->h_proto = htons(ETH_P_IP);
    ether_addr_copy(temp, eth->h_source);
    ether_addr_copy(eth->h_source, eth->h_dest);
    ether_addr_copy(eth->h_dest, temp);
}

/* Initialize GSO segments for a packet. */
static void dcpim_set_skb_gso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	// if (skb->len <= mss_now) {
	// 	/* Avoid the costly divide in the normal
	// 	 * non-TSO case.
	// 	 */
	// 	tcp_skb_pcount_set(skb, 1);
	// 	TCP_SKB_CB(skb)->tcp_gso_size = 0;
	// } else {
	// 	tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
	// 	TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	// }
	if(skb->len > mss_now) {
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// WARN_ON(skb->len != DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);

	} else {
                skb_shinfo(skb)->gso_segs = 1;
                skb_shinfo(skb)->gso_size = 0;
                skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
        }
}

struct sk_buff *dcpim_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule)
{
	struct sk_buff *skb;
	/* The DCPIM header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	// if (unlikely(tcp_under_memory_pressure(sk)))
	// 	sk_mem_reclaim_partial(sk);

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);
	if (likely(skb)) {
		// bool mem_scheduled;

		// if (force_schedule) {
		// 	mem_scheduled = true;
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// } else {
		// 	mem_scheduled = sk_wmem_schedule(sk, skb->truesize);
		// }
		// if (likely(mem_scheduled)) {
		// 	skb_reserve(skb, sk->sk_prot->max_header);
		// 	/*
		// 	 * Make sure that we have exactly size bytes
		// 	 * available to the caller, no more, no less.
		// 	 */
		// 	skb->reserved_tailroom = skb->end - skb->tail - size;
		// 	INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		// 	return skb;
		// }
		// __kfree_skb(skb);
		skb_reserve(skb, sk->sk_prot->max_header);
		skb->reserved_tailroom = skb->end - skb->tail - size;
		skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));

		return skb;
	} 
	// else {
	// 	sk->sk_prot->enter_memory_pressure(sk);
	// 	sk_stream_moderate_sndbuf(sk);
	// }
	// __kfree_skb(skb);
	return NULL;
}

/* assume hold bh_sock_lock */
int dcpim_fragment(struct sock *sk, enum dcpim_queue dcpim_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	// struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	// int max_pkt_data;
	// int old_factor;
	long limit;
	int nlen;
	// u8 flags;



	if (len == 0)
		return -EINVAL;
	if (len >= skb->len)
		return -EINVAL;

	/* dcpim_sendmsg() can overshoot sk_wmem_queued by one full size skb.
	 * We need some allowance to not penalize applications setting small
	 * SO_SNDBUF values.
	 * Also allow first and last skb in retransmit queue to be split.
	 */
	limit = sk->sk_sndbuf + 2 * SKB_TRUESIZE(GSO_MAX_SIZE);
	if (unlikely((sk->sk_wmem_queued >> 1) > limit &&
		     dcpim_queue != DCPIM_FRAG_IN_WRITE_QUEUE &&
		     skb != dcpim_rtx_queue_head(sk) &&
		     skb != dcpim_rtx_queue_tail(sk))) {
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWQUEUETOOBIG);
		return -ENOMEM;
	}

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = dcpim_stream_alloc_skb(sk, skb->len - len, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */
	skb_copy_decrypted(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	// sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len;
	buff->truesize += nlen;
	skb->truesize -= nlen;
	// printk("do fragment\n");
	// printk("new buff seq:%u\n", DCPIM_SKB_CB(skb)->seq + len);
	/* Correct the sequence numbers. */
	DCPIM_SKB_CB(buff)->seq = DCPIM_SKB_CB(skb)->seq + len;
	DCPIM_SKB_CB(buff)->end_seq = DCPIM_SKB_CB(skb)->end_seq;
	DCPIM_SKB_CB(skb)->end_seq = DCPIM_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	// flags = DCPIM_SKB_CB(skb)->tcp_flags;
	// DCPIM_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	// DCPIM_SKB_CB(buff)->tcp_flags = flags;
	// DCPIM_SKB_CB(buff)->sacked = DCPIM_SKB_CB(skb)->sacked;
	// tcp_skb_fragment_eor(skb, buff);
	skb_split(skb, buff, len);

	buff->ip_summed = CHECKSUM_PARTIAL;

	// buff->tstamp = skb->tstamp;
	// tcp_fragment_tstamp(skb, buff);

	// old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	dcpim_set_skb_gso_segs(skb, mss_now);
	dcpim_set_skb_gso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	// TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	// if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
	// 	int diff = old_factor - tcp_skb_pcount(skb) -
	// 		tcp_skb_pcount(buff);

	// 	if (diff)
	// 		tcp_adjust_pcount(sk, skb, diff);
	// }

	/* Link BUFF into the send queue. */
	// __skb_header_release(buff);

	dcpim_insert_write_queue_after(skb, buff, sk, dcpim_queue);
	// if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
	// 	list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}

/**
 * dcpim_fill_packets_message() - Create one or more packets and fill them with
 * data from user space, and link them to the corresponding message.
 * @sk:   socket which invokes the sendmsg.
 * @dcpim_msg:   Short message that holds the created packets.
 * @msg:         Address of the user-space source buffer.
 * @len:         Number of bytes of user data.
 * 
 * Return:   Return the length (bytes) that has been moved to the kernel space
 *           from user space, or a negative errno if there was an error. 
 */
int dcpim_fill_packets_message(struct sock* sk, struct dcpim_message *dcpim_msg,
		struct msghdr *msg, size_t len)
{
	int bytes_left, sent_len = 0;
	uint32_t write_seq = 0;
	struct sk_buff *skb;
	// struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	// struct sk_buff **last_link;
	struct dst_entry *dst;
	// struct dcpim_sock* dsk = dcpim_sk(sk);
	/* check socket has enough space */
	if (unlikely(len == 0)) {
		err = -EINVAL;
		goto error;
	}

	dst = sk_dst_get(sk);
	if(dst == NULL) {
		printk("dst is NULL\n");
		return -ENOTCONN;
	}
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	bytes_left = len;


	if (len <= max_pkt_data ) {
		max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = dst->dev->gso_max_size;
		if (gso_size > dcpim_params.bdp)
			gso_size = dcpim_params.bdp;
		// if(gso_size > dcpim_params.gso_size)
		// 	gso_size = dcpim_params.gso_size;
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct dcpim_data_hdr);
			WARN_ON(max_pkt_data < 0);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
	}
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	// ktime_t start, end;
	// start = ktime_get();
	for (; bytes_left > 0; ) {
		// struct dcpim_data_hdr *h;
		struct data_segment *seg;
		int available;
		int current_len = 0;
		 // last_pkt_length;
		
		/* The sizeof(void*) creates extra space for dcpim_next_skb. */
		skb = dcpim_stream_alloc_skb(sk, gso_size, GFP_KERNEL, true);
		/* this is a temp solution; will remove after adding split buffer mechanism */
		if (unlikely(!skb)) {
			// goto finish;
			err = -ENOMEM;
			goto error;
		}
		// if ((max_gso_data > bytes_left)) {
		// 	// if(!sk->sk_tx_skb_cache)
		// 	// 	sk->sk_tx_skb_cache = skb;
		// 	// else
		// 	kfree_skb(skb);
		// 	break;
		// }
		available = max_gso_data;
		current_len = available > bytes_left? bytes_left : available;
		// h->message_id = 256;
		WRITE_ONCE(DCPIM_SKB_CB(skb)->seq, write_seq + len - bytes_left);
		WRITE_ONCE(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(skb)->seq + current_len);
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */
		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left + write_seq);
			// printk("seq: %lu\n", len - bytes_left + write_seq);
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
			available -= seg_size;
		} while ((available > 0) && (bytes_left > 0));
		sent_len += current_len;
		dcpim_set_skb_gso_segs(skb, max_pkt_data + sizeof(struct data_segment));
		skb_queue_tail(&dcpim_msg->pkt_queue, skb);
		/* we allow the actual socket buffer size is one msg size larger than the limit */
		sk_wmem_queued_add(sk, skb->truesize);
		// dcpim_add_write_queue_tail(sk, skb);
	}
	WRITE_ONCE(write_seq, write_seq + sent_len);
	return sent_len;
	
error:
	return err;
}

/**
 * dcpim_fill_packets() - Create one or more packets and fill them with
 * data from user space.
 * @sk:      Socket that performs data copy.
 * @msg:     Address of the user-space source buffer.
 * @len:     Number of bytes of user data.
 * 
 * Return:   Return the length (bytes) that has been moved to the kernel space
 *           from user space, or a negative errno if there was an error. 
 */
int dcpim_fill_packets(struct sock *sk,
		struct msghdr *msg, size_t len)
{
	int bytes_left, sent_len = 0;
	struct sk_buff *skb;
	// struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	// struct sk_buff **last_link;
	struct dst_entry *dst;
	struct dcpim_sock* dsk = dcpim_sk(sk);
	/* check socket has enough space */
	if (unlikely(len == 0)) {
		err = -EINVAL;
		goto error;
	}

	dst = sk_dst_get(sk);
	if(dst == NULL) {
		printk("dst is NULL\n");
		return -ENOTCONN;
	}
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	bytes_left = len;


	if (len <= max_pkt_data ) {
		max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;
		
		gso_size = dst->dev->gso_max_size;
		if (gso_size > dcpim_params.bdp)
			gso_size = dcpim_params.bdp;
		// if(gso_size > dcpim_params.gso_size)
		// 	gso_size = dcpim_params.gso_size;
		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size / mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - sizeof(struct iphdr)
					- sizeof(struct dcpim_data_hdr);
			WARN_ON(max_pkt_data < 0);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;
		/* Round unscheduled bytes *up* to an even number of gsos. */
		// unsched = rtt_bytes + max_gso_data - 1;
		// unsched -= unsched % max_gso_data;
		// if (unsched > sent_len)
		// 	unsched = sent_len;
	}
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	// ktime_t start, end;
	// start = ktime_get();
	for (; bytes_left > 0; ) {
		// struct dcpim_data_hdr *h;
		struct data_segment *seg;
		int available;
		int current_len = 0;
		 // last_pkt_length;
		
		/* The sizeof(void*) creates extra space for dcpim_next_skb. */
		if(sk_stream_wspace(sk) <= 0)
			break;
		skb = dcpim_stream_alloc_skb(sk, gso_size, GFP_KERNEL, true);
		// if(sk->sk_tx_skb_cache != NULL) {
		// 	skb = sk->sk_tx_skb_cache;
		// 	sk->sk_tx_skb_cache = NULL;
		// } else {
		// 	skb = alloc_skb(gso_size, GFP_KERNEL);
		// }
		// skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
		/* this is a temp solution; will remove after adding split buffer mechanism */
		if (unlikely(!skb)) {
			// goto finish;
			err = -ENOMEM;
			goto error;
		}
		// if (skb->truesize > sk_stream_wspace(sk)) {
		// 	// if(!sk->sk_tx_skb_cache)
		// 	// 	sk->sk_tx_skb_cache = skb;
		// 	// else
		// 	kfree_skb(skb);
		// 	break;
		// }

		// if ((bytes_left > max_pkt_data)
		// 		&& (max_gso_data > max_pkt_data)) {
		// 	skb_shinfo(skb)->gso_size = max_pkt_data;
		// 	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		// }
		// skb_shinfo(skb)->gso_segs = 0;

		// skb_reserve(skb, sizeof(struct iphdr));
		// skb_reset_transport_header(skb);
		// h = (struct dcpim_data_hdr *) skb_put(skb, sizeof(*h));
		available = max_gso_data;
		current_len = available > bytes_left? bytes_left : available;
		// h->message_id = 256;
		WRITE_ONCE(DCPIM_SKB_CB(skb)->seq, dsk->sender.write_seq + len - bytes_left);
		WRITE_ONCE(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(skb)->seq + current_len);
		// if (!copy_from_iter_full(skb_put(skb, current_len),
		// 		current_len, &msg->msg_iter)) {
		// 	err = -EFAULT;
		// 	kfree_skb(skb);
		// 	goto error;
		// }
		// skb_shinfo(skb)->gso_segs += current_len / max_pkt_data;
		// if (current_len % max_pkt_data)
		// 	skb_shinfo(skb)->gso_segs += 1;
		// bytes_left -= current_len;
		// h->common.seq = 200;
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */

		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left + dsk->sender.write_seq);

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
			// (skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
			// h->common.len = htons(ntohs(h->common.len) + sizeof(*seg));
		} while ((available > 0) && (bytes_left > 0));
		sent_len += current_len;
		// h->incoming = htonl(((len - bytes_left) > unsched) ?
		// 		(len - bytes_left) : unsched);
		
		/* Make sure that the last segment won't result in a
		 * packet that's too small.
		 */


		// last_pkt_length = htonl(seg->segment_length) + sizeof(*h);
		// if (unlikely(last_pkt_length < DCPIM_HEADER_MAX_SIZE)){
		// 	skb_put(skb, DCPIM_HEADER_MAX_SIZE - last_pkt_length);
		// }
		// *last_link = skb;
		// last_link = dcpim_next_skb(skb);
		// *last_link = NULL;
		dcpim_set_skb_gso_segs(skb, max_pkt_data + sizeof(struct data_segment));
		dcpim_add_write_queue_tail(sk, skb);
		sk_wmem_queued_add(sk, skb->truesize);

		// sk_mem_charge(sk, skb->truesize);
	}
		// end = ktime_get();

		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
	// if (!sent_len) {
	// 	printk("total len:%ld\n", len);
	// 	printk("sent length:%d\n", sent_len);
	// 	printk("(sk_stream_wspace(sk):%d\n", (sk_stream_wspace(sk)));
	// }
// finish:
	WRITE_ONCE(dsk->sender.write_seq, dsk->sender.write_seq + sent_len);
	if(dsk->host) {
		atomic_add(sent_len, &dsk->host->total_unsent_bytes);
	}
	return sent_len;
	
error:
	// dcpim_free_skbs(first);
	return err;
}

/**
 * dcpim_release_cb - dcpim release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void dcpim_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & DCPIM_DEFERRED_ALL))
			return;
		nflags = flags & ~DCPIM_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	// if (flags & TCPF_TSQ_DEFERRED) {
	// 	tcp_tsq_write(sk);
	// 	__sock_put(sk);
	// }
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	// sock_release_ownership(sk);

	/* First check read memory */
	if (flags & DCPIMF_TOKEN_TIMER_DEFERRED) {
		dcpim_token_timer_defer_handler(sk);
		__sock_put(sk);
	}
	if (flags & DCPIMF_RTX_FLOW_SYNC_DEFERRED) {
		dcpim_rtx_sync_handler(dcpim_sk(sk));
		__sock_put(sk);
	}
	if(flags & DCPIMF_MSG_RX_DEFERRED) {
		dcpim_msg_fin_rx_bg_handler(dcpim_sk(sk));
		__sock_put(sk);
	} 
	if(flags & DCPIMF_MSG_TX_DEFERRED) {
		dcpim_msg_fin_tx_bg_handler(dcpim_sk(sk));
		__sock_put(sk);
	}
	if(flags & DCPIMF_MSG_RTX_DEFERRED) {
		dcpim_msg_rtx_bg_handler(dcpim_sk(sk));
		__sock_put(sk);
	}
	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(dcpim_release_cb);


struct sk_buff* __construct_control_skb(struct sock* sk, int size) {

	struct sk_buff *skb;
	if(!size)
		size = DCPIM_HEADER_MAX_SIZE;
	skb = alloc_skb(size, GFP_ATOMIC);
	skb->sk = sk;
	// int extra_bytes;
	if (unlikely(!skb))
		return NULL;
	skb_reserve(skb, DCPIM_HEADER_MAX_SIZE);
	skb_reset_transport_header(skb);

	// h = (struct dcpim_hdr *) skb_put(skb, length);
	// memcpy(h, contents, length);
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	// ((struct inet_sock *) sk)->tos = TOS_7;
	// skb->priority = sk.sk_priority = 7;
	// dst_hold(peer->dst);
	// skb_dst_set(skb, peer->dst);

	return skb;
}

struct sk_buff* construct_flow_sync_pkt(struct sock* sk, enum dcpim_packet_type type) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct dcpim_flow_sync_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	dh = (struct dcpimhdr *) skb_put(skb, sizeof(struct dcpimhdr));
	// dh = (struct dcpimhdr*) (&fh->common);
	// dh->len = htons(sizeof(struct dcpimhdr));
	dh->type = type;
	// fh->message_id = message_id;
	// fh->message_size = message_size;
	// fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_flow_sync_msg_pkt(struct sock* sk, __u64 message_id, 
	uint32_t message_size, __u64 start_time) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_flow_sync_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_flow_sync_hdr *) skb_put(skb, sizeof(struct dcpim_flow_sync_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_flow_sync_hdr));
	dh->type = NOTIFICATION_MSG;
	fh->message_id = message_id;
	fh->message_size = message_size;
	// fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_syn_ack_pkt(struct sock* sk) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct dcpim_syn_ack_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	dh = (struct dcpimhdr*) skb_put(skb, sizeof(struct dcpimhdr));
	// dh = (struct dcpimhdr*) (&fh->common);
	// dh->len = htons(sizeof(struct dcpimhdr));
	dh->type = SYN_ACK;
	// fh->message_id = message_id;
	// fh->message_size = message_size;
	// fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority, __u32 token_nxt) {
	// int extra_bytes = 0;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff* skb = __construct_control_skb(sk, DCPIM_HEADER_MAX_SIZE
		 + dsk->num_sacks * sizeof(struct dcpim_sack_block_wire));
	struct dcpim_token_hdr* fh;
	struct dcpimhdr* dh;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_token_hdr *) skb_put(skb, sizeof(struct dcpim_token_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_token_hdr));
	dh->type = TOKEN;
	fh->priority = priority;
	fh->rcv_nxt = dsk->receiver.rcv_nxt;
	fh->token_nxt = token_nxt;
	fh->num_sacks = 0;
	return skb;
}

struct sk_buff* construct_rtx_token_pkt(struct sock* sk, unsigned short priority,
	 __u32 prev_token_nxt, __u32 token_nxt, int *rtx_bytes) {
	// int extra_bytes = 0;
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff* skb = __construct_control_skb(sk, DCPIM_HEADER_MAX_SIZE
		 + dsk->num_sacks * sizeof(struct dcpim_sack_block_wire));
	struct dcpim_token_hdr* fh;
	struct dcpimhdr* dh;
	struct dcpim_sack_block_wire *sack;
	int i = 1;
	bool manual_end_point = true;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_token_hdr *) skb_put(skb, sizeof(struct dcpim_token_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_token_hdr));
	dh->type = TOKEN;
	fh->priority = priority;
	fh->rcv_nxt = dsk->receiver.rcv_nxt;
	fh->token_nxt = token_nxt;
	fh->num_sacks = 0;
	// printk("TOKEN: new grant next:%u\n", fh->grant_nxt);
	// printk("prev_grant_nxt:%u\n", prev_grant_nxt);
	// printk("new rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	// printk("copied seq:%u\n", dsk->receiver.copied_seq);
	// printk("rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	while(i <= dsk->num_sacks) {
		__u32 start_seq = dsk->selective_acks[dsk->num_sacks - i].start_seq;
		__u32 end_seq = dsk->selective_acks[dsk->num_sacks - i].end_seq;

		if(after(start_seq,prev_token_nxt))
			goto next;
		if(after(end_seq,prev_token_nxt)) {
			end_seq = prev_token_nxt;
			manual_end_point = false;
		}

		sack = (struct dcpim_sack_block_wire*) skb_put(skb, sizeof(struct dcpim_sack_block_wire));
		sack->start_seq = htonl(start_seq);
		sack->end_seq = htonl(end_seq);
		// printk("start seq:%u\n", start_seq);
		// printk("end seq:%u\n", end_seq);
		*rtx_bytes += end_seq - start_seq;
		fh->num_sacks++;
	next:
		i++;
	}
	if(manual_end_point) {
		sack = (struct dcpim_sack_block_wire*) skb_put(skb, sizeof(struct dcpim_sack_block_wire));
		sack->start_seq = htonl(prev_token_nxt);
		sack->end_seq = htonl(prev_token_nxt);
		// printk("sack start seq:%u\n", prev_token_nxt);
		fh->num_sacks++;
	}



	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_ack_hdr* ah;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	ah = (struct dcpim_ack_hdr *) skb_put(skb, sizeof(struct dcpim_ack_hdr));
	dh = (struct dcpimhdr*) (&ah->common);
	dh->len = htons(sizeof(struct dcpim_ack_hdr));
	dh->type = ACK;
	ah->rcv_nxt = rcv_nxt;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_pkt(struct sock* sk) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	dh = (struct dcpimhdr*) skb_put(skb, sizeof(struct dcpimhdr));
	dh->len = htons(sizeof(struct dcpimhdr));
	dh->type = FIN;
	// fh->message_id = message_id;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_msg_pkt(struct sock* sk, uint64_t msg_id) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpimhdr* dh; 
	struct dcpim_fin_hdr *fh;
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_fin_hdr*) skb_put(skb, sizeof(struct dcpim_fin_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_fin_hdr));
	dh->type = FIN_MSG;
	fh->message_id = msg_id;
	fh->num_msgs = dcpim_sk(sk)->receiver.num_msgs;
	dcpim_sk(sk)->receiver.last_sent_num_msgs = dcpim_sk(sk)->receiver.num_msgs;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_resync_msg_pkt(struct sock* sk, uint64_t msg_id) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpimhdr* dh; 
	struct dcpim_resync_msg_hdr *rh;
	if(unlikely(!skb)) {
		return NULL;
	}
	rh = (struct dcpim_resync_msg_hdr*) skb_put(skb, sizeof(struct dcpim_resync_msg_hdr));
	dh = (struct dcpimhdr*) (&rh->common);
	dh->len = htons(sizeof(struct dcpim_resync_msg_hdr));
	dh->type = RESYNC_MSG;
	rh->message_id = msg_id;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_ack_pkt(struct sock* sk) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_fin_ack_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_fin_ack_hdr *) skb_put(skb, sizeof(struct dcpim_fin_ack_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_fin_ack_hdr));
	dh->type = FIN_ACK;
	// fh->message_id = message_id;
	// fh->message_size = message_size;
	// fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_fin_ack_msg_pkt(struct sock* sk, __u64 message_id) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_fin_ack_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_fin_ack_hdr *) skb_put(skb, sizeof(struct dcpim_fin_ack_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_fin_ack_hdr));
	dh->type = FIN_ACK_MSG;
	fh->message_id = message_id;
	// fh->message_size = message_size;
	// fh->start_time = start_time;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz, bool rtx_channel, bool prompt_channel) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_rts_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_rts_hdr *) skb_put(skb, sizeof(struct dcpim_rts_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_rts_hdr));
	dh->type = RTS;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->rtx_channel = rtx_channel;
	fh->prompt_channel = prompt_channel;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz, bool prompt, bool rtx_channel, bool prompt_channel) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_grant_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_grant_hdr *) skb_put(skb, sizeof(struct dcpim_grant_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_grant_hdr));
	dh->type = GRANT;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->rtx_channel = rtx_channel;
	fh->prompt_channel = prompt_channel;
	// fh->prompt = prompt;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}

struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short round, int epoch, int remaining_sz, bool rtx_channel, bool prompt_channel) {
	// int extra_bytes = 0;
	struct sk_buff* skb = __construct_control_skb(sk, 0);
	struct dcpim_accept_hdr* fh;
	struct dcpimhdr* dh; 
	if(unlikely(!skb)) {
		return NULL;
	}
	fh = (struct dcpim_accept_hdr *) skb_put(skb, sizeof(struct dcpim_accept_hdr));
	dh = (struct dcpimhdr*) (&fh->common);
	dh->len = htons(sizeof(struct dcpim_accept_hdr));
	dh->type = ACCEPT;
	fh->round = round;
	fh->epoch = epoch;
	fh->remaining_sz = remaining_sz;
	fh->rtx_channel = rtx_channel;
	fh->prompt_channel = prompt_channel;
	// extra_bytes = DCPIM_HEADER_MAX_SIZE - length;
	// if (extra_bytes > 0)
	// 	memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	return skb;
}
/**
 * dcpim_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as NOTIFICATION.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of common_header except type, will be set from this.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
// int dcpim_xmit_control(enum dcpim_packet_type type, struct sk_buff *skb,
// 	size_t len, struct flowi4 *fl4)
// {
// 	struct sock *sk = skb->sk;
// 	struct inet_sock *inet = inet_sk(sk);
// 	struct dcpim_header *dh = dcpim_hdr(skb);
// 	dh->type = type;
// 	dh->source = inet->inet_sport;
// 	dh->dest = fl4->fl4_dport;
// 	uh->check = 0;
// 	uh->len = htons(len);

// 	// if (rpc->is_client) {
// 	// 	h->sport = htons(rpc->hsk->client_port);
// 	// } else {
// 	// 	h->sport = htons(rpc->hsk->server_port);
// 	// }
// 	h->dport = htons(rpc->dport);
// 	h->id = rpc->id;
// 	return __dcpim_xmit_control(contents, length, rpc->peer, rpc->hsk);
// }


void dcpim_retransmit(struct sock* sk) {
	struct dcpim_sock* dsk = dcpim_sk(sk);
	// struct dcpim_sack_block *sp;
	struct sk_buff *skb;
	int start_seq, end_seq, mss_now, mtu, i;
	struct dst_entry *dst;
	dst = sk_dst_get(sk);
	mtu = dst_mtu(dst);
	mss_now = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	/* last sack is the fake sack [prev_grant_next, prev_grant_next) */
	skb = skb_rb_first(&sk->tcp_rtx_queue);
	for (i = 0; i < dsk->sender.num_sacks; i++) {
		if(!skb)
			break;
		if(i == 0) {
			start_seq = dsk->sender.snd_una;
		} else {
			start_seq = dsk->sender.selective_acks[i - 1].end_seq;
		}
		end_seq = dsk->sender.selective_acks[i].start_seq;

		while(skb) {
			if(!before(start_seq, DCPIM_SKB_CB(skb)->end_seq)) {
				goto go_to_next;
			}
			if(!after(end_seq, DCPIM_SKB_CB(skb)->seq)) {
				break;
			}
			/* split the skb buffer; after split, end sequence of skb will change */
			if(after(start_seq, DCPIM_SKB_CB(skb)->seq)) {
				/* move the start seq forward to the start of a MSS packet */
				int seg = (start_seq - DCPIM_SKB_CB(skb)->seq) / mss_now;
				int ret = dcpim_fragment(sk, DCPIM_FRAG_IN_RTX_QUEUE, skb,
				 seg * (mss_now + sizeof(struct data_segment)), mss_now  + sizeof(struct data_segment), GFP_ATOMIC);
				/* move forward after the split */
				if(!ret)
					skb = skb_rb_next(skb);
			}
			if(before(end_seq, DCPIM_SKB_CB(skb)->end_seq)) {
				/* split the skb buffer; Round up this time */
				int seg = DIV_ROUND_UP((end_seq - DCPIM_SKB_CB(skb)->seq), mss_now);
				dcpim_fragment(sk, DCPIM_FRAG_IN_RTX_QUEUE, skb,
				 seg * (mss_now + sizeof(struct data_segment)), mss_now  + sizeof(struct data_segment), GFP_ATOMIC);		
			}
			dcpim_retransmit_data(skb, dcpim_sk(sk));
go_to_next:
			skb = skb_rb_next(skb);
		}


	}	
	dsk->sender.num_sacks = 0;
}
/**
 * __dcpim_xmit_control() - Lower-level version of dcpim_xmit_control: sends
 * a control packet.
 * @skb:	   Packet payload
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int dcpim_xmit_control(struct sk_buff* skb, struct sock* sk)
{
	// struct dcpim_hdr *h;
	int result;
	struct dcpimhdr* dh;
	struct inet_sock *inet = inet_sk(sk);
	// struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = dcpim_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = inet->inet_dport;
	dh->check = 0;
	dh->doff = (sizeof(struct dcpimhdr)) >> 2;
	// inet->tos = IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL;
	skb->sk = sk;
	// dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, __sk_dst_get(sk));
	// skb_get(skb);
	result = __ip_queue_xmit(sk, skb, &inet->cork.fl, 0);
	if (unlikely(result != 0)) {
		// INC_METRIC(control_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		// if (refcount_read(&skb->users) > 1)
		// 	printk(KERN_NOTICE "ip_queue_xmit didn't free "
		// 			"DCPIM control packet after error\n");
	}
	// kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 * __dcpim_xmit_rts_control() - xmit rts packets
 * @skb:	   Packet payload
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int __dcpim_xmit_rts_control(struct sk_buff* skb, struct sock* sk)
{
	// struct dcpim_hdr *h;
	int result;
	struct dcpimhdr* dh;
	struct inet_sock *inet = inet_sk(sk);
	// struct flowi4 *fl4 = &peer->flow.u.ip4;

	if(!skb) {
		return -1;
	}
	dh = dcpim_hdr(skb);
	dh->source = inet->inet_sport;
	dh->dest = inet->inet_dport;
	dh->check = 0;
	dh->doff = (sizeof(struct dcpimhdr)) >> 2;
	// inet->tos = IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL;
	skb->sk = sk;
	// dst_confirm_neigh(peer->dst, &fl4->daddr);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, __sk_dst_get(sk));
	// skb_get(skb);
	result = __ip_queue_xmit(sk, skb, &inet->cork.fl, IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL);
	if (unlikely(result != 0)) {
		// INC_METRIC(control_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		// if (refcount_read(&skb->users) > 1)
		// 	printk(KERN_NOTICE "ip_queue_xmit didn't free "
		// 			"DCPIM control packet after error\n");
	}
	// kfree_skb(skb);
	// INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 *
 */
void dcpim_xmit_data(struct sk_buff* skb, struct dcpim_sock* dsk)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb))) 
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, 0, 0, 0, 0);
	/* change the state of queue and metadata*/

	// dcpim_unlink_write_queue(oskb, sk);
	dcpim_rbtree_insert(&sk->tcp_rtx_queue, oskb);
	WRITE_ONCE(dsk->sender.snd_nxt, DCPIM_SKB_CB(oskb)->end_seq);
	// sk_wmem_queued_add(sk, -skb->truesize);
}

/** dcpim_xmit_data_message - send skb of a short message
 * 
 */
void dcpim_xmit_data_message(struct sk_buff* skb, struct dcpim_sock* dsk, uint64_t id, uint32_t msg_bytes, bool flow_sync)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	// printk("tx data");
	if (unlikely(skb_cloned(oskb))) 
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, true, id, msg_bytes, flow_sync);
}

/** dcpim_xmit_data_message - send the whole short message. Assume caller holds the lock.
 * 
 */
void dcpim_xmit_data_whole_message(struct dcpim_message* msg, struct dcpim_sock* dsk)
{
	struct sk_buff* skb;
	bool flow_sync = false;
	skb_queue_walk(&msg->pkt_queue, skb) {
		dcpim_xmit_data_message(skb, dsk, msg->id, msg->total_len, flow_sync);
	}
}

void dcpim_retransmit_data(struct sk_buff* skb, struct dcpim_sock* dsk)
{
	struct sock* sk = (struct sock*)(dsk);
	struct sk_buff* oskb;
	oskb = skb;
	if (unlikely(skb_cloned(oskb)))
		skb = pskb_copy(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	else
		skb = skb_clone(oskb,  sk_gfp_mask(sk, GFP_ATOMIC));
	__dcpim_xmit_data(skb, dsk, 0, 0, 0, 0);
}

/**
 * __dcpim_xmit_data() - Handles packet transmission stuff that is common
 * to dcpim_xmit_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @dsk:      DCPIM socket
 * @is_short: Whether packets belonged to short messages.
 * @msg_id:   The ID of message.

 */
void __dcpim_xmit_data(struct sk_buff *skb, struct dcpim_sock* dsk, bool is_short, uint64_t msg_id, uint32_t msg_size, bool flow_sync)
{
	int err;
	__u8 tos = 0;
	// struct dcpim_data_hder *h = (struct dcpim_data_hder *)
	// 		skb_transport_header(skb);
	struct sock* sk = (struct sock*)dsk;
	struct inet_sock *inet = inet_sk(sk);
	struct dcpim_data_hdr *h;
	// struct dcpimhdr* dh;

	// dh = dcpim_hdr(skb);

	// dh->source = inet->inet_sport;

	// dh->dest = dport;

	// inet->tos = TOS_1;

	// set_priority(skb, rpc->hsk, priority);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	// if(free_token) 
	// 	tos = IPTOS_LOWDELAY | IPTOS_PREC_INTERNETCONTROL;
	// else 
	// 	tos = IPTOS_THROUGHPUT | IPTOS_PREC_IMMEDIATE;
	skb_push(skb, sizeof(struct dcpim_data_hdr) - sizeof(struct data_segment));
	skb_reset_transport_header(skb);
	h = (struct dcpim_data_hdr *)
				skb_transport_header(skb);
	dst_hold(__sk_dst_get(sk));
	// skb_dst_set(skb, peer->dst);
	skb->sk = sk;
	skb_dst_set(skb, __sk_dst_get(sk));
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct dcpimhdr, check);
	h->common.source = inet->inet_sport;
	h->common.dest = inet->inet_dport;
	// h->common.len = htons(DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq);
	// h->common.seq = htonl(DCPIM_SKB_CB(skb)->seq);
	if(is_short)
		h->common.type = DATA_MSG;
	else 
		h->common.type = DATA;
	// printk("type: %d %u \n", h->common.type, skb->len);
	/* doesn't change to network order for now */
	h->message_size = msg_size;
	h->message_id = msg_id;
	h->flow_sync = flow_sync;
	dcpim_set_doff(h);
	
	skb_set_hash_from_sk(skb, sk);

	// h->common.seq = htonl(200);
	err = __ip_queue_xmit(sk, skb, &inet->cork.fl, tos);
//	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
//			"next_offset %d",
//			h->common.id, ntohl(h->seg.offset), skb->len,
//			rpc->msgout.next_offset);
	if (err) {
		// INC_METRIC(data_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code raises an alert if this
		 * isn't actually the case.
		 */
		if (refcount_read(&skb->users) > 1) {
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"DCPIM data packet after error\n");
			kfree_skb(skb);
		}
	}
	// INC_METRIC(packets_sent[0], 1);
}

/* Called with bottom-half processing disabled.
   assuming hold the socket lock */
int dcpim_write_timer_handler(struct sock *sk)
{    
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sk_buff *skb;
	int sent_bytes = 0;
	int mss_now, mtu;
	int ret, seg;
	struct dst_entry *dst;
	dst = sk_dst_get(sk);
	WARN_ON_ONCE(dst == NULL);
	mtu = dst_mtu(dst);
	mss_now = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	if(dsk->sender.num_sacks > 0) {
		// printk("retransmit\n");
		dcpim_retransmit(sk);
	}
	while((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (!before(dsk->sender.token_seq, DCPIM_SKB_CB(skb)->end_seq)) {
			skb_dequeue(&sk->sk_write_queue);
			dcpim_xmit_data(skb, dsk);
			sent_bytes += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
		}  else if(after(dsk->sender.token_seq, DCPIM_SKB_CB(skb)->seq)) {
			seg = (dsk->sender.token_seq - DCPIM_SKB_CB(skb)->seq) / mss_now;
			if(seg == 0) {
				break;
			}
			// printk("call fragment\n");
			ret = dcpim_fragment(sk, DCPIM_FRAG_IN_WRITE_QUEUE, skb,
				 seg * (mss_now + sizeof(struct data_segment)), mss_now  + sizeof(struct data_segment), GFP_ATOMIC);
			// printk("finish call fragment\n");
			if(ret < 0) {
				break;
			}
			skb_dequeue(&sk->sk_write_queue);
			dcpim_xmit_data(skb, dsk);
			sent_bytes += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
		} else {
			break;
		}
		/* To Do: grant_nxt might be somewhere in the middle of seq and end_seq; need to split skb to do the transmission */
	}
	return sent_bytes;
}


uint32_t dcpim_xmit_token(struct dcpim_sock* dsk, uint32_t token_bytes) {
	// struct inet_sock *inet = inet_sk((struct sock*)dsk);
	struct sock *sk = (struct sock*)dsk;
	if(token_bytes == 0) {
		return token_bytes;
	}
	dsk->receiver.prev_token_nxt = dsk->receiver.token_nxt;
	dsk->receiver.token_nxt += token_bytes; 
	dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	dsk->receiver.inflight_bytes += token_bytes;
	dcpim_xmit_control(construct_token_pkt((struct sock*)dsk, 3, dsk->receiver.token_nxt),
	 	sk);
	return token_bytes;
}

int dcpim_token_timer_defer_handler(struct sock *sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	// uint32_t prev_token_nxt = dsk->receiver.token_nxt;
	unsigned long matched_bw = atomic64_read(&dsk->receiver.pacing_rate);
	unsigned long token_bytes = dcpim_avail_token_space((struct sock*)dsk);
	ktime_t time_delta = ktime_get() - dsk->receiver.latest_token_sent_time;
	ktime_t tx_time = 0;
	if(sk->sk_state != DCPIM_ESTABLISHED)
		return 0;
	if(matched_bw == 0)
		return 0;
	if(token_bytes == 0)
		return 0;
	/* allow window to be one token_batch larger */
	if(token_bytes < dsk->receiver.token_batch)
		token_bytes = dsk->receiver.token_batch;
	tx_time = ns_to_ktime(token_bytes * 1000000000 / matched_bw);
	if(time_delta < tx_time) {
		if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
			hrtimer_start(&dsk->receiver.token_pace_timer,
				tx_time - time_delta, HRTIMER_MODE_REL_PINNED_SOFT);
		}
		return 0;
	}
	token_bytes = dcpim_xmit_token(dsk, token_bytes);
	dsk->receiver.latest_token_sent_time += tx_time;
	// printk("defer token_bytes:%u %u\n", token_bytes, dsk->receiver.token_nxt);
	if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
		if(time_delta / tx_time > 1) {
			hrtimer_start(&dsk->receiver.token_pace_timer,
				0, HRTIMER_MODE_REL_PINNED_SOFT);
		} else {
			hrtimer_start(&dsk->receiver.token_pace_timer,
				2 * tx_time - time_delta, HRTIMER_MODE_REL_PINNED_SOFT);
		}
	}
	return token_bytes;
}

enum hrtimer_restart dcpim_delay_ack_timer_handler(struct hrtimer *timer) {
	struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, receiver.delay_ack_timer);
	queue_work_on(dsk->core_id, dcpim_wq, &dsk->receiver.delay_ack_work);
	return HRTIMER_NORESTART;
}

void dcpim_delay_ack_work(struct work_struct *work) {
	struct dcpim_sock *dsk = container_of(work, struct dcpim_sock, receiver.delay_ack_work);
	struct sock *sk = (struct sock*) dsk;
	lock_sock(sk);
	if(sk->sk_state == DCPIM_ESTABLISHED) {
		dcpim_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk);
	}
	dsk->receiver.delay_ack = false;
	release_sock(sk);
}


/* hrtimer may fire twice for some reaons; need to check what happens later. */
enum hrtimer_restart dcpim_xmit_token_handler(struct hrtimer *timer) {

	struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, receiver.token_pace_timer);
	struct sock* sk = (struct sock *)dsk;
	unsigned long matched_bw = atomic64_read(&dsk->receiver.pacing_rate);
	unsigned long token_bytes = 0;
	ktime_t current_time = ktime_get();
	ktime_t delta = 0;
	ktime_t tx_time = 0;
	if(matched_bw == 0)
		goto put_sock;
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		if(sk->sk_state != DCPIM_ESTABLISHED)
			goto unlock_sock;
		token_bytes = dcpim_avail_token_space((struct sock*)dsk);
		delta = current_time - dsk->receiver.latest_token_sent_time;
		if(token_bytes == 0)
			goto unlock_sock;
		/* allow window one token_batch larger than the window */
		if(token_bytes < dsk->receiver.token_batch)
			token_bytes = dsk->receiver.token_batch;
		tx_time = ns_to_ktime(token_bytes * 1000000000 / matched_bw);
		if(delta < tx_time) {
			if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
				hrtimer_forward_now(timer, tx_time - delta);
			}
			bh_unlock_sock(sk);
			return HRTIMER_RESTART;
		}
		dcpim_xmit_token(dsk, token_bytes);
		dsk->receiver.latest_token_sent_time += tx_time;
		// printk("timer token_bytes:%u %u\n", token_bytes, dsk->receiver.token_nxt);
		if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
			if(delta / tx_time > 1)
				hrtimer_forward_now(timer, 0);
			else
				hrtimer_forward_now(timer, 2 * tx_time - delta);
		}
		bh_unlock_sock(sk);
		/* still need to sock_hold */
		return HRTIMER_RESTART;
	} else {
		/* delegate our work to dcpim_release_cb() */
		// WARN_ON(sk->sk_state == DCPIM_CLOSE);
		// printk("delay timer\n");
		if (!test_and_set_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
			sock_hold(sk);
		}

	}
unlock_sock:
	bh_unlock_sock(sk);
put_sock:
	// sock_put(sk);
	return HRTIMER_NORESTART;
}

void dcpim_xmit_token_work(struct work_struct *work) {
	struct dcpim_sock *dsk = container_of(work, struct dcpim_sock, receiver.token_work);
	struct sock *sk = (struct sock*)dsk;
	unsigned long matched_bw;
	unsigned long token_bytes;
	ktime_t time_delta;
	int rtx_bytes = 0;		
	lock_sock(sk);
	// sk->sk_max_pacing_rate = 3062500000;
	matched_bw = atomic64_read(&dsk->receiver.pacing_rate);
	time_delta = ktime_get() - dsk->receiver.latest_token_sent_time;
	if(sk->sk_state != DCPIM_ESTABLISHED)
		goto release_sock;
	if(matched_bw == 0)
		goto release_sock;
	dsk->receiver.max_congestion_win = dcpim_params.bdp / (dcpim_params.bandwidth * 1000000000 / 8 / matched_bw);
	token_bytes = dcpim_avail_token_space((struct sock*)dsk);
	/* perform retransmission */
	if(atomic_read(&dsk->receiver.rtx_status) == 1) {
		/* avoid retransmission because user doesn't call recvmsg() for a long time */
		if(dsk->receiver.rtx_rcv_nxt == dsk->receiver.rcv_nxt && (int)(dsk->receiver.rcv_nxt - dsk->receiver.copied_seq) <  READ_ONCE(sk->sk_rcvbuf) / 2) {
			// printk("port: %d perform retransmission dsk->receiver.rcv_nxt: %u dsk->receiver.token_nxt: %u max_congestion_win: %u token_bytes: %lu \n", ntohs(inet_sk(sk)->inet_sport), 
			// 	dsk->receiver.rcv_nxt, dsk->receiver.token_nxt, dsk->receiver.max_congestion_win, token_bytes);
			// printk("dcpim_space: %u dcpim_congestion_space: %u atomic_read(&sk->sk_rmem_alloc): %u atomic_read(&dsk->receiver.backlog_len): %u", dcpim_space(sk), dcpim_congestion_space(sk),
			// 	atomic_read(&sk->sk_rmem_alloc), atomic_read(&dsk->receiver.backlog_len));
			// printk("epoch:%llu value: %u %u \n", dcpim_epoch.epoch, dsk->receiver.rtx_rcv_nxt, dsk->receiver.rcv_nxt);
			dcpim_xmit_control(construct_rtx_token_pkt((struct sock*)dsk, 3, dsk->receiver.token_nxt, dsk->receiver.token_nxt, &rtx_bytes), sk);
		} 
		atomic_set(&dsk->receiver.rtx_status, 0);
		dsk->receiver.rtx_rcv_nxt = dsk->receiver.rcv_nxt;
	}
	
	/* perfrom transmission */
	if(token_bytes == 0) {
		/* transmit ack packet to clean up the sender side buffer in case we don't send token */
		dcpim_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk); 
		goto release_sock;
	}
	/* allow window one token_batch larger than the window */
	if(token_bytes < dsk->receiver.token_batch)
		token_bytes = dsk->receiver.token_batch;
	// tx_time = ns_to_ktime(token_bytes * 1000000000 / matched_bw);
	// if(time_delta < tx_time) {
	// 	if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
	// 		hrtimer_start(&dsk->receiver.token_pace_timer,
	// 			tx_time - time_delta, HRTIMER_MODE_REL_PINNED_SOFT);
	// 	}
	// 	goto release_sock;
	// }
	token_bytes = dcpim_xmit_token(dsk, token_bytes);
	/* set lastst_token_sent_time to the current time */
	dsk->receiver.latest_token_sent_time += time_delta;
	// printk("defer token_bytes:%u %u\n", token_bytes, dsk->receiver.token_nxt);
	if(!hrtimer_is_queued(&dsk->receiver.token_pace_timer)) {
		hrtimer_start(&dsk->receiver.token_pace_timer, ns_to_ktime(token_bytes * 1000000000 / matched_bw), HRTIMER_MODE_REL_PINNED_SOFT);
	}
release_sock:
	sock_put(sk);
	atomic_set(&dsk->receiver.token_work_status, 0);
	release_sock(sk);
	return;
}

/* hrtimer may fire twice for some reaons; need to check what happens later. */
enum hrtimer_restart dcpim_rtx_sync_timer_handler(struct hrtimer *timer) {

	struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, sender.rtx_flow_sync_timer);
	struct sock* sk = (struct sock *)dsk;
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		if(!dsk->sender.syn_ack_recvd) {
			/* maximum retried times = 5 */
			if(dsk->sender.sync_sent_times >= 10) {
				dcpim_set_state(sk, DCPIM_CLOSE);
				/* TO DO: might need to wake up socket */
			} else {
				/*  retransmit flow sync */
				if(sk->sk_priority != 7) {
					dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_LONG), sk); 
				} else {
					/* to do: add short flow syn retransmission */
					dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_SHORT), sk); 
				}
				dsk->sender.sync_sent_times += 1;
				hrtimer_forward_now(timer, ns_to_ktime(1000000));
				bh_unlock_sock(sk);
				return HRTIMER_RESTART;
			}
		} 
	} else {
		/* delegate our work to dcpim_release_cb() */
		if (!test_and_set_bit(DCPIM_RTX_FLOW_SYNC_DEFERRED, &sk->sk_tsq_flags)) {
			sock_hold(sk);
		}
	}
	bh_unlock_sock(sk);
	// sock_put(sk);
	return HRTIMER_NORESTART;
}

void dcpim_rtx_sync_handler(struct dcpim_sock *dsk) {

	struct sock* sk = (struct sock *)dsk;
	if(!dsk->sender.syn_ack_recvd) {
	/*  retransmit flow sync */
		if(dsk->sender.sync_sent_times >= 10) {
				dcpim_set_state(sk, DCPIM_CLOSE);
				/* TO DO: might need to wake up socket */
		}  else {
			if(sk->sk_priority != 7) {
				dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_LONG), sk); 
			} else {
				/* to do: add short flow syn retransmission */
				dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_SHORT), sk); 
			}
			dsk->sender.sync_sent_times += 1;
			hrtimer_start(&dsk->sender.rtx_flow_sync_timer, ns_to_ktime(1000000), HRTIMER_MODE_REL_PINNED_SOFT);
		}
	} 
	return;
}

void rtx_fin_handler(struct work_struct *work) {
	struct dcpim_sock *dsk = container_of(work, struct dcpim_sock, rtx_fin_work);
	struct sock* sk = (struct sock*)dsk;
	bool need_put = false;
	lock_sock(sk);
	if(!dsk->delay_destruct || dsk->fin_sent_times >= 5) {
		need_put = true;
		goto put_sock;
	} 
	dcpim_xmit_control(construct_fin_pkt(sk), sk); 
	dsk->fin_sent_times += 1;
	hrtimer_start(&dsk->rtx_fin_timer, ns_to_ktime(dcpim_params.rtt * 1000), HRTIMER_MODE_REL_PINNED_SOFT);
put_sock:
	if(need_put) {
		sk->sk_prot->unhash(sk);
		/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
		if (inet_csk(sk)->icsk_bind_hash) {
			inet_put_port(sk);
		} 
		sock_put(sk);
	}
	release_sock(sk);
}

void dcpim_rtx_msg_handler(struct work_struct *work) {
	struct dcpim_sock *dsk = container_of(work, struct dcpim_sock, sender.rtx_msg_work);
	struct sock* sk = (struct sock*)dsk;
	struct list_head *list, *temp;
	struct dcpim_message *msg;
	int num_rtx_msgs = 0;
	bool rtx = false, remove_message = false, established;
	int tx_size, total_tx_size = atomic_read(&dsk->sender.rtx_msg_size);
	ktime_t cur_time = ktime_get();
	if(total_tx_size == 0)
		return;
	tx_size = total_tx_size;
	lock_sock(sk);
	/* for now, only add to list if dsk is in established state. */
	established = ((struct sock*)dsk)->sk_state == DCPIM_ESTABLISHED;
	if(!established)
		goto release_sock;
	num_rtx_msgs = dsk->sender.num_rtx_msgs;
	list_for_each_safe(list, temp, &dsk->sender.rtx_msg_list) {
		rtx = false;
		remove_message = false;
		msg = list_entry(list, struct dcpim_message, table_link);
		list_del(&msg->table_link);
		dsk->sender.num_rtx_msgs -= 1;
		spin_lock_bh(&msg->lock);
		if(msg->state == DCPIM_WAIT_FOR_MATCHING) {
			/* burst packets of short flows
			* No need to hold the lock because we just initialize the message.
			* Flow sync packet currently doesn't 
			*/
			if(cur_time - msg->last_rtx_time >= msg->timeout) {
				rtx = true;
				msg->last_rtx_time = ktime_get();
			}
			list_add_tail(&msg->table_link, &dsk->sender.rtx_msg_list);
			dsk->sender.num_rtx_msgs += 1;
		} else if (msg->state == DCPIM_FINISH_TX)
			remove_message = true;
		if(rtx) {
			dcpim_xmit_control(construct_flow_sync_msg_pkt(sk, msg->id, msg->total_len, 0), sk); 
			dcpim_xmit_data_whole_message(msg, dsk);
			/* at least transmit one short mtessage */
			tx_size -= 1;
		}
		spin_unlock_bh(&msg->lock);
		if(remove_message){
			// dcpim_remove_message(dcpim_tx_messages, msg);
			/* Give one channel to retransmitted messages at a time until it is finished */
			atomic_sub(dcpim_epoch.epoch_bytes_per_k, &msg->dsk->host->total_unsent_bytes);
			atomic_sub(1, &msg->dsk->host->rtx_msg_size);
			dcpim_message_put(msg);
		}
		num_rtx_msgs -= 1;
		if(num_rtx_msgs == 0 || tx_size <= 0)
			break;
	}
release_sock:
	/* reduce the tx_size regardless */
	atomic_sub(1, &dsk->sender.rtx_msg_size);
	release_sock(sk);

	return;
}

/* hrtimer may fire twice for some reaons; need to check what happens later. */
enum hrtimer_restart dcpim_rtx_fin_timer_handler(struct hrtimer *timer) {

	struct dcpim_sock *dsk = container_of(timer, struct dcpim_sock, rtx_fin_timer);
	queue_work_on(raw_smp_processor_id(), dcpim_wq, &dsk->rtx_fin_work);
	return HRTIMER_NORESTART;
}

enum hrtimer_restart dcpim_rtx_msg_timer_handler(struct hrtimer *timer) {

	struct dcpim_message *msg = container_of(timer, struct dcpim_message, rtx_timer);
	// struct sk_buff* fin_skb = NULL;
	struct sock* sk = (struct sock*)(msg->dsk);
	struct dcpim_sock* dsk = NULL;
	bool remove_msg = false;
	if(sk != NULL)
		dsk = dcpim_sk(sk);
	spin_lock(&msg->lock);
	// if(msg->state == DCPIM_WAIT_ACK) {
	// 	fin_skb = dcpim_message_get_fin(msg);
	// 	spin_unlock(&msg->lock);
	// 	if(dev_queue_xmit(fin_skb)) {
	// 		WARN_ON_ONCE(true);
	// 	}
	// 	hrtimer_forward_now(timer, msg->timeout);
	// 	return HRTIMER_RESTART;
	// } else
	 if (msg->state == DCPIM_WAIT_FIN_TX) {
		msg->state = DCPIM_WAIT_FOR_MATCHING;
		spin_unlock(&msg->lock);
		bh_lock_sock(sk);
		/* for now, only retransmit if the socket is still in established state */
		if(!sock_owned_by_user(sk)) {
			if(sk->sk_state == DCPIM_ESTABLISHED) {
				/* add msg_list to the head of rtx_msg_list */
				list_add(&msg->table_link, &dsk->sender.rtx_msg_list);
				dcpim_message_hold(msg);
				dsk->sender.num_rtx_msgs += 1;
				/* Give one message one channel for doing rtx at one epoch */
				atomic_add(dcpim_epoch.epoch_bytes_per_k, &msg->dsk->host->total_unsent_bytes);
				atomic_add(1, &msg->dsk->host->rtx_msg_size);
				/* wake up socket and participate matcihing for retransmssion */
				// queue_work_on(raw_smp_processor_id(), dcpim_wq, &dsk->rtx_msg_work);
			} else
				remove_msg = true;
		} else {
			list_add_tail(&msg->table_link, &dsk->sender.rtx_msg_backlog);
			dcpim_message_hold(msg);
			if (!test_and_set_bit(DCPIM_MSG_RTX_DEFERRED, &sk->sk_tsq_flags)) {
				sock_hold(sk);
			}
		}
		bh_unlock_sock(sk);
		if(remove_msg) {
			spin_lock(&msg->lock);
			dcpim_message_flush_skb(msg);
			spin_unlock(&msg->lock);
			/* inside the timer, avoid calling hrtimer_cancel */
			dcpim_remove_message(dcpim_tx_messages, msg, false);
		}
		// dcpim_message_put(msg);
		return HRTIMER_NORESTART;
	} else if (msg->state == DCPIM_WAIT_FIN_RX || msg->state == DCPIM_INIT)
		WARN_ON(true);
	spin_unlock(&msg->lock);
	// dcpim_message_put(msg);
	return HRTIMER_NORESTART;
}

enum hrtimer_restart dcpim_fast_rtx_msg_timer_handler(struct hrtimer *timer) {

	struct dcpim_message *msg = container_of(timer, struct dcpim_message, fast_rtx_timer);
	// struct sk_buff* fin_skb = NULL;
	struct sock* sk = (struct sock*)(msg->dsk);
	dcpim_xmit_control(construct_resync_msg_pkt(sk, msg->id), sk);
	// dcpim_message_put(msg);
	return HRTIMER_NORESTART;
}

void dcpim_msg_fin_rx_bg_handler(struct dcpim_sock *dsk) {
	struct list_head *list, *temp;
	struct dcpim_message *msg;
	/* for now, only add to list if dsk is in established state. */
	bool established = ((struct sock*)dsk)->sk_state == DCPIM_ESTABLISHED;
	list_for_each_safe(list, temp, &dsk->receiver.msg_backlog) {
		msg = list_entry(list, struct dcpim_message, table_link);
		list_del(&msg->table_link);
		if(established) {
			/* construct the fin */
			dsk->receiver.num_msgs += 1;
			list_add_tail(&msg->table_link, &dsk->receiver.msg_list);
			((struct sock*)dsk)->sk_data_ready(((struct sock*)dsk));
			dcpim_message_hold(msg);
		}
		dcpim_xmit_control(construct_fin_msg_pkt(((struct sock*)dsk), msg->id), ((struct sock*)dsk));
		dcpim_message_put(msg);
	}
}

void dcpim_msg_fin_tx_bg_handler(struct dcpim_sock *dsk) {
	struct list_head *list, *temp;
	struct dcpim_message *msg;
	struct sock *sk = (struct sock*)dsk;
	/* for now, only add to list if dsk is in established state. */
	// bool established = ((struct sock*)dsk)->sk_state == DCPIM_ESTABLISHED;
	list_for_each_safe(list, temp, &dsk->sender.fin_msg_backlog) {
		msg = list_entry(list, struct dcpim_message, fin_link);
		list_del(&msg->fin_link);
		// if(established) {
		dsk->sender.inflight_msgs -= 1;
		spin_lock(&msg->lock);
		dcpim_message_flush_skb(msg);
		spin_unlock(&msg->lock);
		if (sk->sk_socket && test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) && dsk->sender.inflight_msgs + dsk->sender.accmu_rx_msgs <= dsk->sender.msg_threshold) {
			sk_stream_write_space(sk);
		}
		// sk_stream_write_space((struct sock*)dsk);
		// }
		dcpim_message_put(msg);
	}
}

void dcpim_msg_rtx_bg_handler(struct dcpim_sock *dsk) {
	struct list_head *list, *temp;
	struct dcpim_message *msg;
	/* for now, only add to list if dsk is in established state. */
	bool established = ((struct sock*)dsk)->sk_state == DCPIM_ESTABLISHED;
	list_for_each_safe(list, temp, &dsk->sender.rtx_msg_backlog) {
		msg = list_entry(list, struct dcpim_message, table_link);
		list_del(&msg->table_link);
		if(established) {
			/* add to the head of rtx_msg_list */
			list_add(&msg->table_link, &dsk->sender.rtx_msg_list);
			dsk->sender.num_rtx_msgs += 1;
			/* add to total unsent bytes */
			atomic_add(dcpim_epoch.epoch_bytes_per_k, &msg->dsk->host->total_unsent_bytes);
			atomic_add(1, &msg->dsk->host->rtx_msg_size);
		}
		else {
			/* remove message since the socket is closed */
			spin_lock_bh(&msg->lock);
			dcpim_message_flush_skb(msg);
			spin_unlock_bh(&msg->lock);
			dcpim_remove_message(dcpim_tx_messages, msg, true);
			dcpim_message_put(msg);
		}
	}
}

