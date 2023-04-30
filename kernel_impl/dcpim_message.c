// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		DATACENTER ADMISSION CONTROL PROTOCOL(DCPIM) 
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 */
#define pr_fmt(fmt) "DCPIM: " fmt

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
#include "dcpim_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_dcpim.h"
 #include "net_dcpim.h"
// #include "net_dcpimlite.h"
#include "uapi_linux_dcpim.h"
#include "dcpim_impl.h"

static inline bool before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)

/**
 * dcpim_hash_slot() - Hash function for five tuples + message ID.
 * @hash:   hash being looked up.
 *
 * Return:  The index of the bucket in which this hash will be found (if
 *          it exists.
 */
static inline int dcpim_hash_slot(uint32_t hash)
{
        /* We can use a really simple hash function here because client
         * port numbers are allocated sequentially and server port numbers
         * are unpredictable.
         */
        return hash & (DCPIM_BUCKETS - 1);
}

/* laddr, lport: src address and src port. faddr, fport: dst address and dst port. */
unsigned int dcpim_message_hash(__be32 laddr, __u16 lport,
		__be32 faddr, __be16 fport, uint64_t id)
{
	return jhash_3words((__force __u32) (laddr + (id >> 32)),
			    (__force __u32) (faddr + (id & 0xffffffff)) ,
			    ((__u32) lport) << 16 | (__force __u32)fport, 0);
}

static inline bool dcpim_message_match(struct dcpim_message* msg, __be32 saddr, __u16 sport,
		__be32 daddr, __be16 dport, uint64_t id)
{
	struct sock* sk = (struct sock*)msg->dsk;
	if(msg->id == id && sk->sk_rcv_saddr == saddr 
		&& sk->sk_num == sport && sk->sk_daddr == daddr && sk->sk_dport == dport)
		return true;
	return false;
}
/**
 * dcpim_message_new() - Constructor for dcpim_message.
 * @dsk:		  The corresponding dcpim sock that creates/receives the message.
 * @id:       	  ID of message.
 * @length:       Total number of bytes in message.
 */

struct dcpim_message* dcpim_message_new(struct dcpim_sock* dsk, 
			__be32 saddr, __be16 sport, __be32 daddr,  u16 dport,
			uint64_t id,  uint32_t length) {

	struct dcpim_message* msg = NULL;
	struct sock* sk = (struct sock*)dsk;
	msg = kmalloc(sizeof(struct dcpim_message), GFP_KERNEL);
	if(msg == NULL)
		return msg;

	// WRITE_ONCE(msg->dsk, dsk);
	msg->id = id;
	msg->saddr = saddr;
	msg->sport = sport;
	msg->daddr = daddr;
	msg->dport = dport;
	if(!dsk) {
		msg->dsk = dsk;
		sock_hold(sk);
	} else {
		msg->dsk = NULL;
	}
	msg->hash = dcpim_message_hash(saddr, sport, daddr, dport, id);
	/* For now, we initialize wait for fin, assuming we can always burst short flows. */
	msg->state = DCPIM_INIT;
	// msg->hash = 0;
	spin_lock_init(&msg->lock);
	skb_queue_head_init(&msg->pkt_queue);
	msg->total_len = length;
	msg->remaining_len = length;
	hrtimer_init(&msg->rtx_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	msg->rtx_timer.function = dcpim_rtx_msg_timer_handler;
	INIT_HLIST_NODE(&msg->hash_link);
	INIT_LIST_HEAD(&msg->table_link);
	msg->fin_skb = NULL;
	/* new message will be added to the hash table later*/
	refcount_set(&msg->refcnt, 1);
	return msg;
}

 /**
 * dcpim_message_hold() - increment msg refcnt by 1.
 * @msg:	The dcpim_message. 
 */
void dcpim_message_hold(struct dcpim_message *msg) {
	if(!refcount_inc_not_zero(&msg->refcnt)) 
		WARN_ON(true);
	return;
}

 /**
 * dcpim_message_put() - decrement msg refcnt by 1.
 * @msg:	The dcpim_message. 
 */
void dcpim_message_put(struct dcpim_message *msg) {
	if(refcount_dec_and_test(&msg->refcnt)) 
		dcpim_message_destroy(msg);
	return;
}

//  /**
//  * dcpim_message_finish() - set msg to finish, remove msgs from any table, and cancel hrtimer.
//  *  @hashinfo:	msg table. 
//  *  @msg:	The dcpim_message. 
//  */
// void dcpim_message_finish(struct dcpim_message_bucket *hashinfo, struct dcpim_message *msg) {
// 	/* first cancel the timer to avoid race condition */
// 	hrtimer_cancel(&msg->rtx_timer);
// 	spin_lock_bh(&msg->lock);
// 	msg->state = DCPIM_FINISH;
// 	/* TO DO: may need to remove message from matching table depending on the old state at sender side */
// 	spin_unlock_bh(&msg->lock);
// 	dcpim_remove_message(hashinfo, msg);
// 	return;
// }

 /**
  * dcpim_message_destroy() - Destroy msg: the last fucntion of msg lifecycle.
  * @msg:	The dcpim_message that will be destroyed. 
  */
void dcpim_message_destroy(struct dcpim_message *msg) {
	struct sk_buff *skb, *n;
	struct sock *sk = (struct sock*)(msg->dsk);
	spin_lock_bh(&msg->lock);
	skb_queue_walk_safe(&msg->pkt_queue, skb, n) {
		kfree_skb(skb);
	}
	skb_queue_head_init(&msg->pkt_queue);
	if(msg->fin_skb) {
		kfree_skb(msg->fin_skb);
		msg->fin_skb = NULL;
	}
	spin_unlock_bh(&msg->lock);
	kfree(msg);
	if(sk)
		sock_put(sk);
	return;
}

 /**
  * dcpim_message_receive_data() - receive new data packets into the short message.
  * Assume bh is disabled and msg lock is hold.
  * @msg:	The dcpim_message that are receiving pkts. 
  * @skb:	The data packets
  * Return true if the message is finished.
  */
bool dcpim_message_receive_data(struct dcpim_message *msg, struct sk_buff *skb) {
	struct sk_buff *iter, *tmp;
	bool is_insert = false, is_complete = false;
	__skb_pull(skb, (dcpim_hdr(skb)->doff >> 2)+ sizeof(struct data_segment));
	if(msg->remaining_len == 0){
		kfree_skb(skb);
		goto unlock_return;
	}
	/* reverse traversing */
	skb_queue_reverse_walk_safe(&msg->pkt_queue, iter, tmp) {
		if (after(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(iter)->end_seq)) {
			if(before(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* iter is covered by skb; remove it */
				msg->remaining_len += DCPIM_SKB_CB(iter)->end_seq - DCPIM_SKB_CB(iter)->seq;
				kfree_skb(iter);
				continue;
			}
			if(before(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->end_seq) && 
				after(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* shrink skb as needed */
				__skb_pull(skb, DCPIM_SKB_CB(iter)->end_seq - DCPIM_SKB_CB(skb)->seq);
				DCPIM_SKB_CB(skb)->seq = DCPIM_SKB_CB(iter)->end_seq;
			} 
			if(DCPIM_SKB_CB(skb)->seq == DCPIM_SKB_CB(skb)->end_seq) {
				kfree_skb(skb);
				skb = NULL;
				break;
			}
			__skb_queue_after(&msg->pkt_queue, iter, skb);
			is_insert = true;
			msg->remaining_len -= DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
			break;
		} else {
			if(after(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* skb is covered by iter; remove it */
				kfree_skb(skb);
				skb = NULL;
				break;
			} else {
				if(after(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(iter)->seq)) {
					/* pull iter due to overlapping */
					__skb_pull(iter, DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(iter)->seq);
					msg->remaining_len += DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(iter)->seq;
					DCPIM_SKB_CB(iter)->seq = DCPIM_SKB_CB(skb)->end_seq;
				}
				continue;
			}
		}
	}
	if(skb != NULL && !is_insert) {
		__skb_queue_head(&msg->pkt_queue, skb);
		msg->remaining_len -= DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
	}
	if(msg->remaining_len == 0) {
		is_complete = true;
		msg->state = DCPIM_WAIT_ACK;
	}
unlock_return:
	return is_complete;
}


 /**
  * dcpim_message_pass_to_sock() - pass the message to the socket.
  * Assume bh is disabled.
  * @msg:	The dcpim_message 
  * Return whether the message is finished or not.
  */
// void dcpim_message_pass_to_sock(struct dcpim_message *msg) {
// 	if(unlikely(msg->dsk == NULL)) {
// 		WARN_ON(true);
// 		/* find established socket */
// 		/* if no estabilied socket, find listen socket */
// 		return;
// 	}
// 	bh_lock_sock((struct sock*)msg->dsk);
// 	if(msg->dsk == DCPIM_ESTABLISHED) {
		
// 	}
// 	bh_unlock_sock((struct sock*)msg->dsk);

// }
/**
 * dcpim_message_table_init() - Constructor for dcpim_message_table.
 */
void dcpim_message_table_init(void) {
	int i = 0;
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		struct dcpim_message_bucket *bucket = &dcpim_tx_messages[i];
		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->slot);
	}
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		struct dcpim_message_bucket *bucket = &dcpim_rx_messages[i];
		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->slot);
	}
}

struct dcpim_message* dcpim_lookup_message(struct dcpim_message_bucket *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 dport,
				  const uint64_t id)
{
	struct dcpim_message *msg;

	unsigned int hash = dcpim_message_hash(saddr, sport, daddr, dport, id);
	unsigned int slot = dcpim_hash_slot(hash);
	struct dcpim_message_bucket *head = &hashinfo[slot];

	hlist_for_each_entry_rcu(msg, &head->slot, hash_link) {
		if (msg->hash != hash)
			continue;
		if (likely(dcpim_message_match(msg, saddr, sport, daddr, dport, id))) {
			if (unlikely(!refcount_inc_not_zero(&msg->refcnt)))
				goto out;
			goto found;
		}
	}
out:
	msg = NULL;
found:
	return msg;
}

bool dcpim_insert_message(struct dcpim_message_bucket *hashinfo, struct dcpim_message *msg)
{
	unsigned int slot; 
	struct dcpim_message_bucket *head;
	spinlock_t *lock;
	struct dcpim_message *iter;

	slot =  dcpim_hash_slot(msg->hash);
	head = &hashinfo[slot];
	lock = &head->lock;
	spin_lock(lock);
	if(!hlist_unhashed(&msg->hash_link)) {
		spin_unlock(lock);
		return false;
	}
	hlist_for_each_entry_rcu(iter, &head->slot, hash_link) {
		if (iter->hash != msg->hash)
			continue;
		if (likely(dcpim_message_match(iter, msg->saddr, msg->sport, msg->daddr, msg->dport, msg->id))) {
			spin_unlock(lock);
			return false;
		}
	}
	hlist_add_head_rcu(&msg->hash_link, &head->slot);
	spin_unlock(lock);
	return true;
}

void dcpim_remove_message(struct dcpim_message_bucket *hashinfo, struct dcpim_message *msg)
{
	unsigned int slot; 
	struct dcpim_message_bucket *head;
	spinlock_t *lock;

	slot =  dcpim_hash_slot(msg->hash);
	head = &hashinfo[slot];
	lock = &head->lock;
	spin_lock(lock);
	if(hlist_unhashed(&msg->hash_link)) {
		spin_unlock(lock);
		return;
	}
	hlist_del_rcu(&msg->hash_link);
	spin_unlock(lock);
	/* need to sync  for deletion */
	dcpim_message_put(msg);
	return;
}


 /**
 * dcpim_tx_msg_fin() - Assume the spin_lock is hold by the caller.
 * @msg:	The dcpim_message. 
 */
void dcpim_tx_msg_fin(struct dcpim_message *msg) {

	struct sk_buff *skb;
	if(msg->fin_skb) {
		if (unlikely(skb_cloned(msg->fin_skb))) 
			skb = pskb_copy(msg->fin_skb,  GFP_ATOMIC);
		else
			skb = skb_clone(msg->fin_skb, GFP_ATOMIC);
		if(skb) {
			if(!dev_queue_xmit(skb))
				WARN_ON(true);
		}
	}
}