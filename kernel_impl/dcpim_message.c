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
	if(msg->id == id && msg->saddr == saddr 
		&& msg->sport == sport && msg->daddr == daddr && msg->dport == dport)
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
	/* GFP_ATOMIC may change later */
	msg = kmalloc(sizeof(struct dcpim_message), GFP_ATOMIC);
	if(msg == NULL)
		return msg;

	// WRITE_ONCE(msg->dsk, dsk);
	msg->id = id;
	msg->saddr = saddr;
	msg->sport = sport;
	msg->daddr = daddr;
	msg->dport = dport;
	if(dsk) {
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
	hrtimer_init(&msg->fast_rtx_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	msg->fast_rtx_timer.function = dcpim_fast_rtx_msg_timer_handler;
	INIT_HLIST_NODE(&msg->hash_link);
	INIT_LIST_HEAD(&msg->table_link);
	INIT_LIST_HEAD(&msg->fin_link);
	msg->fin_skb = NULL;
	msg->last_rtx_time = 0;
	/* timeout set to be epoch_length; so it will join the next round of matching at tx side */
	msg->timeout = dcpim_params.epoch_length;
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
  * dcpim_message_flush_skb() - Destroy skb in msg; Called by tx side and assume msg->lock is hold. 
  * @msg:	The dcpim_message.
  */
void dcpim_message_flush_skb(struct dcpim_message *msg) {
	struct sk_buff *skb, *n;
	// struct sock *sk = (struct sock*)(msg->dsk);
	// bool tx = false;
	// hrtimer_cancel(&msg->rtx_timer);
	// tx = (msg->state == DCPIM_WAIT_FIN_TX || msg->state == DCPIM_FIN_TX);
	skb_queue_walk_safe(&msg->pkt_queue, skb, n) {
		sk_wmem_queued_add((struct sock*)msg->dsk, -skb->truesize);
		kfree_skb(skb);
	}
	skb_queue_head_init(&msg->pkt_queue);
	return;
}

 /**
  * dcpim_message_destroy() - Destroy msg: the last fucntion of msg lifecycle.
  * @msg:	The dcpim_message that will be destroyed. 
  */
void dcpim_message_destroy(struct dcpim_message *msg) {
	struct sk_buff *skb, *n;
	struct sock *sk = (struct sock*)(msg->dsk);
	// bool tx = false;
	// hrtimer_cancel(&msg->rtx_timer);
	spin_lock_bh(&msg->lock);
	// tx = (msg->state == DCPIM_WAIT_FIN_TX || msg->state == DCPIM_FIN_TX);
	skb_queue_walk_safe(&msg->pkt_queue, skb, n) {
		kfree_skb(skb);
	}
	skb_queue_head_init(&msg->pkt_queue);
	if(msg->fin_skb) {
		kfree_skb(msg->fin_skb);
		msg->fin_skb = NULL;
	}
	spin_unlock_bh(&msg->lock);
	// if(tx)
	// 	dcpim_remove_message(dcpim_tx_messages, msg);
	// else
	// 	dcpim_remove_message(dcpim_rx_messages);
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
	__skb_pull(skb, (dcpim_hdr(skb)->doff << 2)+ sizeof(struct data_segment));
	if(msg->remaining_len == 0 || DCPIM_SKB_CB(skb)->seq == DCPIM_SKB_CB(skb)->end_seq){
		WARN_ON_ONCE(true);
		kfree_skb(skb);
		goto unlock_return;
	}
	/* reverse traversing */
	skb_queue_reverse_walk_safe(&msg->pkt_queue, iter, tmp) {
		if (after(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(iter)->end_seq)) {
			if(!after(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* iter is covered by skb; remove it */
				msg->remaining_len += DCPIM_SKB_CB(iter)->end_seq - DCPIM_SKB_CB(iter)->seq;
				kfree_skb(iter);
				continue;
			}
			if(before(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->end_seq) && 
				after(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* shrink skb as needed */
				pskb_may_pull(skb, DCPIM_SKB_CB(iter)->end_seq - DCPIM_SKB_CB(skb)->seq);
				__skb_pull(skb, DCPIM_SKB_CB(iter)->end_seq - DCPIM_SKB_CB(skb)->seq);
				DCPIM_SKB_CB(skb)->seq = DCPIM_SKB_CB(iter)->end_seq;
			} 
			__skb_queue_after(&msg->pkt_queue, iter, skb);
			is_insert = true;
			msg->remaining_len -= DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(skb)->seq;
			break;
		} else {
			if(!before(DCPIM_SKB_CB(skb)->seq, DCPIM_SKB_CB(iter)->seq)) {
				/* skb is covered by iter; remove it */
				kfree_skb(skb);
				skb = NULL;
				break;
			} else {
				if(after(DCPIM_SKB_CB(skb)->end_seq, DCPIM_SKB_CB(iter)->seq)) {
					/* pull iter due to overlapping */
					pskb_may_pull(iter, DCPIM_SKB_CB(skb)->end_seq - DCPIM_SKB_CB(iter)->seq);
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

/**
 * dcpim_hlist_move_list - Move an hlist
 * @old: hlist_head for old list.
 * @new: hlist_head for new list.
 *
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void dcpim_hlist_move_list(struct hlist_head *old,
				   struct hlist_head *new)
{
	new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	/* the hlist_move_tail doesn't use write once. */
	WRITE_ONCE(old->first, NULL);
}

/**
 * dcpim_message_table_destroy() - Destructor for dcpim_message_table.
 */
void dcpim_message_table_destroy(void) {
	int i = 0;
	struct dcpim_message *msg;
	struct hlist_node *next;
	struct dcpim_message_bucket* message_table_tmp = kzalloc(sizeof(struct dcpim_message_bucket) * DCPIM_BUCKETS, GFP_KERNEL);
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		struct dcpim_message_bucket *bucket = &dcpim_tx_messages[i];
		INIT_HLIST_HEAD(&message_table_tmp[i].slot);
		spin_lock_bh(&bucket->lock);
		dcpim_hlist_move_list(&bucket->slot, &message_table_tmp[i].slot);
		spin_unlock_bh(&bucket->lock);
	}
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		hlist_for_each_entry_safe(msg, next, &message_table_tmp[i].slot, hash_link) {
			hlist_del_init(&msg->hash_link);
			dcpim_message_put(msg);
		}
	}
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		struct dcpim_message_bucket *bucket = &dcpim_rx_messages[i];
		INIT_HLIST_HEAD(&message_table_tmp[i].slot);
		spin_lock_bh(&bucket->lock);
		dcpim_hlist_move_list(&bucket->slot, &message_table_tmp[i].slot);
		spin_unlock_bh(&bucket->lock);
	}
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		hlist_for_each_entry_safe(msg, next, &message_table_tmp[i].slot, hash_link) {
			hlist_del_init(&msg->hash_link);
			dcpim_message_put(msg);
		}
	}
	kfree(message_table_tmp);

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
	spin_lock(&hashinfo[slot].lock);
	hlist_for_each_entry(msg, &head->slot, hash_link) {
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
	spin_unlock(&hashinfo[slot].lock);
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
	hlist_for_each_entry(iter, &head->slot, hash_link) {
		if (iter->hash != msg->hash)
			continue;
		if (likely(dcpim_message_match(iter, msg->saddr, msg->sport, msg->daddr, msg->dport, msg->id))) {
			spin_unlock(lock);
			return false;
		}
	}
	hlist_add_head(&msg->hash_link, &head->slot);
	spin_unlock(lock);
	return true;
}

/* remove message from hash table and also cancenl the hrtimer; The message is done in the transport layer. */
void dcpim_remove_message(struct dcpim_message_bucket *hashinfo, struct dcpim_message *msg, bool cancel_timer)
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
	hlist_del_init(&msg->hash_link);
	spin_unlock(lock);
	/* remove hrtimer */
	if(cancel_timer) {
		hrtimer_cancel(&msg->rtx_timer);
		hrtimer_cancel(&msg->fast_rtx_timer);
	}
	/* need to sync for deletion */
	dcpim_message_put(msg);
	return;
}


 /**
 * dcpim_message_get_fin() - Assume the spin_lock is hold by the caller.
 * @msg:	The dcpim_message. 
 */
// struct sk_buff* dcpim_message_get_fin(struct dcpim_message *msg) {

// 	struct sk_buff *skb = NULL;
// 	if(msg->fin_skb) {
// 		if (unlikely(skb_cloned(msg->fin_skb))) 
// 			skb = pskb_copy(msg->fin_skb,  GFP_ATOMIC);
// 		else
// 			skb = skb_clone(msg->fin_skb, GFP_ATOMIC);
// 	}
// 	return skb;
// }
