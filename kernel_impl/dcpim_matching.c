#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include "dcpim_impl.h"
// static void recevier_iter_event_handler(struct work_struct *work);
// static void sender_iter_event_handler(struct work_struct *work);
// __u64 js, je;

struct dcpim_sock* fake_sk;

u32 dcpim_host_hash(struct dcpim_host *host) {
	return hash_64(((u64)(host->src_ip) << 32) + (u64)(host->dst_ip), DCPIM_MATCH_DEFAULT_HOST_BITS);
}
void dcpim_host_init(struct dcpim_host *host) {
	host->src_ip = 0;
	host->dst_ip = 0;
	spin_lock_init(&host->lock);
	refcount_set(&host->refcnt, 1);
	INIT_LIST_HEAD(&host->flow_list);
	INIT_LIST_HEAD(&host->short_flow_list);
	atomic_set(&host->total_unsent_bytes, 0);
	atomic_set(&host->rtx_msg_bytes, 0);
	host->next_pacing_rate = 0;
	host->grant_index = -1;
	host->grant = NULL;
	host->rts_index = -1;
	host->grant = NULL;
	host->num_flows = 0;
	host->num_long_flows = 0;
	host->num_short_flows = 0;
	host->sk = NULL;
	INIT_LIST_HEAD(&host->entry);
	INIT_HLIST_NODE(&host->hlist);
}

void dcpim_host_destroy(struct dcpim_host *host) {
	WARN_ON_ONCE(!host->num_flows);
	kfree(host);
}
void dcpim_host_hold(struct dcpim_host *host) {
	refcount_inc(&host->refcnt);
}

void dcpim_host_put(struct dcpim_host *host) {
	if (refcount_dec_and_test(&host->refcnt))
		dcpim_host_destroy(host);
}

/* Responsible for inc refcnt of socket and dcpim_host */
void dcpim_host_add_sock(struct dcpim_host *host, struct sock *sk) {
	spin_lock_bh(&host->lock);
	WARN_ON(dcpim_sk(sk)->in_host_table);
	dcpim_sk(sk)->in_host_table = true;
	dcpim_sk(sk)->host = host;
	sock_hold(sk);
	dcpim_host_hold(host);
	if(sk->sk_priority != 7) {
		list_add_tail_rcu(&dcpim_sk(sk)->entry, &host->flow_list);
		host->num_long_flows += 1;
	}
	else {
		list_add_tail_rcu(&dcpim_sk(sk)->entry, &host->short_flow_list);
		host->num_short_flows += 1;
	}
	host->num_flows += 1;
	if(!host->sk)
		host->sk = sk;
	spin_unlock_bh(&host->lock);
}

/* Caller is responsible for dec refcnt of socket and dcpim_host ;
 * Return true if the calller need to decrement the count.
 */
bool dcpim_host_delete_sock(struct dcpim_host *host, struct sock *sk) {
	bool in_host_table = false;
	spin_lock_bh(&host->lock);
	if(dcpim_sk(sk)->in_host_table) {
		list_del_rcu(&dcpim_sk(sk)->entry);
		dcpim_sk(sk)->host = NULL;
		dcpim_sk(sk)->in_host_table = false;
		host->num_flows -= 1;
		if(sk->sk_priority != 7) {
			host->num_long_flows -= 1;
		} else
			host->num_short_flows -= 1;
		if(host->sk == sk) {
			host->sk = NULL;
			if(host->num_flows > 0) {
				if(!list_empty(&host->flow_list))
					host->sk = (struct sock*)list_first_entry(&host->flow_list, struct dcpim_sock, entry);
				else if(!list_empty(&host->short_flow_list))
					host->sk = (struct sock*)list_first_entry(&host->short_flow_list, struct dcpim_sock, entry);
				else
					WARN_ON(true);
			}
		}
		spin_unlock_bh(&host->lock);
		in_host_table = true;
	} else {
		spin_unlock_bh(&host->lock);
	}
	return in_host_table;
}

/* find dcpim_host in the hash table; also increment the refcnt of dcpim_host */
struct dcpim_host* dcpim_host_find_rcu(struct dcpim_epoch *epoch, __be32 src_ip, __be32 dst_ip) {
	struct dcpim_host *host;
	bool found = false;
	u32 key = hash_64(((u64)(src_ip) << 32)+ (u64)(dst_ip), DCPIM_MATCH_DEFAULT_HOST_BITS);
	rcu_read_lock();
	hash_for_each_possible_rcu(epoch->host_table, host, hlist, key) {
		if (host->src_ip == src_ip && host->dst_ip == dst_ip) {
			found = true;
			dcpim_host_hold(host);
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		host = NULL;
	return host;
}

/* Add to tx hash table and the link list;
 * The caller should hold corresponding epoch table lock.
 */
void dcpim_host_add(struct dcpim_epoch *epoch, struct dcpim_host* host) {
	hash_add_rcu(epoch->host_table, &host->hlist, host->hash);
	list_add_tail_rcu(&host->entry, &epoch->host_list);
}

/* Delete from tx hash table and link list;
 * The caller should hold corresponding epoch table lock.
 */
void dcpim_host_delete(struct dcpim_host* host) {
	hash_del_rcu( &host->hlist);
	list_del_rcu(&host->entry);
}

void dcpim_add_mat_tab(struct dcpim_epoch *epoch, struct sock *sk) {
	struct dcpim_host *host;
	struct inet_sock *inet = inet_sk(sk);
	spin_lock_bh(&epoch->table_lock);
	host = dcpim_host_find_rcu(epoch, inet->inet_saddr, inet->inet_daddr);
	if(!host) {
		host = kzalloc(sizeof(struct dcpim_host), GFP_KERNEL);
		dcpim_host_init(host);
		host->src_ip = inet->inet_saddr;
		host->dst_ip = inet->inet_daddr;
		host->hash = dcpim_host_hash(host);
		/* add to epoch host table */
		dcpim_host_add(epoch, host);
		/* find rcu will increment the refcnt of dcpim_host */
		dcpim_host_hold(host);
	}
	dcpim_host_add_sock(host, sk);
	/* dec refcnt due to find_rcu */
	dcpim_host_put(host);
	spin_unlock_bh(&epoch->table_lock);
}

void dcpim_remove_mat_tab(struct dcpim_epoch *epoch, struct sock *sk) {
	bool in_host_table = false, remove_host = false;
	struct dcpim_host *host;
	struct inet_sock *inet = inet_sk(sk);

	/* The current way is simple for handling race condition, but not vey efficient; */
	spin_lock_bh(&epoch->table_lock);
	host = dcpim_host_find_rcu(epoch, inet->inet_saddr, inet->inet_daddr);
	if(host) {
		in_host_table = dcpim_host_delete_sock(host, sk);
		if(in_host_table) {
			/* remove the host if the flow list is empty */
			if(host->num_flows == 0) {
				dcpim_host_delete(host);
				remove_host = true;
			}
		}
	}
	spin_unlock_bh(&epoch->table_lock);
	if(in_host_table) {
		synchronize_rcu();
		sock_put(sk);
		dcpim_host_put(host);
	}
	if(remove_host) {
		synchronize_rcu();
		dcpim_host_put(host);
	}
}

uint64_t test_pacing_rate = 0;
uint64_t test_count = 0;
static void dcpim_update_flows_rate(struct dcpim_epoch *epoch) {
	int i = 0, j = 0;
	int total_flows = 0;
	int total_channels, matched_channels, num_flows;
	// unsigned long max_pacing_rate = 0;
	// struct dcpim_host **temp_arr;
	struct dcpim_sock *dsk, *temp;
	struct dcpim_host *host;
	int rtx_msg_size = 0;
	struct sk_buff** temp_arr;
	// sockptr_t optval;
	struct sock *sk;
	for (i = 0; i < epoch->cur_matched_flows; i++) {
		dsk = epoch->cur_matched_arr[i];
		// if(dsk->receiver.next_pacing_rate == 0) {
			// max_pacing_rate = 0;
			WRITE_ONCE(((struct sock*)dsk)->sk_max_pacing_rate, 0);
			// if(READ_ONCE(dsk->receiver.rtx_rcv_nxt) ==  READ_ONCE(dsk->receiver.rcv_nxt)) {
			// printk("epoch:%llu set rtx status sock:%p \n", dcpim_epoch.epoch, dsk);
			/* need to check retransmission when new epoch starts */	
			atomic_cmpxchg(&dsk->receiver.rtx_status, 0, 1);
			// }
			// optval = KERNEL_SOCKPTR(&max_pacing_rate);
			// sock_setsockopt(((struct sock*)dsk)->sk_socket, SOL_SOCKET,
			// 			SO_MAX_PACING_RATE, optval, sizeof(max_pacing_rate));
			// flow->cur_matched_bytes = 0;
		// }
		sock_put((struct sock*)dsk);
	}
	spin_lock_bh(&epoch->matched_lock);
	/* get rtx msg  packets */
	rtx_msg_size = epoch->rtx_msg_size;
	temp_arr = epoch->temp_rtx_msg_array;
	epoch->temp_rtx_msg_array = epoch->rtx_msg_array;
	epoch->rtx_msg_array = temp_arr;
	epoch->rtx_msg_size = 0;
	/* perform long flow transmission */
	for (i = 0; i < epoch->next_matched_hosts; i++) {
		j = 0;
		host = epoch->next_matched_arr[i];
		// max_pacing_rate = host->next_pacing_rate; // bytes per second
		// optval = KERNEL_SOCKPTR(&max_pacing_rate);
		if(host->next_pacing_rate == 0)
			goto put_host;
		test_pacing_rate += host->next_pacing_rate;
		test_count += 1;
		total_channels = host->next_pacing_rate / epoch->rate_per_channel;
		num_flows = host->num_flows;
		if(epoch->epoch % 100000 == 0)
			printk("average pacing rate:%llu\n", test_pacing_rate / test_count);
		// if((epoch->epoch - 1) % 10000 == 0)
		// 	printk("dsk:%p, max_pacing_rate: %lu\n", dsk, max_pacing_rate);
		// WRITE_ONCE(sk->sk_max_pacing_rate, max_pacing_rate);
		// sock_setsockopt(((struct sock*)dsk)->sk_socket, SOL_SOCKET,
		// 			SO_MAX_PACING_RATE, optval, sizeof(max_pacing_rate));
		// hrtimer_start(&dsk->receiver.token_pace_timer,
		// 	0, HRTIMER_MODE_REL_PINNED_SOFT);
		// flow->cur_matched_bytes = flow->next_matched_bytes; 
		spin_lock_bh(&host->lock);
		list_for_each_entry_safe(dsk, temp, &host->flow_list, entry) {
			if(j == host->num_long_flows)
				break;
			if(total_flows >= epoch->max_array_size)
				break;
			// if(host->next_pacing_rate == 0)
			// 	break;
			if(total_channels == 0)
				break;
			if(total_channels % num_flows)
				matched_channels = total_channels / num_flows + 1;
			else
				matched_channels = total_channels / num_flows;
			// max_pacing_rate = min(epoch->max_pacing_rate_per_flow, host->next_pacing_rate);
			WRITE_ONCE(((struct sock*)dsk)->sk_max_pacing_rate, matched_channels *  epoch->rate_per_channel);
			epoch->cur_matched_arr[total_flows] = dsk;
			sock_hold((struct sock*)dsk);
			list_move_tail(&dsk->entry, &host->flow_list);
			j++;
			total_flows++;
			total_channels -= matched_channels;
			num_flows--;
			// host->next_pacing_rate -= max_pacing_rate;
		}
		spin_unlock_bh(&host->lock);
		host->next_pacing_rate = 0;
put_host:
		dcpim_host_put(host);
	}
	/* swap two arrays */
	// temp_arr = epoch->cur_matched_arr;
	// epoch->cur_matched_arr = epoch->next_matched_arr;
	// epoch->next_matched_arr = temp_arr;
	// epoch->cur_matched_hosts = epoch->next_matched_hosts;
	epoch->next_matched_hosts = 0;
	atomic_set(&epoch->unmatched_recv_bytes, epoch->epoch_bytes);
	spin_unlock_bh(&epoch->matched_lock);

	/* send rtx_msg packets for short messages */
	for(i = 0; i < rtx_msg_size; i++) {
		dev_queue_xmit(epoch->temp_rtx_msg_array[i]);
	}

	/* update the number of flows */
	epoch->cur_matched_flows = total_flows;
	/* wake up sockets in the table */
	for (i = 0; i < epoch->cur_matched_flows; i++) {
		dsk = epoch->cur_matched_arr[i];
		sk = (struct sock*)dsk;
		bh_lock_sock(sk);
		if(sk->sk_state == DCPIM_ESTABLISHED){
			if(sk->sk_priority != 7) {
				// atomic_cmpxchg(&dsk->receiver.rtx_status, 0, 1);
				if (!test_and_set_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
					sock_hold(sk);
				}
				// printk("epoch:%llu set rtx flags sock: %p \n", dcpim_epoch.epoch, dsk);
				if (!test_and_set_bit(DCPIM_RTX_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags)) {
					sock_hold(sk);
				}
				sk->sk_data_ready(sk);
			} 
		}
		// avg_flows += epoch->next_matched_hosts;
		// count += 1;
		// if(epoch->epoch % 1000 == 0)
		// 	printk("avg_flow: %llu %llu %llu\n", avg_flows / count, avg_flows, count);
		bh_unlock_sock(sk);
	}
	
}

static void recevier_matching_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, receiver_matching_work);
	// je = ktime_get_ns();
	// spin_lock_bh(&epoch->lock);
 	// if(dcpim_epoch.epoch % 100 == 0 && dcpim_epoch.iter == 1) {
 	// 	printk("iter:%u time diff:%llu \n", iter, je - js);
 	// }
	// if(epoch->round == 0) {
	// //	dcpim_handle_all_accepts(&dcpim_match_table, epoch); 
	// }
	dcpim_handle_all_rts(epoch);
	// spin_unlock_bh(&epoch->lock);
}

static void epoch_start_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, epoch_work);
	ktime_t now;
	s64 time;
	now = hrtimer_cb_get_time(&epoch->sender_round_timer);
	/* schedule at 100 epoch away */
	time = (ktime_to_ns(now) / epoch->epoch_length + 100) * epoch->epoch_length;
	hrtimer_start(&epoch->sender_round_timer, ktime_set(0, time), HRTIMER_MODE_ABS);
	hrtimer_start(&epoch->receiver_round_timer, ktime_set(0, time + epoch->round_length / 2), HRTIMER_MODE_ABS);
	// je = ktime_get_ns();
	// spin_lock_bh(&epoch->lock);
 	// if(dcpim_epoch.epoch % 100 == 0 && dcpim_epoch.iter == 1) {
 	// 	printk("iter:%u time diff:%llu \n", iter, je - js);
 	// }
}

static void sender_matching_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, sender_matching_work);
	// spin_lock_bh(&epoch->lock);
	if(epoch->round > 0) {
		dcpim_handle_all_grants(epoch);
	}
	// advance rounds
	WRITE_ONCE(epoch->round, READ_ONCE(epoch->round) + 1);
	if(epoch->round >= dcpim_params.num_rounds) {
		// epoch->cur_match_src_addr = epoch->match_src_addr;
		// epoch->cur_match_dst_addr = epoch->match_dst_addr;
		epoch->cur_epoch = epoch->epoch;
		WRITE_ONCE(epoch->round, 0);
		WRITE_ONCE(epoch->epoch, READ_ONCE(epoch->epoch) + 1);
		// spin_lock_bh(&epoch->sender_lock);
		WRITE_ONCE(epoch->unmatched_sent_bytes, epoch->epoch_bytes);
		// spin_unlock_bh(&epoch->sender_lock);
		// spin_lock_bh(&epoch->receiver_lock);
		/* update flow rate */
		dcpim_update_flows_rate(epoch);
		// spin_unlock_bh(&epoch->receiver_lock);
		// dcpim_epoch->min_grant = NULL;
		// dcpim_epoch->grant_size = 0;
		// list_for_each_entry_safe(grant, temp, &epoch->grants_q, list_link) {
		// 	kfree(grant);
		// }
	} 
	dcpim_send_all_rts(epoch);
	// spin_unlock_bh(&epoch->lock);
}

static void dcpim_modify_ctrl_pkt(struct sk_buff *skb, __u8 type,  __u8 round, __be64 epoch) {
	/* the packet might not be grant packet, but doesn't matter for now. */
	struct dcpim_grant_hdr *gh = dcpim_grant_hdr(skb);
	gh->common.type = type;
	gh->round =round;
	gh->epoch = epoch;
	dcpim_swap_dcpim_header(skb);
	dcpim_swap_ip_header(skb);
	dcpim_swap_eth_header(skb);
	// skb_push(skb, skb->data - skb_mac_header(skb));
}

static void dcpim_modify_ctrl_pkt_size(struct sk_buff *skb, __be32 size, bool rtx_channel) {
	struct dcpim_grant_hdr *gh = dcpim_grant_hdr(skb);
	gh->remaining_sz = size;
	gh->rtx_channel = rtx_channel;
	skb_push(skb, skb->data - skb_mac_header(skb));
}

/* Token */
enum hrtimer_restart dcpim_token_xmit_event(struct hrtimer *timer) {
	// struct dcpim_grant* grant, temp;
	// struct dcpim_epoch *epoch = container_of(timer, struct dcpim_epoch, token_xmit_timer);

	// // printk("token timer handler is called 1\n");
	// spin_lock(&epoch->lock);
	// /* reset the remaining tokens to zero */
	// // atomic_set(&epoch->remaining_tokens, 0);	
	// dcpim_xmit_token(epoch);
	// spin_unlock(&epoch->lock);

 	// queue_work(dcpim_epoch.wq, &dcpim_epoch.token_xmit_struct);
	return HRTIMER_NORESTART;

}

enum hrtimer_restart dcpim_sender_round_timer_handler(struct hrtimer *timer) {
	// struct dcpim_grant* grant, temp;
	struct dcpim_epoch *epoch = container_of(timer, struct dcpim_epoch, sender_round_timer);
	int forward_time = 0;
	/* ToDo: add record mechansim for missing timers */
	forward_time = hrtimer_forward_now(timer, ns_to_ktime(epoch->round_length));
	if(forward_time > 1) {
		epoch->round += forward_time - 1;
		if(epoch->round >= dcpim_params.num_rounds) {
			epoch->epoch += epoch->round / dcpim_params.num_rounds;
			epoch->round = epoch->round %  dcpim_params.num_rounds;
		}
	}
	// if(epoch->epoch == 0 && epoch->round == 0 && hrtimer_get_expires_tv64(timer) % epoch->epoch_length != 0) {
	// 	return 	HRTIMER_RESTART;
	// }
	queue_work_on(epoch->cpu, epoch->wq, &epoch->sender_matching_work);
 	// queue_work(dcpim_epoch.wq, &dcpim_epoch.token_xmit_struct);
	return HRTIMER_RESTART;
}

enum hrtimer_restart dcpim_receiver_round_timer_handler(struct hrtimer *timer) {
	// struct dcpim_grant* grant, temp;
	struct dcpim_epoch *epoch = container_of(timer, struct dcpim_epoch, receiver_round_timer);
	/* ToDo: add record mechansim for missing timers */
	hrtimer_forward_now(timer, ns_to_ktime(epoch->round_length));
	queue_work_on(epoch->cpu, epoch->wq, &epoch->receiver_matching_work);
 	// queue_work(dcpim_epoch.wq, &dcpim_epoch.token_xmit_struct);
	return HRTIMER_RESTART;
}

// void dcpim_match_entry_init(struct dcpim_match_entry* entry, __be32 addr, 
//  bool(*comp)(const struct list_head*, const struct list_head*)) {
// 	spin_lock_init(&entry->lock);
// 	dcpim_pq_init(&entry->pq, comp);
// 	INIT_HLIST_NODE(&entry->hash_link);
// 	INIT_LIST_HEAD(&entry->list_link);
// 	// struct dcpim_peer *peer;
// 	entry->dst_addr = addr;
// }

// void dcpim_mattab_init(struct dcpim_match_tab *table,
// 	bool(*comp)(const struct list_head*, const struct list_head*)) {
// 	int i;
// 	// int ret, opt;
// 	// struct dcpim_peer *peer;
// 	// struct inet_sock *inet;
// 	spin_lock_init(&table->lock);
// 	INIT_LIST_HEAD(&table->hash_list);

// 	table->comp = comp;
// 	printk("size of match entry: %lu\n", sizeof(struct dcpim_match_entry));
// 	table->buckets = kmalloc(sizeof(struct dcpim_match_slot) * DCPIM_BUCKETS, GFP_KERNEL);
// 	for (i = 0; i < DCPIM_BUCKETS; i++) {
// 		spin_lock_init(&table->buckets[i].lock);
// 		INIT_HLIST_HEAD(&table->buckets[i].head);
// 		table->buckets[i].count = 0;
// 	}
// 	// inet = inet_sk(table->sock->sk);
// 	// peer =  dcpim_peer_find(&dcpim_peers_table, 167772169, inet);
// 	// dcpim_xmit_control(construct_rts_pkt(table->sock->sk, 1, 2, 3), peer, table->sock->sk, 3000);

// 	return;
// }

// void dcpim_mattab_destroy(struct dcpim_match_tab *table) {
// 	int i = 0, j = 0;
// 	struct dcpim_match_slot *bucket = NULL;
// 	struct dcpim_match_entry *entry;
// 	struct hlist_node *n;
// 	printk("start to remove match table\n");
// 	for (i = 0; i < DCPIM_BUCKETS; i++) {
// 		bucket = &table->buckets[i];
// 		spin_lock_bh(&bucket->lock);
// 		for (j = 0; j < bucket->count; j++) {
// 			hlist_for_each_entry_safe(entry, n, &bucket->head, hash_link) {
// 				printk("kfree an entry\n");

// 				kfree(entry);
// 			}
// 		}
// 		spin_unlock_bh(&bucket->lock);
// 	}
// 	printk("finish remove match table\n");

// 	// sock_release(table->sock);
// 	kfree(table->buckets);
// 	return;
// }

// // lock order: bucket_lock > other two locks
// void dcpim_mattab_add_new_sock(struct dcpim_match_tab *table, struct sock* sk) {
// 	struct dcpim_sock *dsk = dcpim_sk(sk);
// 	struct inet_sock *inet = inet_sk(sk); 
// 	struct dcpim_match_slot *bucket = dcpim_match_bucket(table, inet->inet_daddr);
// 	struct dcpim_match_entry *match_entry = NULL;
// 	spin_lock_bh(&bucket->lock);
// 	hlist_for_each_entry(match_entry, &bucket->head,
// 			hash_link) {
// 		if (match_entry->dst_addr == inet->inet_daddr) {
// 			spin_lock(&match_entry->lock);
// 			dcpim_pq_push(&match_entry->pq, &dsk->match_link);
// 			spin_unlock(&match_entry->lock);
// 			spin_unlock_bh(&bucket->lock);
// 			return;
// 		}
// 		// INC_METRIC(peer_hash_links, 1);
// 	}

// 	// create new match entry
// 	match_entry = kmalloc(sizeof(struct dcpim_match_entry), GFP_KERNEL);
// 	dcpim_match_entry_init(match_entry, inet->inet_daddr, table->comp);
// 	dcpim_pq_push(&match_entry->pq, &dsk->match_link);
// 	hlist_add_head(&match_entry->hash_link, &bucket->head);
// 	bucket->count += 1;
// 	// add this entry to the hash list
// 	spin_lock(&table->lock);
// 	list_add_tail(&match_entry->list_link, &table->hash_list);
// 	spin_unlock(&table->lock);

// 	spin_unlock_bh(&bucket->lock);
// }

// void dcpim_mattab_delete_sock(struct dcpim_match_tab *table, struct sock* sk) {
// 	struct dcpim_sock *dsk = dcpim_sk(sk);
// 	struct inet_sock *inet = inet_sk(sk); 
// 	struct dcpim_match_slot *bucket = dcpim_match_bucket(table, inet->inet_daddr);
// 	struct dcpim_match_entry *match_entry = NULL;
// 	// bool empty = false;
// 	spin_lock_bh(&bucket->lock);
// 	hlist_for_each_entry(match_entry, &bucket->head,
// 			hash_link) {
// 		if (match_entry->dst_addr == inet->inet_daddr) {
// 			break;
// 		}
// 		// INC_METRIC(peer_hash_links, 1);
// 	}
// 	if(match_entry != NULL) {
// 		spin_lock(&match_entry->lock);
// 		// assume the msg still in the list, which might not be true'
// 		dcpim_pq_delete(&match_entry->pq, &dsk->match_link);
// 		spin_unlock(&match_entry->lock);
// 	}

// 	spin_unlock_bh(&bucket->lock);

// }

// void dcpim_mattab_delete_match_entry(struct dcpim_match_tab *table, struct dcpim_match_entry* entry) {
// 	return;
// }

void dcpim_epoch_init(struct dcpim_epoch *epoch) {
	// int ret;
	// ktime_t now;
	// s64 time;
	// struct inet_sock *inet;
	// struct dcpim_peer* peer;
	int i = 0;
	epoch->epoch = 0;
	epoch->round = 0;
	epoch->k = 4;
	epoch->prompt = false;
	/* hold RTS/GRANTs at most DCPIM_MAX_HOST. */
	epoch->max_array_size = DCPIM_MATCH_DEFAULT_HOST;
	// epoch->match_src_addr = 0;
	// epoch->match_dst_addr = 0;
	// epoch->matched_k = 0;
	// epoch->min_rts = NULL;
	// epoch->min_grant = NULL;
	epoch->epoch_length = dcpim_params.epoch_length;
	epoch->round_length = dcpim_params.round_length;
	epoch->epoch_bytes_per_k = epoch->epoch_length * dcpim_params.bandwidth / 8 / epoch->k;
	epoch->epoch_bytes = epoch->epoch_bytes_per_k * epoch->k;
	epoch->port = 0;
	epoch->port_range = 15;
	/* bytes per second: 5 GB/s */
	// epoch->max_pacing_rate_per_flow = 4375000000;
	epoch->rate_per_channel = dcpim_params.bandwidth * 1000000000 / 8 / epoch->k;

	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	// epoch->start_cycle = 0;
	WRITE_ONCE(epoch->unmatched_sent_bytes, epoch->epoch_bytes);
	atomic_set(&epoch->unmatched_recv_bytes, epoch->epoch_bytes);
	epoch->cur_matched_arr = kzalloc(sizeof(struct dcpim_sock*) * epoch->max_array_size, GFP_KERNEL);
	epoch->next_matched_arr = kzalloc(sizeof(struct dcpim_host*) * epoch->k, GFP_KERNEL);
	epoch->cur_matched_flows = 0;
	epoch->next_matched_hosts = 0;
	epoch->rts_array = kzalloc(sizeof(struct dcpim_rts) * epoch->max_array_size, GFP_KERNEL);
	epoch->grants_array = kzalloc(sizeof(struct dcpim_grant) * epoch->max_array_size, GFP_KERNEL);
	epoch->rts_skb_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->grant_skb_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->rtx_msg_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->temp_rtx_msg_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	// current epoch and address
	epoch->cur_epoch = 0;
	// epoch->cur_match_src_addr = 0;
	// epoch->cur_match_dst_addr = 0;
	epoch->cpu = 60;
	// ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM, &epoch->sock);
	// inet = inet_sk(epoch->sock->sk);
	// peer =  dcpim_peer_find(&dcpim_peers_table, 167772169, inet);

	// if(ret) {
	// 	printk("fail to create socket\n");
	// 	return;
	// }
	for(i = 0; i < epoch->max_array_size; i++) {
		epoch->rts_array[i].skb_arr = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
		epoch->grants_array[i].skb_arr = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	}

	spin_lock_init(&epoch->table_lock);
	spin_lock_init(&epoch->sender_lock);
	spin_lock_init(&epoch->receiver_lock);
	spin_lock_init(&epoch->matched_lock);

	epoch->rts_size = 0;
	epoch->grant_size = 0;
	epoch->rtx_msg_size = 0;
	/* token xmit timer*/
	// atomic_set(&epoch->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);

	// hrtimer_init(&epoch->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// epoch->token_xmit_timer.function = &dcpim_token_xmit_event;

	// INIT_WORK(&epoch->token_xmit_struct, dcpim_xmit_token_handler);
	/* pHost Queue */
	// dcpim_pq_init(&epoch->flow_q, flow_compare);
	INIT_LIST_HEAD(&epoch->host_list);
	hash_init(epoch->host_table);


	epoch->wq = alloc_workqueue("epoch_wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	INIT_WORK(&epoch->sender_matching_work, sender_matching_handler);
	INIT_WORK(&epoch->receiver_matching_work, recevier_matching_handler);
	INIT_WORK(&epoch->epoch_work, epoch_start_handler);
	// hrtimer_init(&epoch->epoch_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->sender_round_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->receiver_round_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	epoch->sender_round_timer.function = &dcpim_sender_round_timer_handler;
	epoch->receiver_round_timer.function = &dcpim_receiver_round_timer_handler;
	queue_work_on(epoch->cpu, epoch->wq, &epoch->epoch_work);
	// epoch->epoch_timer.function = &dcpim_new_epoch;
}

void dcpim_epoch_destroy(struct dcpim_epoch *epoch) {
	// struct socket *sk;
	// hrtimer_cancel(&epoch->epoch_timer);
	int i = 0;
	hrtimer_cancel(&epoch->sender_round_timer);
	hrtimer_cancel(&epoch->receiver_round_timer);
	flush_workqueue(epoch->wq);
	destroy_workqueue(epoch->wq);
	// spin_lock_bh(&epoch->lock);
	// // sk = epoch->sock;
	// epoch->sock = NULL;
	// spin_unlock_bh(&epoch->lock);
	for(i = 0; i < epoch->max_array_size; i++) {
		for(i = 0; i < epoch->max_array_size; i++) {
			kfree(epoch->rts_array[i].skb_arr); 
			kfree(epoch->grants_array[i].skb_arr); 
			epoch->rts_array[i].skb_arr = NULL;
			epoch->grants_array[i].skb_arr = NULL;
		}
		if(epoch->grants_array[i].host != NULL) {
			dcpim_host_put(epoch->grants_array[i].host);
			epoch->grants_array[i].host = NULL;
		}
	}

	kfree(epoch->grants_array);
	kfree(epoch->rts_array);
	epoch->grants_array = NULL;
	epoch->rts_array = NULL;
	kfree(epoch->cur_matched_arr);
	kfree(epoch->next_matched_arr);
	epoch->cur_matched_arr = NULL;
	epoch->next_matched_arr = NULL;
	kfree(epoch->grant_skb_array);
	kfree(epoch->rts_skb_array);
	epoch->grant_skb_array = NULL;
	epoch->rts_skb_array = NULL;

	kfree(epoch->rtx_msg_array);
	epoch->rtx_msg_array = NULL;
	kfree(epoch->temp_rtx_msg_array);
	epoch->temp_rtx_msg_array = NULL;
	/* dcpim_destroy_sock needs to hold the epoch lock */
    // sock_release(sk);

}
// static struct dcpim_flow* dcpim_find_flow(struct dcpim_epoch* epoch, __be32 src_addr, __be32 dst_addr, __be16 src_port, __be16 dst_port) {
// 	struct dcpim_flow *ftemp;
// 	struct inet_sock *inet;
// 	rcu_read_lock();
// 	list_for_each_entry_rcu(ftemp, &epoch->flow_list, entry) {
// 			inet = inet_sk(ftemp->sock);
// 			if(inet->inet_saddr == src_addr && inet->inet_daddr == dst_addr &&
// 				inet->inet_sport == src_port && inet->inet_dport == dst_port) {
// 				rcu_read_unlock();
// 				return ftemp;
// 			}
// 	}
// 	rcu_read_unlock();
// 	return NULL;

// }
void dcpim_send_all_rts (struct dcpim_epoch* epoch) {
	// struct dcpim_match_entry *entry = NULL;
 	// struct dcpim_peer *peer;
	// struct inet_sock *inet;
	// struct sk_buff* pkt;
	// struct dcpim_flow *ftemp;
	// struct tcp_sock* tsk;
	struct dcpim_host *host;
	int flow_size, rts_size, rtx_size , i;
	struct sk_buff *skb;
	struct inet_sock *inet;
	int err = 0;
	bool rtx_channel = false;
	// spin_lock(&table->lock);
	// list_for_each_entry(entry, &table->hash_list, list_link) {
	// 	struct list_head *list_head = NULL;
	// 	struct dcpim_sock *dsk = NULL;
	// 	spin_lock(&entry->lock);
	// 	list_head = dcpim_pq_peek(&entry->pq);
	// 	if(list_head != NULL) {
			// don't need to hold dsk lock, beacuase holding the priority lock
			// dsk = list_entry(list_head, struct dcpim_sock, match_link);
			// send rts

		// }
		// spin_unlock(&entry->lock);
	// }
	spin_lock_bh(&epoch->sender_lock);
	if(epoch->unmatched_sent_bytes > 0) {
		rcu_read_lock();
		list_for_each_entry_rcu(host, &epoch->host_list, entry) {
			spin_lock_bh(&host->lock);
			rtx_size = atomic_read(&host->rtx_msg_bytes);
			flow_size = min(epoch->unmatched_sent_bytes, atomic_read(&host->total_unsent_bytes));
			// if(READ_ONCE(epoch->round) == 0)
			//      atomic_set(&(dcpim_sk)(ftemp->sock)->sender.matched, 0);
			// /* the flow has already been matched */
			// if(READ_ONCE(epoch->round) != 0 && atomic_read(&(dcpim_sk)(ftemp->sock)->sender.matched))
			//      continue;
			if(flow_size > 0 && host->sk == NULL)
				WARN_ON_ONCE(true);
			if(flow_size > 0 && host->sk != NULL) {
				for(i = 0; i < epoch->k; i++) {
					rtx_channel = false;
					rts_size = min(epoch->epoch_bytes_per_k, flow_size);
					if(rtx_size > 0) {
						rtx_channel = true;
						rtx_size -= rts_size;
					}
					inet = inet_sk(host->sk);
					skb = construct_rts_pkt(host->sk, epoch->round, epoch->epoch, epoch->epoch_bytes_per_k, rtx_channel);
					dcpim_fill_dcpim_header(skb, htons(epoch->port), htons(epoch->port));
					dcpim_fill_dst_entry(host->sk, skb,&inet->cork.fl);
					dcpim_fill_ip_header(skb, host->src_ip, host->dst_ip);
					err = ip_local_out(sock_net(host->sk), host->sk, skb);
					if(unlikely(err > 0)) {
							// WARN_ON(true);
							// kfree_skb(skb);
						printk("local out fails: %d\n", err);
						// net_xmit_eval(err);
					}
					flow_size -= rts_size;
					if(flow_size <= 0)
							break;
					epoch->port = (epoch->port + 1) % epoch->port_range;
				}
					// __ip_queue_xmit(ftemp->sock, skb, &inet->cork.fl, IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL);
			}
			spin_unlock_bh(&host->lock);
		}
		rcu_read_unlock();
	}
	spin_unlock_bh(&epoch->sender_lock);

	// if(epoch->sock != NULL) {
	// 	inet = inet_sk(epoch->sock->sk);
	// 	// printk("inet is null: %d\n", inet == NULL);
	// 	peer =  dcpim_peer_find(&dcpim_peers_table, 167772169, inet);
	// 	pkt = construct_rts_pkt(epoch->sock->sk, epoch->iter, epoch->epoch, 3);
	// 	dcpim_xmit_control(pkt, peer, epoch->sock->sk, 3000);

	// }


// 	spin_unlock(&table->lock);

}

int dcpim_handle_rts (struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct dcpim_rts_hdr *rh;
	struct iphdr *iph;
	// struct sock* sk;
	struct dcpim_rts *rts;
	struct dcpim_host *host;
	// bool refcounted = false;
	// int sdif = inet_sdif(skb);
	int rts_index;
	struct sk_buff *temp = NULL;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_rts_hdr)))
		goto drop;		/* No space for header. */
	// spin_lock_bh(&epoch->lock);
	// if(epoch->sock == NULL) {
		// spin_unlock_bh(&epoch->lock);
		// goto drop;
	// }
	rh = dcpim_rts_hdr(skb);
	if(rh->remaining_sz == 0)
		goto drop;
	iph = ip_hdr(skb);
	/* TO DO: check round number and epoch number */
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&rh->common), rh->common.source,
    //         rh->common.dest, sdif, &refcounted);
	if(!host)
		goto drop;
	// if(!sk)
	// 	goto drop;
	// if (READ_ONCE(dcpim_sk(sk)->receiver.next_pacing_rate) > 0) {
	// 	kfree_skb(skb);
	// 	goto put_sock;
	// }
	spin_lock(&epoch->receiver_lock);
	if(host->rts_index > 0 && 
		host->rts->host == host && 
			host->rts_index < epoch->rts_size) {
		rts = &epoch->rts_array[host->rts_index];
		if(rts->skb_size < epoch->k) {
			// printk("handle rts: index: %d epoch->rts_size:%d %p \n", dcpim_sk(sk)->receiver.rts_index, epoch->rts_size, dcpim_sk(sk));
			rts->remaining_sz += rh->remaining_sz;
			rts->rtx_channel += rh->rtx_channel;
		} else {
			kfree_skb(skb);
			goto unlock_receiver;
		}
	} else {
		rts_index = epoch->rts_size;
		// printk("rts_index:%d\n", rts_index);
		// iph = ip_hdr(skb);
		if(rts_index < epoch->max_array_size) {
			rts = &epoch->rts_array[rts_index];
			rts->skb_size = 0;
			rts->remaining_sz = rh->remaining_sz;
			rts->rtx_channel = rh->rtx_channel;
			/* does not have to hold host */
			rts->host = host;
			// if(dcpim_sk(sk)->receiver.rts)
			// 	printk("handle  new rts: index: %d epoch->rts_size:%d %p %p \n", dcpim_sk(sk)->receiver.rts_index, epoch->rts_size, dcpim_sk(sk)->receiver.rts->dsk, dcpim_sk(sk));
			// printk("handle  new rts: index: %d epoch->rts_size:%d\n", dcpim_sk(sk)->receiver.rts_index, epoch->rts_size);

			// smp_wmb();
			WRITE_ONCE(rts->epoch, READ_ONCE(epoch->epoch));
			WRITE_ONCE(rts->round, READ_ONCE(epoch->round));
			// printk("receive rts:%llu %d %d %d\n", rts->epoch, rts->round, rts->remaining_sz, rts_index);
			/* change host rts state */
			host->rts_index = rts_index;
			host->rts = rts;
			epoch->rts_size += 1;
		} else {
			/* rts_array is full */
			kfree_skb(skb);
			goto unlock_receiver;
		}
	}
	/* add new control packet */
	dcpim_modify_ctrl_pkt(skb, GRANT, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round));
	temp = rts->skb_arr[rts->skb_size];
	rts->skb_arr[rts->skb_size] = skb;
	rts->skb_size++;
	// printk("rts->skb_size:%d\n", rts->skb_size);
unlock_receiver:
	spin_unlock(&epoch->receiver_lock);

	if(temp != NULL)
		kfree_skb(temp);
	// rts->epoch = rh->epoch; 
	// rts->iter = rh->iter;
	// rts->peer = dcpim_peer_find(&dcpim_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
	// // spin_lock_bh(&epoch->lock);
	// if (epoch->min_rts == NULL || epoch->min_rts->remaining_sz > rts->remaining_sz) {
	// 	epoch->min_rts = rts;
	// }
	// spin_lock(&epoch->receiver_lock);
	// epoch->rts_size += 1;
	// spin_unlock(&epoch->receiver_lock);
// put_sock:
//     if (refcounted) {
//         sock_put(sk);
//     }
	dcpim_host_put(host);
	return 0;
drop:
	kfree_skb(skb);
	return 0;
}

void dcpim_handle_all_rts(struct dcpim_epoch *epoch) {
	struct dcpim_rts *rts;
	int recv_bytes = 0;
	int cur_recv_bytes = 0;
	int cur_k = 0;
	int remaining_rts_size;
	int index = 0;
	int unmatched_recv_bytes = atomic_read(&epoch->unmatched_recv_bytes);
	int rts_size = 0, i = 0;
	bool rtx_channel = false;
	spin_lock_bh(&epoch->receiver_lock);
	rts_size = epoch->rts_size;

	if(rts_size > epoch->max_array_size)
		rts_size = epoch->max_array_size;
	remaining_rts_size = rts_size;
	// spin_lock_bh(&epoch->lock);
	// uint32_t iter = READ_ONCE(epoch->iter);
	// if(epoch->match_dst_addr == 0  && epoch->rts_size > 0) {
	// 	if (dcpim_params.fct_iter >= iter) {
	// 		dcpim_xmit_control(construct_grant_pkt(epoch->sock->sk, 
	// 			iter, epoch->epoch, epoch->min_rts->remaining_sz, epoch->cur_match_dst_addr == 0), 
	// 			epoch->min_rts->peer, epoch->sock->sk, dcpim_params.match_socket_port);	
	// 	} else {
	while(1) {
		rtx_channel = false;
		if(remaining_rts_size <= 0 || unmatched_recv_bytes <= recv_bytes)
			break;
		// printk("index:%d\n", index);
		index = get_random_u32() % rts_size;
		rts = &epoch->rts_array[index];
		// if(READ_ONCE(rts->epoch) != READ_ONCE(epoch->epoch)) {
		// 	remaining_rts_size -= 1;
		// 	// rts->remaining_sz = 0;
		// 	// printk("rts->epoch: %llu epoch->epoch: %llu index:%d rts_size:%d \n", rts->epoch, READ_ONCE(epoch->epoch), index, rts_size);
		// 	// printk("rts->round: %u epoch->round: %u \n", rts->round, READ_ONCE(epoch->round));
		// 	// WARN_ON(true);
		// 	continue;
		// }
		if(rts->remaining_sz <= 0) {
			continue;
		}	
		// printk("index:%d, rts->remaning_sz:%d, remaining_rts_size:%d unmatched_recv_bytes:%d recv_bytes:%d, rts->epoch:%llu, rts->round:%u \n",
			// index, rts->remaining_sz, remaining_rts_size, unmatched_recv_bytes, recv_bytes, rts->epoch, rts->round);
		// if(rts_size >= epoch->k) {
		// 	/* fast path perform fair sharing for chosen k */
		// 	cur_recv_bytes = epoch->epoch_bytes_per_k;
		// } else {
		cur_recv_bytes = min(rts->remaining_sz, epoch->epoch_bytes_per_k);
		/* priortize short message retransmission first */
		if(rts->rtx_channel > 0) {
			rtx_channel = true;
			rts->rtx_channel -= 1;
		}
			// if(cur_recv_bytes  % epoch->epoch_bytes_per_k != 0)
			// 	cur_recv_bytes = (cur_recv_bytes / epoch->epoch_bytes_per_k + 1) * epoch->epoch_bytes_per_k;
			// cur_recv_bytes = min(unmatched_recv_bytes - recv_bytes, cur_recv_bytes);
		// }
		// dcpim_xmit_control(construct_grant_pkt((struct sock*)rts->dsk, 
		// 	epoch->round, epoch->epoch, min(rts->remaining_sz, cur_recv_bytes), 0), (struct sock*)rts->dsk);
		// if(epoch->epoch % 10000 == 0) {
		// 	printk("grant index:%d, port:%d, cur_recv_bytes:%d\n", index,  ntohs(dcpim_hdr(rts->skb)->dest), cur_recv_bytes);
		// }
		dcpim_modify_ctrl_pkt_size(rts->skb_arr[rts->skb_size - 1], cur_recv_bytes, rtx_channel);
		// printk("epoch:%llu, round:%d, cur_recv_bytes:%d, remaining_rts_size:%d, rts->remaining_sz:%d\n",epoch->epoch, epoch->round,  cur_recv_bytes, remaining_rts_size, rts->remaining_sz);
		epoch->rts_skb_array[cur_k] = rts->skb_arr[rts->skb_size - 1];
		cur_k += 1;
		rts->skb_arr[rts->skb_size - 1] = NULL;
		rts->skb_size--;
		/* we will add epoch->epoch_bytes_per_k regardless cur_recv_bytes */
		recv_bytes += epoch->epoch_bytes_per_k;
		rts->remaining_sz -= cur_recv_bytes;
		// rts->remaining_sz = 0;
		if(rts->remaining_sz <= 0)
			remaining_rts_size -= 1;
		// printk("rts->remaining_sz:%d, unmatched_recv_bytes:%d recv_bytes:%d remaining_rts_size:%d \n", rts->remaining_sz, unmatched_recv_bytes, recv_bytes, remaining_rts_size);

	}
	epoch->rts_size = 0;
	spin_unlock_bh(&epoch->receiver_lock);
	for (i = 0; i < cur_k; i++) {
		/* need to add error checking */
		dev_queue_xmit(epoch->rts_skb_array[i]);
	}
	// }
	// epoch->min_rts = NULL;
}


int dcpim_handle_grant(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	// struct sock *sk;
	struct dcpim_host *host;
	struct dcpim_grant_hdr *gh;
	// struct iphdr *iphdr;
	// struct ethhdr *ethhdr;
	struct dcpim_grant *grant;
	struct iphdr *iph;
	// bool refcounted = false;
	// int sdif = inet_sdif(skb);
	int grant_index = 0;
	struct sk_buff *temp = NULL;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_grant_hdr)))
		goto drop;		/* No space for header. */
	gh = dcpim_grant_hdr(skb);
	/* TO DO: check round number and epoch number after time is synced */
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&gh->common), gh->common.source,
    //         gh->common.dest, sdif, &refcounted);
	// if(!sk)
	// 	goto drop;

	iph = ip_hdr(skb);
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	if(!host)
		goto drop;
	// ethhdr = eth_hdr(skb);
	// if(epoch->sock == NULL) {
	// 	spin_unlock_bh(&epoch->lock);
	// 	goto drop;
	// }
	// grant = kmalloc(sizeof(struct dcpim_grant), GFP_KERNEL);
	// INIT_LIST_HEAD(&grant->entry);
	// iph = ip_hdr(skb);
	spin_lock(&epoch->sender_lock);
	// if(atomic_read(&dcpim_sk(sk)->sender.matched)) {
	// 	kfree_skb(skb);
	// 	spin_unlock(&epoch->sender_lock);
	// 	goto put_sock;
	// }
	// printk("receive grant\n");
	if(host->grant_index > 0 && 
		host->grant->host == host && 
			host->grant_index < epoch->grant_size) {
		grant = &epoch->grants_array[host->grant_index];
		if(grant->skb_size < epoch->k) {
			grant->remaining_sz += gh->remaining_sz;
			grant->rtx_channel += gh->rtx_channel;
		} else {
			kfree_skb(skb);
			goto unlock_receiver;
		}
	} else {
		grant_index = epoch->grant_size;
		if(grant_index < epoch->max_array_size) {
			grant = &epoch->grants_array[grant_index];
			grant->skb_size = 0;
			grant->remaining_sz = gh->remaining_sz;
			/* doesn't hold the host refcnt, only for comparsion purpos*/
			grant->host = host;
			grant->rtx_channel = gh->rtx_channel;
			/* hold the socket pointer */
			// dcpim_host_hold(host);
			WRITE_ONCE(grant->epoch, READ_ONCE(epoch->epoch));
			WRITE_ONCE(grant->round, READ_ONCE(epoch->round));
			host->grant_index = grant_index;
			host->grant = grant;
			epoch->grant_size += 1;
		} else {
			kfree_skb(skb);
			goto unlock_receiver;
		}
	}
	dcpim_modify_ctrl_pkt(skb, ACCEPT, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round));
	temp = grant->skb_arr[grant->skb_size];
	grant->skb_arr[grant->skb_size] = skb;
	grant->skb_size++;
unlock_receiver:
	spin_unlock(&epoch->sender_lock);
	if(temp != NULL)
		kfree_skb(temp);
	/* Make sure the change of grant array is visiable */

	// grant->epoch = gh->epoch; 
	// grant->iter = gh->iter;
	// grant->prompt = gh->prompt;
	// grant->peer = dcpim_peer_find(&dcpim_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
	// if (epoch->min_grant == NULL || epoch->min_grant->remaining_sz > grant->remaining_sz) {
	// 	epoch->min_grant = grant;
	// }
	// spin_lock(&epoch->sender_lock);
	// llist_add(&grant->lentry, &epoch->grants_q);
	// spin_unlock(&epoch->sender_lock);
// put_sock:
// 	if(refcounted) {
// 		sock_put(sk);
// 	}
// put_host:
	dcpim_host_put(host);
	return 0;
drop:
	kfree_skb(skb);

	return 0;
}

void dcpim_handle_all_grants(struct dcpim_epoch *epoch) {
	struct dcpim_grant *grant;
	int sent_bytes = 0;
	int cur_sent_bytes = 0;
	int cur_k = 0;
	int i = 0;
	int grant_size;
	int remaining_grant_size;
	bool rtx_channel = false;
	// struct dcpim_flow* flow;
	spin_lock_bh(&epoch->sender_lock);
	grant_size = epoch->grant_size;
	// struct sk_buff *head_skb = NULL, *skb;
	if(grant_size > epoch->max_array_size)
		grant_size = epoch->max_array_size;
	remaining_grant_size = grant_size;
	while(1) {
		if(remaining_grant_size <= 0 || epoch->unmatched_sent_bytes <= sent_bytes)
			break;
		grant = &epoch->grants_array[get_random_u32() % grant_size];
		// if(READ_ONCE(grant->epoch) != READ_ONCE(epoch->epoch) || READ_ONCE(grant->round) != READ_ONCE(epoch->round)) {
		// 	remaining_grant_size -= 1;
		// 	// grant->remaining_sz = 0;
		// 	// WARN_ON(true);
		// 	continue;
		// }
		if (grant->remaining_sz <= 0) {
			continue;
		}
		// if(atomic_read(&grant->dsk->sender.matched)) {
		// 	grant->remaining_sz = 0;
		// 	remaining_grant_size -= 1;
		// 	continue;
		// }
		// if(grant_size >= epoch->k) {
			/* fast path: sharing the bandwidth */
			// cur_sent_bytes = epoch->epoch_bytes_per_k;
		// } else {
		// 	cur_sent_bytes = grant->remaining_sz;
		// 	if(cur_sent_bytes % epoch->epoch_bytes_per_k != 0) 
		// 		cur_sent_bytes = (cur_sent_bytes / epoch->epoch_bytes_per_k + 1) * epoch->epoch_bytes_per_k;
		cur_sent_bytes = min(grant->remaining_sz, epoch->epoch_bytes_per_k);
		if(grant->rtx_channel > 0) {
			rtx_channel = true;
			grant->rtx_channel -= 1;
		}
		// }
		// printk("send accept pkt:%d\n", __LINE__);
		/*construct accept pkt */
		// skb = construct_accept_pkt((struct sock*)grant->dsk, epoch->round, epoch->epoch, 
		// 	min(grant->remaining_sz, cur_sent_bytes));
		// dcpim_fill_dcpim_header(skb, grant->sport, grant->dport);
		// dcpim_fill_ip_header(skb, grant->saddr, grant->daddr);
		// dcpim_fill_eth_header(skb, grant->h_source, grant->h_dest);
		// if(!head_skb) {
		// 	head_skb = skb;
		// } else {
		// 	skb->next = head_skb;
		// 	head_skb = skb;
		// }
		// dcpim_xmit_control(construct_accept_pkt((struct sock*)grant->dsk, 
        //     epoch->round, epoch->epoch, min(grant->remaining_sz, cur_sent_bytes)), (struct sock*)grant->dsk);
		dcpim_modify_ctrl_pkt_size(grant->skb_arr[grant->skb_size - 1], cur_sent_bytes, rtx_channel);
		epoch->grant_skb_array[cur_k] = grant->skb_arr[grant->skb_size - 1];
		cur_k += 1;
		grant->skb_arr[grant->skb_size - 1] = NULL;
		grant->skb_size--;
		// kfree_skb(skb);
		/* sent bytes incremented by  epoch->epoch_bytes_per_k */
		sent_bytes += epoch->epoch_bytes_per_k;
		grant->remaining_sz -= cur_sent_bytes;
		if(grant->remaining_sz <= 0) {
			remaining_grant_size -= 1;
		}
		/* set matched to be true */
		// if(grant->dsk == NULL) {
		// 	WARN_ON(true);
		// } else {
		// 	atomic_set(&grant->dsk->sender.matched, 1);
		// }
	}
	epoch->unmatched_sent_bytes -= sent_bytes;
	// for(i = 0; i < grant_size; i ++) {
	// 	/* put socket pointer */
	// 	sock_put((struct sock*)epoch->grants_array[i].dsk);
	// 	epoch->grants_array[i].dsk = NULL;
	// }
	// dev_queue_xmit(head_skb);
	// epoch->grant_size = 0;
	// epoch->min_grant = NULL;
	epoch->grant_size = 0;
	spin_unlock_bh(&epoch->sender_lock);
	for (i = 0; i < cur_k; i++) {
		/* need to add error checking here */
		dev_queue_xmit(epoch->grant_skb_array[i]);
	}
	// spin_unlock_bh(&epoch->lock);
}

int dcpim_handle_accept(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	// struct sock* sk;
	struct dcpim_host *host;
	struct dcpim_accept_hdr *ah;
	// struct dcpim_flow* flow;
	struct iphdr *iph;
	bool skip_free = true;
	// bool refcounted = false;
	// struct dcpim_sock *dsk;
	// unsigned int max_pacing_rate = 0;
	// sockptr_t optval;
	int value;
	// int sdif = inet_sdif(skb);
	// struct iphdr *iph;
	// bool refcounted = false;
	// int sdif = inet_sdif(skb);
	if (!pskb_may_pull(skb, sizeof(struct dcpim_accept_hdr)))
		goto drop;		/* No space for header. */

	ah = dcpim_accept_hdr(skb);
	iph = ip_hdr(skb);
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
    //         ah->common.dest, sdif, &refcounted);
	// sk = __inet_lookup_skb(&tcp_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
    //         ah->common.dest, sdif, &refcounted);
	// if(!sk)
	// 	goto drop;
	if(host) {
		// spin_lock_bh(&epoch->receiver_lock);
		/* TO DO: check round number and epoch number */
		// dsk = dcpim_sk(sk);
		// if(value >= 0) {
			/* To Do: check the epoch and round value after checking */
			/* add flows */
			// flow = dcpim_find_flow(epoch, iph->saddr, iph->daddr, ah->common.source, ah->common.dest);
			// if(flow == NULL) {
			// 	goto drop;
			// }
			spin_lock(&epoch->matched_lock);
			value = atomic_sub_return(ah->remaining_sz, &epoch->unmatched_recv_bytes);
			if(value >= 0 && epoch->next_matched_hosts < epoch->k) {
				// host->next_pacing_rate += dcpim_params.bandwidth * ah->remaining_sz / epoch->epoch_bytes * 1000000000 / 8;
				/* only count long flow transmission rate */
				if(ah->rtx_channel == 0)
					host->next_pacing_rate  += epoch->rate_per_channel;
				else {
					if(epoch->rtx_msg_size < epoch->k) {
						skip_free = false;
						dcpim_modify_ctrl_pkt(skb, RTX_MSG, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round));
						dcpim_modify_ctrl_pkt_size(skb, ah->remaining_sz, true);
						epoch->rtx_msg_array[epoch->rtx_msg_size] = skb;
						epoch->rtx_msg_size += 1; 
					} else {
						WARN_ON(true);
					}
				}
				// if(epoch->epoch % 10000 == 0)
				// 	printk("dsk:%p ah->remaining_sz: %u %lu\n", dsk, ah->remaining_sz, dsk->receiver.next_pacing_rate );
				epoch->next_matched_arr[epoch->next_matched_hosts] = host;
				epoch->next_matched_hosts += 1;
				dcpim_host_hold(host);
			}
			spin_unlock(&epoch->matched_lock);
			// max_pacing_rate = dcpim_params.bandwidth * ah->remaining_sz / epoch->epoch_bytes;
			// optval = KERNEL_SOCKPTR(&max_pacing_rate);
			// sock_setsockopt(sk->sk_socket, SOL_SOCKET,
			// 			SO_MAX_PACING_RATE, optval, sizeof(max_pacing_rate));
		// } else {
		// 	/* TO DO: send reverse accept packet if needed */
		// 	/* Add statistic counting here */
		// }
	}

	// spin_unlock_bh(&epoch->receiver_lock);
	// if(epoch->sock == NULL) {
	// 	spin_unlock_bh(&epoch->lock);
	// 	goto drop;
	// }
	// grant = kmalloc(sizeof(struct dcpim_grant), GFP_KERNEL);
	// INIT_LIST_HEAD(&grant->list_link);
	// iph = ip_hdr(skb);
	// grant->remaining_sz = gh->remaining_sz;
	// grant->epoch = gh->epoch; 
	// grant->iter = gh->iter;
	// grant->prompt = gh->prompt;
	// grant->peer = dcpim_peer_find(&dcpim_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
	// if (epoch->min_grant == NULL || epoch->min_grant->remaining_sz > grant->remaining_sz) {
	// 	epoch->min_grant = grant;
	// }
	// list_add_tail(&grant->list_link, &epoch->grants_q);
	// epoch->grant_size += 1;
	// spin_unlock_bh(&epoch->lock);
	// if(refcounted) {
	// 	sock_put(sk);
	// }
    // if (refcounted) {
    //     sock_put(sk);
    // }
	dcpim_host_put(host);
drop:
	if(skip_free)
		kfree_skb(skb);

	return 0;
}

int dcpim_handle_rtx_msg(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	// struct sock* sk;
	struct dcpim_sock *dsk, *temp;
	struct dcpim_host *host;
	struct dcpim_rtx_msg_hdr *ah;
	// struct dcpim_flow* flow;
	struct iphdr *iph;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_rtx_msg_hdr)))
		goto drop;		/* No space for header. */

	ah = dcpim_rtx_msg_hdr(skb);
	iph = ip_hdr(skb);
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
    //         ah->common.dest, sdif, &refcounted);
	// sk = __inet_lookup_skb(&tcp_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
    //         ah->common.dest, sdif, &refcounted);
	// if(!sk)
	// 	goto drop;
	if(host) {
		spin_lock(&host->lock);
		list_for_each_entry_safe(dsk, temp, &host->short_flow_list, entry) {
			atomic_add(ah->remaining_sz , &dsk->sender.rtx_msg_bytes);
			queue_work_on(dsk->core_id, dcpim_wq, &dsk->sender.rtx_msg_work);
			list_move_tail(&dsk->entry, &host->short_flow_list);
			break;
			// host->next_pacing_rate -= max_pacing_rate;
		}
		spin_unlock(&host->lock);
		dcpim_host_put(host);
	}
drop:
	kfree_skb(skb);

	return 0;
}

// int dcpim_handle_accept(struct sk_buff *skb, struct dcpim_match_tab *table, struct dcpim_epoch *epoch) {
// 	struct dcpim_accept_hdr *ah;
// 	struct iphdr *iph;

// 	if (!pskb_may_pull(skb, sizeof(struct dcpim_accept_hdr)))
// 		goto drop;		/* No space for header. */
// 	iph = ip_hdr(skb);
// 	ah = dcpim_accept_hdr(skb);
// 	printk("receive accept pkt: %llu\n", ah->epoch);
// 	spin_lock_bh(&epoch->lock);
// 	if(epoch->match_dst_addr == 0)
// 		epoch->match_dst_addr = iph->saddr;
// 	spin_unlock_bh(&epoch->lock);

// drop:
// 	kfree_skb(skb);
// 	return 0;
// }



/* Assume hold socket lock 
 * Return 0 if flow should be pushed_back;
 * Return 1 if RMEM is unavailable.
 * Return 2 if timer is setup.
 */

// int rtx_bytes_count(struct dcpim_sock* dsk, __u32 prev_grant_nxt) {
// 	int retransmit_bytes = 0; 
// 	if(dsk->receiver.rcv_nxt < prev_grant_nxt) {
// 		int i = 0;
// 		__u32 sum = 0;
// 		// printk("prev_grant_nxt:%u\n", prev_grant_nxt);
// 		while(i < dsk->num_sacks) {
// 			__u32 start_seq = dsk->selective_acks[i].start_seq;
// 			__u32 end_seq = dsk->selective_acks[i].end_seq;
// 			// printk("start seq: %u\n", start_seq);
// 			// printk("end seq:%u\n", end_seq);
// 			if(start_seq > prev_grant_nxt)
// 				goto next;
// 			if(end_seq > prev_grant_nxt) {
// 				end_seq = prev_grant_nxt;
// 			}
// 			sum += end_seq - start_seq;
// 		next:
// 			i++;
// 		}
// 		retransmit_bytes = prev_grant_nxt - dsk->receiver.rcv_nxt - sum;
// 		// atomic_add_return(retransmit_bytes, &dcpim_epoch.remaining_tokens);
// 	} 
// 	return retransmit_bytes;
// }

/* Assume BH is disabled and epoch->lock is hold
 * Return true if we need to push back the flow to pq.
 */
 // ktime_t start2,end2;
 // __u64 num_tokens = 0;
 // ktime_t total_time = 0;
// void dcpim_xmit_token(struct dcpim_epoch *epoch) {
// 	struct list_head *match_link;
// 	struct sock *sk;
// 	struct dcpim_sock *dsk;
// 	struct inet_sock *inet;
// 		// start2 = ktime_get();
// 	// printk("dcpim xmit token\n");
// 	while(!dcpim_pq_empty(&epoch->flow_q)) {
// 		bool not_push_bk = false;
// 		if(atomic_read(&dcpim_epoch.remaining_tokens) >= dcpim_params.control_pkt_bdp / 2 
// 			&& atomic_read(&dcpim_epoch.remaining_tokens) != 0) {
// 			// WARN_ON(true);
// 			return;
// 		}
// 		match_link = dcpim_pq_peek(&epoch->flow_q);
// 		dsk =  list_entry(match_link, struct dcpim_sock, match_link);
// 		sk = (struct sock*)dsk;
// 		inet = inet_sk(sk);
// 		dcpim_pq_pop(&epoch->flow_q);
//  		bh_lock_sock(sk);
//  		if(sk->sk_state == DCPIM_ESTABLISHED) {
//  			dsk->receiver.prev_grant_bytes = 0;
// 	 		if (!sock_owned_by_user(sk)) {
// 	 			int grant_bytes = calc_grant_bytes(sk);
// 	 			// printk("grant bytes:%d\n", grant_bytes);
// 	 			not_push_bk = xmit_batch_token(sk, grant_bytes, true);
// 		 		if(grant_bytes == dsk->receiver.max_grant_batch) {
// 					dsk->prev_grant_nxt = dsk->grant_nxt;
// 					dsk->grant_nxt = dsk->new_grant_nxt;
// 		  			if (!not_push_bk){
// 		  				dcpim_pq_push(&epoch->flow_q, &dsk->match_link);
// 		  			}
// 		 		}
// 		 		else {
// 	 				// xmit_batch_token(sk, grant_bytes, true);
// 					// atomic_add(dsk->receiver.grant_batch, &dcpim_epoch.remaining_tokens);
// 					// printk("set timer deferred 1\n");
// 	 				test_and_set_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
// 		 		}

// 	 		// 	if (grant_bytes < dsk->receiver.grant_batch) {
// 				// 	printk("RMEM_LIMIT\n");
// 			 //    	test_and_set_bit(DCPIM_RMEM_CHECK_DEFERRED, &sk->sk_tsq_flags);
// 			 //    	goto unlock;
// 				// } else {
					
// 				// }
// 	 		} else {
// 	 			// printk("delay \n");
// 	 			int grant_bytes = calc_grant_bytes(sk);
// 	 			if (!grant_bytes)
// 	 				 xmit_batch_token(sk, grant_bytes, false);
// 	 			// printk("delay bytes:%d\n", grant_bytes);
// 	 			// atomic_add(dsk->receiver.grant_batch, &epoch->remaining_tokens);
// 	 			// atomic_add(dsk=>receiver.);
// 	 			/* pre-assign the largest number of tokens; will be deleted later */
// 				// atomic_add(dsk->receiver.grant_batch, &dcpim_epoch.remaining_tokens);
// 				// printk("set timer deferred\n");
// 	 			test_and_set_bit(DCPIM_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
// 	 		}
//  		} else {
//  			goto unlock;
//  		}

// 		bh_unlock_sock(sk);
// 		break;
// unlock:
//         bh_unlock_sock(sk);
// 	}
// 	if (!dcpim_pq_empty(&epoch->flow_q)) {
// 		// printk("timer expire time:%d\n", dcpim_params.rtt * 10 * 1000);
// 		// hrtimer_start(&dcpim_epoch.token_xmit_timer, ktime_set(0, dcpim_params.rtt * 10 * 1000), HRTIMER_MODE_REL);
// 		// dcpim_epoch.token_xmit_timer.function = &dcpim_token_xmit_event;
// 	}
	// end2 = ktime_get();
	// total_time = ktime_add(total_time, ktime_sub(end2, start2));
	// num_tokens += 1;
	// if(num_tokens == 1000) {
	// 	num_tokens = 0;
	// 	printk("transmission time:%llu\n", ktime_to_us(total_time) / 1000);
	// 	total_time = ktime_set(0, 0);
	// }
// }

// void dcpim_xmit_token_handler(struct work_struct *work) {
	// struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, token_xmit_struct);
// }

// enum hrtimer_restart receiver_iter_event(struct hrtimer *timer) {
// 	// struct dcpim_grant* grant, temp;
//  	uint32_t iter;
//  	hrtimer_forward(timer, hrtimer_cb_get_time(timer), ktime_set(0, dcpim_params.iter_size));
//  	queue_work(dcpim_epoch.wq, &dcpim_epoch.receiver_iter_struct);
//  	iter = READ_ONCE(dcpim_epoch.iter);
//  	if(iter >= dcpim_params.num_iters) {
//  		return HRTIMER_NORESTART;
//  	}
// 	return HRTIMER_RESTART;

// }

// enum hrtimer_restart sender_iter_event(struct hrtimer *timer) {
//  	uint32_t iter;
//  	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0, dcpim_params.iter_size));
//  	queue_work(dcpim_epoch.wq, &dcpim_epoch.sender_iter_struct);

//  	// js = ktime_get_ns();
//  	iter = READ_ONCE(dcpim_epoch.iter);

//  	if(iter >= dcpim_params.num_iters) {
//  		return HRTIMER_NORESTART;
//  	}
// 	return HRTIMER_RESTART;

// }

// enum hrtimer_restart dcpim_new_epoch(struct hrtimer *timer) {

//  	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0,dcpim_params.epoch_size));
// 	dcpim_epoch.epoch += 1;
// 	WRITE_ONCE(dcpim_epoch.iter, 0);
// 	dcpim_epoch.match_src_addr = 0;
// 	dcpim_epoch.match_dst_addr = 0;
// 	dcpim_epoch.prompt = false;
// 	hrtimer_start(&dcpim_epoch.receiver_iter_timer, ktime_set(0, 0), HRTIMER_MODE_ABS);
// 	dcpim_epoch.receiver_iter_timer.function = &receiver_iter_event;
// 	hrtimer_start(&dcpim_epoch.sender_iter_timer, ktime_set(0, dcpim_params.iter_size / 2), HRTIMER_MODE_ABS);
// 	dcpim_epoch.sender_iter_timer.function = &sender_iter_event;

// 	return HRTIMER_RESTART;
// }

