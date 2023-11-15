#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include "dcpim_impl.h"

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
	INIT_LIST_HEAD(&host->idle_flow_list);
	INIT_LIST_HEAD(&host->short_flow_list);
	atomic_set(&host->total_unsent_bytes, 0);
	atomic_set(&host->rtx_msg_size, 0);
	host->next_pacing_rate = 0;
	host->grant_index = -1;
	host->grant = NULL;
	host->rts_index = -1;
	host->grant = NULL;
	host->num_flows = 0;
	host->num_long_flows = 0;
	host->idle_long_flows = 0;
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
		list_add_tail_rcu(&dcpim_sk(sk)->entry, &host->idle_flow_list);
		host->idle_long_flows += 1;
		dcpim_sk(sk)->is_idle = true;
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

void dcpim_host_set_sock_active(struct dcpim_host *host, struct sock *sk) {
	spin_lock_bh(&host->lock);
	WARN_ON(!dcpim_sk(sk)->in_host_table);
	WARN_ON(sk->sk_priority == 7);
	if(dcpim_sk(sk)->is_idle) {
		list_del_rcu(&dcpim_sk(sk)->entry);
		list_add_tail_rcu(&dcpim_sk(sk)->entry, &host->flow_list);
		host->num_long_flows += 1;
		host->idle_long_flows -= 1;
		dcpim_sk(sk)->is_idle = false;
		if(dcpim_sk(host->sk)->is_idle) {
			if(!list_empty(&host->flow_list))
				host->sk = (struct sock*)list_first_entry(&host->flow_list, struct dcpim_sock, entry);
		}
	}
	spin_unlock_bh(&host->lock);
}

void dcpim_host_set_sock_idle(struct dcpim_host *host, struct sock *sk) {
	spin_lock_bh(&host->lock);
	WARN_ON(!dcpim_sk(sk)->in_host_table);
	WARN_ON(sk->sk_priority == 7);
	if(!dcpim_sk(sk)->is_idle) {
		list_del_rcu(&dcpim_sk(sk)->entry);
		list_add_tail_rcu(&dcpim_sk(sk)->entry, &host->idle_flow_list);
		host->num_long_flows -= 1;
		host->idle_long_flows += 1;
		dcpim_sk(sk)->is_idle = true;
		if(host->sk == sk) {
			if(!list_empty(&host->flow_list))
				host->sk = (struct sock*)list_first_entry(&host->flow_list, struct dcpim_sock, entry);
		}
	}
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
			if(dcpim_sk(sk)->is_idle)
				host->idle_long_flows -= 1;
			else
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
				else if(!list_empty(&host->idle_flow_list))
					host->sk = (struct sock*)list_first_entry(&host->idle_flow_list, struct dcpim_sock, entry);
				else	
					WARN_ON(true);
			}
		}
		dcpim_sk(sk)->is_idle = false;
		spin_unlock_bh(&host->lock);
		in_host_table = true;
	} else {
		spin_unlock_bh(&host->lock);
	}
	return in_host_table;
}

/* Find dcpim_host in the hash table; also increment the refcnt of dcpim_host */
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
	int i = 0;
	// int total_channels, matched_channels, num_flows;
	// unsigned long max_pacing_rate = 0;
	// struct dcpim_host **temp_arr;
	struct dcpim_sock *dsk;
	// struct dcpim_host *host;
	int rtx_msg_size = 0;
	struct sk_buff** temp_arr;
	// sockptr_t optval;
	struct sock *sk;
	void* temp_match_arr;
	/* set the current matching flow rates to be zero */
	for (i = 0; i < epoch->cur_matched_flows; i++) {
		dsk = epoch->cur_matched_arr[i];
		if(dsk->receiver.next_pacing_rate == 0)
			atomic64_set(&dsk->receiver.pacing_rate, 0);
		/* need to check retransmission when new epoch starts */	
		atomic_cmpxchg(&dsk->receiver.rtx_status, 0, 1);
		sock_put((struct sock*)dsk);
	}
	spin_lock_bh(&epoch->matched_lock);
	/* get rtx msg  packets */
	rtx_msg_size = epoch->rtx_msg_size;
	temp_arr = epoch->temp_rtx_msg_array;
	epoch->temp_rtx_msg_array = epoch->rtx_msg_array;
	epoch->rtx_msg_array = temp_arr;
	epoch->rtx_msg_size = 0;
	/* find flow to send tokens from hosts */
// 	for (i = 0; i < epoch->next_matched_hosts; i++) {
// 		j = 0;
// 		host = epoch->next_matched_host_arr[i];
// 		// max_pacing_rate = host->next_pacing_rate; // bytes per second
// 		// optval = KERNEL_SOCKPTR(&max_pacing_rate);
// 		if(host->next_pacing_rate == 0)
// 			goto put_host;
// 		test_pacing_rate += host->next_pacing_rate;
// 		test_count += 1;
// 		total_channels = host->next_pacing_rate / epoch->rate_per_channel;
// 		num_flows = host->num_long_flows;
// 		if(epoch->epoch % 100000 == 0)
// 			printk("average pacing rate:%llu num_long_flows: %d\n", test_pacing_rate / test_count, host->num_long_flows);
// 		spin_lock_bh(&host->lock);
// 		list_for_each_entry_safe(dsk, temp, &host->flow_list, entry) {
// 			if(j == host->num_long_flows)
// 				break;
// 			if(epoch->next_matched_flows >= epoch->max_array_size)
// 				break;
// 			// if(host->next_pacing_rate == 0)
// 			// 	break;
// 			if(total_channels == 0)
// 				break;
// 			if(total_channels <= num_flows)
// 				matched_channels = 1;
// 			else
// 				matched_channels = total_channels / num_flows;
// 			// max_pacing_rate = min(epoch->max_pacing_rate_per_flow, host->next_pacing_rate);
// 			WRITE_ONCE(dsk->receiver.next_pacing_rate, READ_ONCE(dsk->receiver.next_pacing_rate) + matched_channels *  epoch->rate_per_channel);
// 			epoch->next_matched_arr[epoch->next_matched_flows] = dsk;
// 			sock_hold((struct sock*)dsk);
// 			list_move_tail(&dsk->entry, &host->flow_list);
// 			j++;
// 			epoch->next_matched_flows++;
// 			total_channels -= matched_channels;
// 			num_flows--;
// 			// host->next_pacing_rate -= max_pacing_rate;
// 		}
// 		spin_unlock_bh(&host->lock);
// 		host->next_pacing_rate = 0;
// put_host:
// 		dcpim_host_put(host);
// 	}
	epoch->cur_matched_flows = epoch->next_matched_flows;
	/* swap two matched flow arr */
	temp_match_arr = epoch->cur_matched_arr;
	epoch->cur_matched_arr = epoch->next_matched_arr;
	epoch->next_matched_arr = temp_match_arr;

	/* reset matching state */
	epoch->next_matched_hosts = 0;
	epoch->next_matched_flows = 0;
	WRITE_ONCE(epoch->last_unmatched_recv_bytes, epoch->unmatched_recv_bytes);
	WRITE_ONCE(epoch->unmatched_recv_bytes, epoch->epoch_bytes);	

	/* wake up sockets in the table */
	for (i = 0; i < epoch->cur_matched_flows; i++) {
		dsk = epoch->cur_matched_arr[i];
		sk = (struct sock*)dsk;
		if(READ_ONCE(dsk->receiver.next_pacing_rate) != 0) {
			// test_pacing_rate += READ_ONCE(dsk->receiver.next_pacing_rate);
			// if(inet_sk(sk)->inet_sport != inet_sk(sk)->inet_dport)
			// 	printk("epoch:%llu sk: %p src port: %d dst port:%d pacing_rate: %lu\n", epoch->epoch, sk, ntohs(inet_sk(sk)->inet_sport), ntohs(inet_sk(sk)->inet_dport), READ_ONCE(dsk->receiver.next_pacing_rate));
			atomic64_set(&dsk->receiver.pacing_rate, READ_ONCE(dsk->receiver.next_pacing_rate));
			WRITE_ONCE(dsk->receiver.next_pacing_rate, 0);
			if(atomic_cmpxchg(&dsk->receiver.token_work_status, 0, 1) == 0) {
				sock_hold(sk);
				queue_work_on(dsk->core_id, dcpim_wq, &dsk->receiver.token_work);
			}	
		}
	}
	spin_unlock_bh(&epoch->matched_lock);

	/* send rtx_msg packets for short messages */
	for(i = 0; i < rtx_msg_size; i++) {
		dev_queue_xmit(epoch->temp_rtx_msg_array[i]);
	}
}

static void sender_matching_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, sender_matching_work);
	dcpim_handle_all_rts(epoch);
}

static void epoch_start_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, epoch_work);
	ktime_t now;
	s64 time;
	now = hrtimer_cb_get_time(&epoch->receiver_round_timer);
	/* schedule at 100 epoch away */
	time = (ktime_to_ns(now) / epoch->epoch_length + 100) * epoch->epoch_length;
	hrtimer_start(&epoch->receiver_round_timer, ktime_set(0, time), HRTIMER_MODE_ABS);
	hrtimer_start(&epoch->sender_round_timer, ktime_set(0, time + epoch->round_length / 2), HRTIMER_MODE_ABS);
}

static void receiver_matching_handler(struct work_struct *work) {
	struct dcpim_epoch *epoch = container_of(work, struct dcpim_epoch, receiver_matching_work);
	// spin_lock_bh(&epoch->lock);
	if(epoch->round > 0) {
		dcpim_handle_all_grants(epoch);
	}
	// advance rounds
	WRITE_ONCE(epoch->round, READ_ONCE(epoch->round) + 1);
	if(epoch->round >= dcpim_params.num_rounds) {
		/* update flow rate */
		dcpim_update_flows_rate(epoch);
		epoch->cur_epoch = epoch->epoch;
		WRITE_ONCE(epoch->round, 0);
		WRITE_ONCE(epoch->epoch, READ_ONCE(epoch->epoch) + 1);
		atomic_set(&epoch->last_unmatched_sent_bytes, atomic_read(&epoch->unmatched_sent_bytes));
		atomic_set(&epoch->unmatched_sent_bytes, epoch->epoch_bytes);
	} 
	dcpim_send_all_rts(epoch);
}

static void dcpim_modify_ctrl_pkt(struct sk_buff *skb, __u8 type,  __u8 round, __be64 epoch, bool swap) {
	/* the packet might not be grant packet, but doesn't matter for now. */
	struct dcpim_grant_hdr *gh = dcpim_grant_hdr(skb);
	gh->common.type = type;
	gh->round =round;
	gh->epoch = epoch;
	if(swap) {
		dcpim_swap_dcpim_header(skb);
		dcpim_swap_ip_header(skb);
		dcpim_swap_eth_header(skb);
	}
}

static void dcpim_modify_ctrl_pkt_size(struct sk_buff *skb, __be32 size, bool rtx_channel, bool prompt_channel, u16 source, u16 dest) {
	struct dcpim_grant_hdr *gh = dcpim_grant_hdr(skb);
	gh->remaining_sz = size;
	gh->rtx_channel = rtx_channel;
	gh->prompt_channel = prompt_channel;
	gh->source = source;
	gh->dest = dest;
	skb_push(skb, skb->data - skb_mac_header(skb));
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

void dcpim_epoch_init(struct dcpim_epoch *epoch) {
	int i = 0;
	epoch->epoch = 0;
	epoch->round = 0;
	epoch->k = 4;
	epoch->prompt = false;
	/* hold RTS/GRANTs at most DCPIM_MAX_HOST. */
	epoch->max_array_size = DCPIM_MATCH_DEFAULT_HOST;
	epoch->epoch_length = dcpim_params.epoch_length;
	epoch->round_length = dcpim_params.round_length;
	epoch->epoch_bytes_per_k = epoch->epoch_length * dcpim_params.bandwidth / 8 / epoch->k;
	epoch->epoch_bytes = epoch->epoch_bytes_per_k * epoch->k;
	epoch->port = 0;
	epoch->port_range = 15;
	epoch->rate_per_channel = dcpim_params.bandwidth * 1000000000 / 8 / epoch->k;

	atomic_set(&epoch->unmatched_sent_bytes, epoch->epoch_bytes);
	WRITE_ONCE(epoch->unmatched_recv_bytes, epoch->epoch_bytes);
	atomic_set(&epoch->last_unmatched_sent_bytes, epoch->epoch_bytes);
	WRITE_ONCE(epoch->last_unmatched_recv_bytes, epoch->epoch_bytes);

	epoch->cur_matched_arr = kzalloc(sizeof(struct dcpim_sock*) * epoch->max_array_size, GFP_KERNEL);
	epoch->next_matched_arr = kzalloc(sizeof(struct dcpim_sock*) * epoch->max_array_size, GFP_KERNEL);
	epoch->next_matched_host_arr = kzalloc(sizeof(struct dcpim_host*) * epoch->k, GFP_KERNEL);
	epoch->cur_matched_flows = 0;
	epoch->next_matched_flows = 0;
	epoch->next_matched_hosts = 0;
	epoch->rts_array = kzalloc(sizeof(struct dcpim_rts) * epoch->max_array_size, GFP_KERNEL);
	epoch->grants_array = kzalloc(sizeof(struct dcpim_grant) * epoch->max_array_size, GFP_KERNEL);
	epoch->rts_skb_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->grant_skb_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->rtx_msg_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->temp_rtx_msg_array = kzalloc(sizeof(struct sk_buff*) * epoch->k, GFP_KERNEL);
	epoch->accept_array = kzalloc(sizeof(struct dcpim_accept) * epoch->k, GFP_KERNEL);
	// current epoch and address
	epoch->cur_epoch = 0;
	epoch->cpu = 60;
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
	INIT_LIST_HEAD(&epoch->host_list);
	hash_init(epoch->host_table);


	epoch->wq = alloc_workqueue("epoch_wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	INIT_WORK(&epoch->sender_matching_work, sender_matching_handler);
	INIT_WORK(&epoch->receiver_matching_work, receiver_matching_handler);
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
	int i = 0, j;
	hrtimer_cancel(&epoch->sender_round_timer);
	hrtimer_cancel(&epoch->receiver_round_timer);
	flush_workqueue(epoch->wq);
	destroy_workqueue(epoch->wq);
	for(i = 0; i < epoch->max_array_size; i++) {
		for(j = 0; j < epoch->k; j++) {
			if(epoch->rts_array[i].skb_arr[j]) {
				kfree_skb(epoch->rts_array[i].skb_arr[j]);
				epoch->rts_array[i].skb_arr[j] = NULL;
			}
			if(epoch->grants_array[i].skb_arr[j]) {
				kfree_skb(epoch->grants_array[i].skb_arr[j]);
				epoch->grants_array[i].skb_arr[j] = NULL;
			}

		}
		kfree(epoch->rts_array[i].skb_arr); 
		kfree(epoch->grants_array[i].skb_arr); 
		epoch->rts_array[i].skb_arr = NULL;
		epoch->grants_array[i].skb_arr = NULL;
		if(epoch->grants_array[i].host)
			dcpim_host_put(epoch->grants_array[i].host);
		if(epoch->rts_array[i].host)
			dcpim_host_put(epoch->rts_array[i].host);
		epoch->grants_array[i].host = NULL;
		epoch->rts_array[i].host = NULL;
	}

	kfree(epoch->grants_array);
	kfree(epoch->rts_array);
	epoch->grants_array = NULL;
	epoch->rts_array = NULL;
	kfree(epoch->cur_matched_arr);
	kfree(epoch->next_matched_arr);
	kfree(epoch->next_matched_host_arr);
	epoch->cur_matched_arr = NULL;
	epoch->next_matched_arr = NULL;
	epoch->next_matched_host_arr = NULL;
	kfree(epoch->grant_skb_array);
	kfree(epoch->rts_skb_array);
	epoch->grant_skb_array = NULL;
	epoch->rts_skb_array = NULL;

	kfree(epoch->rtx_msg_array);
	epoch->rtx_msg_array = NULL;
	kfree(epoch->temp_rtx_msg_array);
	epoch->temp_rtx_msg_array = NULL;
	kfree(epoch->accept_array);
	epoch->accept_array = NULL;
	/* dcpim_destroy_sock needs to hold the epoch lock */
    // sock_release(sk);

}

void dcpim_send_all_rts (struct dcpim_epoch* epoch) {
	struct dcpim_host *host;
	int flow_size, rts_size , i;
	struct sk_buff *skb;
	struct inet_sock *inet;
	int err = 0;
	// bool rtx_channel = false;
	int total_flow_size = 0;
	// int prompt_flow_size, total_prompt_flow_size, prompt_size;
	spin_lock_bh(&epoch->receiver_lock);
	total_flow_size = READ_ONCE(epoch->unmatched_recv_bytes);
	/* remove prompt optimization for rts packet */
	// total_prompt_flow_size = READ_ONCE(epoch->last_unmatched_recv_bytes);
	if(total_flow_size == 0) {
		goto unlock_receiver;
	}
	rcu_read_lock();
	list_for_each_entry_rcu(host, &epoch->host_list, entry) {
		spin_lock_bh(&host->lock);
		// rtx_size = atomic_read(&host->rtx_msg_bytes);
		// if(READ_ONCE(epoch->round) == 0)
		//      atomic_set(&(dcpim_sk)(ftemp->sock)->sender.matched, 0);
		// /* the flow has already been matched */
		// if(READ_ONCE(epoch->round) != 0 && atomic_read(&(dcpim_sk)(ftemp->sock)->sender.matched))
		//      continue;
		flow_size = total_flow_size;
		/* for prompt transmission optimization */
		// prompt_flow_size = total_prompt_flow_size;
		if(host->sk == NULL)
			goto unlock_host;
		for(i = 0; i < epoch->k; i++) {
			// rtx_channel = false;
			rts_size = min(epoch->epoch_bytes_per_k, flow_size);
			// prompt_size = min(rts_size, prompt_flow_size);
			// if(rtx_size > 0) {
			// 	rtx_channel = true;
			// 	rtx_size -= rts_size;
			// }
			inet = inet_sk(host->sk);
			skb = construct_rts_pkt(host->sk, epoch->round, epoch->epoch, rts_size, 0, 1);
			dcpim_fill_dcpim_header(skb, htons(epoch->port), htons(epoch->port));
			dcpim_fill_dst_entry(host->sk, skb,&inet->cork.fl);
			dcpim_fill_ip_header(skb, host->src_ip, host->dst_ip);
			err = ip_local_out(sock_net(host->sk), host->sk, skb);
			flow_size -= rts_size;
			// if(prompt_size > 0)
			// 	prompt_flow_size -= prompt_size;
			if(flow_size <= 0)
					break;
			epoch->port = (epoch->port + 1) % epoch->port_range;
		}
unlock_host:
				// __ip_queue_xmit(ftemp->sock, skb, &inet->cork.fl, IPTOS_LOWDELAY | IPTOS_PREC_NETCONTROL);
		spin_unlock_bh(&host->lock);
	}
	rcu_read_unlock();
unlock_receiver:
	spin_unlock_bh(&epoch->receiver_lock);
}

int dcpim_handle_rts (struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct dcpim_rts_hdr *rh;
	struct iphdr *iph;
	// struct sock* sk;
	struct dcpim_rts *rts;
	struct dcpim_host *host, *temp_host = NULL;
	// bool refcounted = false;
	// int sdif = inet_sdif(skb);
	int rts_index, flow_size;
	struct sk_buff *temp = NULL;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_rts_hdr)))
		goto drop;		/* No space for header. */
	rh = dcpim_rts_hdr(skb);
	if(rh->remaining_sz == 0)
		goto drop;
	iph = ip_hdr(skb);
	/* TO DO: check round number and epoch number */
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	if(!host)
		goto drop;
	spin_lock(&epoch->sender_lock);
	if(host->rts_index >= 0 && 
		host->rts->host == host && 
			host->rts_index < epoch->rts_size) {
		rts = &epoch->rts_array[host->rts_index];
		if(rts->skb_size < epoch->k) {
			rts->remaining_sz += rh->remaining_sz;
			if(rh->prompt_channel)
				rts->prompt_remaining_sz += rh->remaining_sz;
			rts->rtx_channel = atomic_read(&host->rtx_msg_size);;
		} else {
			kfree_skb(skb);
			goto unlock_sender;
		}
	} else {
		rts_index = epoch->rts_size;
		flow_size = atomic_read(&host->total_unsent_bytes);
		if(flow_size % epoch->epoch_bytes_per_k != 0)
			flow_size = (flow_size / epoch->epoch_bytes_per_k + 1) *  epoch->epoch_bytes_per_k; 
		if(flow_size == 0) {
			kfree_skb(skb);
			goto unlock_sender;
		}
		// printk("rts_index:%d\n", rts_index);
		// iph = ip_hdr(skb);
		if(rts_index < epoch->max_array_size) {
			rts = &epoch->rts_array[rts_index];
			rts->skb_size = 0;
			rts->remaining_sz = rh->remaining_sz;
			if(rh->prompt_channel)
				rts->prompt_remaining_sz += rh->remaining_sz;
			rts->flow_size = flow_size;
			rts->rtx_channel = atomic_read(&host->rtx_msg_size);;
			temp_host = rts->host;
			rts->host = host;
			dcpim_host_hold(host);
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
			goto unlock_sender;
		}
	}
	/* add new control packet */
	dcpim_modify_ctrl_pkt(skb, GRANT, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round), true);
	temp = rts->skb_arr[rts->skb_size];
	rts->skb_arr[rts->skb_size] = skb;
	rts->skb_size++;
	// printk("rts->skb_size:%d\n", rts->skb_size);
unlock_sender:
	spin_unlock(&epoch->sender_lock);

	if(temp != NULL)
		kfree_skb(temp);
	if(temp_host != NULL)
		dcpim_host_put(temp_host);
	dcpim_host_put(host);

	return 0;
drop:
	kfree_skb(skb);
	return 0;
}

void dcpim_handle_all_rts(struct dcpim_epoch *epoch) {
	struct dcpim_rts *rts;
	int sent_bytes = 0, prompt_sent_bytes = 0;
	int cur_sent_bytes = 0;
	int cur_k = 0;
	int remaining_rts_size;
	int index = 0;
	int unmatched_sent_bytes = atomic_read(&epoch->unmatched_sent_bytes);
	int unmatched_prompt_sent_bytes = atomic_read(&epoch->last_unmatched_sent_bytes);
	int rts_size = 0, i = 0;
	bool rtx_channel = false, prompt_channel = false;
	struct dcpim_sock *dsk, *temp;
	struct dcpim_host *host;
	u16 src_port = 0, dst_port = 0;
	bool find = false;
	int num_flows = 0;
	spin_lock_bh(&epoch->sender_lock);
	rts_size = epoch->rts_size;

	if(rts_size > epoch->max_array_size)
		rts_size = epoch->max_array_size;
	remaining_rts_size = rts_size;
	while(1) {
		rtx_channel = false;
		/* for prompt optimization */
		prompt_channel = false;
		if(remaining_rts_size <= 0 || unmatched_sent_bytes <= sent_bytes)
			break;
		// printk("index:%d\n", index);
		index = get_random_u32() % rts_size;
		rts = &epoch->rts_array[index];
		if(rts->remaining_sz <= 0 || rts->flow_size <= 0) {
			continue;
		}	
		// printk("index:%d, rts->remaning_sz:%d, remaining_rts_size:%d unmatched_sent_bytes:%d sent_bytes:%d, rts->epoch:%llu, rts->round:%u \n",
			// index, rts->remaining_sz, remaining_rts_size, unmatched_sent_bytes, sent_bytes, rts->epoch, rts->round);
		cur_sent_bytes = epoch->epoch_bytes_per_k;
		// cur_sent_bytes= min(rts->flow_size, cur_sent_bytes);
		/* priortize short message retransmission first */
		if(rts->rtx_channel > 0) {
			rtx_channel = true;
			rts->rtx_channel -= 1;
			src_port = 0;
			dst_port = 0;
		} else {
			/* find long flow socket to match */
			host = rts->host;
			find = false;
			spin_lock(&host->lock);
			num_flows = host->num_long_flows;
			list_for_each_entry_safe(dsk, temp, &host->flow_list, entry) {
				// max_pacing_rate = min(epoch->max_pacing_rate_per_flow, host->next_pacing_rate);
				if(num_flows == 0)
					break;
				list_move_tail(&dsk->entry, &host->flow_list);
				if(READ_ONCE(((struct sock*)dsk)->sk_wmem_queued) > 0) {
					src_port = inet_sk((struct sock*)dsk)->inet_sport;	
					dst_port = inet_sk((struct sock*)dsk)->inet_dport;
					find = true;					
					break;
				}
				num_flows--;
				// host->next_pacing_rate -= max_pacing_rate;
			}
			spin_unlock(&host->lock);
			if(!find) {
				rts->remaining_sz = 0;
				rts->flow_size = 0;
				goto continue_loop;
			}

		}
		/* for prompt optimization */
		if (rts->prompt_remaining_sz && cur_sent_bytes + prompt_sent_bytes <= unmatched_prompt_sent_bytes) {
			prompt_channel = true;
			prompt_sent_bytes += cur_sent_bytes;
			rts->prompt_remaining_sz -= cur_sent_bytes;
		}
		dcpim_modify_ctrl_pkt_size(rts->skb_arr[rts->skb_size - 1], cur_sent_bytes, rtx_channel, prompt_channel, src_port, dst_port);
		epoch->rts_skb_array[cur_k] = rts->skb_arr[rts->skb_size - 1];
		cur_k += 1;
		rts->skb_arr[rts->skb_size - 1] = NULL;
		rts->skb_size--;

		sent_bytes += cur_sent_bytes;
		rts->remaining_sz -= cur_sent_bytes;
		rts->flow_size -= cur_sent_bytes;
continue_loop:
		if(rts->remaining_sz <= 0 || rts->flow_size <= 0)
			remaining_rts_size -= 1;
	}
	epoch->rts_size = 0;
	spin_unlock_bh(&epoch->sender_lock);
	for (i = 0; i < cur_k; i++) {
		/* need to add error checking */
		dev_queue_xmit(epoch->rts_skb_array[i]);
	}
}

int dcpim_handle_grant(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct dcpim_host *host, *temp_host = NULL;
	struct dcpim_grant_hdr *gh;
	struct dcpim_grant *grant;
	struct iphdr *iph;
	int grant_index = 0;
	struct sk_buff *temp = NULL;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_grant_hdr)))
		goto drop;		/* No space for header. */
	gh = dcpim_grant_hdr(skb);
	// printk("handle grant grant_hdr->source: %d grant_hdr->dest: %d  __dcpim_hdrlen(&grant_hdr->common):%d sdif:%d\n",
	// 	ntohs(gh->source), ntohs(gh->dest),  __dcpim_hdrlen(&gh->common), inet_sdif(skb));
	// printk("srcip: %d dstip: %d\n", ip_hdr(skb)->saddr, ip_hdr(skb)->daddr);
	/* TO DO: check round number and epoch number after time is synced */
	// sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&gh->common), gh->common.source,
    //         gh->common.dest, sdif, &refcounted);
	// if(!sk)
	// 	goto drop;

	iph = ip_hdr(skb);
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	if(!host)
		goto drop;
	spin_lock(&epoch->receiver_lock);
	if(host->grant_index >= 0 && 
		host->grant->host == host && 
		host->grant_index < epoch->grant_size) {
		grant = &epoch->grants_array[host->grant_index];
		if(grant->skb_size < epoch->k) {
			grant->remaining_sz += gh->remaining_sz;
			if(gh->prompt_channel)
				grant->prompt_remaining_sz += gh->remaining_sz;
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
			if(gh->prompt_channel)
				grant->prompt_remaining_sz += gh->remaining_sz;
			temp_host = grant->host;
			grant->host = host;
			dcpim_host_hold(host);
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
	// dcpim_modify_ctrl_pkt(skb, ACCEPT, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round), true);
	temp = grant->skb_arr[grant->skb_size];
	grant->skb_arr[grant->skb_size] = skb;
	grant->skb_size++;
unlock_receiver:
	spin_unlock(&epoch->receiver_lock);
	if(temp != NULL)
		kfree_skb(temp);
	if(temp_host != NULL)
		dcpim_host_put(temp_host);
	dcpim_host_put(host);
	return 0;
drop:
	kfree_skb(skb);
	return 0;
}

void dcpim_handle_all_grants(struct dcpim_epoch *epoch) {
	struct dcpim_sock *dsk;
	struct dcpim_grant *grant;
	struct dcpim_grant_hdr *grant_hdr;
	// struct dcpim_host *host;
	struct sk_buff *skb, *grant_skb, *temp;
	struct sock* sk;
	int recv_bytes = 0, prompt_recv_bytes = 0;
	int cur_recv_bytes = 0;
	int cur_k = 0;
	int i = 0;
	int index = 0;
	int grant_size;
	int remaining_grant_size;
	bool rtx_channel = false, prompt_channel = false;
	bool refcounted = false;
	// struct dcpim_flow* flow;
	spin_lock_bh(&epoch->receiver_lock);
	grant_size = epoch->grant_size;
	// struct sk_buff *head_skb = NULL, *skb;
	if(grant_size > epoch->max_array_size)
		grant_size = epoch->max_array_size;
	remaining_grant_size = grant_size;
	while(1) {
		rtx_channel = false;
		/* for prompt optimization */
		prompt_channel = false;
		if(remaining_grant_size <= 0 || epoch->unmatched_recv_bytes <= recv_bytes)
			break;
		index = get_random_u32() % grant_size;
		grant = &epoch->grants_array[index];
		if (grant->remaining_sz <= 0) {
			continue;
		}
		cur_recv_bytes = epoch->epoch_bytes_per_k;
		/* find corresponding long flow socket to grant channel */
		sk = NULL;
		if(grant->rtx_channel > 0) {
			for(int i = grant->skb_size - 1; i >= 0; i--) {
				grant_skb = grant->skb_arr[i];
				grant_hdr = dcpim_grant_hdr(grant_skb);
				if(grant_hdr->rtx_channel == 0) {
					continue;
				}
				if (i == grant->skb_size - 1) {
					break;
				} else {
					/* swap the rtx grant to the last entry */
					temp = grant->skb_arr[grant->skb_size - 1];
					grant->skb_arr[grant->skb_size - 1] = grant_skb;
					grant->skb_arr[i] = temp;
				}
			}
			WARN_ON(grant_hdr->rtx_channel == 0);
			rtx_channel = true;
			grant->rtx_channel -= 1;
		} else {
			grant_skb = grant->skb_arr[grant->skb_size - 1];
			grant_hdr = dcpim_grant_hdr(grant_skb);
			sk = __inet_lookup_skb(&dcpim_hashinfo, grant_skb, __dcpim_hdrlen(&grant_hdr->common), grant_hdr->source,
				grant_hdr->dest, inet_sdif(grant_skb), &refcounted);
			if(!sk || sk->sk_state  != DCPIM_ESTABLISHED) {
				kfree_skb(grant_skb);
				if(refcounted) {
					sock_put(sk);
				}
				goto free_skb;
			}
		} 
		/* check the number of channels we need; whether used for prompt */
		if(grant->prompt_remaining_sz > 0 && prompt_recv_bytes + cur_recv_bytes <= epoch->last_unmatched_recv_bytes) {
			prompt_channel = true;
			prompt_recv_bytes += cur_recv_bytes;
			grant->prompt_remaining_sz -= cur_recv_bytes;
		}
		// if(epoch->epoch % 1000 == 0) {
		// 	printk("accept per epoch: %llu\n", total_accepts * 100/ (epoch->epoch - init_epoch));

		// }
		/* update accept array */
		// epoch->accept_array[cur_k].host = grant->host;
		epoch->accept_array[cur_k].rtx_channel = rtx_channel;
		epoch->accept_array[cur_k].remaining_sz = cur_recv_bytes;
		epoch->accept_array[cur_k].prompt_channel = prompt_channel;
		if(sk != NULL) {
			epoch->accept_array[cur_k].dsk = dcpim_sk(sk);
		}
		// dcpim_host_hold(grant->host);
		dcpim_modify_ctrl_pkt(grant->skb_arr[grant->skb_size - 1], ACCEPT, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round), true);
		dcpim_modify_ctrl_pkt_size(grant->skb_arr[grant->skb_size - 1], cur_recv_bytes, rtx_channel, prompt_channel, 0, 0);
		epoch->grant_skb_array[cur_k] = grant->skb_arr[grant->skb_size - 1];
		recv_bytes += cur_recv_bytes;
		cur_k += 1;
free_skb:
		/* update the metadata state */
		grant->skb_arr[grant->skb_size - 1] = NULL;
		grant->skb_size--;
		// kfree_skb(skb);
		grant->remaining_sz -= cur_recv_bytes;
		if(grant->remaining_sz <= 0) {
			remaining_grant_size -= 1;
		}
	}
	epoch->unmatched_recv_bytes -= recv_bytes;
	epoch->last_unmatched_recv_bytes -= prompt_recv_bytes;
	epoch->grant_size = 0;
	spin_unlock_bh(&epoch->receiver_lock);
	/* update matched array */
    spin_lock_bh(&epoch->matched_lock);
	for (i = 0; i < cur_k; i++) {
		// host = epoch->accept_array[i].host;
        /* only count long flow transmission rate */
        if(epoch->accept_array[i].rtx_channel == 0) {
			dsk = epoch->accept_array[i].dsk;
			WARN_ON_ONCE(dsk == NULL);
			if(epoch->next_matched_flows < epoch->k) {
				epoch->next_matched_arr[epoch->next_matched_flows] = dsk;
				epoch->next_matched_flows += 1;
				WRITE_ONCE(dsk->receiver.next_pacing_rate, READ_ONCE(dsk->receiver.next_pacing_rate) +  epoch->rate_per_channel);
				/* perform prompt optimization */
				if(epoch->accept_array[i].prompt_channel) {
					// max_pacing_rate = min(epoch->max_pacing_rate_per_flow, host->next_pacing_rate);
					atomic64_set(&dsk->receiver.pacing_rate, atomic64_read(&dsk->receiver.pacing_rate) + epoch->rate_per_channel);
					if(atomic_cmpxchg(&dsk->receiver.token_work_status, 0, 1) == 0) {
						sock_hold((struct sock*)dsk);
						queue_work_on(dsk->core_id, dcpim_wq, &dsk->receiver.token_work);
					}
				
				}
			} else {
				WARN_ON_ONCE(true);
				sock_put((struct sock*)dsk);
			}
		} else {
			/* To Do: check if we can send the rtx token directly if the channel is prompt. */
            if(epoch->rtx_msg_size < epoch->k) {
				skb = skb_copy(epoch->grant_skb_array[i], GFP_ATOMIC);
                dcpim_modify_ctrl_pkt(skb, RTX_MSG, READ_ONCE(epoch->epoch), READ_ONCE(epoch->round), false);
                dcpim_modify_ctrl_pkt_size(skb,  epoch->accept_array[i].remaining_sz, true, true, 0, 0);
                epoch->rtx_msg_array[epoch->rtx_msg_size] = skb;
                epoch->rtx_msg_size += 1; 
            } else {
                WARN_ON(true);
            }
			// dcpim_host_put(host);
        }
	}
    spin_unlock_bh(&epoch->matched_lock);
	for (i = 0; i < cur_k; i++) {
		/* need to add error checking here */
		dev_queue_xmit(epoch->grant_skb_array[i]);
	}
}

int dcpim_handle_accept(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct dcpim_host *host;
	struct dcpim_accept_hdr *ah;
	struct iphdr *iph;
	bool skip_free = true;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_accept_hdr)))
		goto drop;		/* No space for header. */

	ah = dcpim_accept_hdr(skb);
	iph = ip_hdr(skb);
	host = dcpim_host_find_rcu(epoch, iph->daddr, iph->saddr);
	if(!host)
		goto drop;
	atomic_sub_return(ah->remaining_sz, &epoch->unmatched_sent_bytes);
	if(ah->prompt_channel)
		atomic_sub_return(ah->remaining_sz, &epoch->last_unmatched_sent_bytes);
	/* To Do: add optimization to avoid over-provisioning # channels in one epoch */
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
	if(host) {
		spin_lock(&host->lock);
		list_for_each_entry_safe(dsk, temp, &host->short_flow_list, entry) {
			if(dsk->sender.num_rtx_msgs > 0) {
				atomic_add(1, &dsk->sender.rtx_msg_size);
				/* To Do: add socket refcnt */
				queue_work_on(dsk->core_id, dcpim_wq, &dsk->sender.rtx_msg_work);
				list_move_tail(&dsk->entry, &host->short_flow_list);
				break;
			}
			// host->next_pacing_rate -= max_pacing_rate;
		}
		spin_unlock(&host->lock);
		dcpim_host_put(host);
	}
drop:
	kfree_skb(skb);

	return 0;
}
