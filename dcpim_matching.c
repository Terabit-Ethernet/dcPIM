#include "dcpim_impl.h"
// static void recevier_iter_event_handler(struct work_struct *work);
// static void sender_iter_event_handler(struct work_struct *work);
// __u64 js, je;

struct dcpim_sock* fake_sk;

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
	epoch->round += 1;
	if(epoch->round >= dcpim_params.num_rounds) {
		// epoch->cur_match_src_addr = epoch->match_src_addr;
		// epoch->cur_match_dst_addr = epoch->match_dst_addr;
		epoch->cur_epoch = epoch->epoch;
		epoch->round = 0;
		epoch->epoch += 1;
		// spin_lock_bh(&epoch->sender_lock);
		WRITE_ONCE(epoch->unmatched_sent_bytes, epoch->epoch_bytes);
		// spin_unlock_bh(&epoch->sender_lock);
		// spin_lock_bh(&epoch->receiver_lock);
		atomic_set(&epoch->unmatched_recv_bytes, epoch->epoch_bytes);
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

void dcpim_match_entry_init(struct dcpim_match_entry* entry, __be32 addr, 
 bool(*comp)(const struct list_head*, const struct list_head*)) {
	spin_lock_init(&entry->lock);
	dcpim_pq_init(&entry->pq, comp);
	INIT_HLIST_NODE(&entry->hash_link);
	INIT_LIST_HEAD(&entry->list_link);
	// struct dcpim_peer *peer;
	entry->dst_addr = addr;
}

void dcpim_mattab_init(struct dcpim_match_tab *table,
	bool(*comp)(const struct list_head*, const struct list_head*)) {
	int i;
	// int ret, opt;
	// struct dcpim_peer *peer;
	// struct inet_sock *inet;
	spin_lock_init(&table->lock);
	INIT_LIST_HEAD(&table->hash_list);

	table->comp = comp;
	printk("size of match entry: %lu\n", sizeof(struct dcpim_match_entry));
	table->buckets = kmalloc(sizeof(struct dcpim_match_slot) * DCPIM_BUCKETS, GFP_KERNEL);
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		spin_lock_init(&table->buckets[i].lock);
		INIT_HLIST_HEAD(&table->buckets[i].head);
		table->buckets[i].count = 0;
	}
	// inet = inet_sk(table->sock->sk);
	// peer =  dcpim_peer_find(&dcpim_peers_table, 167772169, inet);
	// dcpim_xmit_control(construct_rts_pkt(table->sock->sk, 1, 2, 3), peer, table->sock->sk, 3000);

	return;
}

void dcpim_mattab_destroy(struct dcpim_match_tab *table) {
	int i = 0, j = 0;
	struct dcpim_match_slot *bucket = NULL;
	struct dcpim_match_entry *entry;
	struct hlist_node *n;
	printk("start to remove match table\n");
	for (i = 0; i < DCPIM_BUCKETS; i++) {
		bucket = &table->buckets[i];
		spin_lock_bh(&bucket->lock);
		for (j = 0; j < bucket->count; j++) {
			hlist_for_each_entry_safe(entry, n, &bucket->head, hash_link) {
				printk("kfree an entry\n");

				kfree(entry);
			}
		}
		spin_unlock_bh(&bucket->lock);
	}
	printk("finish remove match table\n");

	// sock_release(table->sock);
	kfree(table->buckets);
	return;
}

// lock order: bucket_lock > other two locks
void dcpim_mattab_add_new_sock(struct dcpim_match_tab *table, struct sock* sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct inet_sock *inet = inet_sk(sk); 
	struct dcpim_match_slot *bucket = dcpim_match_bucket(table, inet->inet_daddr);
	struct dcpim_match_entry *match_entry = NULL;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == inet->inet_daddr) {
			spin_lock(&match_entry->lock);
			dcpim_pq_push(&match_entry->pq, &dsk->match_link);
			spin_unlock(&match_entry->lock);
			spin_unlock_bh(&bucket->lock);
			return;
		}
		// INC_METRIC(peer_hash_links, 1);
	}

	// create new match entry
	match_entry = kmalloc(sizeof(struct dcpim_match_entry), GFP_KERNEL);
	dcpim_match_entry_init(match_entry, inet->inet_daddr, table->comp);
	dcpim_pq_push(&match_entry->pq, &dsk->match_link);
	hlist_add_head(&match_entry->hash_link, &bucket->head);
	bucket->count += 1;
	// add this entry to the hash list
	spin_lock(&table->lock);
	list_add_tail(&match_entry->list_link, &table->hash_list);
	spin_unlock(&table->lock);

	spin_unlock_bh(&bucket->lock);
}

void dcpim_mattab_delete_sock(struct dcpim_match_tab *table, struct sock* sk) {
	struct dcpim_sock *dsk = dcpim_sk(sk);
	struct inet_sock *inet = inet_sk(sk); 
	struct dcpim_match_slot *bucket = dcpim_match_bucket(table, inet->inet_daddr);
	struct dcpim_match_entry *match_entry = NULL;
	// bool empty = false;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == inet->inet_daddr) {
			break;
		}
		// INC_METRIC(peer_hash_links, 1);
	}
	if(match_entry != NULL) {
		spin_lock(&match_entry->lock);
		// assume the msg still in the list, which might not be true'
		dcpim_pq_delete(&match_entry->pq, &dsk->match_link);
		spin_unlock(&match_entry->lock);
	}

	spin_unlock_bh(&bucket->lock);

}

void dcpim_mattab_delete_match_entry(struct dcpim_match_tab *table, struct dcpim_match_entry* entry) {
	return;
}

void dcpim_epoch_init(struct dcpim_epoch *epoch) {
	// int ret;
	// ktime_t now;
	// s64 time;
	// struct inet_sock *inet;
	// struct dcpim_peer* peer;
	epoch->epoch = 0;
	epoch->round = 0;
	epoch->k = 4;
	epoch->prompt = false;
	epoch->max_array_size = 200;
	// epoch->match_src_addr = 0;
	// epoch->match_dst_addr = 0;
	// epoch->matched_k = 0;
	// epoch->min_rts = NULL;
	// epoch->min_grant = NULL;
	epoch->epoch_length = dcpim_params.epoch_length;
	epoch->round_length = dcpim_params.round_length;
	epoch->epoch_bytes_per_k = epoch->epoch_length * dcpim_params.bandwidth / 8 / epoch->k;
	epoch->epoch_bytes = epoch->epoch_bytes_per_k * epoch->k;
	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	// epoch->start_cycle = 0;
	epoch->rts_array = kmalloc(sizeof(struct dcpim_rts) * epoch->max_array_size, GFP_KERNEL);
	epoch->grants_array = kmalloc(sizeof(struct dcpim_grant) * epoch->max_array_size, GFP_KERNEL);

	// current epoch and address
	epoch->cur_epoch = 0;
	// epoch->cur_match_src_addr = 0;
	// epoch->cur_match_dst_addr = 0;
	epoch->cpu = 28;
	// ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM, &epoch->sock);
	// inet = inet_sk(epoch->sock->sk);
	// peer =  dcpim_peer_find(&dcpim_peers_table, 167772169, inet);

	// if(ret) {
	// 	printk("fail to create socket\n");
	// 	return;
	// }
	spin_lock_init(&epoch->lock);
	spin_lock_init(&epoch->sender_lock);
	spin_lock_init(&epoch->receiver_lock);

	/* token xmit timer*/
	// atomic_set(&epoch->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);

	// hrtimer_init(&epoch->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// epoch->token_xmit_timer.function = &dcpim_token_xmit_event;

	// INIT_WORK(&epoch->token_xmit_struct, dcpim_xmit_token_handler);
	/* pHost Queue */
	dcpim_pq_init(&epoch->flow_q, flow_compare);




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
	hrtimer_cancel(&epoch->sender_round_timer);
	hrtimer_cancel(&epoch->receiver_round_timer);
	flush_workqueue(epoch->wq);
	destroy_workqueue(epoch->wq);
	spin_lock_bh(&epoch->lock);
	// sk = epoch->sock;
	epoch->sock = NULL;
	spin_unlock_bh(&epoch->lock);
	kfree(epoch->grants_array);
	kfree(epoch->rts_array);
	epoch->grants_array = NULL;
	epoch->rts_array = NULL;
	/* dcpim_destroy_sock needs to hold the epoch lock */
    // sock_release(sk);

}
void dcpim_send_all_rts (struct dcpim_epoch* epoch) {
	// struct dcpim_match_entry *entry = NULL;
 	// struct dcpim_peer *peer;
	// struct inet_sock *inet;
	// struct sk_buff* pkt;

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
			dcpim_xmit_control(construct_rts_pkt((struct sock*)fake_sk, 
				epoch->round, epoch->epoch, 50000), (struct sock*)fake_sk);
		// }
		// spin_unlock(&entry->lock);
	// }
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
	// struct iphdr *iph;
	struct sock* sk;
	bool refcounted = false;
	int sdif = inet_sdif(skb);
	int rts_index;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_rts_hdr)))
		goto drop;		/* No space for header. */
	// spin_lock_bh(&epoch->lock);
	// if(epoch->sock == NULL) {
		// spin_unlock_bh(&epoch->lock);
		// goto drop;
	// }
	if(!sk)
		goto drop;
	rh = dcpim_rts_hdr(skb);
	/* TO DO: check round number and epoch number */
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&rh->common), rh->common.source,
            rh->common.dest, sdif, &refcounted);
	if(!sk)
		goto drop;
	rts_index = atomic_inc_return(&epoch->rts_size);
	// iph = ip_hdr(skb);
	if(rts_index <= epoch->max_array_size) {
		epoch->rts_array[rts_index].remaining_sz = rh->remaining_sz;
		epoch->rts_array[rts_index].dsk = dcpim_sk(sk);
	} else {
		atomic_dec(&epoch->rts_size);
	}
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
    if (refcounted) {
        sock_put(sk);
    }
drop:
	kfree_skb(skb);
	return 0;
}

void dcpim_handle_all_rts(struct dcpim_epoch *epoch) {
	struct dcpim_rts *rts;
	int recv_bytes = 0;
	int cur_recv_bytes = 0;
	int unmatched_recv_bytes = atomic_read(&epoch->unmatched_recv_bytes);
	int rts_size = atomic_read(&epoch->rts_size);
	int remaining_rts_size;
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
		if(remaining_rts_size <= 0 || unmatched_recv_bytes <= recv_bytes)
			break;
		rts = &epoch->rts_array[get_random_u32() % rts_size];
		if(rts->remaining_sz <= 0) {
			continue;
		}	
		cur_recv_bytes = max(rts->remaining_sz, epoch->epoch_bytes_per_k);
		// printk("send accept pkt:%d\n", __LINE__);
		cur_recv_bytes = min(unmatched_recv_bytes - recv_bytes, 
			(cur_recv_bytes / epoch->epoch_bytes_per_k) * epoch->epoch_bytes_per_k);
		dcpim_xmit_control(construct_grant_pkt((struct sock*)rts->dsk, 
			epoch->round, epoch->epoch, min(rts->remaining_sz, cur_recv_bytes), 0), (struct sock*)rts->dsk);
		recv_bytes += cur_recv_bytes;
		rts->remaining_sz -= cur_recv_bytes;
		if(rts->remaining_sz <= 0)
			remaining_rts_size -= 1;
	}
	atomic_set(&epoch->rts_size, 0);
	// }
	// epoch->min_rts = NULL;
}


int dcpim_handle_grant(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct sock* sk;
	struct dcpim_grant_hdr *gh;
	// struct iphdr *iph;
	bool refcounted = false;
	int sdif = inet_sdif(skb);
	int grant_index = 0;
	if (!pskb_may_pull(skb, sizeof(struct dcpim_grant_hdr)))
		goto drop;		/* No space for header. */
	gh = dcpim_grant_hdr(skb);
	/* TO DO: check round number and epoch number */
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&gh->common), gh->common.source,
            gh->common.dest, sdif, &refcounted);
	if(!sk)
		goto drop;
	// if(epoch->sock == NULL) {
	// 	spin_unlock_bh(&epoch->lock);
	// 	goto drop;
	// }
	// grant = kmalloc(sizeof(struct dcpim_grant), GFP_KERNEL);
	// INIT_LIST_HEAD(&grant->entry);
	// iph = ip_hdr(skb);
	grant_index = atomic_inc_return(&epoch->grant_size);
	if(grant_index <= epoch->max_array_size) {
		epoch->grants_array[grant_index - 1].remaining_sz = gh->remaining_sz;
		epoch->grants_array[grant_index - 1].dsk = dcpim_sk(sk);
	} else {
		atomic_dec(&epoch->grant_size);
	}
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
	if(refcounted) {
		sock_put(sk);
	}
drop:
	kfree_skb(skb);

	return 0;
}

void dcpim_handle_all_grants(struct dcpim_epoch *epoch) {
	struct dcpim_grant *grant;
	int sent_bytes = 0;
	int cur_sent_bytes = 0;
	int grant_size = atomic_read(&epoch->grant_size);
	int remaining_grant_size;
	if(grant_size > epoch->max_array_size)
		grant_size = epoch->max_array_size;
	remaining_grant_size = grant_size;
	while(1) {
		if(remaining_grant_size <= 0 || epoch->unmatched_sent_bytes <= sent_bytes)
			break;
		grant = &epoch->grants_array[get_random_u32() % grant_size];
		if (grant->remaining_sz <= 0) {
			continue;
		}
		cur_sent_bytes = max(grant->remaining_sz, epoch->epoch_bytes_per_k);
		// printk("send accept pkt:%d\n", __LINE__);
		cur_sent_bytes = min(epoch->unmatched_sent_bytes - sent_bytes, 
			(cur_sent_bytes / epoch->epoch_bytes_per_k) * epoch->epoch_bytes_per_k);
		dcpim_xmit_control(construct_accept_pkt((struct sock*)grant->dsk, 
			epoch->round, epoch->epoch, min(grant->remaining_sz, cur_sent_bytes)), (struct sock*)grant->dsk);
		sent_bytes += cur_sent_bytes;
		grant->remaining_sz -= cur_sent_bytes;
		if(grant->remaining_sz <= 0)
			remaining_grant_size -= 1;
	}
	epoch->unmatched_sent_bytes -= sent_bytes;
	// epoch->grant_size = 0;
	// epoch->min_grant = NULL;
	atomic_set(&epoch->grant_size, 0);
	// spin_unlock_bh(&epoch->lock);
}

int dcpim_handle_accept(struct sk_buff *skb, struct dcpim_epoch *epoch) {
	struct sock* sk;
	struct dcpim_accept_hdr *ah;
	// struct iphdr *iph;
	bool refcounted = false;
	int sdif = inet_sdif(skb);
	if (!pskb_may_pull(skb, sizeof(struct dcpim_accept_hdr)))
		goto drop;		/* No space for header. */
	ah = dcpim_accept_hdr(skb);
	sk = __inet_lookup_skb(&dcpim_hashinfo, skb, __dcpim_hdrlen(&ah->common), ah->common.source,
            ah->common.dest, sdif, &refcounted);
	if(!sk)
		goto drop;

	// spin_lock_bh(&epoch->receiver_lock);
	/* TO DO: check round number and epoch number */
	int value = atomic_sub_return(ah->remaining_sz, &epoch->unmatched_recv_bytes);
	if(value < 0) {

	} else {
		
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
	if(refcounted) {
		sock_put(sk);
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
