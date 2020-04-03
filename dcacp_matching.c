#include "dcacp_impl.h"



void dcacp_match_entry_init(struct dcacp_match_entry* entry, __be32 addr, 
 bool(*comp)(const struct list_head*, const struct list_head*)) {
	spin_lock_init(&entry->lock);
	dcacp_pq_init(&entry->pq, comp);
	INIT_HLIST_NODE(&entry->hash_link);
	INIT_LIST_HEAD(&entry->list_link);
	// struct dcacp_peer *peer;
	entry->dst_addr = addr;
}

void dcacp_mattab_init(struct dcacp_match_tab *table,
	bool(*comp)(const struct list_head*, const struct list_head*)) {
	int i;
	int ret, opt;
	// struct dcacp_peer *peer;
	// struct inet_sock *inet;
	spin_lock_init(&table->lock);
	INIT_LIST_HEAD(&table->hash_list);

	table->comp = comp;
	printk("size of match entry: %lu\n", sizeof(struct dcacp_match_entry));
	table->buckets = kmalloc(sizeof(struct dcacp_match_slot) * DCACP_MATCH_BUCKETS, GFP_KERNEL);
	for (i = 0; i < DCACP_MATCH_BUCKETS; i++) {
		spin_lock_init(&table->buckets[i].lock);
		INIT_HLIST_HEAD(&table->buckets[i].head);
		table->buckets[i].count = 0;
	}
	// inet = inet_sk(table->sock->sk);
	// peer =  dcacp_peer_find(&dcacp_peers_table, 167772169, inet);
	// dcacp_xmit_control(construct_rts_pkt(table->sock->sk, 1, 2, 3), peer, table->sock->sk, 3000);

	return;
}

void dcacp_mattab_destroy(struct dcacp_match_tab *table) {
	int i = 0, j = 0;
	struct dcacp_match_slot *bucket = NULL;
	struct dcacp_match_entry *entry;
	struct hlist_node *n;
	printk("start to remove match table\n");
	for (i = 0; i < DCACP_MATCH_BUCKETS; i++) {
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
void dcacp_mattab_add_new_message(struct dcacp_match_tab *table, struct dcacp_message_in* msg) {
	struct dcacp_match_slot *bucket = dcacp_match_bucket(table, msg->peer->addr);
	struct dcacp_match_entry *match_entry = NULL;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == msg->peer->addr) {
			spin_lock_bh(&match_entry->lock);
			dcacp_pq_push(&match_entry->pq, &msg->match_link);
			spin_unlock_bh(&match_entry->lock);
			spin_unlock_bh(&bucket->lock);
			return;
		}
		// INC_METRIC(peer_hash_links, 1);
	}

	// create new match entry
	match_entry = kmalloc(sizeof(struct dcacp_match_entry), GFP_KERNEL);
	dcacp_match_entry_init(match_entry, msg->peer->addr, table->comp);
	dcacp_pq_push(&match_entry->pq, &msg->match_link);
	hlist_add_head(&match_entry->hash_link, &bucket->head);
	bucket->count += 1;
	// add this entry to the hash list
	spin_lock_bh(&table->lock);
	list_add_tail(&match_entry->list_link, &table->hash_list);
	spin_unlock_bh(&table->lock);

	spin_unlock_bh(&bucket->lock);
}

void dcacp_mattab_delete_message(struct dcacp_match_tab *table, struct dcacp_message_in* msg) {
	struct dcacp_match_slot *bucket = dcacp_match_bucket(table, msg->peer->addr);
	struct dcacp_match_entry *match_entry = NULL;
	// bool empty = false;
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(match_entry, &bucket->head,
			hash_link) {
		if (match_entry->dst_addr == msg->peer->addr) {
			break;
		}
		// INC_METRIC(peer_hash_links, 1);
	}
	if(match_entry != NULL) {
		spin_lock_bh(&match_entry->lock);
		// assume the msg still in the list, which might not be true'
		dcacp_pq_delete(&match_entry->pq, &msg->match_link);
		spin_unlock_bh(&match_entry->lock);
	}

	spin_unlock_bh(&bucket->lock);

}

void dcacp_mattab_delete_match_entry(struct dcacp_match_tab *table, struct dcacp_match_entry* entry) {
	return;
}
void dcacp_epoch_init(struct dcacp_epoch *epoch) {
	int ret;
	struct inet_sock *inet;
	struct dcacp_peer* peer;
	epoch->epoch = 0;
	epoch->iter = 0;
	epoch->prompt = false;
	epoch->match_src_addr = 0;
	epoch->match_dst_addr = 0;
	INIT_LIST_HEAD(&epoch->rts_q);
	INIT_LIST_HEAD(&epoch->grants_q);
	epoch->grant_size = 0;
	epoch->rts_size = 0;
	epoch->min_rts = NULL;
	epoch->min_grant = NULL;
	// struct rte_timer epoch_timer;
	// struct rte_timer sender_iter_timers[10];
	// struct rte_timer receiver_iter_timers[10];
	// struct pim_timer_params pim_timer_params;
	epoch->start_cycle = 0;

	// current epoch and address
	epoch->cur_epoch = 0;
	epoch->cur_match_src_addr = 0;
	epoch->cur_match_dst_addr = 0;
	ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_DCACP, &epoch->sock);
	inet = inet_sk(epoch->sock->sk);
	peer =  dcacp_peer_find(&dcacp_peers_table, 167772169, inet);

	if(ret) {
		printk("fail to create socket\n");
		return;
	}
	spin_lock_init(&epoch->lock);

	hrtimer_init(&epoch->epoch_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->sender_iter_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_init(&epoch->receiver_iter_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_start(&epoch->epoch_timer, ktime_set(0, 5000000), HRTIMER_MODE_ABS);
	epoch->epoch_timer.function = &dcacp_new_epoch;
}

void dcacp_epoch_destroy(struct dcacp_epoch *epoch) {
	struct dcacp_rts *rts, *temp;
	struct dcacp_grant *grant, *temp2;
	hrtimer_cancel(&epoch->epoch_timer);
	hrtimer_cancel(&epoch->sender_iter_timer);
	hrtimer_cancel(&epoch->receiver_iter_timer);
	spin_lock_bh(&epoch->lock);
	list_for_each_entry_safe(rts, temp, &epoch->rts_q, list_link) {
		kfree(rts);
	}
	list_for_each_entry_safe(grant, temp2, &epoch->grants_q, list_link) {
		kfree(grant);
	}
    sock_release(epoch->sock);
    epoch->sock = NULL;
	spin_unlock_bh(&epoch->lock);


}
void dcacp_send_all_rts (struct dcacp_match_tab *table, struct dcacp_epoch* epoch) {
	struct dcacp_match_entry *entry = NULL;
 	struct dcacp_peer *peer;
	struct inet_sock *inet;
	spin_lock(&table->lock);
	struct sk_buff* pkt;
	list_for_each_entry(entry, &table->hash_list, list_link) {
		struct list_head *list_head = NULL;
		struct dcacp_message_in *msg = NULL;
		spin_lock(&entry->lock);
		list_head = dcacp_pq_peek(&entry->pq);
		if(list_head != NULL) {
			// don't need to hold msg lock, beacuase holding the priority lock
			msg = list_entry(list_head, struct dcacp_message_in, match_link);
			// send rts
			dcacp_xmit_control(construct_rts_pkt(epoch->sock->sk, 
				epoch->iter, epoch->epoch, msg->total_length), 
				msg->peer, epoch->sock->sk, dcacp_params.match_socket_port);
		}
		spin_unlock(&entry->lock);
	}
	if(epoch->sock != NULL) {
		inet = inet_sk(epoch->sock->sk);
		// printk("inet is null: %d\n", inet == NULL);
		peer =  dcacp_peer_find(&dcacp_peers_table, 167772169, inet);
		pkt = construct_rts_pkt(epoch->sock->sk, epoch->iter, epoch->epoch, 3);
		dcacp_xmit_control(pkt, peer, epoch->sock->sk, 3000);

	}


	spin_unlock(&table->lock);

}

// void dcacp_send_rts (struct dcacp_message_in *msg) {

// }

int dcacp_handle_rts (struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch) {
	struct dcacp_rts *rts;

	struct dcacp_rts_hdr *rh;
	struct iphdr *iph;
	if (!pskb_may_pull(skb, sizeof(struct dcacp_rts_hdr)))
		goto drop;		/* No space for header. */
	spin_lock_bh(&epoch->lock);
	if(epoch->sock == NULL) {
		spin_unlock_bh(&epoch->lock);
		goto drop;
	}
	rts = kmalloc(sizeof(struct dcacp_rts), GFP_KERNEL);
	INIT_LIST_HEAD(&rts->list_link);
	iph = ip_hdr(skb);
	rh = dcacp_rts_hdr(skb);
	rts->remaining_sz = rh->remaining_sz;

	// rts->epoch = rh->epoch; 
	// rts->iter = rh->iter;
	rts->peer = dcacp_peer_find(&dcacp_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
	// spin_lock_bh(&epoch->lock);
	if (epoch->min_rts == NULL || epoch->min_rts->remaining_sz > rts->remaining_sz) {
		epoch->min_rts = rts;
	}
	list_add_tail(&rts->list_link, &epoch->rts_q);
	epoch->rts_size += 1;
	spin_unlock_bh(&epoch->lock);

drop:
	kfree_skb(skb);
	return 0;
}

void dcacp_handle_all_rts(struct dcacp_match_tab* table, struct dcacp_epoch *epoch) {
	struct dcacp_rts *rts, *temp;
	// spin_lock_bh(&epoch->lock);
	if(epoch->match_dst_addr == 0  && epoch->rts_size > 0) {
		if (dcacp_params.min_iter >= epoch->iter) {
			dcacp_xmit_control(construct_grant_pkt(epoch->sock->sk, 
				epoch->iter, epoch->epoch, epoch->min_rts->remaining_sz, epoch->cur_match_dst_addr == 0), 
				epoch->min_rts->peer, epoch->sock->sk, dcacp_params.match_socket_port);	
		} else {
			uint32_t index = 0;
			uint32_t i = 0;
			index = get_random_u32() % epoch->rts_size;
			list_for_each_entry(rts, &epoch->rts_q, list_link) {
				if (i == index) {
					dcacp_xmit_control(construct_grant_pkt(epoch->sock->sk, 
						epoch->iter, epoch->epoch, rts->remaining_sz, epoch->cur_match_dst_addr == 0), 
						rts->peer, epoch->sock->sk, dcacp_params.match_socket_port);
					break;
				}
				i += 1;
			}
		}
	}
	epoch->rts_size = 0;
	epoch->min_rts = NULL;
	list_for_each_entry_safe(rts, temp, &epoch->rts_q, list_link) {
		kfree(rts);
	}
	INIT_LIST_HEAD(&epoch->rts_q);
	// spin_unlock_bh(&epoch->lock);
}


int dcacp_handle_grant(struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch) {
	struct dcacp_grant *grant;

	struct dcacp_grant_hdr *gh;
	struct iphdr *iph;
	if (!pskb_may_pull(skb, sizeof(struct dcacp_grant_hdr)))
		goto drop;		/* No space for header. */
	spin_lock_bh(&epoch->lock);
	if(epoch->sock == NULL) {
		spin_unlock_bh(&epoch->lock);
		goto drop;
	}
	grant = kmalloc(sizeof(struct dcacp_grant), GFP_KERNEL);
	INIT_LIST_HEAD(&grant->list_link);
	iph = ip_hdr(skb);
	gh = dcacp_grant_hdr(skb);

	grant->remaining_sz = gh->remaining_sz;
	// grant->epoch = gh->epoch; 
	// grant->iter = gh->iter;
	grant->prompt = gh->prompt;
	grant->peer = dcacp_peer_find(&dcacp_peers_table, iph->saddr, inet_sk(epoch->sock->sk));
	if (epoch->min_grant == NULL || epoch->min_grant->remaining_sz > grant->remaining_sz) {
		epoch->min_grant = grant;
	}
	list_add_tail(&grant->list_link, &epoch->grants_q);
	epoch->grant_size += 1;
	spin_unlock_bh(&epoch->lock);

drop:
	kfree_skb(skb);

	return 0;
}

void dcacp_handle_all_grants(struct dcacp_match_tab *table, struct dcacp_epoch *epoch) {
	struct dcacp_grant *grant, *temp, *resp = NULL;
	// spin_lock_bh(&epoch->lock);

	if(epoch->match_src_addr == 0 && epoch->grant_size > 0) {
		if (dcacp_params.min_iter >= epoch->iter) {
			// printk("send accept pkt:%d\n", __LINE__);
			dcacp_xmit_control(construct_accept_pkt(epoch->sock->sk, 
				epoch->iter, epoch->epoch), 
				epoch->min_grant->peer, epoch->sock->sk, dcacp_params.match_socket_port);
			resp = epoch->min_grant;
		} else {
			uint32_t index = 0;
			uint32_t i = 0;
			index = get_random_u32() % epoch->grant_size;
			list_for_each_entry(grant, &epoch->grants_q, list_link) {
				printk("i:%d\n", i);
				if (i == index) {
					// printk("send accept pkt:%d\n", __LINE__);
					dcacp_xmit_control(construct_accept_pkt(epoch->sock->sk, 
						epoch->iter, epoch->epoch), 
						grant->peer, epoch->sock->sk, dcacp_params.match_socket_port);
					resp = grant;
					break;
				}
				i += 1;
			}
		}
		epoch->match_src_addr = resp->peer->addr;
		if(resp != NULL && resp->prompt) {
			epoch->cur_match_src_addr = resp->peer->addr;
		}
	}

	epoch->grant_size = 0;
	epoch->min_grant = NULL;

	list_for_each_entry_safe(grant, temp, &epoch->grants_q, list_link) {
		kfree(grant);

	}
	INIT_LIST_HEAD(&epoch->grants_q);
	// spin_unlock_bh(&epoch->lock);
}

int dcacp_handle_accept(struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch) {
	struct dcacp_accept_hdr *ah;
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(struct dcacp_accept_hdr)))
		goto drop;		/* No space for header. */
	iph = ip_hdr(skb);
	ah = dcacp_accept_hdr(skb);

	spin_lock_bh(&epoch->lock);
	if(epoch->match_dst_addr == 0)
		epoch->match_dst_addr = iph->saddr;
	spin_unlock_bh(&epoch->lock);

drop:
	kfree_skb(skb);
	return 0;
}

enum hrtimer_restart receiver_iter_event(struct hrtimer *timer) {
	// struct dcacp_grant* grant, temp;
 	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0, dcacp_params.iter_size));
	spin_lock(&dcacp_epoch.lock);
	if(dcacp_epoch.iter > 0) {
		dcacp_handle_all_grants(&dcacp_match_table, &dcacp_epoch);
	}
	// advance iteration
	dcacp_epoch.iter += 1;
	if(dcacp_epoch.iter > dcacp_params.num_iters) {
		dcacp_epoch.cur_match_src_addr = dcacp_epoch.match_src_addr;
		dcacp_epoch.cur_match_dst_addr = dcacp_epoch.match_dst_addr;
		dcacp_epoch.cur_epoch = dcacp_epoch.epoch;
		// dcacp_epoch->min_grant = NULL;
		// dcacp_epoch->grant_size = 0;
		// list_for_each_entry_safe(grant, temp, &epoch->grants_q, list_link) {
		// 	kfree(grant);
		// }
		spin_unlock(&dcacp_epoch.lock);
		return HRTIMER_NORESTART;
	} 
	dcacp_send_all_rts(&dcacp_match_table, &dcacp_epoch);
	spin_unlock(&dcacp_epoch.lock);
	return HRTIMER_RESTART;

}

enum hrtimer_restart sender_iter_event(struct hrtimer *timer) {
 	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0, dcacp_params.iter_size));
	spin_lock(&dcacp_epoch.lock);
	if(dcacp_epoch.iter <= dcacp_params.num_iters) {
		dcacp_handle_all_rts(&dcacp_match_table, &dcacp_epoch);
		spin_unlock(&dcacp_epoch.lock);
		return HRTIMER_RESTART;
	}
	spin_unlock(&dcacp_epoch.lock);
	return HRTIMER_NORESTART;

}

enum hrtimer_restart dcacp_new_epoch(struct hrtimer *timer) {

 	hrtimer_forward(timer,hrtimer_cb_get_time(timer),ktime_set(0,dcacp_params.epoch_size));
	dcacp_epoch.epoch += 1;
	dcacp_epoch.iter = 0;
	dcacp_epoch.match_src_addr = 0;
	dcacp_epoch.match_dst_addr = 0;
	dcacp_epoch.prompt = false;
	hrtimer_start(&dcacp_epoch.receiver_iter_timer, ktime_set(0, 0), HRTIMER_MODE_ABS);
	dcacp_epoch.receiver_iter_timer.function = &receiver_iter_event;
	hrtimer_start(&dcacp_epoch.sender_iter_timer, ktime_set(0, dcacp_params.iter_size / 2), HRTIMER_MODE_ABS);
	dcacp_epoch.sender_iter_timer.function = &sender_iter_event;

	return HRTIMER_RESTART;
}
