#include "dcacp_impl.h"

#define MAX_ACTIVE_CORE 3

struct xmit_core_table xmit_core_tab;
struct rcv_core_table rcv_core_tab;


bool flow_compare(const struct list_head* node1, const struct list_head* node2) {
    struct dcacp_sock *e1, *e2;
    e1 = list_entry(node1, struct dcacp_sock, match_link);
    e2 = list_entry(node2, struct dcacp_sock, match_link);
    if(e1->total_length > e2->total_length)
        return true;
    return false;

}

void rcv_core_entry_init(struct rcv_core_entry *entry, int core_id) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	atomic_set(&entry->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);
	entry->core_id = 0;
	entry->state = DCACP_IDLE;
	// hrtimer_init(&entry->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->token_xmit_timer.function = &dcacp_token_xmit_event;

	/* pHost Queue */
	dcacp_pq_init(&entry->flow_q, flow_compare);

	INIT_LIST_HEAD(&entry->list_link);
	INIT_WORK(&entry->token_xmit_struct, dcacp_xmit_token_event);


}

int rcv_core_table_init(struct rcv_core_table *tab) {
	int i;
	// atomic_set(&tab->remaining_tokens, 0);
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	tab->wq = alloc_workqueue("dcacp-rcv-wq",
		WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!tab->wq)
		return -ENOMEM;
	for (i = 0; i < NR_CPUS; i++) {
		rcv_core_entry_init(&tab->table[i], i);
	}
	return 0;
}

void rcv_core_table_destory(struct rcv_core_table *tab) {
	flush_workqueue(tab->wq);
	destroy_workqueue(tab->wq);
}

/* Assume table is hold */
void rcv_invoke_next(struct rcv_core_table* tab) {
	if (!list_empty(&tab->sche_list)) {
		struct rcv_core_entry *next_entry = list_first_entry(&tab->sche_list, struct rcv_core_entry, list_link);
		// WARN_ON(next_entry == entry);
		// WARN_ON(skb_queue_empty(next_entry->token_q));
		list_del_init(&next_entry->list_link);
		tab->num_active_cores += 1;
		// printk("invoke next CPU Core:%d\n", raw_smp_processor_id());
		/* need to check whether is from the same core or not */
		queue_work_on(next_entry->core_id, tab->wq, &next_entry->token_xmit_struct);
		// hrtimer_start(&next_entry->data_xmit_timer, ns_to_ktime(0), 
		// HRTIMER_MODE_REL_PINNED_SOFT);
	}
}

#define DCACP_RMEM_LIMIT 1
#define DCACP_TIMER_SETUP 2

int xmit_batch_token(struct sock *sk, int grant_bytes, bool handle_rtx) {
	struct dcacp_sock *dsk = dcacp_sk(sk);
	struct rcv_core_entry* entry = &rcv_core_tab.table[raw_smp_processor_id()];
	int grant_len = 0;
	struct inet_sock *inet;
	int push_bk = 0;
	int retransmit_bytes = 0;
	__u32 prev_grant_nxt = dsk->prev_grant_nxt;
	inet = inet_sk(sk);
	// dsk->new_grant_nxt = dsk->grant_nxt;
	// printk("remaining_tokens:%d\n", atomic_read(&dcacp_epoch.remaining_tokens));
	// printk("remaining_tokens:%d\n", atomic_read(&dcacp_epoch.remaining_tokens));
	if (dsk->receiver.flow_wait)
		return DCACP_TIMER_SETUP;
	/* this is only exception for retransmission*/
	if (grant_bytes < 0)
		grant_bytes = 0;
	/*compute total sack bytes*/
	if(handle_rtx && dsk->receiver.rcv_nxt < prev_grant_nxt) {
		retransmit_bytes = rtx_bytes_count(dsk, prev_grant_nxt);
		grant_len += retransmit_bytes;
		// atomic_add_return(retransmit_bytes, &dcacp_epoch.remaining_tokens);
		if (retransmit_bytes > dcacp_params.control_pkt_bdp / 2)
			grant_bytes = 0;
	} 
	/* if retransmit_bytes is larger, then we don't increment grant_nxt */

	// printk("grant bytes:%u\n", grant_bytes);
	/* set grant next*/
	/* receiver buffer bottleneck; or token is dropped */
	// if(prev_grant_nxt == dsk->receiver.rcv_nxt) {
	// 	dsk->grant_nxt = dsk->receiver.rcv_nxt;
	// 	printk("shrink grant nxt:%d\n", dsk->grant_nxt);
	// }
	/* this is a temporary solution */
	if(dsk->new_grant_nxt + grant_bytes > dsk->total_length) {
		grant_bytes =  dsk->total_length - dsk->grant_nxt;
		dsk->new_grant_nxt = dsk->total_length;
	} else {
		dsk->new_grant_nxt += grant_bytes;
	}

	grant_len += grant_bytes;
	if (grant_len == 0) {
		dsk->receiver.rmem_exhausted += 1;
	}
	if(dsk->new_grant_nxt == dsk->total_length) {
		push_bk = DCACP_TIMER_SETUP;
		/* TO DO: setup a timer here */
		/* current set timer to be 10 RTT */
		dsk->receiver.flow_wait = true;
		hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(dcacp_params.rtt * 10 * 1000), 
			HRTIMER_MODE_REL_PINNED_SOFT);
	}
	// printk("xmit token grant next:%u\n", dsk->new_grant_nxt);
	// printk("prev_grant_nxt:%u\n", dsk->prev_grant_nxt);
	// printk ("dsk->receiver.rcv_nxt:%u\n", dsk->receiver.rcv_nxt);
	// printk("remaining_tokens:%d\n", atomic_read(&dcacp_epoch.remaining_tokens));
	// printk("grant_len:%d\n", grant_len);
	atomic_add(grant_len, &entry->remaining_tokens);
	dsk->receiver.prev_grant_bytes += grant_len;
	atomic_add(grant_len, &dsk->receiver.in_flight_bytes);
	dcacp_xmit_control(construct_token_pkt((struct sock*)dsk, 3, prev_grant_nxt, dsk->new_grant_nxt, handle_rtx),
	 dsk->peer, sk, inet->inet_dport);
	return push_bk;
}

/* assume entry lock is hold and bh is disabled */
bool dcacp_xmit_token_single_core(struct rcv_core_entry *entry) {
	bool find_flow = false;
	struct list_head *match_link;
	struct dcacp_sock *dsk;
	struct inet_sock *inet;
	struct sock* sk;
	while(!dcacp_pq_empty(&entry->flow_q)) {
		bool not_push_bk = false;
		match_link = dcacp_pq_peek(&entry->flow_q);
		dsk =  list_entry(match_link, struct dcacp_sock, match_link);
		sk = (struct sock*)dsk;
		inet = inet_sk(sk);
		dcacp_pq_pop(&entry->flow_q);
 		bh_lock_sock(sk);
 		if(sk->sk_state == DCACP_RECEIVER) {
 			dsk->receiver.prev_grant_bytes = 0;
	 		if (!sock_owned_by_user(sk)) {
	 			int grant_bytes = calc_grant_bytes(sk);
	 			// printk("grant bytes:%d\n", grant_bytes);
	 			not_push_bk = xmit_batch_token(sk, grant_bytes, true);
		 		if(grant_bytes == dsk->receiver.grant_batch) {
					dsk->prev_grant_nxt = dsk->grant_nxt;
					dsk->grant_nxt = dsk->new_grant_nxt;
		  			if (!not_push_bk){
		  				dcacp_pq_push(&entry->flow_q, &dsk->match_link);
		  			}
		 		}
		 		else {
	 				test_and_set_bit(DCACP_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
		 		}
	 		} else {
	 			int grant_bytes = calc_grant_bytes(sk);
	 			if (!grant_bytes)
	 				 xmit_batch_token(sk, grant_bytes, false);
	 			test_and_set_bit(DCACP_TOKEN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	 		}
 		} else {
 			goto unlock;
 		}
 		find_flow = true;
		bh_unlock_sock(sk);
		break;
unlock:
        bh_unlock_sock(sk);
	}
	if (!dcacp_pq_empty(&entry->flow_q)) {
	}
	return find_flow;
}

/* Process Context */
void dcacp_xmit_token_event(struct work_struct *w) {
	struct rcv_core_entry *entry = container_of(w, struct rcv_core_entry, token_xmit_struct);
	bool find_flow = false;
		// start2 = ktime_get();
	// printk("dcacp xmit token\n");
	spin_lock_bh(&entry->lock);
	// WARN_ON(entry->is_active);
	if(entry->state == DCACP_ACTIVE) {
		goto not_find_flow;
	}
	WARN_ON(entry->state != DCACP_IN_QUEUE);
	entry->state = DCACP_ACTIVE;
	find_flow = dcacp_xmit_token_single_core(entry);
	if(!find_flow)
		entry->state = DCACP_IDLE;

not_find_flow:
	spin_unlock_bh(&entry->lock);
	if(!find_flow) {
		spin_lock_bh(&rcv_core_tab.lock);
		rcv_core_tab.num_active_cores -= 1;
		rcv_invoke_next(&rcv_core_tab);
		spin_unlock_bh(&rcv_core_tab.lock);
	}
}

void rcv_handle_new_flow(struct dcacp_sock* dsk) {
	int core_id = raw_smp_processor_id();
	// bool is_empty = false;
	struct rcv_core_entry* entry = &rcv_core_tab.table[core_id];
	spin_lock(&entry->lock);
	/* push the long flow to the control plane for scheduling*/
	dcacp_pq_push(&entry->flow_q, &dsk->match_link);
	// if(dcacp_pq_size(&entry->flow_q) == 1) {
	// 	is_empty = true;
	// }
	if(entry->state == DCACP_IDLE) {
		spin_lock(&rcv_core_tab.lock);
		/* list empty*/
		if(rcv_core_tab.num_active_cores < MAX_ACTIVE_CORE) {
			rcv_core_tab.num_active_cores += 1;
			entry->state = DCACP_ACTIVE;
			spin_unlock(&rcv_core_tab.lock);
			dcacp_xmit_token_single_core(entry);
			goto end;
		} else {
			entry->state = DCACP_IN_QUEUE;
			list_add_tail(&entry->list_link, &rcv_core_tab.sche_list);
		}
		spin_unlock(&rcv_core_tab.lock);
	}
end:
	spin_unlock(&entry->lock);
}

/* entry lock is hold and bh is disabled */
void rcv_flowlet_done(struct rcv_core_entry *entry) {

	bool pq_empty = dcacp_pq_empty(&entry->flow_q);
	if(atomic_read(&entry->remaining_tokens) <= dcacp_params.control_pkt_bdp / 2 
		&& entry->state == DCACP_ACTIVE) {
		spin_lock(&rcv_core_tab.lock);
		if(pq_empty) {
			entry->state = DCACP_IDLE;
			rcv_core_tab.num_active_cores -= 1;
			rcv_invoke_next(&rcv_core_tab);
		} else if (list_empty(&rcv_core_tab.sche_list)) {
			/* send next token in the same core */
			spin_unlock(&rcv_core_tab.lock);
			dcacp_xmit_token_single_core(entry);
			goto end;
		} else {
			entry->state = DCACP_IN_QUEUE;
			rcv_core_tab.num_active_cores -= 1;
			list_add_tail(&entry->list_link, &rcv_core_tab.sche_list);
			rcv_invoke_next(&rcv_core_tab);
		}
		spin_unlock(&rcv_core_tab.lock);
		// hrtimer_start(&dcacp_epoch.token_xmit_timer, ktime_set(0, 0), HRTIMER_MODE_REL_PINNED_SOFT);
	}
end:
	return;
}




void xmit_core_entry_init(struct xmit_core_entry *entry, int core_id) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	// atomic_set(&epoch->pending_flows, 0);
	entry->core_id = core_id;
	// hrtimer_init(&entry->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->token_xmit_timer.function = &dcacp_token_xmit_event;
	// hrtimer_init(&entry->data_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->data_xmit_timer.function = &dcacp_xmit_data_event;
	skb_queue_head_init(&entry->token_q);

	INIT_LIST_HEAD(&entry->list_link);
	INIT_WORK(&entry->data_xmit_struct, dcacp_xmit_data_event);
}

int xmit_core_table_init(struct xmit_core_table *tab) {
	int i;
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	tab->wq = alloc_workqueue("dcacp-xmit-wq",
		WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!tab->wq) 
		return -ENOMEM;

	for (i = 0; i < NR_CPUS; i++) {
		xmit_core_entry_init(&tab->table[i], i);
	}
	return 0;
}

void xmit_core_table_destory(struct xmit_core_table *tab) {
	flush_workqueue(tab->wq);
	destroy_workqueue(tab->wq);
}
int xmit_use_token(struct sk_buff* skb) {
	struct dcacp_token_hdr *th;
	struct sock* sk;
	struct dcacp_sock *dsk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	int sent_bytes = 0;

	th = dcacp_token_hdr(skb);
	sk = __dcacp_lookup_skb(&dcacp_hashinfo, skb, __dcacp_hdrlen(&th->common), th->common.source,
            th->common.dest, sdif, &refcounted);
	if(sk) {
		// printk("reach here:%d\n", __LINE__);
		// printk("use token\n");
	 	dsk = dcacp_sk(sk);
 		bh_lock_sock(sk);
		/* add token */
 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 		/* add sack info */
 		dcacp_get_sack_info(sk, skb);
	    if(!sock_owned_by_user(sk) || dsk->num_sacks == 0) {
	 		sent_bytes += dcacp_write_timer_handler(sk);
	    } else {
	 		test_and_set_bit(DCACP_RTX_DEFERRED, &sk->sk_tsq_flags);
	    }
	    bh_unlock_sock(sk);
	}
	if (refcounted) {
        sock_put(sk);
    }
	kfree_skb(skb);
	return sent_bytes;
}

/* Assume table lock is hold*/
void xmit_invoke_next(struct xmit_core_table *tab) {
	if (!list_empty(&tab->sche_list)) {
		struct xmit_core_entry *next_entry = list_first_entry(&tab->sche_list, struct xmit_core_entry, list_link);
		// WARN_ON(next_entry == entry);
		// WARN_ON(skb_queue_empty(next_entry->token_q));
		list_del_init(&next_entry->list_link);
		tab->num_active_cores += 1;
		// printk("invoke next CPU Core:%d\n", raw_smp_processor_id());
		queue_work_on(next_entry->core_id, tab->wq, &next_entry->data_xmit_struct);
		// hrtimer_start(&next_entry->data_xmit_timer, ns_to_ktime(0), 
		// HRTIMER_MODE_REL_PINNED_SOFT);
	}
}
void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb) {
	bool send_now = false;
	bool is_empty = false;
	int core_id = raw_smp_processor_id();
	struct xmit_core_entry *entry = &tab->table[core_id];
	spin_lock(&entry->lock);
	if(skb_queue_empty(&entry->token_q))
		is_empty = true;

	// 	printk("push the skb\n");
	__skb_queue_tail(&entry->token_q, skb);
	// }	
	// printk("entry->token q is_empty:%d\n", skb_queue_empty(&entry->token_q));
	if(is_empty) {
		/* Deadlock won't happen because entry is not in sche_list yet*/
		spin_lock(&tab->lock);
		if(tab->num_active_cores < MAX_ACTIVE_CORE) {
			tab->num_active_cores += 1;
			send_now = true;
		}
		else {
			list_add_tail(&entry->list_link, &tab->sche_list);
		}
		spin_unlock(&tab->lock);
		if(send_now) {
			__skb_dequeue_tail(&entry->token_q);
			xmit_use_token(skb);
			spin_lock(&tab->lock);
			tab->num_active_cores -= 1;
			xmit_invoke_next(tab);
			spin_unlock(&tab->lock);
		}
		// xmit_invoke_next(tab);
	}

	spin_unlock(&entry->lock);
	return;
}

/* In Process Context */
void dcacp_xmit_data_event(struct work_struct *w) {
	// struct dcacp_grant* grant, temp;
	int num_bytes_sent;
	struct xmit_core_entry *entry = container_of(w, struct xmit_core_entry, data_xmit_struct);

	// printk("xmit data timer handler is called: %d\n", raw_smp_processor_id());
	/* reset the remaining tokens to zero */
	// atomic_set(&epoch->remaining_tokens, 0);	
start_sent:
	num_bytes_sent = 0;
	while(1) {
		struct sk_buff* skb;
		spin_lock_bh(&entry->lock);
		if(num_bytes_sent > dcacp_params.data_budget) {
			goto stop;
		}
		if(skb_queue_empty(&entry->token_q)) {
			goto stop;
		}
		skb = __skb_dequeue(&entry->token_q);
		spin_unlock_bh(&entry->lock);
		local_bh_disable();
		num_bytes_sent += xmit_use_token(skb);
		local_bh_enable();
		continue;
	stop:
		spin_unlock_bh(&entry->lock);
		break;
	}
	spin_lock_bh(&xmit_core_tab.lock);
	spin_lock_bh(&entry->lock);

	if (!skb_queue_empty(&entry->token_q)) {
		if(xmit_core_tab.num_active_cores <= MAX_ACTIVE_CORE) {
			spin_unlock_bh(&entry->lock);
			spin_unlock_bh(&xmit_core_tab.lock);
			goto start_sent;
		}
		/* add this entry back to the schedule list */
		list_add_tail(&entry->list_link, &xmit_core_tab.sche_list);

	}
	xmit_core_tab.num_active_cores -= 1;
	
	spin_unlock_bh(&entry->lock);
	xmit_invoke_next(&xmit_core_tab);
	spin_unlock_bh(&xmit_core_tab.lock);
 	// queue_work(dcacp_epoch.wq, &dcacp_epoch.token_xmit_struct);
	return;

}
// bool xmit_finish() {
// 	int core_id = raw_smp_processor_id();
// 	struct xmit_core_entry *entry = &tab->table[core_id];
// 	return false;
// }