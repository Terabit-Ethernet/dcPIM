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

void rcv_core_entry_init(struct rcv_core_entry *entry) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	atomic_set(&entry->remaining_tokens, 0);
	// atomic_set(&epoch->pending_flows, 0);

	hrtimer_init(&entry->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	entry->token_xmit_timer.function = &dcacp_token_xmit_event;

	/* pHost Queue */
	dcacp_pq_init(&entry->flow_q, flow_compare);

	INIT_LIST_HEAD(&entry->list_link);

}

void rcv_core_table_init(struct rcv_core_table *tab) {
	int i;
	atomic_set(&tab->remaining_tokens, 0);
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	for (i = 0; i < NR_CPUS; i++) {
		rcv_core_entry_init(&tab->table[i]);
	}
}

void xmit_core_entry_init(struct xmit_core_entry *entry) {
	spin_lock_init(&entry->lock);
	/* token xmit timer*/
	// atomic_set(&epoch->pending_flows, 0);

	// hrtimer_init(&entry->token_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	// entry->token_xmit_timer.function = &dcacp_token_xmit_event;
	hrtimer_init(&entry->data_xmit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	entry->data_xmit_timer.function = &dcacp_xmit_data_event;
	skb_queue_head_init(&entry->token_q);

	INIT_LIST_HEAD(&entry->list_link);

}

void xmit_core_table_init(struct xmit_core_table *tab) {
	int i;
	tab->num_active_cores = 0;
	spin_lock_init(&tab->lock);
	INIT_LIST_HEAD(&tab->sche_list);
	for (i = 0; i < NR_CPUS; i++) {
		xmit_core_entry_init(&tab->table[i]);
	}
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
		hrtimer_start(&next_entry->data_xmit_timer, ns_to_ktime(0), 
		HRTIMER_MODE_REL_PINNED_SOFT);
	}
}
void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb) {
	bool send_now = false;
	bool is_empty = false;
	int core_id = raw_smp_processor_id();
	struct xmit_core_entry *entry = &tab->table[core_id];
	spin_lock(&entry->lock);
	if(skb_queue_empty(&entry->token_q)) {
		is_empty = true;
	} else {
		__skb_queue_tail(&entry->token_q, skb);
	}	

	if(is_empty) {
		/* Deadlock won't happen because entry is not in sche_list yet*/
		spin_lock(&tab->lock);
		tab->num_active_cores += 1;
		if(tab->num_active_cores <= MAX_ACTIVE_CORE) 
			send_now = true;
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
	}

	spin_unlock(&entry->lock);
	return;
}

/* Token */
enum hrtimer_restart dcacp_xmit_data_event(struct hrtimer *timer) {
	// struct dcacp_grant* grant, temp;
	int num_bytes_sent;
	struct xmit_core_entry *entry = container_of(timer, struct xmit_core_entry, data_xmit_timer);

	// printk("token timer handler is called 1\n");
	/* reset the remaining tokens to zero */
	// atomic_set(&epoch->remaining_tokens, 0);	
start_sent:
	num_bytes_sent = 0;
	while(1) {
		struct sk_buff* skb;
		spin_lock(&entry->lock);
		if(num_bytes_sent > dcacp_params.data_budget) {
			goto stop;
		}
		if(skb_queue_empty(&entry->token_q)) {
			goto stop;
		}
		skb = __skb_dequeue(&entry->token_q);
		spin_unlock(&entry->lock);
		num_bytes_sent += xmit_use_token(skb);
		continue;
	stop:
		spin_unlock(&entry->lock);
		break;
	}
	spin_lock(&xmit_core_tab.lock);
	spin_lock(&entry->lock);

	if (!skb_queue_empty(&entry->token_q)) {
		if(xmit_core_tab.num_active_cores <= MAX_ACTIVE_CORE) {
			spin_unlock(&entry->lock);
			spin_unlock(&xmit_core_tab.lock);
			goto start_sent;
		}
		/* add this entry back to the schedule list */
		list_add_tail(&entry->list_link, &xmit_core_tab.sche_list);

	} else {
		xmit_core_tab.num_active_cores -= 1;
	}
	spin_unlock(&entry->lock);
	xmit_invoke_next(&xmit_core_tab);
	spin_unlock(&xmit_core_tab.lock);
 	// queue_work(dcacp_epoch.wq, &dcacp_epoch.token_xmit_struct);
	return HRTIMER_NORESTART;

}
// bool xmit_finish() {
// 	int core_id = raw_smp_processor_id();
// 	struct xmit_core_entry *entry = &tab->table[core_id];
// 	return false;
// }