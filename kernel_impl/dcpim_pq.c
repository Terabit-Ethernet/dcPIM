/* Copyright (c) 2019-2020, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file manages dcpim_peertab objects and is responsible for creating
 * and deleting dcpim_peer objects.
 */

#include "dcpim_impl.h"

void dcpim_pq_init(struct dcpim_pq* pq, bool(*comp)(const struct list_head*, const struct list_head*)) {
	// spin_lock_init(&pq->lock);
	INIT_LIST_HEAD(&pq->list);
	pq->count = 0;
	pq->comp = comp;
}

bool dcpim_pq_empty(struct dcpim_pq* pq) {
	// spin_lock_bh(&pq->lock);
	// spin_unlock_bh(&pq->lock);
	return pq->count == 0;
}

bool dcpim_pq_empty_lockless(struct dcpim_pq* pq) {
	return READ_ONCE(pq->list.next) == (const struct list_head *) (&pq->list);
}
int dcpim_pq_size(struct dcpim_pq* pq) {
	return pq->count;
}
void dcpim_pq_delete(struct dcpim_pq* pq, struct list_head* node) {
	// spin_lock_bh(&pq->lock);
	/* list empty use is not traditional use of the function; 
	it is checked whether this node has already been removed before */
	if(pq->count > 0 && !list_empty(node)) {
		list_del_init(node);
		pq->count--;
	}
	if(pq->count == 0) {
		INIT_LIST_HEAD(&pq->list);
	}
	// spin_unlock_bh(&pq->lock);
	return; 
}
struct list_head* dcpim_pq_pop(struct dcpim_pq* pq) {
	struct list_head *head = NULL;
	// spin_lock_bh(&pq->lock);
	if(pq->count > 0) {
		head = pq->list.next;
		list_del_init(head);
		pq->count--;
	}
	if(pq->count == 0) {
		INIT_LIST_HEAD(&pq->list);
	}
	// spin_unlock_bh(&pq->lock);
	return head;
}

void dcpim_pq_push(struct dcpim_pq* pq, struct list_head* node) {
	// spin_lock_bh(&pq->lock);
	struct list_head* pos;
	list_for_each(pos, &pq->list) {
		if(!pq->comp(node, pos)) {
			list_add_tail(node, pos);
			pq->count++;
			return;
		}
	}
	list_add_tail(node, &pq->list);
	pq->count++;
	// spin_unlock_bh(&pq->lock);
	return;
}

struct list_head* dcpim_pq_peek(struct dcpim_pq* pq) {
	if(pq->count == 0)
		return NULL;
	return pq->list.next;
}


