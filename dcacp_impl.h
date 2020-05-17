/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UDP4_IMPL_H
#define _UDP4_IMPL_H
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "net_dcacp.h"
#include "net_dcacplite.h"
#include "dcacp_hashtables.h"
#include "dcacp_sock.h"
extern struct inet_hashinfo dcacp_hashinfo;
extern struct dcacp_peertab dcacp_peers_table;
extern struct dcacp_match_tab dcacp_match_table;

extern struct dcacp_params dcacp_params;
extern struct dcacp_epoch dcacp_epoch;
extern struct request_sock_ops dcacp_request_sock_ops;

extern struct xmit_core_table xmit_core_tab;
extern struct rcv_core_table rcv_core_tab;
void* allocate_hash_table(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit);
int dcacp_dointvec(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp, loff_t *ppos);
void dcacp_sysctl_changed(struct dcacp_params *params);
void dcacp_params_init(struct dcacp_params *params);
// DCACP matching logic
// DCACP priority queue
int calc_grant_bytes(struct sock *sk);
int xmit_batch_token(struct sock *sk, int grant_bytes, bool handle_rtx);
void dcacp_xmit_token(struct dcacp_epoch* epoch);
int rtx_bytes_count(struct dcacp_sock* dsk, __u32 prev_grant_nxt);
void dcacp_xmit_token_handler(struct work_struct *work);
enum hrtimer_restart dcacp_token_xmit_event(struct hrtimer *timer);
void dcacp_pq_init(struct dcacp_pq* pq, bool(*comp)(const struct list_head*, const struct list_head*));
bool dcacp_pq_empty(struct dcacp_pq* pq);
bool dcacp_pq_empty_lockless(struct dcacp_pq* pq);
struct list_head* dcacp_pq_pop(struct dcacp_pq* pq);
void dcacp_pq_push(struct dcacp_pq* pq, struct list_head* node);
struct list_head* dcacp_pq_peek(struct dcacp_pq* pq); 
void dcacp_pq_delete(struct dcacp_pq* pq, struct list_head* node);
int dcacp_pq_size(struct dcacp_pq* pq);

void dcacp_match_entry_init(struct dcacp_match_entry* entry, __be32 addr, 
 bool(*comp)(const struct list_head*, const struct list_head*));
void dcacp_mattab_init(struct dcacp_match_tab *table,
	bool(*comp)(const struct list_head*, const struct list_head*));

void dcacp_mattab_destroy(struct dcacp_match_tab *table);
void dcacp_mattab_add_new_sock(struct dcacp_match_tab *table, struct sock *sk);
void dcacp_mattab_delete_sock(struct dcacp_match_tab *table, struct sock *sk);

void dcacp_mattab_delete_match_entry(struct dcacp_match_tab *table, struct dcacp_match_entry* entry);


void dcacp_epoch_init(struct dcacp_epoch *epoch);
void dcacp_epoch_destroy(struct dcacp_epoch *epoch);
// void dcacp_send_all_rts (struct dcacp_match_tab *table, struct dcacp_epoch* epoch);

// int dcacp_handle_rts (struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch);

// void dcacp_handle_all_rts(struct dcacp_match_tab* table, struct dcacp_epoch *epoch);
// int dcacp_handle_grant(struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch);
// void dcacp_handle_all_grants(struct dcacp_match_tab *table, struct dcacp_epoch *epoch);
// int dcacp_handle_accept(struct sk_buff *skb, struct dcacp_match_tab *table, struct dcacp_epoch *epoch);


/* scheduling */
bool flow_compare(const struct list_head* node1, const struct list_head* node2);
void rcv_core_entry_init(struct rcv_core_entry *entry, int core_id);
int rcv_core_table_init(struct rcv_core_table *tab);
void xmit_core_entry_init(struct xmit_core_entry *entry, int core_id);
int xmit_core_table_init(struct xmit_core_table *tab);
void rcv_core_table_destory(struct rcv_core_table *tab);
void xmit_core_table_destory(struct xmit_core_table *tab);

/* sender */
void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb);
void dcacp_xmit_data_event(struct work_struct *w);

/* receiver */
void dcacp_xmit_token_event(struct work_struct *w);
void rcv_handle_new_flow(struct dcacp_sock* dsk);
void rcv_flowlet_done(struct rcv_core_entry *entry);
enum hrtimer_restart flowlet_done_event(struct hrtimer *timer);



int dcacp_fragment(struct sock *sk, enum dcacp_queue dcacp_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp);
int dcacp_fill_packets(struct sock *sk,
		struct msghdr *msg, size_t len);

/*DCACP peer table*/
int dcacp_peertab_init(struct dcacp_peertab *peertab);
void dcacp_peertab_destroy(struct dcacp_peertab *peertab);
struct dcacp_peer *dcacp_peer_find(struct dcacp_peertab *peertab, __be32 addr,
	struct inet_sock *inet);

/*DCACP incoming function*/
void dcacp_get_sack_info(struct sock *sk, struct sk_buff *skb);
enum hrtimer_restart dcacp_new_epoch(struct hrtimer *timer);

int dcacp_handle_data_pkt(struct sk_buff *skb);
int dcacp_handle_flow_sync_pkt(struct sk_buff *skb);
int dcacp_handle_token_pkt(struct sk_buff *skb);
int dcacp_handle_fin_pkt(struct sk_buff *skb);
int dcacp_handle_ack_pkt(struct sk_buff *skb);
int dcacp_data_queue(struct sock *sk, struct sk_buff *skb);
bool dcacp_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check);
int dcacp_v4_do_rcv(struct sock *sk, struct sk_buff *skb);

void dcacp_rem_check_handler(struct sock *sk);
void dcacp_token_timer_defer_handler(struct sock *sk);
int dcacp_clean_rtx_queue(struct sock *sk);

enum hrtimer_restart dcacp_flow_wait_event(struct hrtimer *timer);
/*DCACP outgoing function*/
struct sk_buff* construct_flow_sync_pkt(struct sock* sk, __u64 message_id, 
	uint32_t message_size, __u64 start_time);
struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority, __u32 prev_grant_nxt,
	 __u32 grant_nxt, bool handle_rtx);
struct sk_buff* construct_fin_pkt(struct sock* sk);
struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt);
struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz);
struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool prompt);
struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short iter, int epoch);
int dcacp_xmit_control(struct sk_buff* skb, struct dcacp_peer *peer, struct sock *dcacp_sk, int dport);
void dcacp_xmit_data(struct sk_buff *skb, struct dcacp_sock* dsk, bool free_token);
void dcacp_retransmit_data(struct sk_buff *skb, struct dcacp_sock* dsk);
void __dcacp_xmit_data(struct sk_buff *skb, struct dcacp_sock* dsk, bool free_token);
void dcacp_retransmit(struct sock* sk);

int dcacp_write_timer_handler(struct sock *sk);

void dcacp_write_queue_purge(struct sock *sk);

void dcacp_release_cb(struct sock *sk);
int __dcacp4_lib_rcv(struct sk_buff *, struct udp_table *, int);
int __dcacp4_lib_err(struct sk_buff *, u32, struct udp_table *);

int dcacp_v4_get_port(struct sock *sk, unsigned short snum);
void dcacp_v4_rehash(struct sock *sk);

int dcacp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen);
int dcacp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
int compat_dcacp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen);
int compat_dcacp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);
#endif
int dcacp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len);
int dcacp_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		 int flags);
void dcacp_destroy_sock(struct sock *sk);

#ifdef CONFIG_PROC_FS
int udp4_seq_show(struct seq_file *seq, void *v);
#endif
#endif	/* _UDP4_IMPL_H */
