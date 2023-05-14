#ifndef _UDP4_IMPL_H
#define _UDP4_IMPL_H
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "net_dcpim.h"
#include "dcpim_hashtables.h"
#include "dcpim_sock.h"
extern struct inet_hashinfo dcpim_hashinfo;
extern struct dcpim_peertab dcpim_peers_table;
extern struct dcpim_match_tab dcpim_match_table;

extern struct workqueue_struct *dcpim_wq;
extern struct dcpim_params dcpim_params;
extern struct dcpim_epoch dcpim_epoch;
extern struct request_sock_ops dcpim_request_sock_ops;

extern struct xmit_core_table xmit_core_tab;
extern struct rcv_core_table rcv_core_tab;
extern struct dcpim_message_bucket dcpim_tx_messages[DCPIM_BUCKETS];
extern struct dcpim_message_bucket dcpim_rx_messages[DCPIM_BUCKETS];

void* allocate_hash_table(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit);
int dcpim_dointvec(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp, loff_t *ppos);
void dcpim_sysctl_changed(struct dcpim_params *params);
void dcpim_params_init(struct dcpim_params *params);
// DCPIM matching logic
// DCPIM priority queue
int calc_grant_bytes(struct sock *sk);
int xmit_batch_token(struct sock *sk, int grant_bytes, bool handle_rtx);
uint32_t dcpim_xmit_token(struct dcpim_sock* dsk, uint32_t token_bytes);
int rtx_bytes_count(struct dcpim_sock* dsk, __u32 prev_grant_nxt);
enum hrtimer_restart dcpim_xmit_token_handler(struct hrtimer *timer);
enum hrtimer_restart dcpim_rtx_token_handler(struct hrtimer *timer);
enum hrtimer_restart dcpim_rtx_sync_timer_handler(struct hrtimer *timer);
void dcpim_rtx_sync_handler(struct dcpim_sock *dsk);
void rtx_fin_handler(struct work_struct *work);
enum hrtimer_restart dcpim_rtx_fin_timer_handler(struct hrtimer *timer);
void dcpim_pq_init(struct dcpim_pq* pq, bool(*comp)(const struct list_head*, const struct list_head*));
bool dcpim_pq_empty(struct dcpim_pq* pq);
bool dcpim_pq_empty_lockless(struct dcpim_pq* pq);
struct list_head* dcpim_pq_pop(struct dcpim_pq* pq);
void dcpim_pq_push(struct dcpim_pq* pq, struct list_head* node);
struct list_head* dcpim_pq_peek(struct dcpim_pq* pq); 
void dcpim_pq_delete(struct dcpim_pq* pq, struct list_head* node);
int dcpim_pq_size(struct dcpim_pq* pq);

// void dcpim_match_entry_init(struct dcpim_match_entry* entry, __be32 addr, 
//  bool(*comp)(const struct list_head*, const struct list_head*));
// void dcpim_mattab_init(struct dcpim_match_tab *table,
// 	bool(*comp)(const struct list_head*, const struct list_head*));
void dcpim_remove_mat_tab(struct dcpim_epoch *epoch, struct sock *sk);
void dcpim_add_mat_tab(struct dcpim_epoch *epoch, struct sock *sk);

void dcpim_mattab_destroy(struct dcpim_match_tab *table);
void dcpim_mattab_add_new_sock(struct dcpim_match_tab *table, struct sock *sk);
void dcpim_mattab_delete_sock(struct dcpim_match_tab *table, struct sock *sk);

// void dcpim_mattab_delete_match_entry(struct dcpim_match_tab *table, struct dcpim_match_entry* entry);


void dcpim_epoch_init(struct dcpim_epoch *epoch);
void dcpim_epoch_destroy(struct dcpim_epoch *epoch);
void dcpim_send_all_rts (struct dcpim_epoch* epoch);

int dcpim_handle_rts (struct sk_buff *skb, struct dcpim_epoch *epoch);

void dcpim_handle_all_rts(struct dcpim_epoch *epoch);
int dcpim_handle_grant(struct sk_buff *skb, struct dcpim_epoch *epoch);
void dcpim_handle_all_grants(struct dcpim_epoch *epoch);
int dcpim_handle_accept(struct sk_buff *skb, struct dcpim_epoch *epoch);
int dcpim_handle_syn_ack_pkt(struct sk_buff *skb);
int dcpim_handle_fin_ack_pkt(struct sk_buff *skb);
int dcpim_handle_rtx_msg(struct sk_buff *skb, struct dcpim_epoch *epoch);

void dcpim_fill_eth_header(struct sk_buff *skb, const void *saddr, const void *daddr);
void dcpim_fill_ip_header(struct sk_buff *skb, __be32 saddr, __be32 daddr);
void dcpim_fill_dcpim_header(struct sk_buff *skb, __be16 sport, __be16 dport); 
void dcpim_fill_dst_entry(struct sock *sk, struct sk_buff *skb, struct flowi *fl);
void dcpim_swap_dcpim_header(struct sk_buff *skb);
void dcpim_swap_ip_header(struct sk_buff *skb);
void dcpim_swap_eth_header(struct sk_buff *skb);
/* scheduling */
bool flow_compare(const struct list_head* node1, const struct list_head* node2);
void rcv_core_entry_init(struct rcv_core_entry *entry, int core_id);
int rcv_core_table_init(struct rcv_core_table *tab);
void xmit_core_entry_init(struct xmit_core_entry *entry, int core_id);
int xmit_core_table_init(struct xmit_core_table *tab);
void rcv_core_table_destory(struct rcv_core_table *tab);
void xmit_core_table_destory(struct xmit_core_table *tab);
void dcpim_update_and_schedule_sock(struct dcpim_sock *dsk);
void dcpim_unschedule_sock(struct dcpim_sock *dsk);
/* sender */
void xmit_handle_new_token(struct xmit_core_table *tab, struct sk_buff* skb);
void dcpim_xmit_data_event(struct work_struct *w);

/* receiver */
void dcpim_xmit_token_event(struct work_struct *w);
void rcv_handle_new_flow(struct dcpim_sock* dsk);
void rcv_flowlet_done(struct rcv_core_entry *entry);
enum hrtimer_restart flowlet_done_event(struct hrtimer *timer);



int dcpim_fragment(struct sock *sk, enum dcpim_queue dcpim_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp);
int dcpim_fill_packets(struct sock *sk,
		struct msghdr *msg, size_t len);

/*DCPIM peer table*/
int dcpim_peertab_init(struct dcpim_peertab *peertab);
void dcpim_peertab_destroy(struct dcpim_peertab *peertab);
struct dcpim_peer *dcpim_peer_find(struct dcpim_peertab *peertab, __be32 addr,
	struct inet_sock *inet);

/*DCPIM incoming function*/
bool dcpim_try_send_token(struct sock *sk);
void dcpim_get_sack_info(struct sock *sk, struct sk_buff *skb);
enum hrtimer_restart dcpim_new_epoch(struct hrtimer *timer);

int dcpim_handle_data_pkt(struct sk_buff *skb);
int dcpim_handle_flow_sync_pkt(struct sk_buff *skb);
int dcpim_handle_token_pkt(struct sk_buff *skb);
int dcpim_handle_fin_pkt(struct sk_buff *skb);
int dcpim_handle_ack_pkt(struct sk_buff *skb);
int dcpim_data_queue(struct sock *sk, struct sk_buff *skb);
bool dcpim_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check);
int dcpim_v4_do_rcv(struct sock *sk, struct sk_buff *skb);

void dcpim_rem_check_handler(struct sock *sk);
int dcpim_token_timer_defer_handler(struct sock *sk);
int dcpim_clean_rtx_queue(struct sock *sk);

enum hrtimer_restart dcpim_flow_wait_event(struct hrtimer *timer);
void dcpim_flow_wait_handler(struct sock *sk);
/*DCPIM outgoing function*/
struct sk_buff* construct_flow_sync_pkt(struct sock* sk, __u64 message_id, 
	uint32_t message_size, __u64 start_time);
struct sk_buff* construct_token_pkt(struct sock* sk, unsigned short priority, __u32 grant_nxt);
struct sk_buff* construct_rtx_token_pkt(struct sock* sk, unsigned short priority,
	 __u32 prev_token_nxt, __u32 token_nxt, int *rtx_bytes);
struct sk_buff* construct_fin_pkt(struct sock* sk);
struct sk_buff* construct_ack_pkt(struct sock* sk, __be32 rcv_nxt);
struct sk_buff* construct_rts_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool rtx_channel);
struct sk_buff* construct_grant_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool prompt, bool rtx_channel);
struct sk_buff* construct_accept_pkt(struct sock* sk, unsigned short iter, int epoch, int remaining_sz, bool rtx_channel);
struct sk_buff* construct_syn_ack_pkt(struct sock* sk, __u64 message_id, 
	uint32_t message_size, __u64 start_time);
struct sk_buff* construct_fin_ack_pkt(struct sock* sk, __u64 message_id);

int dcpim_xmit_control(struct sk_buff* skb, struct sock *dcpim_sk);
void dcpim_xmit_data(struct sk_buff *skb, struct dcpim_sock* dsk);
void dcpim_retransmit_data(struct sk_buff *skb, struct dcpim_sock* dsk);
void __dcpim_xmit_data(struct sk_buff *skb, struct dcpim_sock* dsk, bool free_token, uint64_t msg_id);
void dcpim_retransmit(struct sock* sk);
uint32_t dcpim_check_rtx_token(struct dcpim_sock* dsk);

int dcpim_write_timer_handler(struct sock *sk);

void dcpim_write_queue_purge(struct sock *sk);

void dcpim_release_cb(struct sock *sk);
int __dcpim4_lib_rcv(struct sk_buff *, struct udp_table *, int);
int __dcpim4_lib_err(struct sk_buff *, u32, struct udp_table *);

int dcpim_v4_get_port(struct sock *sk, unsigned short snum);
void dcpim_v4_rehash(struct sock *sk);

int dcpim_setsockopt(struct sock *sk, int level, int optname,
		   sockptr_t optval, unsigned int optlen);
int dcpim_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen);

int dcpim_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int flags, int *addr_len);
int dcpim_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		 int flags);
void dcpim_destroy_sock(struct sock *sk);


/* dcpim message functions */
void dcpim_message_table_init(void);
void dcpim_message_table_destroy(void);
unsigned int dcpim_message_hash(__be32 laddr, __u16 lport, __be32 faddr, __be16 fport, uint64_t id);
struct dcpim_message* dcpim_message_new(struct dcpim_sock* dsk, 
			__be32 saddr, __be16 sport, __be32 daddr,  u16 dport,
			uint64_t id,  uint32_t length);			
void dcpim_message_hold(struct dcpim_message *msg);
void dcpim_message_put(struct dcpim_message *msg);
void dcpim_message_finish(struct dcpim_message_bucket *hashinfo, struct dcpim_message *msg);
void dcpim_message_destroy(struct dcpim_message *msg);
struct sk_buff* dcpim_message_get_fin(struct dcpim_message *msg);
bool dcpim_message_receive_data(struct dcpim_message *msg, struct sk_buff *skb);
int dcpim_fill_packets_message(struct sock* sk, struct dcpim_message *dcpim_msg,
		struct msghdr *msg, size_t len);
void dcpim_xmit_data_message(struct sk_buff* skb, struct dcpim_sock* dsk, uint64_t id);
void dcpim_xmit_data_whole_message(struct dcpim_message* msg, struct dcpim_sock* dsk);
int dcpim_handle_data_msg_pkt(struct sk_buff *skb);
int dcpim_handle_flow_sync_msg_pkt(struct sk_buff *skb);
int dcpim_handle_fin_msg_pkt(struct sk_buff *skb);
int dcpim_handle_fin_ack_msg_pkt(struct sk_buff *skb);
enum hrtimer_restart dcpim_rtx_msg_timer_handler(struct hrtimer *timer);
void dcpim_msg_fin_bg_handler(struct dcpim_sock *dsk);
enum hrtimer_restart dcpim_rtx_msg_timer_handler(struct hrtimer *timer);
void dcpim_msg_rtx_bg_handler(struct dcpim_sock *dsk);
void dcpim_rtx_msg_handler(struct work_struct *work);
struct sk_buff* construct_flow_sync_msg_pkt(struct sock* sk, __u64 message_id, 
	uint32_t message_size, __u64 start_time);
struct sk_buff* construct_fin_msg_pkt(struct sock* sk, uint64_t msg_id);
struct sk_buff* construct_fin_ack_msg_pkt(struct sock* sk, __u64 message_id);

/* dcpim message hash table functions */
void dcpim_message_table_init(void);
struct dcpim_message* dcpim_lookup_message(struct dcpim_message_bucket *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 dport,
				  const uint64_t id);
bool dcpim_insert_message(struct dcpim_message_bucket *hashinfo, struct dcpim_message* msg);
void dcpim_remove_message(struct dcpim_message_bucket *hashinfo, struct dcpim_message* msg);

#ifdef CONFIG_PROC_FS
int udp4_seq_show(struct seq_file *seq, void *v);
#endif
#endif	/* _UDP4_IMPL_H */
