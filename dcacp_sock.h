/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock 
 *
 * Authors:	Many people, see the TCP sources
 *
 * 		From code originally in TCP
 */
#ifndef _DCACP_SOCK_H
#define _DCACP_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <linux/kernel.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

struct inet_bind_bucket;


static inline int dcacp_sk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&dcacp_sk(sk)->icsk_accept_queue);
}

static inline int dcacp_sk_reqsk_queue_young(const struct sock *sk)
{
	return reqsk_queue_len_young(&dcacp_sk(sk)->icsk_accept_queue);
}

static inline int dcacp_sk_reqsk_queue_is_full(const struct sock *sk)
{
	return dcacp_sk_reqsk_queue_len(sk) >= sk->sk_max_ack_backlog;
}

static inline struct dcacp_request_sock *dcacp_rsk(const struct request_sock *req)
{
	return (struct dcacp_request_sock *)req;
}


// struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern);
void dcacp_set_state(struct sock* sk, int state);
int dcacp_sk_get_port(struct sock *sk, unsigned short snum);

/* sender side sys call: connect */
int dcacp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

/* receiver side sys call: listen and accept */
int dcacp_listen_start(struct sock *sk, int backlog);
int dcacp_listen(struct socket *sock, int backlog);
struct sock *dcacp_sk_accept(struct sock *sk, int flags, int *err, bool kern);

void dcacp_sk_prepare_forced_close(struct sock *sk);


struct request_sock *dcacp_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener);

struct sock *dcacp_sk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child);

// static void dcacp_v4_init_req(struct request_sock *req,
//                             const struct sock *sk_listener,
//                             struct sk_buff *skb);
struct dst_entry *dcacp_sk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req);
struct sock *dcacp_sk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority);
struct sock *dcacp_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb);
struct sock *dcacp_create_con_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst);
struct sock* dcacp_conn_request(struct sock *sk, struct sk_buff *skb);

#endif /* _INET_CONNECTION_SOCK_H */
