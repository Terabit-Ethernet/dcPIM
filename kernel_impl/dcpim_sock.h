#ifndef _DCPIM_SOCK_H
#define _DCPIM_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <linux/kernel.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

// struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern);
void dcpim_set_state(struct sock* sk, int state);

/* sender side sys call: connect */
int dcpim_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

/* receiver side sys call: listen and accept */
int dcpim_listen_start(struct sock *sk, int backlog);
int dcpim_listen(struct socket *sock, int backlog);

void dcpim_sk_prepare_forced_close(struct sock *sk);


struct request_sock *dcpim_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener);

struct sock *dcpim_sk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child);

// static void dcpim_v4_init_req(struct request_sock *req,
//                             const struct sock *sk_listener,
//                             struct sk_buff *skb);
struct dst_entry *dcpim_sk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req);
struct sock *dcpim_sk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority);
struct sock *dcpim_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb);
struct sock *dcpim_create_con_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst);
struct sock* dcpim_conn_request(struct sock *sk, struct sk_buff *skb);

#endif /* _INET_CONNECTION_SOCK_H */
