#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>
#include <net/flow.h>
// #include <net/tcp.h>
#include <net/sock_reuseport.h>
#include <net/addrconf.h>

// #include "linux_dcpim.h"
#include "dcpim_impl.h"
#include "dcpim_hashtables.h"
#include "dcpim_ioat.h"

struct inet_timewait_death_row dcpim_death_row = {
	.tw_refcount = REFCOUNT_INIT(1),
	.sysctl_max_tw_buckets = NR_FILE * 2,
	.hashinfo	= &dcpim_hashinfo,
};

EXPORT_SYMBOL_GPL(dcpim_death_row);

static void set_max_grant_batch(struct dst_entry *dst, struct dcpim_sock* dsk) {
	// int bufs_per_gso, mtu, max_pkt_data, gso_size, max_gso_data;
	// // int num_gso_per_bdp;
	// mtu = dst_mtu(dst);
	// gso_size = dst->dev->gso_max_size;
	// /* we assume BDP is larger than max_gso_data for now */
	// // if (gso_size > dcpim_params.bdp)
	// // 	gso_size = dcpim_params.bdp;
	// // if (gso_size > dcpim_params.gso_size)
	// // 	gso_size = dcpim_params.gso_size;
	// bufs_per_gso = gso_size / mtu;
	// max_pkt_data = mtu - sizeof(struct iphdr) - sizeof(struct dcpim_data_hdr);
	// max_gso_data = bufs_per_gso * max_pkt_data;
	// gso_size = bufs_per_gso * mtu;
	// num_gso_per_bdp = DIV_ROUND_UP(dcpim_params.bdp, max_gso_data);
	// dsk->receiver.max_gso_data = max_gso_data;
	// dsk->receiver.max_grant_batch = num_gso_per_bdp * max_gso_data;
}

void reqsk_queue_alloc(struct request_sock_queue *queue)
{
	spin_lock_init(&queue->rskq_lock);

	spin_lock_init(&queue->fastopenq.lock);
	queue->fastopenq.rskq_rst_head = NULL;
	queue->fastopenq.rskq_rst_tail = NULL;
	queue->fastopenq.qlen = 0;

	queue->rskq_accept_head = NULL;
}

void inet_sk_state_store(struct sock *sk, int newstate)
{
	// trace_inet_sock_set_state(sk, sk->sk_state, newstate);
	smp_store_release(&sk->sk_state, newstate);
}


void dcpim_set_state(struct sock* sk, int state) {
	// struct inet_sock* inet = inet_sk(sk);
	struct dcpim_sock *dsk = dcpim_sk(sk);
	switch (state) {
	case DCPIM_ESTABLISHED:
		break;
	case DCPIM_CLOSE:
		// if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
		// 	TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);
		if (sk->sk_state == DCPIM_ESTABLISHED) {
			if(dcpim_sk(sk)->delay_destruct) {
				/* start the timer for rtx fin */
				dsk->fin_sent_times += 1;
				sock_hold(sk);
				hrtimer_start(&dsk->rtx_fin_timer, ns_to_ktime(dcpim_params.rtt * 1000), HRTIMER_MODE_REL_PINNED_SOFT);
				dcpim_xmit_control(construct_fin_pkt(sk), sk); 
			}
		} else if(sk->sk_state == DCPIM_LISTEN){
			sk->sk_prot->unhash(sk);
			/* !(sk->sk_userlocks & SOCK_BINDPORT_LOCK) may need later*/
			if (inet_csk(sk)->icsk_bind_hash) {
				inet_put_port(sk);
			} 
		}
		/* fall through */
	default:
		// if (oldstate == TCP_ESTABLISHED)
			// TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;
	}
	inet_sk_state_store(sk, state);
}

/* This will initiate an outgoing connection. */
int dcpim_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	// struct dcpim_sock *dsk = dcpim_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	// struct dcpim_sock *tp = dcpim_sk(sk);
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;
	struct flowi4 *fl4;
	struct rtable *rt;
	int err;
	// uint32_t flow_len;
	struct ip_options_rcu *inet_opt;
	// struct inet_timewait_death_row *tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;
	// flow_len = (uint32_t)usin->sin_zero[0] << 24 |
    //   (uint32_t)usin->sin_zero[1] << 16 |
    //   (uint32_t)usin->sin_zero[2] << 8  |
    //   (uint32_t)usin->sin_zero[3];	
    WARN_ON(sk->sk_state != DCPIM_CLOSE);
    if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     lockdep_sock_is_held(sk));
	if (inet_opt && inet_opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet_opt->opt.faddr;
	}

	orig_sport = inet->inet_sport;
	orig_dport = usin->sin_port;
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, nexthop, inet->inet_saddr, sk->sk_bound_dev_if,
			      IPPROTO_DCPIM,
			      orig_sport, orig_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return err;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet_opt || !inet_opt->opt.srr)
		daddr = fl4->daddr;

	// set source address
	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;
	sk_rcv_saddr_set(sk, inet->inet_saddr);

	// if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
	// 	/* Reset inherited state */
	// 	tp->rx_opt.ts_recent	   = 0;
	// 	tp->rx_opt.ts_recent_stamp = 0;
	// 	if (likely(!tp->repair))
	// 		WRITE_ONCE(tp->write_seq, 0);
	// }

	// set dest port and address
	inet->inet_dport = usin->sin_port;
	sk_daddr_set(sk, daddr);

	// inet_csk(sk)->icsk_ext_hdr_len = 0;
	// if (inet_opt)
	// 	inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	// tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	dcpim_set_state(sk, DCPIM_ESTABLISHED);
	// source port is decided by bind; if not, set in hash_connect
	err = inet_hash_connect(&dcpim_death_row, sk);
	if (err)
		goto failure;

	sk_set_txhash(sk);

	rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
			       inet->inet_sport, inet->inet_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto failure;
	}
	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	/*set gso capacity */
	sk_setup_caps(sk, &rt->dst);
	/* set dst */
	if (dst_hold_safe(&rt->dst)) {
		// sk->sk_rx_dst = &rt->dst;
		// inet_sk(sk)->rx_dst_ifindex = rt->rt_iif;
		rcu_assign_pointer(sk->sk_rx_dst, &rt->dst);
		sk->sk_rx_dst_ifindex = rt->rt_iif;
	}
	rt = NULL;

	// if (likely(!tp->repair)) {
	// 	if (!tp->write_seq)
	// 		WRITE_ONCE(tp->write_seq,
	// 			   secure_tcp_seq(inet->inet_saddr,
	// 					  inet->inet_daddr,
	// 					  inet->inet_sport,
	// 					  usin->sin_port));
	// 	tp->tsoffset = secure_tcp_ts_off(sock_net(sk),
	// 					 inet->inet_saddr,
	// 					 inet->inet_daddr);
	// }

	inet->inet_id = prandom_u32();

	// if (tcp_fastopen_defer_connect(sk, &err))
	// 	return err;
	// if (err)
	// 	goto failure;

	// err = tcp_connect(sk);

	// send notification pkt
	// if(!dsk->peer)
	// 	dsk->peer = dcpim_peer_find(&dcpim_peers_table, daddr, inet);

	/* in-case the socket priority is 7, the socket are used for sending short flows only. */
	if(sk->sk_priority == 7) {
		dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_SHORT), sk); 
	} else {
		dcpim_xmit_control(construct_flow_sync_pkt(sk, NOTIFICATION_LONG), sk); 
		if(dcpim_sk(sk)->dma_device == NULL && dcpim_enable_ioat)
			dcpim_sk(sk)->dma_device = get_free_ioat_dma_device(sk);
	}
	dcpim_sk(sk)->sender.sync_sent_times += 1;
	hrtimer_start(&dcpim_sk(sk)->sender.rtx_flow_sync_timer,
		ns_to_ktime(1000000), HRTIMER_MODE_REL_PINNED_SOFT);
	/* add to flow matching table */
	dcpim_add_mat_tab(&dcpim_epoch, sk);


	// dsk->total_length = flow_len;

	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	dcpim_set_state(sk, DCPIM_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}
EXPORT_SYMBOL(dcpim_v4_connect);

/*
 *	Move a socket into listening state.
 */
int dcpim_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;

	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_DGRAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (DCPIMF_CLOSE | DCPIMF_LISTEN)))
		goto out;

	WRITE_ONCE(sk->sk_max_ack_backlog, backlog);
	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != DCPIM_LISTEN) {
		/* Enable TFO w/o requiring TCP_FASTOPEN socket option.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopen backlog may already been set via the option
		 * because the socket was in TCP_LISTEN state previously but
		 * was shutdown() rather than close().
		 */
		// tcp_fastopen = sock_net(sk)->ipv4.sysctl_tcp_fastopen;
		// if ((tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) &&
		//     (tcp_fastopen & TFO_SERVER_ENABLE) &&
		//     !inet_csk(sk)->icsk_accept_queue.fastopenq.max_qlen) {
		// 	fastopen_queue_tune(sk, backlog);
		// 	tcp_fastopen_init_key_once(sock_net(sk));
		// }
		err = inet_csk_listen_start(sk);
		if (err)
			goto out;
		// tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_LISTEN_CB, 0, NULL);
	}
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(dcpim_listen);

struct request_sock *dcpim_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener)
{
	struct request_sock *req = reqsk_alloc(ops, sk_listener,
					       attach_listener);

	if (req) {
		struct inet_request_sock *ireq = inet_rsk(req);
		atomic64_set(&ireq->ir_cookie, 0);
		// ireq->ireq_state = TCP_NEW_SYN_RECV;
		write_pnet(&ireq->ireq_net, sock_net(sk_listener));
		ireq->ireq_family = sk_listener->sk_family;
	}

	return req;
}
EXPORT_SYMBOL(dcpim_reqsk_alloc);

/* This function allows to force a closure of a socket after the call to
 * dcpim_create_openreq_child().
 */
void dcpim_sk_prepare_forced_close(struct sock *sk)
	__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	// percpu_counter_inc(sk->sk_prot->orphan_count);
	inet_sk(sk)->inet_num = 0;
}
EXPORT_SYMBOL(dcpim_sk_prepare_forced_close);

struct sock *dcpim_sk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;

	spin_lock(&queue->rskq_lock);
	if (unlikely(sk->sk_state != DCPIM_LISTEN)) {
		// inet_child_forget(sk, req, child);
		WARN_ON(sk->sk_state != DCPIM_CLOSE);
		WARN_ON(!sock_flag(sk, SOCK_DEAD));

		/* It cannot be in hash table! */
		WARN_ON(!sk_unhashed(sk));
		/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
		WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);
		/* Remove from the bind table */
		inet_put_port(child);
		/* Remove step may change latter */
		dcpim_sk_prepare_forced_close(child);
		sock_put(child);
		child = NULL;
	} else {
		req->sk = child;
		req->dl_next = NULL;
		if (queue->rskq_accept_head == NULL)
			WRITE_ONCE(queue->rskq_accept_head, req);
		else
			queue->rskq_accept_tail->dl_next = req;
		queue->rskq_accept_tail = req;
		sk_acceptq_added(sk);
	}
	spin_unlock(&queue->rskq_lock);
	return child;
}
EXPORT_SYMBOL(dcpim_sk_reqsk_queue_add);

static void dcpim_v4_init_req(struct request_sock *req,
                            const struct sock *sk_listener,
                            struct sk_buff *skb)
{
	    struct inet_request_sock *ireq = inet_rsk(req);
        sk_rcv_saddr_set(req_to_sk(req), ip_hdr(skb)->daddr);
        sk_daddr_set(req_to_sk(req), ip_hdr(skb)->saddr);
        ireq->ir_rmt_port = dcpim_hdr(skb)->source;
        ireq->ir_num = ntohs(dcpim_hdr(skb)->dest);
        ireq->ir_mark = inet_request_mark(sk_listener, skb);
		ireq->no_srccheck = inet_sk(sk_listener)->transparent;
		/* Note: tcp_v6_init_req() might override ir_iif for link locals */
		ireq->ir_iif = inet_request_bound_dev_if(sk_listener, skb);
		/* For now, ireq_opt is always NULL */
		ireq->ireq_opt = NULL;
        // RCU_INIT_POINTER(ireq->ireq_opt, dcpim_v4_save_options(net, skb));
		refcount_set(&req->rsk_refcnt, 1);
}


/**
 *	dcpim_sk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *dcpim_sk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);

	if (newsk) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);
		newicsk->icsk_bind_hash = NULL;
		// dsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->ir_rmt_port;
		inet_sk(newsk)->inet_num = inet_rsk(req)->ir_num;
		inet_sk(newsk)->inet_sport = htons(inet_rsk(req)->ir_num);

		/* listeners have SOCK_RCU_FREE, not the children */
		sock_reset_flag(newsk, SOCK_RCU_FREE);

		inet_sk(newsk)->mc_list = NULL;

		newsk->sk_mark = inet_rsk(req)->ir_mark;
		atomic64_set(&newsk->sk_cookie,
			     atomic64_read(&inet_rsk(req)->ir_cookie));
		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;
		newicsk->icsk_probes_tstamp = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

	}
	return newsk;
}
EXPORT_SYMBOL_GPL(dcpim_sk_clone_lock);


/* This is not only more efficient than what we used to do, it eliminates
 * a lot of code duplication between IPv4/IPv6 SYN recv processing. -DaveM
 *
 * Actually, we could lots of memory writes here. tp of listening
 * socket contains all necessary default parameters.
 */
struct sock *dcpim_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb)
{
	struct sock *newsk = dcpim_sk_clone_lock(sk, req, GFP_ATOMIC);

	// const struct inet_request_sock *ireq = inet_rsk(req);
	// struct dcpim_sock *olddp, *newdp;
	// u32 seq;
	if (!newsk)
		return NULL;
	/*TODO: initialize the dcpim socket here */
	return newsk;
}
EXPORT_SYMBOL(dcpim_create_openreq_child);

struct dst_entry *dcpim_sk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	// printk("reach to ireq is null:%d %p \n", ireq == NULL, ireq);
	struct net *net = read_pnet(&ireq->ireq_net);
	// printk("reach to net is null:%d %p \n", net == NULL, ireq);

	struct inet_sock *newinet = inet_sk(newsk);
	struct ip_options_rcu *opt;
	struct flowi4 *fl4;
	struct rtable *rt;

	opt = rcu_dereference(ireq->ireq_opt);
	// printk("reach to fl4 opt is null:%d %p \n", opt == NULL, opt);
	fl4 = &newinet->cork.fl.u.ip4;
	// printk("fl4: %p %d %d %d\n", fl4, ireq->ir_iif, ireq->ir_mark, RT_CONN_FLAGS(sk));
	// printk("second: %d %d %d %d\n", sk->sk_protocol,  inet_sk_flowi_flags(sk), (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr, ireq->ir_loc_addr);
	// printk("thrid: %d %d %u \n",  ireq->ir_rmt_port, htons(ireq->ir_num), sk->sk_uid);

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, ireq->ir_rmt_port,
			   htons(ireq->ir_num), sk->sk_uid);
	security_req_classify_flow(req, flowi4_to_flowi_common(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	// printk("finish ip route output output\n");
	// printk("finish init output\n");

	if (IS_ERR(rt)) {
		// printk("goto no route\n");
		goto no_route;
	}
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway) {
		// printk("got to route err\n");
		goto route_err;
	}
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(dcpim_sk_route_child_sock);

void inet_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	if (dst && dst_hold_safe(dst)) {
		rcu_assign_pointer(sk->sk_rx_dst, dst);
		sk->sk_rx_dst_ifindex = skb->skb_iif;
	}
}
/*
 * Receive flow sync pkt: create new socket and push this to the accept queue
 */
struct sock *dcpim_create_con_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct dcpim_sock *newdp;
	struct sock *newsk;
	struct dcpim_sock *dsk;
	struct ip_options_rcu *inet_opt;
	// struct dcpim_flow_sync_hdr *fhdr = dcpim_flow_sync_hdr(skb);
	bool state;
	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	newsk = dcpim_create_openreq_child(sk, req, skb);

	/* this init function may be used later */
	dcpim_init_sock(newsk);
	if (!newsk)
		goto exit_nonewsk;
 	if(!dst) {
 		dst = dcpim_sk_route_child_sock(sk, newsk, req);
	    if (!dst)
	        goto put_and_exit;
 	}

	newsk->sk_gso_type = SKB_GSO_TCPV4;
	inet_sk_rx_dst_set(newsk, skb);

	newdp		      = dcpim_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	sk_daddr_set(newsk, ireq->ir_rmt_addr);
	sk_rcv_saddr_set(newsk, ireq->ir_loc_addr);
	newsk->sk_bound_dev_if = ireq->ir_iif;
	newinet->inet_saddr   = ireq->ir_loc_addr;
	inet_opt	      = rcu_dereference(ireq->ireq_opt);
	RCU_INIT_POINTER(newinet->inet_opt, inet_opt);

	/* set up flow ID and flow size */
	dsk = dcpim_sk(newsk);
	// dsk->flow_id = fhdr->flow_id;
	dsk->core_id = dcpim_sk(sk)->core_id;
	// dsk->total_length = ntohl(fhdr->flow_size);
	set_max_grant_batch(dst, dsk);
	/* set up max gso segment */
	sk_setup_caps(newsk, dst);

	/* add new socket to binding table */
	if (__inet_inherit_port(sk, newsk) < 0)
		goto put_and_exit;

	/* add socket to request queue */
    newsk = dcpim_sk_reqsk_queue_add(sk, req, newsk);
    if(newsk) {
		/* Unlike TCP, req_sock will not be inserted in the ehash table initially.*/
	  	dcpim_set_state(newsk, DCPIM_ESTABLISHED);
		state = inet_ehash_nolisten(newsk, NULL, NULL);
		/* TO DO: if state is false, go to put_exit */
    	sock_rps_save_rxhash(newsk, skb);
    } 
	return newsk;

exit_overflow:

	NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit_nonewsk:

	dst_release(dst);
exit:
	// tcp_listendrop(sk);
	return NULL;
put_and_exit:
	// newinet->inet_opt = NULL;
	printk("put and exit");
	dcpim_sk_prepare_forced_close(newsk);
	sock_put(newsk);
	// inet_csk_prepare_forced_close(newsk);
	// tcp_done(newsk);
	// dcpim_set_state(newsk, DCPIM_CLOSE);
	goto exit;
}
EXPORT_SYMBOL(dcpim_create_con_sock);

struct sock* dcpim_conn_request(struct sock *sk, struct sk_buff *skb)
{
	// struct tcp_fastopen_cookie foc = { .len = -1 };
	// __u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
	// struct tcp_options_received tmp_opt;
	// struct dcpim_sock *dp = dcpim_sk(sk);
	// struct net *net = sock_net(sk);
	struct sock *child = NULL;
	// struct dst_entry *dst = NULL;
	struct request_sock *req;
	// struct flowi fl;

	/* sk_acceptq_is_full(sk) should be
	 * the same as dcpim_sk_reqsk_is_full in DCPIM.
	 */
	if (sk_acceptq_is_full(sk)) {
		goto drop;
	}

	/* create the request sock and don't attach to the listener socket. */
	req = dcpim_reqsk_alloc(&dcpim_request_sock_ops, sk, false);
	if (!req)
		goto drop;

	/* Initialize the request sock `*/
	dcpim_v4_init_req(req, sk, skb);

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	// reqsk_put(req);

    child = dcpim_create_con_sock(sk, skb, req, NULL);

    if (!child){
    	goto drop_and_free;
    }
	sk->sk_data_ready(sk);
	bh_unlock_sock(child);
	sock_put(child);
	return child;

drop_and_free:
	reqsk_free(req);

drop:
	return NULL;
}
EXPORT_SYMBOL(dcpim_conn_request);
