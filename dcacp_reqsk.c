



int dcacp_rtx_synack (const struct sock *sk, struct request_sock *req) {
   printk(KERN_WARNING "unimplemented dcacp rtx synack \n");
   return -ENOSYS;
}

static void dcacp_v4_reqsk_send_ack(const struct sock *sk, struct sk_buff *skb,
                                  struct request_sock *req)
{
   printk(KERN_WARNING "unimplemented dcacp reqsk_send_ack \n");
   return -ENOSYS;
}

static void dcacp_v4_reqsk_destructor(struct request_sock *req)
{
    kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
}

static void tcp_v4_send_reset(const struct sock *sk, struct sk_buff *skb) {
   printk(KERN_WARNING "unimplemented dcacp send_reset \n");
   return -ENOSYS;
}

void dcacp_syn_ack_timeout(const struct request_sock *req)
{
   printk(KERN_WARNING "unimplemented dcacp syn ack timeout \n");
   return -ENOSYS;
        // struct net *net = read_pnet(&inet_rsk(req)->ireq_net);

        // __NET_INC_STATS(net, LINUX_MIB_TCPTIMEOUTS);
}
