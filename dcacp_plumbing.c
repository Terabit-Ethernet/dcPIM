#include <linux/skbuff.h>
#include <net/protocol.h>
#include <net/inet_common.h>

//#include "include/net/dcacp.h"
//#include "dcacp_impl.h"
#include <linux/socket.h>
#include <net/sock.h>
#include <net/udp.h>
#include "dcacp_impl.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qizhe");
MODULE_DESCRIPTION("DCACP transport protocol");
MODULE_VERSION("0.01");

#include "net_dcacp.h"


/* True means that the DCACP module is in the process of unloading itself,
 * so everyone should clean up.
 */

static bool exiting = false;


/* DCACP's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */

#define IPPROTO_DCACP 18
#define IPPROTO_DCACPLITE 19

struct proto dcacp_prot = {
    .name           = "DCACP",
    .owner          = THIS_MODULE,
    .close          = dcacp_lib_close,
    .pre_connect        = dcacp_pre_connect,
    .connect        = ip4_datagram_connect,
    .disconnect     = dcacp_disconnect,
    .ioctl          = dcacp_ioctl,
    .init           = dcacp_init_sock,
    .destroy        = dcacp_destroy_sock,
    .setsockopt     = dcacp_setsockopt,
    .getsockopt     = dcacp_getsockopt,
    .sendmsg        = dcacp_sendmsg,
    .recvmsg        = dcacp_recvmsg,
    .sendpage       = dcacp_sendpage,
    .release_cb     = ip4_datagram_release_cb,
    .hash           = dcacp_lib_hash,
    .unhash         = dcacp_lib_unhash,
    .rehash         = dcacp_v4_rehash,
    .get_port       = dcacp_v4_get_port,
    .memory_allocated   = &dcacp_memory_allocated,
    .sysctl_mem     = sysctl_dcacp_mem,
    .sysctl_wmem_offset = offsetof(struct net, ipv4.sysctl_udp_wmem_min),
    .sysctl_rmem_offset = offsetof(struct net, ipv4.sysctl_udp_rmem_min),
    .obj_size       = sizeof(struct dcacp_sock),
    .h.udp_table        = &dcacp_table,
#ifdef CONFIG_COMPAT
    .compat_setsockopt  = compat_dcacp_setsockopt,
    .compat_getsockopt  = compat_dcacp_getsockopt,
#endif
    .diag_destroy       = dcacp_abort,
};
// EXPORT_SYMBOL(dcacp_prot);

/* Top-level structure describing the DCACP protocol. */

struct inet_protosw dcacp_protosw = {
        .type              = SOCK_DGRAM,
        .protocol          = IPPROTO_DCACP,
        .prot              = &dcacp_prot,
        .ops               = &inet_dgram_ops,
        .flags             = INET_PROTOSW_REUSE,
};

/* thinking of making this const? Don't.
 * early_demux can change based on sysctl.
 */
static struct net_protocol dcacp_protocol = {
        .early_demux =  dcacp_v4_early_demux,
        .early_demux_handler =  dcacp_v4_early_demux,
        .handler =      dcacp_rcv,
        .err_handler =  dcacp_err,
        .no_policy =    1,
        .netns_ok =     1,
};

/**
 * dcacp_load() - invoked when this module is loaded into the Linux kernel
 * Return: 0 on success, otherwise a negative errno.
 */
static int __init dcacp_load(void) {
        int status;
        // struct timespec ts;
        
        printk(KERN_NOTICE "DCACP module loading\n");
        status = proto_register(&dcacp_prot, 1);
        if (status != 0) {
                printk(KERN_ERR "proto_register failed in dcacp_init: %d\n",
                    status);
                goto out;
        }
        printk("dcacp protocol register\n");
        inet_register_protosw(&dcacp_protosw);
        printk("dcacp protocol sw \n");
        status = inet_add_protocol(&dcacp_protocol, IPPROTO_DCACP);
        printk("inet add dcacp\n");

        if (status != 0) {
                printk(KERN_ERR "inet_add_protocol failed in dcacp_load: %d\n",
                    status);
                goto out_cleanup;
        }

        dcacp_init();
        // if (status)
        //         goto out_cleanup;
        // dcacplite4_register();
        // metrics_dir_entry = proc_create("homa_metrics", S_IRUGO,
        //                 init_net.proc_net, &homa_metrics_fops);
        // if (!metrics_dir_entry) {
        //         printk(KERN_ERR "couldn't create /proc/net/homa_metrics\n");
        //         status = -ENOMEM;
        //         goto out_cleanup;
        // }

        // homa_ctl_header = register_net_sysctl(&init_net, "net/homa",
        //                 homa_ctl_table);
        // if (!homa_ctl_header) {
        //         printk(KERN_ERR "couldn't register Homa sysctl parameters\n");
        //         status = -ENOMEM;
        //         goto out_cleanup;
        // }
        
        status = dcacpv4_offload_init();
        printk("init the offload\n");
        if (status != 0) {
                printk(KERN_ERR "DCACP couldn't init offloads\n");
                goto out_cleanup;
        }
        // tasklet_init(&timer_tasklet, homa_tasklet_handler, 0);
        // hrtimer_init(&hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        // hrtimer.function = &homa_hrtimer;
        // ts.tv_nsec = 1000000;                   /* 1 ms */
        // ts.tv_sec = 0;
        // tick_interval = timespec_to_ktime(ts);
        // hrtimer_start(&hrtimer, tick_interval, HRTIMER_MODE_REL);
        
        // tt_init("timetrace");
        
        return 0;

out_cleanup:
        // unregister_net_sysctl_table(homa_ctl_header);
        // proc_remove(metrics_dir_entry);
        if (dcacpv4_offload_end() != 0)
                printk(KERN_ERR "DCACP couldn't stop offloads\n");
        dcacp_destroy();
        inet_del_protocol(&dcacp_protocol, IPPROTO_DCACP);
        printk("inet delete protocol\n");
        inet_unregister_protosw(&dcacp_protosw);
        printk("inet unregister protosw");
        proto_unregister(&dcacp_prot);
        printk("unregister protocol\n");
        // proto_unregister(&dcacplite_prot);
out:
        return status;
}

/**
 * homa_unload() - invoked when this module is unloaded from the Linux kernel.
 */
static void __exit dcacp_unload(void) {
        printk(KERN_NOTICE "DCACP module unloading\n");
        exiting = true;
        
        // tt_destroy();
        
        /* Stopping the hrtimer and tasklet is tricky, because each
         * reschedules the other. This means that the timer could get
         * invoked again after executing tasklet_disable. So, we stop
         * it yet again. The exiting variable will cause it to do
         * nothing, in case it triggers again before we cancel it the
         * second time. Very tricky! 
         */
        // hrtimer_cancel(&hrtimer);
        // tasklet_kill(&timer_tasklet);
        // hrtimer_cancel(&hrtimer);
        // if (homa_offload_end() != 0)
        //         printk(KERN_ERR "Homa couldn't stop offloads\n");
        // unregister_net_sysctl_table(homa_ctl_header);
        // proc_remove(metrics_dir_entry);
        if (dcacpv4_offload_end() != 0)
                printk(KERN_ERR "DCACP couldn't stop offloads\n");
        dcacp_destroy();
        inet_del_protocol(&dcacp_protocol, IPPROTO_DCACP);
        inet_unregister_protosw(&dcacp_protosw);
        proto_unregister(&dcacp_prot);
        // proto_unregister(&dcacplite_prot);
}

module_init(dcacp_load);
module_exit(dcacp_unload);