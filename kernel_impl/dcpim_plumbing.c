#include <linux/skbuff.h>
#include <net/protocol.h>
#include <net/inet_common.h>

//#include "include/net/dcpim.h"
//#include "dcpim_impl.h"
#include <linux/socket.h>
#include <net/sock.h>
#include <net/udp.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include "dcpim_impl.h"
#include "dcpim_unittest.h"
#include "dcpim_ioat.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qizhe");
MODULE_DESCRIPTION("DCPIM transport protocol");
MODULE_VERSION("0.01");

#include "net_dcpim.h"

#define DCPIM_ADD_FLOW 0xFFAB
#define DCPIM_REMOVE_FLOW 0xFFAC

DEFINE_PER_CPU(int, dcpim_memory_per_cpu_fw_alloc);
EXPORT_PER_CPU_SYMBOL_GPL(dcpim_memory_per_cpu_fw_alloc);

/* True means that the DCPIM module is in the process of unloading itself,
 * so everyone should clean up.
 */

static bool exiting = false;
int sysctl_dcpim_rmem_min __read_mostly;
int sysctl_dcpim_wmem_min __read_mostly;

int dcpim_enable_ioat = 0;
module_param(dcpim_enable_ioat, int ,0660);

/* DCPIM's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */

// struct test_element{
//     struct list_head node;
//     int value;
// };

// bool test_compare(const struct list_head* node1, const struct list_head* node2) {
//     struct test_element *e1, *e2;
//     e1 = list_entry(node1, struct test_element, node);
//     e2 = list_entry(node2, struct test_element, node);
//     if(e1->value > e2->value)
//         return true;
//     return false;

// }
// #define IPPROTO_DCPIM 200

struct _dcpimdevice_data {
	struct cdev cdev;
	uint8_t data;
};
typedef struct _dcpimdevice_data dcpim_data;

static dcpim_data dcpimdevice_data;
static struct class *cl;
static dev_t dev;


static int dcpimdevice_open(struct inode *inode, struct file *file) {
	// cd_data *customdevice_data = container_of(inode->i_cdev, cd_data, cdev);
	return 0;
}

static int dcpimdevice_release(struct inode *inode, struct file *file) {
	// cd_data *customdevice_data = container_of(inode->i_cdev, cd_data, cdev);
	return 0;
}

static long dcpimdevice_ioctl(struct file *file,
			       unsigned int cmd,
			       unsigned long arg) {
        // int fd = arg, err;
        // struct dcpim_flow *flow = NULL, *ftemp;
        // struct socket* sock;
	// switch(cmd) {
        //         case DCPIM_ADD_FLOW:
        //                 sock = sockfd_lookup(fd, &err);
        //                 if(sock) {
        //                         /* add socket into the flow matching table */
        //                         flow = kmalloc(sizeof(struct dcpim_flow), GFP_KERNEL);
        //                         flow->sock = sock->sk;
        //                         sock_hold(sock->sk);
        //                         INIT_LIST_HEAD(&flow->entry);
        //                         spin_lock_bh(&dcpim_epoch.sender_lock);
        //                         list_add_tail_rcu(&flow->entry, &dcpim_epoch.flow_list);
        //                         spin_unlock_bh(&dcpim_epoch.sender_lock);
        //                 }
        //                 break;
        //         case DCPIM_REMOVE_FLOW:
        //                 sock = sockfd_lookup(fd, &err);
        //                 if(sock) {
        //                         rcu_read_lock();
        //                         list_for_each_entry_rcu(ftemp, &dcpim_epoch.flow_list, entry) {
        //                                 if(ftemp->sock == sock->sk) {
        //                                         flow = ftemp;
        //                                         break;
        //                                 }
        //                         }
        //                         rcu_read_unlock();
        //                         /* remove socket from the flow matching table */ 
        //                         if(flow) {
        //                                 spin_lock_bh(&dcpim_epoch.sender_lock);
        //                                 list_del_rcu(&flow->entry);
        //                                 spin_unlock_bh(&dcpim_epoch.sender_lock);
        //                                 synchronize_rcu();
        //                                 sock_put(flow->sock);
        //                                 kfree(flow);
        //                         } 
        //                 }
        //                 break;
	// }
	return 0;
}

const struct file_operations dcpimdevice_fops = {
    .owner = THIS_MODULE,
    .open = dcpimdevice_open,
    .release = dcpimdevice_release,
    .unlocked_ioctl = dcpimdevice_ioctl
};

static int dcpimdevice_init(void) {
	int ret;
	struct device *dev_ret;

	// Create character device region
	ret = alloc_chrdev_region(&dev, 0, 1, "dcpimdevice");
	if (ret < 0) {
		return ret;
	}

	// Create class for sysfs
	cl = class_create(THIS_MODULE, "chardrv");
	if (IS_ERR(cl)) {
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(cl);
	}

	// Create device for sysfs
	dev_ret = device_create(cl, NULL, dev, NULL, "dcpimdevice");
	if (IS_ERR(dev_ret)) {
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(dev_ret);
	}

	// Create character device
	cdev_init(&dcpimdevice_data.cdev, &dcpimdevice_fops);
	ret = cdev_add(&dcpimdevice_data.cdev, dev, 1);
	if (ret < 0) {
		device_destroy(cl, dev);
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		return ret;
	}

	return 0;
}

static void dcpimdevice_exit(void) {
	device_destroy(cl, dev);
	class_destroy(cl);
	cdev_del(&dcpimdevice_data.cdev);
	unregister_chrdev_region(dev, 1);
}

const struct proto_ops dcpim_dgram_ops = {
    .family        = AF_INET,
    .owner         = THIS_MODULE,
    .release       = inet_release,
    .bind          = inet_bind,
    .connect       = inet_dgram_connect,
    .socketpair    = sock_no_socketpair,
    .accept        = inet_accept,
    .getname       = inet_getname,
    .poll          = dcpim_poll,
    .ioctl         = inet_ioctl,
    .gettstamp     = sock_gettstamp,
    .listen        = dcpim_listen,
    .shutdown      = inet_shutdown,
    .setsockopt    = sock_common_setsockopt,
    .getsockopt    = sock_common_getsockopt,
    .sendmsg       = inet_sendmsg,
    .recvmsg       = inet_recvmsg,
    .mmap          = sock_no_mmap,
    .sendpage      = inet_sendpage,
    .set_peek_off      = sk_set_peek_off,
// #ifdef CONFIG_COMPAT
//     .compat_setsockopt = compat_sock_common_setsockopt,
//     .compat_getsockopt = compat_sock_common_getsockopt,
//     // .compat_ioctl      = inet_compat_ioctl,
// #endif
};
// EXPORT_SYMBOL(inet_dgram_ops);

struct proto dcpim_prot = {
    .name           = "DCPIM",
    .owner          = THIS_MODULE,
    .close          = dcpim_lib_close,
    .pre_connect    = NULL,
    .connect        = dcpim_v4_connect,
    .disconnect     = dcpim_disconnect,
    .accept         = inet_csk_accept,
    .ioctl          = dcpim_ioctl,
    .init           = dcpim_init_sock,
    .destroy        = dcpim_destroy_sock,
    .setsockopt     = dcpim_setsockopt,
    .getsockopt     = dcpim_lib_getsockopt,
    .sendmsg        = dcpim_sendmsg,
    .recvmsg        = dcpim_recvmsg,
    .sendpage       = dcpim_sendpage,
    .backlog_rcv    = dcpim_v4_do_rcv,
    .release_cb     = dcpim_release_cb,
    .hash           = inet_hash,
    .unhash         = inet_unhash,
    // .rehash         = dcpim_v4_rehash,
    .get_port       = inet_csk_get_port,
    .memory_allocated   = &dcpim_memory_allocated,
    .per_cpu_fw_alloc	= &dcpim_memory_per_cpu_fw_alloc,
    .sysctl_mem     = sysctl_dcpim_mem,
    .sysctl_wmem = &sysctl_dcpim_wmem_min,
    .sysctl_rmem = &sysctl_dcpim_rmem_min,
    .obj_size       = sizeof(struct dcpim_sock),
    .rsk_prot       = &dcpim_request_sock_ops,
    .h.hashinfo     = &dcpim_hashinfo,
    // .h.udp_table        = &dcpim_table,
    .max_header     = DCPIM_HEADER_MAX_SIZE,
    .diag_destroy       = dcpim_abort,
    .no_autobind       = 1,
};
// EXPORT_SYMBOL(dcpim_prot);

/* Top-level structure describing the DCPIM protocol. */

struct inet_protosw dcpim_protosw = {
        .type              = SOCK_DGRAM,
        .protocol          = IPPROTO_DCPIM,
        .prot              = &dcpim_prot,
        .ops               = &dcpim_dgram_ops,
        .flags             = INET_PROTOSW_REUSE,
};

/* thinking of making this const? Don't.
 * early_demux can change based on sysctl.
 */
static struct net_protocol dcpim_protocol = {
        .handler =      dcpim_rcv,
        .err_handler =  dcpim_err,
        .no_policy =    1,
};

/* Used to configure sysctl access to dcPIM configuration parameters.*/
static struct ctl_table dcpim_ctl_table[] = {
        {
                // this is only being called when unloading the module
                .procname       = "clean_match_sock",
                .data           = &dcpim_params.clean_match_sock,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = dcpim_dointvec
        },
        {
                .procname       = "rmem_default",
                .data           = &dcpim_params.rmem_default,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = dcpim_dointvec
        },
        {
                .procname       = "wmem_default",
                .data           = &dcpim_params.wmem_default,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = dcpim_dointvec
        },
        {
                .procname       = "short_flow_size",
                .data           = &dcpim_params.short_flow_size,
                .maxlen         = sizeof(int),
                .mode           = 0644,
                .proc_handler   = dcpim_dointvec
        },
        {}
};

/*
 *      IPv4 request_sock destructor.
 */
static void dcpim_v4_reqsk_destructor(struct request_sock *req)
{
        if(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1))
		kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
}

struct request_sock_ops dcpim_request_sock_ops __read_mostly = {
        .family         =       AF_INET,
        .obj_size       =       sizeof(struct dcpim_request_sock),
        .rtx_syn_ack    =       NULL,
        .send_ack       =       NULL,
        .destructor     =       dcpim_v4_reqsk_destructor,
        .send_reset     =       NULL,
        .syn_ack_timeout =      NULL,
};


/* Used to remove sysctl values when the module is unloaded. */
static struct ctl_table_header *dcpim_ctl_header;

void dcpim_params_init(struct dcpim_params* params) {
    params->clean_match_sock = 0;
    params->match_socket_port = 3000;
    params->bandwidth = 98; // in Gbps
    params->control_pkt_rtt = 20; // in us
    params->rtt = 60; // in us
    params->bdp  = params->rtt * params->bandwidth / 8 * 1000; // bytes
    /* retransmission time = rtx_message * controk pkt rtt for messages */
    params->rtx_messages = 5;
    // params->bdp = 500000;
    // params->gso_size = 1500;
    // matchiing parameters
    params->alpha = 1;
    params->beta = 13; // beta / 10 is the real beta.
    params->fct_round = 1;
    params->num_rounds = 4;
    params->round_length = params->beta * params->control_pkt_rtt * 1000 / 10; // in ns
    params->epoch_length = params->num_rounds * params->round_length * params->alpha;
    params->rmem_default = 4384520;
    params->wmem_default = 4384520;
    params->short_flow_size = params->bdp;
    params->control_pkt_bdp = params->control_pkt_rtt * params->bandwidth * 1000 / 8;
    params->data_budget = 1000000;
}
/**
 * dcpim_dointvec() - This function is a wrapper around proc_dointvec. It is
 * invoked to read and write sysctl values and also update other values
 * that depend on the modified value.
 * @table:    sysctl table describing value to be read or written.
 * @write:    Nonzero means value is being written, 0 means read.
 * @buffer:   Address in user space of the input/output data.
 * @lenp:     Not exactly sure.
 * @ppos:     Not exactly sure.
 * 
 * Return: 0 for success, nonzero for error. 
 */
int dcpim_dointvec(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp, loff_t *ppos)
{
        int result;
        result = proc_dointvec(table, write, buffer, lenp, ppos);
        if (write) {
                /* Don't worry which particular value changed; update
                 * all info that is dependent on any sysctl value.
                 */
                dcpim_sysctl_changed(&dcpim_params);
        }
        return result;
}

/**
 * dcpim_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any output-related parameters that depend on sysctl-settable values.
 * @params:    Overall data about the DCPIM protocol implementation.
 */
void dcpim_sysctl_changed(struct dcpim_params *params)
{
        // __u64 tmp;
    if(params->clean_match_sock == 1) {
        // sock_release(dcpim_match_table.sock);
        // dcpim_match_table.sock = NULL;
        // dcpim_epoch_destroy(&dcpim_epoch);
        params->clean_match_sock = 0;
    }
}
/**
 * dcpim_load() - invoked when this module is loaded into the Linux kernel
 * Return: 0 on success, otherwise a negative errno.
 */
static int __init dcpim_load(void) {
        int status;
        // struct timespec ts;
        // struct test_element e1, e2, e3, e4, e5;
        // struct test_element *temp;
        // struct dcpim_pq pq;
        // e1.value = 1;
        // e2.value = 6;
        // e3.value = 3;
        // e4.value = 4;
        // e5.value = 5;
        // dcpim_pq_init(&pq, test_compare);
        // dcpim_pq_push(&pq, &e5.node);
        // dcpim_pq_push(&pq, &e4.node);
        // dcpim_pq_push(&pq, &e3.node);
        // dcpim_pq_push(&pq, &e2.node);
        // dcpim_pq_push(&pq, &e1.node);
        //     printk("e5 pos:%p\n", &e5.node);
        // while(!dcpim_pq_empty(&pq)) {
        //     struct list_head *head;
        //     printk("num element:%d\n", pq.count);
        //     head = dcpim_pq_pop(&pq);
        //     temp = list_entry(head, struct test_element, node);
        //     printk("value: %d\n", temp->value);
        // }
        printk(KERN_NOTICE "DCPIM module loading\n");
        init_ioat_dma_devices();
        dcpim_wq = alloc_workqueue("dcpim_wq", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0); 
        dcpim_params_init(&dcpim_params);

        dcpim_init();
        // dcpim_mattab_init(&dcpim_match_table, NULL);

        status = proto_register(&dcpim_prot, 1);
        if (status != 0) {
                printk(KERN_ERR "proto_register failed in dcpim_init: %d\n",
                    status);
                goto out;
        }
        inet_register_protosw(&dcpim_protosw);
        status = inet_add_protocol(&dcpim_protocol, IPPROTO_DCPIM);

        if (status != 0) {
                printk(KERN_ERR "inet_add_protocol failed in dcpim_load: %d\n",
                    status);
                goto out_cleanup;
        }
        dcpim_epoch_init(&dcpim_epoch);
        dcpim_message_table_init();
        dcpim_ctl_header = register_net_sysctl(&init_net, "net/dcpim",
                        dcpim_ctl_table);
        if (!dcpim_ctl_header) {
                printk(KERN_ERR "couldn't register DCPIM sysctl parameters\n");
                status = -ENOMEM;
                goto out_cleanup;
        }
        status = dcpimv4_offload_init();
        if (status != 0) {
                printk(KERN_ERR "DCPIM couldn't init offloads\n");
                goto out_cleanup;
        }
       status = dcpimdevice_init();
       if(status != 0)
                goto out_cleanup;
        
        // tt_init("timetrace");
        return 0;

out_cleanup:
        /* To Do: clean up need to take care more */
        if (dcpimv4_offload_end() != 0)
            printk(KERN_ERR "DCPIM couldn't stop offloads\n");
        dcpim_epoch_destroy(&dcpim_epoch);
        dcpim_message_table_destroy();
        unregister_net_sysctl_table(dcpim_ctl_header);
        dcpim_destroy();
        inet_del_protocol(&dcpim_protocol, IPPROTO_DCPIM);
        inet_unregister_protosw(&dcpim_protosw);
        proto_unregister(&dcpim_prot);
	flush_workqueue(dcpim_wq);
	destroy_workqueue(dcpim_wq);
        release_ioat_dma_devices();
        // proto_unregister(&dcpimlite_prot);
out:
        return status;
}

/**
 * dcpim_unload() - invoked when this module is unloaded from the Linux kernel.
 */
static void __exit dcpim_unload(void) {
        printk(KERN_NOTICE "DCPIM module unloading\n");
        exiting = true;
        dcpimdevice_exit();
        if (dcpimv4_offload_end() != 0)
            printk(KERN_ERR "DCPIM couldn't stop offloads\n");
        dcpim_epoch_destroy(&dcpim_epoch);
        dcpim_message_table_destroy();
        unregister_net_sysctl_table(dcpim_ctl_header);

        // dcpim_mattab_destroy(&dcpim_match_table);
        // printk("remove match table\n");

        dcpim_destroy();

        inet_del_protocol(&dcpim_protocol, IPPROTO_DCPIM);
        inet_unregister_protosw(&dcpim_protosw);
        proto_unregister(&dcpim_prot);
	flush_workqueue(dcpim_wq);
	destroy_workqueue(dcpim_wq);
        release_ioat_dma_devices();
        // proto_unregister(&dcpimlite_prot);
}

module_init(dcpim_load);
module_exit(dcpim_unload);
