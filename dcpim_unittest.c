#include <linux/module.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
// #include <linux/blk-mq.h>
#include <crypto/hash.h>
#include <net/busy_poll.h>
#include "dcpim_impl.h"

struct socket* create_mock_socket(void) {
    struct socket *sock;
	struct sockaddr_storage src_addr, addr;
    int ret;
    char *src_traddr = "192.168.10.125", *traddr = "201.168.15.124";
	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
		src_traddr, NULL, &src_addr);
    if(ret)
        WARN_ON(true);
	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			traddr, "2000", &addr);
    if(ret)
        WARN_ON(true);
    sock_create(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM, &sock);
    ret = kernel_bind(sock, (struct sockaddr *)(&src_addr),
        sizeof(src_addr));
    if (ret) {
        printk("ret:%d\n", ret);
        WARN_ON(true);
        return NULL;
    }
	ret = kernel_connect(sock, (struct sockaddr *)(&addr),
		sizeof(addr), 0);
	if (ret) {
        WARN_ON(true);
	}
    return sock;
}

struct dcpim_epoch* create_epoch(void) {
    struct dcpim_epoch* epoch = kmalloc(sizeof(*epoch), GFP_ATOMIC);
	epoch->epoch = 0;
	epoch->round = 0;
	epoch->k = 4;
    epoch->max_array_size = 200;
	epoch->prompt = false;
	epoch->epoch_length = dcpim_params.epoch_length;
	epoch->round_length = dcpim_params.round_length;
	epoch->epoch_bytes_per_k = epoch->epoch_length * dcpim_params.bandwidth / 8 / epoch->k;
	epoch->epoch_bytes = epoch->epoch_bytes_per_k * epoch->k;

	// current epoch and address
	epoch->cur_epoch = 0;
	epoch->cpu = 28;
	spin_lock_init(&epoch->lock);
	spin_lock_init(&epoch->sender_lock);
	spin_lock_init(&epoch->receiver_lock);
	epoch->rts_array = kmalloc(sizeof(struct dcpim_rts) * epoch->max_array_size, GFP_KERNEL);
	epoch->grants_array = kmalloc(sizeof(struct dcpim_grant) * epoch->max_array_size, GFP_KERNEL);
    return epoch;
}

void set_epoch(struct dcpim_epoch *epoch, int k) {
	epoch->k = k;
	epoch->epoch_bytes_per_k = epoch->epoch_length * dcpim_params.bandwidth / 8 / epoch->k;
	epoch->epoch_bytes = epoch->epoch_bytes_per_k * epoch->k;
}

void prepare_grants(struct dcpim_epoch *epoch, struct socket *sock, int size) {
    int i = 0;
    uint8_t h_src[ETH_ALEN] = {0xb8, 0xce, 0xf6, 0x53, 0xc7, 0x10};
    uint8_t h_dest[ETH_ALEN] = {0xb8, 0xce, 0xf6, 0x53, 0xc7, 0x30};

    for (i = 0; i < size; i++) {
        // iph = ip_hdr(skb);
        epoch->grants_array[i].remaining_sz = 100;
        epoch->grants_array[i].dsk = (struct dcpim_sock*)sock->sk;
        // epoch->grants_array[i].dport = htons(10000);
        // epoch->grants_array[i].sport = htons(20000);
        // epoch->grants_array[i].daddr = htonl(3232238205);
        // epoch->grants_array[i].saddr = htonl(3232238204);
        // ether_addr_copy(epoch->grants_array[i].h_dest, h_dest);
        // ether_addr_copy(epoch->grants_array[i].h_source, h_src);
        atomic_inc_return(&epoch->grant_size);
    }
}

void prepare_rts(struct dcpim_epoch *epoch, struct socket *sock, int size) {
    int i = 0;
    for (i = 0; i < size; i++) {
        // iph = ip_hdr(skb);
        epoch->rts_array[i].remaining_sz = 100;
        epoch->rts_array[i].dsk = (struct dcpim_sock*)sock->sk;
        atomic_inc_return(&epoch->rts_size);
    }
}

void test_handle_all_grants(struct dcpim_epoch *epoch, struct socket *sock, int size, int rep) {
    int i = 0;
    u64 start_time, end_time, total_time = 0;
    
    for (i = 0; i < rep; i++) {
		epoch->unmatched_sent_bytes = epoch->epoch_bytes;
        prepare_grants(epoch, sock, size);
        // set_epoch(epoch, size);
        start_time = ktime_get_ns();
        dcpim_handle_all_grants(epoch);
        end_time = ktime_get_ns();
        total_time += end_time - start_time;
    }
    printk("%llu\n", total_time / rep);

}

void test_handle_all_rts(struct dcpim_epoch *epoch, struct socket *sock, int size, int rep) {
    int i = 0;
    u64 start_time, end_time, total_time = 0;
    
    for (i = 0; i < rep; i++) {
		atomic_set(&epoch->unmatched_recv_bytes, epoch->epoch_bytes);
        prepare_rts(epoch, sock, size);
        // set_epoch(epoch, size);
        start_time = ktime_get_ns();
        dcpim_handle_all_rts(epoch);
        end_time = ktime_get_ns();
        total_time += end_time - start_time;
    }
    printk("%llu\n", total_time / rep);

}

void test_main(void) {
    struct dcpim_epoch *epoch = create_epoch();
    struct socket *sock = create_mock_socket();
    int i = 0;
    if(sock == NULL) {
        kfree(&epoch->rts_array);
        kfree(&epoch->grants_array);
        kfree(epoch);
        return;
    }
    for(i = 1; i < 100; i++) {
        test_handle_all_rts(epoch, sock, i, 200);
    }
	sock_release(sock);
    kfree(epoch->rts_array);
    kfree(epoch->grants_array);
    kfree(epoch);
    // kfree(sock);
    return;
}
