#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

SYMBOL_CRC(dcpim_death_row, 0xcf3cac74, "_gpl");
SYMBOL_CRC(dcpim_v4_connect, 0x8370d16b, "");
SYMBOL_CRC(dcpim_listen, 0x0b04ac40, "");
SYMBOL_CRC(dcpim_reqsk_alloc, 0x39a57470, "");
SYMBOL_CRC(dcpim_sk_prepare_forced_close, 0x1ae5ef17, "");
SYMBOL_CRC(dcpim_sk_reqsk_queue_add, 0x75c99eb2, "");
SYMBOL_CRC(dcpim_sk_clone_lock, 0x1a6d3c91, "_gpl");
SYMBOL_CRC(dcpim_create_openreq_child, 0x64987040, "");
SYMBOL_CRC(dcpim_sk_route_child_sock, 0x5581b5d4, "_gpl");
SYMBOL_CRC(dcpim_create_con_sock, 0x2b114c8e, "");
SYMBOL_CRC(dcpim_conn_request, 0x76b0d074, "");
SYMBOL_CRC(dcpim_release_cb, 0xf8dc0df5, "");
SYMBOL_CRC(sysctl_dcpim_mem, 0xbb3d5dcf, "");
SYMBOL_CRC(dcpim_memory_allocated, 0x4618aeed, "");
SYMBOL_CRC(dcpim_params, 0x1ff41591, "");
SYMBOL_CRC(dcpim_epoch, 0xdd230fd8, "");
SYMBOL_CRC(dcpim_hashinfo, 0xaf9c4f69, "");
SYMBOL_CRC(sk_wait_ack, 0x7cabb7ec, "");
SYMBOL_CRC(dcpim_sendmsg, 0x11008a58, "");
SYMBOL_CRC(dcpim_destruct_sock, 0xb85aa016, "_gpl");
SYMBOL_CRC(dcpim_init_sock, 0x9fb460f1, "_gpl");
SYMBOL_CRC(dcpim_ioctl, 0x3c9cb814, "");
SYMBOL_CRC(dcpim_disconnect, 0x55aee000, "");
SYMBOL_CRC(dcpim_lib_getsockopt, 0x18ac3f9f, "");
SYMBOL_CRC(dcpim_poll, 0xf58c866c, "");
SYMBOL_CRC(dcpim_abort, 0x35b27377, "_gpl");
SYMBOL_CRC(dcpim_memory_per_cpu_fw_alloc, 0x492bf8e2, "_gpl");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xae95276d, "__inet_lookup_established" },
	{ 0xc51781b2, "inet_recvmsg" },
	{ 0xce945996, "inet_hashinfo2_init_mod" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0x27fa66e1, "nr_free_buffer_pages" },
	{ 0xb76ee4db, "__class_create" },
	{ 0xb34f3d73, "inet_unregister_protosw" },
	{ 0xf4707cf4, "inet_ehash_locks_alloc" },
	{ 0x3d853440, "skb_put" },
	{ 0xa0f8d799, "register_net_sysctl" },
	{ 0xdf2c2742, "rb_last" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0xb0e602eb, "memmove" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x51cadfcb, "__inet_lookup_listener" },
	{ 0x8538001, "inet_csk_accept" },
	{ 0x7b0e5658, "skb_dequeue" },
	{ 0xca9360b5, "rb_next" },
	{ 0x7239aa83, "skb_segment" },
	{ 0x51a511eb, "_raw_write_lock_bh" },
	{ 0xa4fc8b5f, "class_destroy" },
	{ 0x2e75ae6e, "sock_common_getsockopt" },
	{ 0xe7bbd167, "inet_bind" },
	{ 0x13265f76, "__inet_inherit_port" },
	{ 0x2d0684a9, "hrtimer_init" },
	{ 0xd4592578, "security_inet_conn_request" },
	{ 0x37a0cba, "kfree" },
	{ 0x14ccfaed, "inet_register_protosw" },
	{ 0x5f2ba55e, "security_req_classify_flow" },
	{ 0x4afb2238, "add_wait_queue" },
	{ 0xe7ab1ecc, "_raw_write_unlock_bh" },
	{ 0x47e78146, "sock_common_setsockopt" },
	{ 0x3eeb2322, "__wake_up" },
	{ 0xe421f8f3, "ip_route_output_flow" },
	{ 0x2d1c97e4, "kmem_cache_create" },
	{ 0xa5526619, "rb_insert_color" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x7f4f9ad0, "kmem_cache_alloc_trace" },
	{ 0x1875fd17, "__pskb_copy_fclone" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf2b27de4, "pskb_expand_head" },
	{ 0x80d48019, "inet_ehash_nolisten" },
	{ 0x710e4eb3, "inet_sock_destruct" },
	{ 0x7afbd238, "inet_put_port" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x92997ed8, "_printk" },
	{ 0x39609826, "inet_getname" },
	{ 0xbc6801f9, "proto_unregister" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0x581f25b9, "make_kuid" },
	{ 0x71b144dc, "__alloc_skb" },
	{ 0x15b466a8, "inet_release" },
	{ 0x7ca19ecb, "udp_poll" },
	{ 0x2aea24a0, "sk_clone_lock" },
	{ 0x970d65ec, "__sk_dst_check" },
	{ 0x54d7701d, "kmem_cache_alloc" },
	{ 0x5ff68ae9, "ip_route_output_key_hash" },
	{ 0xd6faff8f, "skb_try_coalesce" },
	{ 0x78ebe944, "proto_register" },
	{ 0xd0654aba, "woken_wake_function" },
	{ 0x278c315e, "skb_queue_tail" },
	{ 0x4bccdb37, "inet_hash" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xa6f95abf, "cdev_add" },
	{ 0xbcb36fe4, "hugetlb_optimize_vmemmap_key" },
	{ 0xadd139d4, "rfs_needed" },
	{ 0x29604158, "napi_busy_loop" },
	{ 0x6e34e767, "inet_csk_get_port" },
	{ 0xe32137e0, "inet_ioctl" },
	{ 0x9eed781b, "inet_accept" },
	{ 0x2eaf487f, "init_net" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0x5e0a9329, "inet_add_offload" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0xec6dbb73, "ip6_mtu" },
	{ 0x4927ab5b, "device_create" },
	{ 0xe5429b0c, "inet_add_protocol" },
	{ 0xce69fedb, "inet_shutdown" },
	{ 0x7a183de, "sk_free" },
	{ 0x577f6415, "sock_wake_async" },
	{ 0xac60af54, "kfree_skb_reason" },
	{ 0x43aa1e39, "dev_get_by_index_rcu" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xa757b043, "inet_del_offload" },
	{ 0x5d5d7955, "inet_hash_connect" },
	{ 0xdb9862f5, "skb_push" },
	{ 0x75a88912, "__ip_queue_xmit" },
	{ 0xc923df09, "kmem_cache_free" },
	{ 0x893d69bd, "__sk_mem_reclaim" },
	{ 0xd56b9f96, "sk_stream_wait_memory" },
	{ 0x4d9b652b, "rb_erase" },
	{ 0x56802ae8, "rps_cpu_mask" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0xf1e046cc, "panic" },
	{ 0xe590dea3, "sk_busy_loop_end" },
	{ 0x3a375d6e, "lock_sock_nested" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0x4c83cd6a, "security_sk_classify_flow" },
	{ 0x9f358134, "skb_copy_datagram_iter" },
	{ 0x85efdae2, "current_task" },
	{ 0x1a0f3df2, "inet_sendpage" },
	{ 0x2064386c, "l3mdev_master_ifindex_rcu" },
	{ 0x5cba0d9, "tcp_stream_memory_free" },
	{ 0x3755a679, "sock_no_socketpair" },
	{ 0xd188decb, "kfree_skb_partial" },
	{ 0x3c5d543a, "hrtimer_start_range_ns" },
	{ 0x27b65601, "sk_wait_data" },
	{ 0x9166fc03, "__flush_workqueue" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xb724a6ed, "sock_no_mmap" },
	{ 0x53a3af01, "__pskb_pull_tail" },
	{ 0xece784c2, "rb_first" },
	{ 0xb12a31ad, "inet_dgram_connect" },
	{ 0x7fe32873, "rb_replace_node" },
	{ 0x66bc5742, "xfrm_policy_delete" },
	{ 0x78f63c1a, "inet_csk_listen_start" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x4629334c, "__preempt_count" },
	{ 0xc7e681a6, "inet_del_protocol" },
	{ 0x2d77e9ab, "__dev_queue_xmit" },
	{ 0x7f373341, "ipv4_mtu" },
	{ 0x999e8297, "vfree" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x4af9e6d, "sk_set_peek_off" },
	{ 0xcbb79255, "inet_sendmsg" },
	{ 0x818a981e, "device_destroy" },
	{ 0xb43f9365, "ktime_get" },
	{ 0x56470118, "__warn_printk" },
	{ 0x2124474, "ip_send_check" },
	{ 0xd36dc10c, "get_random_u32" },
	{ 0x62679411, "sock_pfree" },
	{ 0x75d4b4bc, "dev_get_by_name" },
	{ 0x231d2266, "skb_clone" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0xe36e2dc1, "dst_release" },
	{ 0x9f616ffe, "_copy_from_iter" },
	{ 0x46a4b118, "hrtimer_cancel" },
	{ 0xb308c97d, "wait_woken" },
	{ 0xa8181adf, "proc_dointvec" },
	{ 0x37110088, "remove_wait_queue" },
	{ 0x3f4f25bd, "sock_gettstamp" },
	{ 0x49103176, "sk_setup_caps" },
	{ 0xd53c67b3, "unregister_net_sysctl_table" },
	{ 0x11d36019, "ip_local_out" },
	{ 0x828e22f4, "hrtimer_forward" },
	{ 0x1367e0cb, "inet_unhash" },
	{ 0x6579361, "iov_iter_revert" },
	{ 0xe9503aa9, "skb_append" },
	{ 0x7aa1756e, "kvfree" },
	{ 0x81ec70a5, "skb_split" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xc972dcf7, "inet_csk_listen_stop" },
	{ 0xd62ecd49, "rps_sock_flow_table" },
	{ 0x97da0bcc, "__kfree_skb" },
	{ 0x2a994334, "cdev_init" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xe2c17b5d, "__SCT__might_resched" },
	{ 0x1502249d, "kmalloc_caches" },
	{ 0xc8135c6e, "cdev_del" },
	{ 0xfbef972f, "kmem_cache_destroy" },
	{ 0x2839e927, "release_sock" },
	{ 0x2daaadb3, "skb_queue_head" },
	{ 0x22e2e09a, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "9651A0F49BF8F8570EDEAE9");
