#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x50a74865, "module_layout" },
	{ 0x2dc0f5aa, "inet_diag_unregister" },
	{ 0x71e0f0ca, "inet_diag_register" },
	{ 0x24297b8b, "inet_diag_bc_sk" },
	{ 0x49c41a57, "_raw_spin_unlock_bh" },
	{ 0xb3635b01, "_raw_spin_lock_bh" },
	{ 0x95a67b07, "udp_table" },
	{ 0xd4d1983c, "udplite_table" },
	{ 0xa705afe1, "netlink_unicast" },
	{ 0x4777a62c, "__udp6_lib_lookup" },
	{ 0xc1e7fb7, "kfree_skb" },
	{ 0x45acb475, "inet_sk_diag_fill" },
	{ 0x93a9bd15, "netlink_net_capable" },
	{ 0x1eeecbd6, "__alloc_skb" },
	{ 0x7be52cbd, "sk_free" },
	{ 0x165b145c, "ex_handler_refcount" },
	{ 0xb9e5fb28, "sock_diag_check_cookie" },
	{ 0xadcaed69, "__udp4_lib_lookup" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "inet_diag");


MODULE_INFO(srcversion, "39997A0D365CE1C66FC1C0C");
