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
	{ 0x8c4d394, "module_layout" },
	{ 0x9c760eab, "inet_diag_unregister" },
	{ 0xbe1eb3f7, "inet_diag_register" },
	{ 0x4c17559c, "netlink_unicast" },
	{ 0xce2100b3, "__udp6_lib_lookup" },
	{ 0x5fe1cd4c, "kfree_skb" },
	{ 0x949c53b3, "__alloc_skb" },
	{ 0x413cddf6, "sk_free" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0xc2d3a8ff, "sock_diag_check_cookie" },
	{ 0xea2826d7, "__udp4_lib_lookup" },
	{ 0x95a67b07, "udp_table" },
	{ 0xd4d1983c, "udplite_table" },
	{ 0xdfe8f001, "inet_sk_diag_fill" },
	{ 0x202f5f50, "inet_diag_bc_sk" },
	{ 0x49c41a57, "_raw_spin_unlock_bh" },
	{ 0xb3635b01, "_raw_spin_lock_bh" },
	{ 0xae0364f2, "netlink_net_capable" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "inet_diag");


MODULE_INFO(srcversion, "39997A0D365CE1C66FC1C0C");
