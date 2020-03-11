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
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x8c4d394, "module_layout" },
	{ 0x10d08340, "sock_release" },
	{ 0x394fc5c6, "metadata_dst_alloc" },
	{ 0x925b8328, "sock_create_kern" },
	{ 0x4a815038, "kernel_setsockopt" },
	{ 0xf75e65de, "kernel_connect" },
	{ 0x3b5b1391, "iptunnel_xmit" },
	{ 0xd3a9b321, "kernel_sock_shutdown" },
	{ 0x99517682, "udp_encap_enable" },
	{ 0x9ae58694, "ipv6_stub" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5f8451c5, "udp_set_csum" },
	{ 0x7b1df49e, "kernel_bind" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "0A315BA6124B0664F4D23FB");
