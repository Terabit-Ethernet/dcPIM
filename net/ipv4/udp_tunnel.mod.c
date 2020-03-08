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
	{ 0x50a74865, "module_layout" },
	{ 0x699303ac, "sock_release" },
	{ 0xeef882d8, "metadata_dst_alloc" },
	{ 0xbf9abbf4, "sock_create_kern" },
	{ 0xb9e90cec, "kernel_setsockopt" },
	{ 0xdd95f7b6, "kernel_connect" },
	{ 0x630e3198, "iptunnel_xmit" },
	{ 0x348bc50c, "kernel_sock_shutdown" },
	{ 0x99517682, "udp_encap_enable" },
	{ 0x781ce93e, "ipv6_stub" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xa56fd836, "udp_set_csum" },
	{ 0x9e62bd76, "kernel_bind" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "0A315BA6124B0664F4D23FB");
