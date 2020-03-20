# Makefile to build DCACP as a Linux module.

obj-m += dcacp_module.o
dcacp_module-y = dcacp_peertab.o \
				 dcacp_outgoing.o \
				 dcacp_tunnel.o \
				 dcacp.o \
				 dcacplite.o \
				 dcacp_offload.o\
				 dcacp_plumbing.o
# dcacp.o \
#             dcacplite.o \
#             dcacp_offload.o \
#             dcacp_tunnel.o \
#  			/dcacp_diag.o
MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
check:
	../dcacpLinux/scripts/kernel-doc -none *.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)
	
printBuild-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	
printClean-%:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
	
