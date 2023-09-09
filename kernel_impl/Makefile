# Makefile to build DCACP as a Linux module.

obj-m += dcpim_module.o
dcpim_module-y = dcpim_ioat.o\
				 dcpim_sock.o\
				 dcpim_hashtables.o \
				 dcpim_message.o\
				 dcpim_matching.o\
				 dcpim_incoming.o\
				 dcpim_outgoing.o \
				 dcpim.o \
				 dcpim_offload.o\
				 dcpim_plumbing.o

# dcpim.o \
#             dcpimlite.o \
#             dcpim_offload.o \
#             dcpim_tunnel.o \
#  			/dcpim_diag.o
MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
check:
	../dcpimLinux/scripts/kernel-doc -none *.c

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
	
