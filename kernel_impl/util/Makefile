# Makefile to build various testing programs for dcPIM.

CFLAGS := -Wall -Werror -fno-strict-aliasing -O3 -I..

BINS := pingpong_client pingpong_server tcp_mmap dcpim_test  server

OBJS := $(patsubst %,%.o,$(BINS))
	
LIB_SRCS := test_utils.cc
LIB_OBJS := $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(LIB_SRCS)))
	
.SECONDARY: $(OBJS) $(LIB_OBJS)

all: $(BINS)
	
cp_node: cp_node.o dist.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@

# This seems to be the only way to disable the built-in implicit rules
# for %:%.c and %:%.cc.
.SUFFIXES:
	
%: %.o $(LIB_OBJS)
	g++ $(CFLAGS) $^ -lpthread -o $@
	
%.o: %.cc test_utils.h 
	g++ -c $(CFLAGS) -std=c++17 $< -o $@
	
%.o: %.c test_utils.h 
	cc -c $(CFLAGS) $< -o $@
	
clean:
	rm -f $(BINS) $(OBJS) $(LIB_OBJS)

# The following target is useful for debugging Makefiles; it
# prints the value of a make variable.
print-%:
	@echo $* = $($*)
	
