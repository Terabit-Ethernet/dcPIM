# dcPIM Kernel Implementation


## Install kernel
The default version is 6.0.3. On Ubuntu 20.04, you can use the following instructions to build and install the kernel.

1. Download Linux kernel source directory.

```
cd ~
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.0.3.tar.gz
tar xzvf linux-6.0.3.tar.gz
```

2. Download and apply the patch to the kernel source. The patch is mainly from the performance consideration. More detail will be discussed later.

```
git clone https://github.com/qizhe/dcpim_kernel.git](https://github.com/Terabit-Ethernet/dcPIM.git
cd ~/linux-6.0.3/
cp ~/dcPIM/kernel_impl/diff.patch .
patch -p1 < diff.patch
```

3. Update kernel configuration.

```
cp /boot/config-x.x.x .config
make oldconfig
scripts/config --disable DEBUG_INFO # Disables building debugging related files
```
`x.x.x` is a kernel version. It can be your current kernel version or latest version your system has. Type  `uname -r` to see your current kernel version.

5. Compile and install. The `LOCALVERSION=-profiling` option can be replaced by any custom marker. Remember to replace `profiling` with your own definition in the rest of the instructions.

```
sudo make -j32 bzImage
sudo make -j32 modules
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make install
```

## Install module 
1. Enter the directory, compile the module and install the module.
```
cd dcpim_kernel
make
sudo insmod dcpim_module.ko
```
2. To unload the module,
```
sudo rmmod dcpim_module.ko
```
## Application interface 
dcPIM utilizes a standard socket interface, making use of the connect/accept/read/write syscalls that are similar to TCP sockets. The provided example can be found in the following files:
`util/dcpim_test.cc` (client code),
`util/server.cc` (server side).

There are only two key distinctions from TCP sockets:

1. When creating socket, we need to specify for dcPIM socket.
```
fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
```

2. Each socket corresponds to a long flow and is only transmitted when matching is approved. In order to transmit short flows that bypass matching, excluding retransmission, prior to performing the connect system call on the client side, the socket priority should be set to the highest priority using the following code:
```
int priority = 7;
setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
```
It's important to note that data sent via a single send system call is treated as one short flow.

## Run sample application

Go to `util` folder, and on the server side
```
cd util
sudo taskset -c 0 ./server --ip 192.168.10.125 --port 4000 --pin 
```

On the client side,
```
cd util
sudo ./dcpim_test 192.168.10.125:4000 --sp 100000 --count 1 dcpimping
```


## The current status of implementation
The first prototype is close to be finished. More testing are needed to be done.

## What is the kernel patch for?
Modern NICs often come equipped with multiple hardware (HW) queues, with each HW queue corresponding to a CPU core. In the RX data path, when a packet is received, the NIC may calculate its hash and distribute it to a dedicated HW queue based on this hash. The hash value can be determined by either the five tuples or the two tuples (source and destination IP addresses). Typically, for TCP or UDP traffic, packets belonging to different flows can be routed to different HW queues based on their five tuples. This enables multiple CPU cores to be activated for processing packets, resulting in optimal performance.

However, when introducing a new protocol like dcPIM, the NIC is unable to recognize its protocol number or understand the packet header format. Consequently, the NIC distributes packets based solely on the two tuples (source and destination IP addresses). As a result, a single CPU core may become a bottleneck in the system.

To address this issue, the current temporary solution employed by dcPIM is to utilize the TCP protocol number but modify one bit in the Type of Service (TOS) field of the IP header. This modification indicates that the packets are dcPIM packets, allowing for their distribution across multiple cores on the RX side. However, it is crucial for the operating system (OS) on the RX side to revert the header format back to its original state before reaching the network layer. It is expected that with future HW support, this workaround will no longer be necessary.

In the event that you prefer not to modify your kernel, you can simply run the following command:
```
sed -i -e 's/IPPROTO_TCP/IPPROTO_DCPIM/g' dcpim_outgoing.c
```
After making this change, recompile the module to ensure the desired functionality.

Please note that the above solution serves as a temporary measure and we anticipate further advancements with HW support in the future.
