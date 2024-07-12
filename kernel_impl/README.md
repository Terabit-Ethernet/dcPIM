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
git clone https://github.com/Terabit-Ethernet/dcPIM.git
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
2. Add IPPROTO_DCPIM in /usr/include/netinet/in.h:

   We need to define **IPPROTO_DCPIM** for applications using dcPIM sockets. Add the two lines with `sudo vi /usr/include/netinet/in.h` in line 83 after `#define IPPROTO_MPTCP	IPPROTO_MPTCP`:

   ```
   ...
   IPPROTO_DCPIM = 0xFE,      /* dcPIM Socket.  */
   #define IPPROTO_DCPIM     IPPROTO_DCPIM
   ...
   ```
2. To unload the module,
```
sudo rmmod dcpim_module.ko
```
## Application interface 
dcPIM utilizes a standard socket interface, making use of the connect/accept/read/write syscalls that are similar to TCP sockets. The provided example can be found in the following files:
`util/dcpim_test.cc` (client code),
`util/server.cc` (server side).

1. When creating socket, we need to specify for dcPIM socket. Similar to a TCP socket, by default, the dcPIM socket supports the streaming interface. Each socket pair corresponds to a long flow in dcPIM protocol.
```
fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
```
In case you don't want to change your application code, you can also use redirect library as [Run Iperf](#run-iperf) section shows.

2. Besides the streaming interface, dcPIM also provides message interface (corresponding to short flows in dcPIM protocol). Message interfaces are used when applications intend to achieve low latency. **Data sent by a write syscall will be treated as a new message and the receiver will receive data in the message granularity.** On the receiver side, if the receiver does not provide enough buffer size to hold the message, an error will be returned after the read syscall. To use the message interface, prior to performing the connect system call on the client side, the socket priority should be set to the highest priority using the following code:
```
int priority = 7;
setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
```
All other operations are exactly same as streaming interface of dcPIM or TCP sockets. The example code can be found at: `util
/pingpong_client.cc` and `util/pingpong_server.cc`.

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
## Run Iperf

Install iperf on servers,
```
sudo apt-get install iperf3
```

Compile socket redirect library

```
cd custom_socket/
make
cd -
```

Run iperf at the server side:

```
sudo LD_PRELOAD=~/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c 0 iperf3 -s -p 10000 -4
```

Run iperf at the client side:

```
sudo LD_PRELOAD=~/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c 0 iperf3 -c 192.168.11.125 -p 10000 --cport 10000 -t 100 -4
```

## Running Microbenchmark 
### Hardware/Software Configuration
We have used the follwing hardware and software configurations for running the experiments.

* CPU: 4-Socket Intel Xeon Gold 6234 3.3 GHz with 8 cores per socket (with hyperthreading enabled)
* RAM: 384 GB
* NIC: Mellanox ConnectX-5 Ex VPI (100 Gbps)
* OS: Ubuntu 20.04 with Linux 6.0.3 (patched)

To run experiments, the client will initiate scripts to run programs on both the client and server. The parameters, including HOST (client) IP address, TARGET (server) IP address, and interface names, need to be set properly in `kernel_impl/env.sh`:
```
HOST=192.168.11.124
TARGET=192.168.11.125
INTF=ens2f1
USER=qizhe
TARGETDIR=/home/qizhe/
TARGETC=128.84.155.146
```
Note: this requires you set up [accessing the remote server on the client without a password](https://builtin.com/articles/ssh-without-password).

### Long flow performance testing (using streaming interfaces)

2. On the client side, setting up the server:
```
./host_setup.sh
```

On the target side, setting up the server:
```
./target_setup.sh
```
Note: The script contains flow steering rules (e.g., ethtool flow type) that route flows to a CPU core based on five tuples. This is required for dcPIM to be compared against TCP with aRFS enabled. The actual rule setup may depend on the server configuration (e.g., which NUMA node the NIC is attached to, how many sockets the CPU has, and how many CPU cores each socket has). More details can be found [here](https://github.com/Terabit-Ethernet/Understanding-network-stack-overheads-SIGCOMM-2021) (Getting the Mapping Between CPU and Receive Queues of NIC).

3. To run dcPIM, on the client side:

```
cd scripts/
./run_dcpim_long.sh
```

To run TCP, on the client side:

```
./run_tcp_long.sh
```

You can change the number of applications/flows to multiple hosts by modifying `run_dcpim_long.sh` and `run_tcp_long.sh`:
```
LINE 1: num_apps=(1 2 3 4)
```
### Short flow performance testing (using message interfaces)
The microbenchmark runs one-sided short message transfers from the host to the target to make an apple-to-apple comparison between dcPIM and TCP. If we use ping-pong traffic, TCP will piggyback ACK packets in the request and response messages, reducing its CPU overhead compared to dcPIM. To measure the message completion time accurately, we need to enable time synchronization on both servers as data transmission is one-sided.


2. On the client side, setting up the server:
```
./host_setup_short.sh
```

On the target side, setting up the server:
```
./target_setup_short.sh
```
3. Setting up the PTP time synchoronization on both servers:

Installing PTP:
```
cd ptp/
./ptp_install.sh
```

Running PTP setup commands at the same time:
```
./ptp_setup.sh
```

You can check if PTP is working by running this command:
```
./ptp_check.sh
```

4. To run dcPIM, on the client side:

```
cd scripts/
./run_dcpim_short.sh
```

5. To run TCP, on the client side:

Sending messages over one socket pair:
```
./run_tcp_short.sh
```

Sending one message per socket pair:
```
./run_tcp_short_conn.sh
```
Note running TCP needs to turn GRO (general receive offload) off as TCP may batch short messages together. dcPIM currently requires to enable GRO for using the  [kernel patch](#what-is-the-kernel-pat. But GRO won't affect the performance of dcPIM short messages.

### Cloudlab performance testing

The [README](https://github.com/Terabit-Ethernet/dcPIM/tree/master/kernel_impl/cloudlab_script) is here.

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
