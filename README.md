# RDP
CPU Efficient Transport Protocol Design 

## Install Kernel
The default versoin is 5.6.0. 
Our patch is based on Linux 5.6.0. On Ubuntu 20.04, you can use the following instructions to build and install the kernel.

1. Download Linux kernel source tree.

```
cd ~
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.6.0.tar.gz
tar xzvf linux-5.6.0.tar.gz
```

2. Download and apply the patch to the kernel source.

```
git clone https://github.com/qizhe/RDP.git
cd ~/linux-5.6.0/
git apply ../RDP/patch
```

3. Update kernel configuration.

```
cp /boot/config-x.x.x .config
make oldconfig
scripts/config --disable DEBUG_INFO # Disables building debugging related files
```
`x.x.x` is a kernel version. It can be your current kernel version or latest version your system has. Type  `uname -r` to see your current kernel version.

4. Compile and install. The `LOCALVERSION=-profiling` option can be replaced by any custom marker. Remember to replace `profiling` with your own definition in the rest of the instructions.

```
sudo make -j24 bzImage
sudo make -j24 modules
sudo make modules_install
sudo make install
```
## Install Module 
1. Enter the directory, compile the module and install the module.
```
cd RDP
make
sudo insmod dcacp_module.ko
```
2. To unload the module,
```
sudo rmmod dcacp_module.ko
```

## Run Program
1. Go to `util` folder, and on the server side
```
cd util
./run_server.sh 1
```
On the client side,
```
cd util
sudo -s
./run_client.sh 1 0
```
