# dcPIM Kernel IMplementation


## Install Kernel
The default version is 6.0.3.
Our patch is based on Linux 6.0.3. On Ubuntu 20.04, you can use the following instructions to build and install the kernel.

1. Download Linux kernel source tree.

```
cd ~
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.0.3.tar.gz
tar xzvf linux-6.0.3.tar.gz
```

2. Download and apply the patch to the kernel source.

```
git clone https://github.com/qizhe/dcpim_kernel.git
cd ~/linux-6.0.3/
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
sudo make -j32 bzImage
sudo make -j32 modules
sudo make modules_install
sudo make install
```
## Install Module 
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
## The current status of implementation
The first prototype is close to be finished. Some additinoal features are still needed to be implemented (like short flow transmission). More testing are needed to be done.
