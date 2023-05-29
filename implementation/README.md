# dcPIM DPDK Implementation

## Setup

If you are running SIGCOMM artifact evaluation, you can skip the Setup section and directly jump into **[SIGCOMM 2022 Artifact Evaluation](#SIGCOMM-2022-Artifact-Evaluation)**.
### Install DPDK

1. Download the dpdk 18.11.10.

```
wget https://fast.dpdk.org/rel/dpdk-18.11.10.tar.xz
tar -xf dpdk-18.11.10.tar.xz
rm dpdk-18.11.10.tar.xz
```

2. Build DPDK with MLX4 PMD (assuming using MLX ConnectX-3). If you are using Intel NIC

 ```
 cd dpdk-stable-18.11.10
 export RTE_SDK=$PWD
 export RTE_TARGET=x86_64-native-linuxapp-gcc
 make config T=$RTE_TARGET O=$RTE_TARGET
 cd $RTE_TARGET
 ```
 
 If you use Mellanox (eg.ConnectX-3) NIC, open .config and set `CONFIG_RTE_LIBRTE_MLX4_PMD=y`.
 Then make
 
 ```
 make -j
 ```
### Configure IP address, enable hugepages and compile the program
Change the dpdk src directory in run.sh to `/path/to/dpdk` in your setup.

```
line 17: export RTE_SDK=/path/to/dpdk
```

Then

```
sudo ./run.sh $num_server
```

`$num_server` is the number of servers in the testbed. The script will get IP addresses of all servers and their ethernet address also enable hugepages and compile the program.

## Run experiments

Suppose we have n servers:
For first n-1 servers, run
```
./build/pim -- send CDF_$workload.txt > result_$workload.txt
```
For the last server:
```
./build/pim -- start CDF_$workload.txt > result_$workload.txt
```
The workloads that provided in this repo are imc10, websearch and datamining.

## SIGCOMM 2022 Artifact Evaluation

### Configure Cloudlab Machines
We conduct our experiment using the [m510](http://docs.cloudlab.us/hardware.html#%28part._cloudlab-utah%29) machines available at CloudLab.
For your convenience, we have provided two profiles that you can choose from to initiate the experiment:

dcpim_chassis.py: This profile requires you to reserve an entire chassis in m510 clusters in advance. To proceed with the reservation, please send an email to the CloudLab team, specifying your requirements.

dcpim_m510.xml: This profile does not necessitate manual reservation through email. However, please note that the servers utilized may not belong to the same chassis. As a result, there may be slightly larger latency variance, although still within an acceptable range (<20 us).


### Run experiments

Clone the repo into your local machine,

```
git clone https://github.com/Terabit-Ethernet/dcPIM.git
cd dcPIM/implementation
```

Download public and private key pairs in the Hotcrp. 
Copy the keys into .ssh repo and add keys.
```
cp id_ed25519 ~/.ssh/id_ed25519
cp id_ed25519.pub ~/.ssh/id_ed25519.pub
ssh-add -K ~/.ssh/id_ed25519
```

We provide oneshot script for running the experiment (32 server testbeds) which sending commands from your local machine to all remote servers:
```
cd script/
./run_32.sh
```
To run 8-server and 16-server experiments, simply run `./run_8.sh` or `./run_16.sh`.

The parsed result is in `implementation/result/websearch_32_slowdown_size.dat`. The format of files:
```
SIZE_OF_FLOWS MEAN_SLOWDOWN TAIL_SLOWDOWN-MEANSLOWDOWN 
```

Running the experiments at first time may take extra ~16 mins for cloning repository. When running the script second time, please ignore the warning/error due to cloning repositiory again. The experiment itself may take ~10 mins.


### Getting Baseline Results (Optional)
In case, you are interested in getting results of baseline(eg. TCP and DCTCP). You can use this [repo](https://github.com/qizhe/tcp_baseline) and follow README to reproduce results.

## Cornell Clusters

If you are using Cornell clusters, you need to do following changes:

1. change line 6 to the correct end host addresses in config.sh:
```
ping 10.10.1.$c  -w 5
```
The correct IP addresses are from (5.0.0.10 to 12.0.0.10) depending on the number of servers you are using.

2. Also, you need to change config.py line 7 for the correct IP prefix/surfix. The current is for cloudlab clusters.

3. Copy the src/main.c from the main branch to src/main.c in this branch. Then, changes follwing to line:
```
line 273: pim_receive_start(&epoch, &host, &pacer, 3);
line 702: rte_eal_remote_launch(launch_host_lcore, NULL, 3); 
line 717: if(rte_eal_wait_lcore(3) < 0)
```
to 
```
line 273: pim_receive_start(&epoch, &host, &pacer, RECEIVE_CORE);
line 702: rte_eal_remote_launch(launch_host_lcore, NULL, RECEIVE_CORE); 
line 717: if(rte_eal_wait_lcore(RECEIVE_CORE) < 0)
```


