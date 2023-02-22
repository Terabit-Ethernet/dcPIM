#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))

# Source the environment file
source $DIR/env.sh
sudo ifconfig $INTF mtu 9000
sudo ifconfig $INTF $TARGET
# Enable aRFS and configure network
sudo service irqbalance stop
sudo ethtool -C $INTF adaptive-rx on adaptive-tx on
sudo ethtool -K $INTF ntuple on gro on gso on tso on lro off
echo 32768 | sudo tee /proc/sys/net/core/rps_sock_flow_entries
for f in /sys/class/net/$INTF/queues/rx-*/rps_flow_cnt; do echo 32768 | sudo tee $f; done
sudo set_irq_affinity.sh $INTF

# Increase sock size limits
sudo sysctl -w net.core.wmem_max=12582912
sudo sysctl -w net.core.rmem_max=12582912

# Enable hardware timestamps
sudo hwstamp_ctl -i $INTF -r 1

#echo HRTICK | sudo tee /sys/kernel/debug/sched_features
#echo 100000 | sudo tee /proc/sys/kernel/sched_latency_ns
#echo 100000 | sudo tee /proc/sys/kernel/sched_min_granularity_ns
#sudo phc2sys -s CLOCK_REALTIME -c $INTF -O 0 &

# synchoronize the hardware timer
#phc2sys -a -r
# comppile compute app
#g++ -pthread compute_md.cpp -o compute

# change the num of open files
ulimit -n 8192
