#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh
sudo ifconfig $INTF mtu 9000 up
sudo ifconfig $INTF $HOST
cd /home/qizhe/synergylab-hardware
python /home/qizhe/synergylab-hardware/setup-arps.py $INTF
cd -
sudo ethtool -U $INTF flow-type tcp4 src-port 10000 dst-port 10000 action 0 loc 0
sudo ethtool -U $INTF flow-type tcp4 src-port 10001 dst-port 10001 action 1 loc 1
sudo ethtool -U $INTF flow-type tcp4 src-port 10002 dst-port 10002 action 2 loc 2
sudo ethtool -U $INTF flow-type tcp4 src-port 10003 dst-port 10003 action 3 loc 3
sudo ethtool -U $INTF flow-type tcp4 src-port 10004 dst-port 10004 action 4 loc 4
sudo ethtool -U $INTF flow-type tcp4 src-port 10005 dst-port 10005 action 5 loc 5
sudo ethtool -U $INTF flow-type tcp4 src-port 10006 dst-port 10006 action 6 loc 6
sudo ethtool -U $INTF flow-type tcp4 src-port 10007 dst-port 10007 action 7 loc 7
sudo ethtool -U $INTF flow-type tcp4 src-port 10008 dst-port 10008 action 8 loc 8
sudo ethtool -U $INTF flow-type tcp4 src-port 10009 dst-port 10009 action 9 loc 9
sudo ethtool -U $INTF flow-type tcp4 src-port 10010 dst-port 10010 action 10 loc 10
sudo ethtool -U $INTF flow-type tcp4 src-port 10011 dst-port 10011 action 11 loc 11
sudo ethtool -U $INTF flow-type tcp4 src-port 10012 dst-port 10012 action 12 loc 12
sudo ethtool -U $INTF flow-type tcp4 src-port 10013 dst-port 10013 action 13 loc 13
sudo ethtool -U $INTF flow-type tcp4 src-port 10014 dst-port 10014 action 14 loc 14
sudo ethtool -U $INTF flow-type tcp4 src-port 0 dst-port 0 action 0 loc 15
sudo ethtool -U $INTF flow-type tcp4 src-port 1 dst-port 1 action 1 loc 16
sudo ethtool -U $INTF flow-type tcp4 src-port 2 dst-port 2 action 2 loc 17
sudo ethtool -U $INTF flow-type tcp4 src-port 3 dst-port 3 action 3 loc 18
sudo ethtool -U $INTF flow-type tcp4 src-port 4 dst-port 4 action 4 loc 19
sudo ethtool -U $INTF flow-type tcp4 src-port 5 dst-port 5 action 5 loc 20
sudo ethtool -U $INTF flow-type tcp4 src-port 6 dst-port 6 action 6 loc 21
sudo ethtool -U $INTF flow-type tcp4 src-port 7 dst-port 7 action 7 loc 22
sudo ethtool -U $INTF flow-type tcp4 src-port 8 dst-port 8 action 8 loc 23
sudo ethtool -U $INTF flow-type tcp4 src-port 9 dst-port 9 action 9 loc 24
sudo ethtool -U $INTF flow-type tcp4 src-port 10 dst-port 10 action 10 loc 25
sudo ethtool -U $INTF flow-type tcp4 src-port 11 dst-port 11 action 11 loc 26
sudo ethtool -U $INTF flow-type tcp4 src-port 12 dst-port 12 action 12 loc 27
sudo ethtool -U $INTF flow-type tcp4 src-port 13 dst-port 13 action 13 loc 28
sudo ethtool -U $INTF flow-type tcp4 src-port 14 dst-port 14 action 14 loc 29

# Enable aRFS and configure network
sudo service irqbalance stop
sudo ethtool -C $INTF adaptive-rx off adaptive-tx off
sudo ethtool -C $INTF rx-usecs 6
sudo ethtool -K $INTF ntuple off gro on gso on tso on lro off
#echo 32768 | sudo tee /proc/sys/net/core/rps_sock_flow_entries
#for f in /sys/class/net/$INTF/queues/rx-*/rps_flow_cnt; do echo 32768 | sudo tee $f; done
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

# change the open file limit
ulimit -n 8192
