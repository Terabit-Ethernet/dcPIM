#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh
#sudo ifconfig $INTF mtu 9000 up
#sudo ifconfig $INTF $HOST
#cd /home/qizhe/synergylab-hardware
#python /home/qizhe/synergylab-hardware/setup-arps.py $INTF
#cd -

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

# Set up flow RFS rules
./ethtool_setup.sh
# Enable hardware timestamps
# sudo hwstamp_ctl -i $INTF -r 1

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

cd ~/dcPIM/kernel_impl
make
sudo rmmod dcpim_module
sudo mkdir /lib/modules/6.0.3/extra
sudo cp dcpim_module.ko /lib/modules/6.0.3/extra/
sudo depmod -a
sudo insmod /lib/modules/6.0.3/extra/dcpim_module.ko
cd ~/dcPIM/kernel_impl/custom_socket/
make
