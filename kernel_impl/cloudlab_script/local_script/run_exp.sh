#!/bin/bash

DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh

# exp=$1
host_arr=(4)
flow_arr=(4)
sys=$1
dim=$2
workload=$3
serverindex=1
for addr in  "${ssh_array[@]}";
	do 
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl/cloudlab_script/; python3 ethtool.py 8 $serverindex > ethtool_setup.sh; ./setup.sh"
		((serverindex++))
	done

for num_hosts in  "${host_arr[@]: 0 : 4}";
	do 
		for flow in  "${flow_arr[@]: 0 : 9}";
			do
				./run_"$workload".sh $num_hosts $dim $sys $flow &
				sleep 30
				./run_profile.sh $num_hosts &
				sleep 200
				./collect_results.sh $num_hosts results/"$workload"/$sys/$num_hosts/$flow/
			done
	done


for num_hosts in  "${host_arr[@]: 0 : 4}";
	do 
		for flow in  "${flow_arr[@]: 0 : 9}";
			do
				python3 dump_all_iperf3.py results/"$workload"/$sys/ $flow $num_hosts
			done
	done