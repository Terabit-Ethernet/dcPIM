#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh

num_hosts=$1
dim=$2
sys=$3
# run experiment

for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
		if [[ $dim -eq 1 ]]
		then
	 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "sudo ethtool -C ens2f0np0 adaptive-rx on adaptive-tx on"
		else
	 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "sudo ethtool -C ens2f0np0 adaptive-rx off adaptive-tx off" 
		fi
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3" 
	done

# run incast


sleep 1
echo ~/dcPIM/kernel_impl/cloudlab_script/run_server.sh $sys 8
ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode${ssh_array[0]}.clemson.cloudlab.us "sudo pkill -9 iperf3; ~/dcPIM/kernel_impl/cloudlab_script/run_server.sh $sys 8" &

sleep 1

serverindex=1
clientindex=2
for addr in  "${ssh_array[@]: 1 : (($num_hosts - 1))}";
	do 
		echo $addr ~/dcPIM/kernel_impl/cloudlab_script/run_client.sh 15 $sys $serverindex $clientindex
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3; ~/dcPIM/kernel_impl/cloudlab_script/run_client.sh 15 $sys $serverindex $clientindex" & 
		((clientindex++))
	done
sleep 150

for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3" 
	done
