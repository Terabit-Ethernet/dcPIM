#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh
num_hosts=$1
dim=$2
sys=$3
flows=$4
# run experiment

for addr in  "${ssh_array[@]: 0 : 8}";
	do 
		if [[ $dim -eq 1 ]]
		then
	 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo ethtool -C ens2f0np0 adaptive-rx on adaptive-tx on"
		else
	 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo ethtool -C ens2f0np0 adaptive-rx off adaptive-tx off" 
		fi
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3" 
	done

# run incast


sleep 1
serverindex=0
for addr in  "${ssh_array[@]: 0 : (($num_hosts))}";
	do 
	echo ~/dcPIM/kernel_impl/cloudlab_script/run_server_sep.sh $sys 8
	ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3; ~/dcPIM/kernel_impl/cloudlab_script/run_server_sep.sh $sys 8 $((serverindex+1))" &
	((serverindex++))
	done

sleep 1

serverindex=0
for addr in  "${ssh_array[@]: 0 : (($num_hosts))}";
	do 
	clientindex=0
	# if [[ $addr -eq 265 || $addr -eq 281 ]]; then
	# 	((serverindex++))
	# 	continue
	# fi
	for caddr in  "${ssh_array[@]: 0 : (($num_hosts))}";
		do 
			if [[ $caddr -eq addr ]]; then
				((clientindex++))
				continue
			fi
			echo $caddr ~/dcPIM/kernel_impl/cloudlab_script/run_client_sep.sh $flows $sys $((serverindex+1)) $((clientindex+1))
	 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$caddr.clemson.cloudlab.us "~/dcPIM/kernel_impl/cloudlab_script/run_client_sep.sh $flows $sys $((serverindex+1)) $((clientindex+1))" & 
			((clientindex++))
		done
	((serverindex++))
	done
sleep 150

for addr in  "${ssh_array[@]: 0 : ((2*$num_hosts))}";
	do 
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo pkill -9 iperf3" 
	done