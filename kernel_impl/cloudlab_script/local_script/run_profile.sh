#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh
num_hosts=$1
# run experiment

for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo apt-get install sysstat; sar -u 55 1 -P ALL > cpu.log" &
	done


for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "sudo /opt/perf record -C 1 -o perf_data_file -- sleep 60; sudo /opt/perf report --stdio --stdio-color never --percent-limit 0.01 -i perf_data_file > perf.log" &
	done
