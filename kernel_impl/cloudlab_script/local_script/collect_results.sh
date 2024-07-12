#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh

num_hosts=$1
src=$2
# run experiment
i=0
rm -rf $src
mkdir -p $src
for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
		mkdir $i/
		scp  -r $USER@clnode$addr.clemson.cloudlab.us:~/*.log $i/
 		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "rm -rf *.log" &
		mv $i/ $src/
		((i++))
	done
