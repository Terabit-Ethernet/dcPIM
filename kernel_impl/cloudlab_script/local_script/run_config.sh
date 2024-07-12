#!/bin/bash
# Get the dir of this project
DIR=$(realpath $(dirname $(readlink -f $0)))
# Source the environment file
source $DIR/env.sh
serverindex=1
# set up the server
for addr in  "${ssh_array[@]}";
	do 
# sudo mv ~/in.h /usr/include/netinet/;
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "git clone https://github.com/Terabit-Ethernet/dcPIM.git;cd ~/dcPIM; git fetch; git pull; git switch new_opti; git checkout ."
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; git checkout dcpim_matching.c dcpim_plumbing.c dcpim_outgoing.c; git pull;"
		# scp -r dcpim_outgoing.c $USER@clnode$addr.clemson.cloudlab.us:~/dcPIM/kernel_impl/
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; cat dcpim_matching.c | sed -e \"s/epoch->cpu = 60;/epoch->cpu = 143;/\" > dcpim_matching_new.c; mv dcpim_matching_new.c dcpim_matching.c"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; cat dcpim_matching.c | sed -e \"s/epoch->port_range = 15;/epoch->port_range = 16;/\" > dcpim_matching_new.c; mv dcpim_matching_new.c dcpim_matching.c"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; cat dcpim_plumbing.c | sed -e \"s/params->bandwidth = 98;/params->bandwidth = 100;/\" > dcpim_plumbing_new.c; mv dcpim_plumbing_new.c dcpim_plumbing.c"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; cat dcpim_plumbing.c | sed -e \"s/params->control_pkt_rtt = 20;/params->control_pkt_rtt = 30;/\" > dcpim_plumbing_new.c; mv dcpim_plumbing_new.c dcpim_plumbing.c"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; cat dcpim_plumbing.c | sed -e \"s/params->rtt = 60;/params->rtt = 60;/\" > dcpim_plumbing_new.c; mv dcpim_plumbing_new.c dcpim_plumbing.c"
		# ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 $USER@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl/cloudlab_script/; python3 ethtool_sep.py 8 $serverindex > ethtool_setup.sh; ./setup.sh"
		((serverindex++))
	done
