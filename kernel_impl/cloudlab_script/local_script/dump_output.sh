#!/bin/bash
num_host=$1
ssh_array=(
272
265
269
253
254
281
275
264
)

# set up the server
for addr in  "${ssh_array[@]}";
	do 
#		scp  -r -i ~/.ssh/id_rsa in.h caiqizhe@$addr.utah.clemson.us:~/
# sudo mv ~/in.h /usr/include/netinet/;
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "git clone https://github.com/Terabit-Ethernet/dcPIM.git;cd ~/dcPIM; git fetch; git pull; git switch new_opti;"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl; git checkout dcpim_matching.c; cat dcpim_matching.c | sed -e \"s/epoch->cpu = 60;/epoch->cpu = 61;/\" > dcpim_matching_new.c; mv dcpim_matching_new.c dcpim_matching.c"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@clnode$addr.clemson.cloudlab.us "cd ~/dcPIM/kernel_impl/cloudlab_script/; ./setup.sh"
	done
