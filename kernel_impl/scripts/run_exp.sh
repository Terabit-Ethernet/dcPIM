num_hosts=$1
flow=$2
server_array=(12)
ssh_array=(11 4 5)


sudo /home/qizhe/dcpim_kernel/util/run_a2a.sh &

sleep 10
for addr in  "${ssh_array[@]: 1 : $num_hosts}";
	do 
        ssh -o StrictHostKeyChecking=no -i genie -p 22 qizhe@genie$addr.cs.cornell.edu "/home/qizhe/dcpim_kernel/util/run_a2a_client.sh $flow dcpim" &
	done

sleep 5
for addr in  "${ssh_array[@]: 1 : $num_hosts}";
	do 
        ssh -o StrictHostKeyChecking=no -i genie -p 22 qizhe@genie$addr.cs.cornell.edu "'sar -u 55 1 -P ALL' > $DIR/cpu-server-"$flow".log" &
	done

sleep 120

for addr in  "${ssh_array[@]: 1 : $num_hosts}";
	do 
        ssh -o StrictHostKeyChecking=no -i genie -p 22 qizhe@genie$addr.cs.cornell.edu "sudo killall server" &
	done


