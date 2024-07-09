NCLIENT=$1
SYS=$2
NSERVER=15
flow=0
core=0
TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
echo "NUM client: $NCLIENT"
while (( flow < NCLIENT ));do
	dport=$((10000 + flow % NSERVER))
	if [[ $SYS == "dcpim" ]]
	then
			sudo LD_PRELOAD=/home/qizhe/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c $((core)) iperf3 -c 192.168.11.125 -p $((dport)) --cport $((dport)) -t 120   -4 -l 1M  > client_$((flow)).log &
	else
			sudo taskset -c $((core)) iperf3 -c 192.168.11.125 -p $((dport)) --cport $((dport)) -t 120 -4  > client_$((flow)).log &
	fi
	((core = (core + 4) % 64))
	(( flow++ ))
done
