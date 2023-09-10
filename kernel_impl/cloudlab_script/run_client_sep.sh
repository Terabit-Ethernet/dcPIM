NCLIENT=$1
SYS=$2
serverindex=$3
clientindex=$4
flow=0
core=33
NSERVER=16
TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
echo "NUM client: $NCLIENT"
while (( flow < NCLIENT ));do
        dport=$((4000 * serverindex + 256 * clientindex + flow))
        serverip="10.10.1.$serverindex"
       ((core = 2 * (flow % (3) + (serverindex - 1 + 8) * 3) + 1))
        echo  taskset -c $((core)) iperf3 -c $serverip -p $((dport)) --cport $dport  -t 120 -4 -l 1M
	if [[ $SYS == "dcpim" ]]
        then
                sudo LD_PRELOAD=/users/caiqizhe/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c $((core))  iperf3 -c $serverip -p $((dport)) --cport $dport  -t 120 -4 -l 1M  > client_"$serverindex"_"$flow".log &
        else
                sudo taskset -c $((core)) iperf3 -c $serverip -p $((dport)) --cport $dport -t 120 -4 -l 1M > client_"$serverindex"_$((flow)).log &
        fi
        # ((core = (core + 2) % 65))
        (( flow++ ))
done
