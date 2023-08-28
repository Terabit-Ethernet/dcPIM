NCLIENT=$1
SYS=$2
serverindex=$3
flow=0
core=0
NSERVER=15
TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
echo "NUM client: $NCLIENT"
while (( flow < NCLIENT ));do
        dport=$((4000 * serverindex + flow % NSERVER))
        serverip="10.10.1.$serverindex"
        if [[ $SYS == "dcpim" ]]
        then
                        sudo LD_PRELOAD=/home/qizhe/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c $((core)) iperf3 -c $serverip -p $((dport)) --cport $dport  -t 120 -4  > client_"$flow".log &
        else
                        sudo taskset -c $((core)) iperf -c $serverip -p $((dport)) --cport $dport -t 120 -4 > client_$((flow)).log &
        fi
        ((core = (core + 4) % 64))
        (( flow++ ))
done
