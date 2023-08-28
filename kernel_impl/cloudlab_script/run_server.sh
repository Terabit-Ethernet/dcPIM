TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
server=0
NSERVER=15
core=0
SYS=$1
while (( server < NSERVER ));do
        if [[ $SYS == "dcpim" ]]
        then
                sudo LD_PRELOAD=~/dcPIM/kernel_impl/custom_socket/socket_wrapper.so taskset -c $((core)) iperf -s -p $((10000 + server)) -4 > server_$((server)).log &
        else
                sudo taskset -c $((core)) iperf -s -p $((10000 + server)) -4 > server_$((server)).log &
        fi
        ((core = (core + 4) % 64))
        (( server++))
done
