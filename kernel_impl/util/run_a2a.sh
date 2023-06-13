TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
server=0
NSERVER=15
while (( server < NSERVER ));do
        sudo taskset -c $TASKSET /home/qizhe/dcPIM/kernel_impl/util/server --ip 192.168.11.125 --port $((10000 + server)) --pin > server_$((server)).log &
        (( server++ ))
done
