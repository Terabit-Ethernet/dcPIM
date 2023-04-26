NCLIENT=$1
SYS=$2
NSERVER=15
flow=0
TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
echo "NUM client: $NCLIENT"
while (( flow < NCLIENT ));do
	dport=$((10000 + flow % NSERVER))
	taskset -c $TASKSET /home/qizhe/dcpim_kernel/util/dcpim_test 192.168.10.125:$(($dport)) --sp $(( 10000 +  flow )) --pin --count 1 "$SYS"ping &
	(( flow++ ))
done
