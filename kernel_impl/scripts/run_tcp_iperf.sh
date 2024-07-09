if [[ $# < 3 ]]; then
    echo "usage: netperf.sh NUM_APPS DIR SIZE"
    exit 1
fi
NCLIENT=$1
DIR=$2
DIM=$3
PERF=$4
WORKLOAD=$5
DIR=$(realpath $(dirname $(readlink -f $0)))
source $DIR/../env.sh
# client-side
sudo trace-cmd clear

#LOG=249
# server-side
ssh $USER\@$TARGETC -t "sudo trace-cmd clear"

# TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60"
TASKSET="0"
mkdir -p $DIR

if [[ $DIM -eq 1 ]]
then
	echo "enable dim"
	ssh $USER\@$TARGETC -t "sudo ethtool -C $INTF adaptive-rx on adaptive-tx on"
	sudo ethtool -C $INTF adaptive-rx on adaptive-tx on
else
	ssh $USER\@$TARGETC -t "sudo ethtool -C $INTF adaptive-rx off adaptive-tx off"
	ssh $USER\@$TARGETC -t "sudo ethtool -C $INTF rx-usecs 6"
	sudo ethtool -C $INTF adaptive-rx off adaptive-tx off
	sudo ethtool -C $INTF rx-usecs 6
fi

# incast
if [[ $WORKLOAD -eq 1 ]]
then
	TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
	echo "INCAST"
    # ssh $USER\@$TARGETC  "sudo $TARGETDIR/dcpim_kernel/util/run_server.sh 1" &
	# echo "ssh $USER\@$TARGETC  "sudo $TARGETDIR/dcpim_kernel/util/run_server.sh 1""
	server=0
	NSERVER=1
	while (( server < NSERVER ));do
			ssh $USER\@$TARGETC -t "sudo taskset -c 0 $TARGETDIR/dcPIM/kernel_impl/util/server --ip $TARGET --port $((4000 + server)) --pin > server_$((server)).log" &
			#taskset -c 0 $TARGETDIR/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
			(( server++ ))
	done
	sleep 3
	flow=0
	while (( flow < NCLIENT ));do
			taskset -c $TASKSET $TARGETDIR/dcPIM/kernel_impl/util/dcpim_test $TARGET:$((4000 + flow)) --pin --sp $(( 10000 * 1 +  flow )) --count 1 tcpping &
			(( flow++ ))
	done
fi

# all-to-all
if [[ $WORKLOAD -eq 2 ]]
then
	TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
	echo "all to all"
    # ssh $USER\@$TARGETC  "sudo $TARGETDIR/dcpim_kernel/util/run_server.sh 1" &
	# echo "ssh $USER\@$TARGETC  "sudo $TARGETDIR/dcpim_kernel/util/run_server.sh 1""
	server=0
	NSERVER=15
	ssh $USER\@$TARGETC -t "$TARGETDIR/dcPIM/kernel_impl/util/run_a2a_iperf3.sh tcp" &
	# while (( server < NSERVER ));do
	# 		ssh $USER\@$TARGETC -t "sudo taskset -c $TASKSET $TARGETDIR/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + server)) > server_$((server)).log" &
	# 		echo "ssh $USER\@$TARGETC -t sudo taskset -c $TASKSET $TARGETDIR/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + server)) > server_$((server)).log"

	# 		#taskset -c 0 $TARGETDIR/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
	# 		(( server++ ))
	# done
	sleep 3
	$TARGETDIR/dcPIM/kernel_impl/util/run_a2a_client_iperf3.sh $NCLIENT tcp
	#flow=0
# echo "NUM client: $NCLIENT"
# while (( flow < NCLIENT ));do
# 	dport=$((4000 + flow % NSERVER))
# 	taskset -c $TASKSET $TARGETDIR/dcpim_kernel/util/dcpim_test 192.168.10.125:$(($dport)) --sp $(( 10000 +  flow )) --count 1 dcpimping &
# 	(( flow++ ))
# done
fi

sar -u 55 1 -P ALL > $DIR/cpu-"$NCLIENT".log &
ssh $USER\@$TARGETC -t "sar -u 55 1 -P ALL" > $DIR/cpu-server-"$NCLIENT".log &

if [[ $PERF -eq 1 ]]
then
    ssh $USER\@$TARGETC -t "cd $TARGETDIR; sudo ./perf record -C 0 -o perf_data_file -- sleep 60" 
	ssh $USER\@$TARGETC -t "cd $TARGETDIR; sudo ./perf report --stdio --stdio-color never --percent-limit 0.01 -i perf_data_file | cat" >  $DIR/perf.log
fi

sleep 120

# get compute log
mkdir temp/
scp -r $USER\@$TARGETC:~/server*.log temp/

PIDS2="$!"
# client-side
sudo trace-cmd clear
sudo killall iperf3
# server-side

ssh $USER\@$TARGETC -t "sudo trace-cmd clear"
ssh $USER\@$TARGETC -t "sudo killall iperf3"
ssh $USER\@$TARGETC -t "sudo rm -rf /home/$USER/server_*.log"

