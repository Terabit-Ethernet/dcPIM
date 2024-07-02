if [[ $# < 3 ]]; then
    echo "usage: netperf.sh NUM_APPS DIR SIZE"
    exit 1
fi
NCLIENT=$1
DIR=$2
DIM=$3
PERF=$4
WORKLOAD=$5
# client-side
sudo trace-cmd clear

#LOG=249
# server-side
ssh jaehyun\@128.84.155.146 -t 'sudo trace-cmd clear'

# TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60"
TASKSET="0"
mkdir -p $DIR

if [[ $DIM -eq 1 ]]
then
	echo "enable dim"
	ssh jaehyun\@128.84.155.146 -t 'sudo ethtool -C ens2f1np1 adaptive-rx on adaptive-tx on'
	sudo ethtool -C ens2f1np1 adaptive-rx on adaptive-tx on
else
	ssh jaehyun\@128.84.155.146 -t 'sudo ethtool -C ens2f1np1 adaptive-rx off adaptive-tx off'
	ssh jaehyun\@128.84.155.146 -t 'sudo ethtool -C ens2f1np1 rx-usecs 6'
	sudo ethtool -C ens2f1np1 adaptive-rx off adaptive-tx off
	sudo ethtool -C ens2f1np1 rx-usecs 6
fi

# incast
if [[ $WORKLOAD -eq 1 ]]
then
	TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
	echo "INCAST"
    # ssh jaehyun\@128.84.155.146  "sudo /home/qizhe/dcpim_kernel/util/run_server.sh 1" &
	# echo "ssh jaehyun\@128.84.155.146  "sudo /home/qizhe/dcpim_kernel/util/run_server.sh 1""
	server=0
	NSERVER=1
	while (( server < NSERVER ));do
			ssh jaehyun\@128.84.155.146 -t "sudo taskset -c 0 /home/qizhe/dcPIM/kernel_impl/util/server --ip 192.168.11.125 --port $((4000 + server)) --pin > server_$((server)).log" &
			#taskset -c 0 /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
			(( server++ ))
	done
	sleep 3
	flow=0
	while (( flow < NCLIENT ));do
			taskset -c $TASKSET /home/qizhe/dcPIM/kernel_impl/util/dcpim_test 192.168.11.125:$((4000 + flow)) --pin --sp $(( 10000 * 1 +  flow )) --count 1 dcpimping &
			(( flow++ ))
	done
fi

# all-to-all
if [[ $WORKLOAD -eq 2 ]]
then
	TASKSET="0,4,8,12,16,20,24,28,32,36,40,44,48,52,56"
	echo "all to all"
    # ssh jaehyun\@128.84.155.146  "sudo /home/qizhe/dcpim_kernel/util/run_server.sh 1" &
	# echo "ssh jaehyun\@128.84.155.146  "sudo /home/qizhe/dcpim_kernel/util/run_server.sh 1""
	server=0
	NSERVER=15
	ssh jaehyun\@128.84.155.146 -t "/home/qizhe/dcPIM/kernel_impl/util/run_a2a_iperf3.sh dcpim" &

	# while (( server < NSERVER ));do
	# 		ssh jaehyun\@128.84.155.146 -t "sudo taskset -c $TASKSET /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + server)) > server_$((server)).log" &
	# 		echo "ssh jaehyun\@128.84.155.146 -t sudo taskset -c $TASKSET /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + server)) > server_$((server)).log"

	# 		#taskset -c 0 /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
	# 		(( server++ ))
	# done
	sleep 3
	/home/qizhe/dcPIM/kernel_impl/util/run_a2a_client_iperf3.sh $NCLIENT dcpim
	#flow=0
# echo "NUM client: $NCLIENT"
# while (( flow < NCLIENT ));do
# 	dport=$((4000 + flow % NSERVER))
# 	taskset -c $TASKSET /home/qizhe/dcpim_kernel/util/dcpim_test 192.168.10.125:$(($dport)) --sp $(( 10000 +  flow )) --count 1 dcpimping &
# 	(( flow++ ))
# done
fi

sar -u 55 1 -P ALL > $DIR/cpu-"$NCLIENT".log &
ssh jaehyun\@128.84.155.146 -t 'sar -u 55 1 -P ALL' > $DIR/cpu-server-"$NCLIENT".log &

if [[ $PERF -eq 1 ]]
then
    ssh jaehyun\@128.84.155.146 -t "cd /home/qizhe; sudo ./perf record -C 0 -o perf_data_file -- sleep 60" 
	ssh jaehyun\@128.84.155.146 -t "cd /home/qizhe; sudo ./perf report --stdio --stdio-color never --percent-limit 0.01 -i perf_data_file | cat" >  $DIR/perf.log
fi

sleep 120

# get compute log
scp -r jaehyun\@128.84.155.146:~/server*.log temp/

PIDS2="$!"
# client-side
sudo trace-cmd clear
sudo killall iperf3 iperf
# server-side

ssh jaehyun\@128.84.155.146 -t 'sudo trace-cmd clear'
ssh jaehyun\@128.84.155.146 -t 'sudo killall iperf3 iperf'
ssh jaehyun\@128.84.155.146 -t 'sudo rm -rf /home/jaehyun/server_*.log'

