if [[ $# < 3 ]]; then
    echo "usage: netperf.sh NUM_APPS DIR SIZE"
    exit 1
fi
NCLIENT=$1
DIR=$2
DIM=$3
PERF=$4
FLOWSIZE=$5
RXUSEC=$6
# client-side
sudo trace-cmd clear
MTU=$((FLOWSIZE+52))
echo $MTU
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
	ssh jaehyun\@128.84.155.146 -t "sudo ethtool -C ens2f1np1 rx-usecs $RXUSEC"
	sudo ethtool -C ens2f1np1 adaptive-rx off adaptive-tx off
	sudo ethtool -C ens2f1np1 rx-usecs $RXUSEC
fi

ssh jaehyun\@128.84.155.146 -t "sudo ifconfig ens2f1np1 mtu $MTU"
sudo ifconfig ens2f1np1 mtu $MTU

# single-core

server=0
# NSERVER=1
# while (( server < NSERVER ));do
ssh jaehyun\@128.84.155.146 -t "sudo taskset -c $TASKSET nice -n -20 /home/qizhe/dcPIM/kernel_impl/util/pingpong_server --ip 192.168.11.125 --port 10000 --iodepth 1 --flowsize $FLOWSIZE --count $NCLIENT --shortflow" &
PIDS="$PIDS $!"
		#taskset -c 0 /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
# 		(( server++ ))
# done
sleep 3
sudo taskset -c $TASKSET nice -n -20 /home/qizhe/dcPIM/kernel_impl/util/pingpong_client 192.168.11.125:10000  --sp 10000 --count $NCLIENT --iodepth 1 --flowsize $FLOWSIZE --tcp --shortflow ping &



sar -u 55 1 -P ALL > $DIR/cpu-"$NCLIENT".log &
ssh jaehyun\@128.84.155.146 -t 'sar -u 55 1 -P ALL' > $DIR/cpu-server-"$NCLIENT".log &

if [[ $PERF -eq 1 ]]
then
    ssh jaehyun\@128.84.155.146 -t "cd /home/qizhe; sudo ./perf record -C 0 -o perf_data_file -- sleep 60" 
	ssh jaehyun\@128.84.155.146 -t "cd /home/qizhe; sudo ./perf report --stdio --stdio-color never --percent-limit 0.01 -i perf_data_file | cat" >  $DIR/perf.log
fi

# sleep 150
wait $PIDS
# get compute log
scp -r jaehyun\@128.84.155.146:~/server*.log temp/
scp -r jaehyun\@128.84.155.146:~/netperf*.log temp/
scp -r jaehyun\@128.84.155.146:~/latency.log temp/
PIDS2="$!"
# client-side
sudo trace-cmd clear
sudo killall pingpong_client
# server-side

ssh jaehyun\@128.84.155.146 -t 'sudo trace-cmd clear'
ssh jaehyun\@128.84.155.146 -t 'sudo killall pingpong_server'
ssh jaehyun\@128.84.155.146 -t 'sudo rm -rf /home/jaehyun/latency.log /home/jaehyun/server_*.log /home/jaehyun/netperf*.log'

