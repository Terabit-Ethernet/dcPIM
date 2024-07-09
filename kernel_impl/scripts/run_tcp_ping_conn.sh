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
DIR=$(realpath $(dirname $(readlink -f $0)))
source $DIR/../env.sh
# client-side
sudo trace-cmd clear
MTU=$((FLOWSIZE+52))
echo $MTU
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
	ssh $USER\@$TARGETC -t "sudo ethtool -C $INTF rx-usecs $RXUSEC"
	sudo ethtool -C $INTF adaptive-rx off adaptive-tx off
	sudo ethtool -C $INTF rx-usecs $RXUSEC
fi

ssh $USER\@$TARGETC -t "sudo ethtool -K $INTF ntuple off gro off gso off tso off lro off"
sudo ethtool -K $INTF ntuple off gro off gso off tso off lro off

ssh $USER\@$TARGETC -t "sudo ifconfig $INTF mtu $MTU"
sudo ifconfig $INTF mtu $MTU

# single-core

server=0
# NSERVER=1
# while (( server < NSERVER ));do
ssh $USER\@$TARGETC -t "sudo taskset -c $TASKSET nice -n -20 $TARGETDIR/dcPIM/kernel_impl/util/pingpong_server --ip $TARGET --port 10000 --iodepth 1 --flowsize $FLOWSIZE --count $NCLIENT --shortflow" &
PIDS="$PIDS $!"
		#taskset -c 0 $TARGETDIR/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
# 		(( server++ ))
# done
sleep 3
sudo taskset -c $TASKSET nice -n -20 $TARGETDIR/dcPIM/kernel_impl/util/pingpong_client $TARGET:10000  --sp 10000 --count $NCLIENT --iodepth 1 --flowsize $FLOWSIZE --tcp --shortflow ping &



sar -u 55 1 -P ALL > $DIR/cpu-"$NCLIENT".log &
ssh $USER\@$TARGETC -t "sar -u 55 1 -P ALL" > $DIR/cpu-server-"$NCLIENT".log &

if [[ $PERF -eq 1 ]]
then
    ssh $USER\@$TARGETC -t "cd $TARGETDIR; sudo ./perf record -C 0 -o perf_data_file -- sleep 60" 
	ssh $USER\@$TARGETC -t "cd $TARGETDIR; sudo ./perf report --stdio --stdio-color never --percent-limit 0.01 -i perf_data_file | cat" >  $DIR/perf.log
fi

# sleep 150
wait $PIDS
# get compute log
scp -r $USER\@$TARGETC:~/server*.log temp/
scp -r $USER\@$TARGETC:~/netperf*.log temp/
scp -r $USER\@$TARGETC:~/latency.log temp/
PIDS2="$!"
# client-side
sudo trace-cmd clear
sudo killall pingpong_client
# server-side

ssh $USER\@$TARGETC -t "sudo trace-cmd clear"
ssh $USER\@$TARGETC -t "sudo killall pingpong_server"
ssh $USER\@$TARGETC -t "sudo rm -rf /home/$USER/latency.log /home/$USER/server_*.log /home/$USER/netperf*.log"

