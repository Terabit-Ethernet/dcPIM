#!/bin/bash

epochs=(0.25 0.5 0.75)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/control_epoch
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!epochs[*]};
	do
    	epoch=${epochs[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$epoch.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$epoch".txt
	    echo $epoch
	    ../../simulator 1 conf_"$algo"_"$2"_"$epoch".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$epoch".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
