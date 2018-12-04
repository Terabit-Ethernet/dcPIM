#!/bin/bash

bandwidths=(5)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/bandwidth
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!bandwidths[*]};
	do
    	bandwidth=${bandwidths[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$load.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$load".txt
	    ../../simulator 1 conf_"$algo"_"$2"_"$bandwidth".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$bandwidth".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
