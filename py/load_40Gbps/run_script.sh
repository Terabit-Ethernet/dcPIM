#!/bin/bash

loads=(5 6 7 8 9)
algos=(pim)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/load_40Gbps
DATE=$1
TRACE=$2
mkdir -p $OUTPUT_FOLDER
mkdir -p $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!loads[*]};
	do
    	load=${loads[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$load.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$load".txt
	    ../../simulator 2 conf_"$algo"_"$2"_"$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$load".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	  wait $pid
        done
    pids=()
done
