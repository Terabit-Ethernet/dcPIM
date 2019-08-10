#!/bin/bash

loads=(1 2 3 4 5 6 7 8 9)
algos=(pim phost pfabric ruf fastpass)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/max_load
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
	    ../../simulator 1 conf_"$algo"_"$2"_"0.7$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"0.7$load".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	  wait $pid
        done
    pids=()
done
