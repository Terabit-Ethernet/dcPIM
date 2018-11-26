#!/bin/bash

tokens=(1 2 3 4 5 6 7 8 9 10)
#tokens=(100)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/max_token
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!tokens[*]};
	do
    	    token=${tokens[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_"$token".txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$token".txt
	    ../../simulator 1 conf_"$algo"_"$2"_"$token".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$TRACE"_"$token".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
