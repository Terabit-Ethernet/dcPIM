#!/bin/bash

tokens=(10 20 30 40 50 60 70 80 90 100)
#tokens=(100 200 300 400 500 600 700 800 900 1000)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/free_token
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
	    ../../simulator 1 conf_"$algo"_"$2"_"$token".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$token".txt
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
