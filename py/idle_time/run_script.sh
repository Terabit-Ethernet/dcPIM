#!/bin/bash

idle_time=(0.5 1 1.5 2 2.5 3 3.5 4 4.5 5)
repeat_time=10000
#tokens=(100 200 300 400 500 600 700 800 900 1000)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/idle_time
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!idle_time[*]};
	do
    	    idle=${idle_time[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_"$token".txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$token".txt
	    #echo $idle
	    ../../simulator 1 conf_"$algo"_"$2"_"$idle".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$idle".txt&
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
