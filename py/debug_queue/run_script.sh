#!/bin/bash

#tokens=(100)
tokens=(10)
control_epoch=(5 6)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/debug_queue
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!control_epoch[*]}
do
        for index in ${!tokens[*]};
        do
            token=${tokens[$index]}
            epoch=${control_epoch[$i]}
            # echo conf_"$algo"_dctcp_"$token".txt
            # echo conf_ranking_"$2"_"$token"_"$epoch".txt
            ../../simulator 1 conf_ranking_"$2"_"$token"_"$epoch".txt > "$OUTPUT_FOLDER/$DATE"/result_ranking_"$TRACE"_"$token"_"$epoch".txt&
        #       nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
            pids[${index}]=$!
        done
        #for pid in ${pids[*]};
        #do
        #	wait $pid
    	#done
    pids=()
done
