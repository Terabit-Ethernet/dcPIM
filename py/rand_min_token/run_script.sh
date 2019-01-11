#!/bin/bash

#tokens=(100)
tokens=(1 2 3 4 5 6 7 8 9)
#control_epoch=(0.25 0.375 0.5 0.625 0.75 0.875 1)
algos=(ranking)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/rand_max_token
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"

for index in ${!tokens[*]};
do
    token=${tokens[$index]}
    # epoch=${control_epoch[$i]}
    # echo conf_"$algo"_dctcp_"$token".txt
    # echo conf_ranking_"$2"_"$token"_"$epoch".txt
    ../../simulator 1 conf_ranking_"$2"_"$token".txt > "$OUTPUT_FOLDER/$DATE"/result_ranking_"$TRACE"_"$token".txt&
#       nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
    pids[${index}]=$!
done
# for pid in ${pids[*]};
# do
# 	wait $pid
# done
pids=()
