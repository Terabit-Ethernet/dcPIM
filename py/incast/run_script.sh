#!/bin/bash

incasts=(1 143)
algos=(phost pfabric fastpass ranking)
pids=()
OUTPUT_FOLDER=../result/incast
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!incasts[*]};
	do
	    incast=${incasts[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$incast.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$incast".txt
	    ../../simulator 1 conf_"$algo"_"$2"_$incast.txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$incast".txt&
	    pids[${index}]=$!
	done
	for pid in ${pids[*]}; 
	do
    	wait $pid
    done
    pids=()
done
