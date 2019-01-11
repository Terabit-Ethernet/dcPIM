#!/bin/bash

incasts=(5 10 15 20 25 30 35 40 45 50)
algos=(phost pfabric fastpass ranking)
pids=()
OUTPUT_FOLDER=../../result/incast/constant
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for j in `seq 1 10000`;
do
	for i in ${!algos[*]}
	do 
		for index in ${!incasts[*]};
		do
		    incast=${incasts[$index]}
		    algo=${algos[$i]}
		    ../../../simulator 1 conf_"$algo"_$2_$incast.txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$incast"_"$j".txt&
		    pids[${index}]=$!
		done
		for pid in ${pids[*]}; 
		do
	    	wait $pid
	    done
	    pids=()
	done
done
