#!/bin/bash

loads=(5 6 7 8 9 10)
algos=(pfabric phost random)
calc(){ awk "BEGIN { print "$*" }"; }

OUTPUT_FOLDER=../result/load
DATE=$1
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!loads[*]};
	do
    	load=${loads[$index]}
	    algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$load.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$load".txt
	    ../../simulator 1 conf_"$algo"_datamining_"$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_datamining_"$load".txt 
	#	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	done
done
