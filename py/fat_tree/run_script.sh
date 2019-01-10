#!/bin/bash

algos=(fastpass)
aids=()
OUTPUT_FOLDER=../result/fat_tree
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	algo=${algos[$i]}
	    # echo conf_"$algo"_dctcp_$incast.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$incast".txt
	../../simulator 1 conf_"$algo"_"$2".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2".txt&
	 pids[${i}]=$!
#	for pid in ${pids[*]}; 
#	do
#       	   wait $pid
#        done
    pids=()
done
