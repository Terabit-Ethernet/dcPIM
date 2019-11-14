#!/bin/bash

algos=(ruf)
locals=(0 1)
conns=(0 1)
aids=()
OUTPUT_FOLDER=../result/oversubscribe
DATE=$1
TRACE=$2
mkdir $OUTPUT_FOLDER
mkdir $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for j in ${!locals[*]}
	do
		for k in ${!conns[*]}
		do 
			algo=${algos[$i]}
			loco=${locals[$j]}
  			con=${conns[$k]}
			  # echo conf_"$algo"_dctcp_$incast.txt
			    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$incast".txt
			../../simulator 1 conf_"$algo"_"$2"_"$loco"_"$con".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$loco"_"$con".txt&
			 pids[${i}]=$!
		#	for pid in ${pids[*]}; 
		#	do
		#       	   wait $pid
		#        done
		    pids=()
		done
	done 
done
