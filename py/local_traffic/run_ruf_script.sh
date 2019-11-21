#!/bin/bash

loads=(0 1 2 3 4 5 6 7 8 9)
local=(0 1)
conn=(0 1)
algos=(ruf)
calc(){ awk "BEGIN { print "$*" }"; }
pids=()

OUTPUT_FOLDER=../result/max_load_oversubscribe
DATE=$1
TRACE=$2
mkdir -p $OUTPUT_FOLDER
mkdir -p $OUTPUT_FOLDER/"$DATE"
for i in ${!algos[*]}
do 
	for index in ${!loads[*]};
	do
    	load=${loads[$index]}
	    algo=${algos[$i]}
	    for j in ${!local[*]}
		do
			for k in ${!conn[*]}
			do 
		   	../../simulator 1 conf_"$algo"_"$2"_"$j"_"$k"_"0.1$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"$j"_"$k"_"0.1$load.txt"&
	    	pids[${index}]=$!
			done
	    # echo conf_"$algo"_dctcp_$load.txt
	    # echo "$OUTPUT_FOLDER"/result_"$algo"_dctcp_"$load".txt
	    #../../simulator 1 conf_"$algo"_"$2"_"0.7$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"0.7$load".txt&
	    #../../simulator 1 conf_"$algo"_"$2"_"0.8$load".txt > "$OUTPUT_FOLDER/$DATE"/result_"$algo"_"$2"_"0.8$load".txt&
            #../../simulator 2 conf_"$algo"_"$2"_"0.5$load".txt > "$OUTPUT_FOLDER/$DATE"/trace_"$2"_"0.5$load".txt&

	    #	nohup ./batch_simulate_sflow.py -P $p -F ../../../data/ -t ${threshold[$index]} -i 10 -N 1000 -s 1 -l results/conext18/flows/percentage-${percentage[$index]}.log &
	    done
        done
        for pid in ${pids[*]};
        do
            wait $pid
        done
        pids=()
done
