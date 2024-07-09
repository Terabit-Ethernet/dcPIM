num_apps=(3)
dim=(0)
# 2: one-to-one
workload=(2)
perf=1
sys="dcpim"
for d in "${dim[@]}"
do  
    for p in "${workload[@]}"
    do
        for k in "${num_apps[@]}"
        do
            ./run_"$sys"_iperf.sh $k temp/ $d $perf $p
            # python3 parse_thpt.py temp/ $k
            mkdir temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"
            mv temp/*.log temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"
            echo "done"    
        done
        sleep 10
    done
done
