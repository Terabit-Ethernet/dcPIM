flowsize=(64)
num_apps=(1)
rx_usec=(6)
dim=(0)
perf=0
sys="dcpim"
for r in "${rx_usec[@]}"
do
    for d in "${dim[@]}"
    do  
        for p in "${flowsize[@]}"
        do
            for k in "${num_apps[@]}"
            do
                ./run_"$sys"_ping.sh $k temp/ $d $perf $p $r
                sleep 20
                python3 parse-netperf.py temp/ $k > temp/result.log
                # rm -rf temp/netperf*.log
                mkdir temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"_"$r"
                mv temp/*.log temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"_"$r"/
                echo "done"    
            done
        done
    done
done
