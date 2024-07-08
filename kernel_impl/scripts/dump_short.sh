iodepth=(1)
num_apps=(1 2 4 8 16 32)
rx_usec=(6)
dim=(0)
# 1: incast
perf=0
sys="dcpim"
for r in "${rx_usec[@]}"
do
    for d in "${dim[@]}"
    do  
        for p in "${iodepth[@]}"
        do
            for k in "${num_apps[@]}"
            do 
                cat temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"_"$r"/result.log
                sudo rm -rf temp/"$sys"_a2a_"$d"_"$p"_"$perf"_"$k"_"$r"/netperf*.log           
	    done
            # for f in  "${flowsize[@]}"
            # do
            #     for i in "${iodepth[@]}"
            #     do
            #         for k in "${num_apps[@]}"
            #         do
            #             mkdir results/our_mc_"$f"_"$k"_"$i"
            #             ./parse-netperf.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" $k > results/our_mc_"$f"_"$k"_"$i"/"$sys"_latency &
            #             # PIDS="$PIDS $!"
            #             # ./parse-breakdown-server.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" $k > results/our_mc_"$f"_"$k"_"$i"/"$sys"_latency_breakdown_s &
            #             # ./parse-breakdown.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" $k >  results/our_mc_"$f"_"$k"_"$i"/"$sys"_latency_breakdown_c &
            #             ./parse-breakdown-rx_sched_c.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" $k > results/our_mc_"$f"_"$k"_"$i"/"$sys"_latency_breakdown_rx_sched_c &
            #             ./parse-breakdown-rx_sched_s.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" $k > results/our_mc_"$f"_"$k"_"$i"/"$sys"_latency_breakdown_rx_sched_s &
            #             # ./parse-cpu.py temp/our_mc_"$f"_"$k"_"$i" $k $j > results/our_mc_"$f"_"$k"_"$i"/"$sys"_cpu &
            #             # ./parse-compute.py temp/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"/"$sys"_mc_"$f"_"$k"_"$i" 2 > results/our_mc_"$f"_"$k"_"$i"/"$sys"_compute &
            #         done
            #     done
            # done            # mkdir results/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"
            # cp -r results/our_mc* results/dim_"$d"_pin_"$p"_tapp_"$t"_sched_"$s"
            # rm -rf results/our_mc*
        done
    done
done

# for f in "${flowsize[@]}"
# do  
#     for i in "${iodepth[@]}"
#     do
#         for j in "${irq_cores[@]}"
#         do
#             for k in "${num_apps[@]}"
#             do
#                 for l in "${compute[@]}"
#                 do
#                     # ./cfs-both-compute.sh "$k" temp/ $f $i $l
#                     # mkdir temp/cfs_sc_"$f"_"$k"_"$i"_"$l"
#                     # mv temp/*.log temp/cfs_sc_"$f"_"$k"_"$i"_"$l"
#                     ./"$sys"-both-8c-compute.sh $k temp/ $f $i $l
#                     mkdir temp/"$sys"_sc_"$f"_"$k"_"$i"_"$l"
#                     mv temp/*.log temp/"$sys"_sc_"$f"_"$k"_"$i"_"$l"
#                     # ./ours-both-8c-compute-k2-redis.sh $k temp/ $f $i $j $l
#                     # mkdir temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"
#                     # mv temp/*.log temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"
#     # #             #  ./caladan-both-8c-compute.sh $k temp/ 64 $i $j $l
#     # #             #  mkdir temp/caladan_mc_"$k"_"$i"_"$j"_"$l"
#     # #             #  mv temp/*.log temp/caladan_mc_"$k"_"$i"_"$j"_"$l"
#     # #             #  ./caladan-both-8c-compute-apps.sh $k temp/ 64 $i $j $l
#     # #             #  mkdir temp/caladan_mp_"$k"_"$i"_"$j"_"$l"
#     # #             #  mv temp/*.log temp/caladan_mp_"$k"_"$i"_"$j"_"$l"
#                     # ./tas-both-8c-compute-redis.sh $k temp/ $f $i $j $l
#                     # mkdir temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l"
#                     # mv temp/*.log temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l"
#                 done
#             done
#         done
#     done
# done

# mkdir results
# for f in  "${flowsize[@]}"
# do
#     for i in "${iodepth[@]}"
#     do
#         for j in "${irq_cores[@]}"
#         do
#             for k in "${num_apps[@]}"
#             do
#                 for l in "${compute[@]}"
#                 do
#                     mkdir results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"
#                     #  ./parse-neper.py temp/"$sys"_mc_"$f"_"$k"_"$i"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_latency &
#                     # ./parse-neper.py temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_latency &
#                     # ./parse-neper.py temp/cfs_mc_"$f"_"$k"_"$i"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/crfs_latency &
#                     # ./parse-neper.py temp/caladan_mc_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$k"_"$i"_"$j"_"$l"/caladan_latency &
#                     # ./parse-neper.py temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/tas_latency &
#                     ./parse-netperf.py temp/"$sys"_sc_"$f"_"$k"_"$i"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_latency &
#                     # ./parse-netperf.py temp/our_sc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_latency &
#                      ./parse-netperf.py temp/cfs_sc_"$f"_"$k"_"$i"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/crfs_latency &
#                     #  ./parse-netperf.py temp/caladan_mc_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$k"_"$i"_"$j"_"$l"/caladan_latency &
#                     #  ./parse-netperf-tas.py temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/tas_latency &
#                     ./parse-breakdown-server.py temp/"$sys"_sc_"$f"_"$k"_"$i"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_latency_breakdown_s &
#                     # ./parse-breakdown-server.py temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_latency_breakdown_s &
#                     ./parse-breakdown-server.py temp/cfs_sc_"$f"_"$k"_"$i"_"$l" $k > results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/crfs_latency_breakdown_s &
#                     ./parse-breakdown.py temp/"$sys"_sc_"$f"_"$k"_"$i"_"$l" $k >  results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_latency_breakdown_c &
#                     # ./parse-breakdown.py temp/our_sc_"$f"_"$k"_"$i"_"$j"_"$l" $k >  results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_latency_breakdown_c &
#                      ./parse-breakdown.py temp/cfs_sc_"$f"_"$k"_"$i"_"$l" $k >  results/our_sc_"$f"_"$k"_"$i"_"$j"_"$l"/crfs_latency_breakdown_c &
#                     # ./parse-cpu.py temp/"$sys"_mc_"$f"_"$k"_"$i"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_cpu &
#                     # ./parse-cpu.py temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_cpu &
#                     #  ./parse-cpu.py temp/cfs_mc_"$k"_"$i"_"$l" $k > results/our_mc_"$k"_"$i"_"$j"_"$l"/crfs_cpu &
#                     # ./parse-cpu.py temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l" $k > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/tas_cpu &
#                     # ./parse-compute.py temp/"$sys"_mc_"$f"_"$k"_"$i"_"$l" 16 > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/"$sys"_compute &
#                     # ./parse-compute.py temp/our_mc_"$f"_"$k"_"$i"_"$j"_"$l" 16 > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/nrfs_compute &
#                     #  ./parse-compute.py temp/cfs_mc_"$k"_"$i"_"$l" 16 > results/our_mc_"$k"_"$i"_"$j"_"$l"/crfs_compute &
#                     # #  ./parse-compute.py temp/caladan_mc_"$k"_"$i"_"$j"_"$l" 8 > results/our_mc_"$k"_"$i"_"$j"_"$l"/caladan_compute &
#                     #  ./parse-compute.py temp/tas_mc_"$f"_"$k"_"$i"_"$j"_"$l" 16 > results/our_mc_"$f"_"$k"_"$i"_"$j"_"$l"/tas_compute &

#                 done
#             done
#         done
#     done
# done
