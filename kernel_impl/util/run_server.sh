#!/bin/bash
CORES=$1
core_id=0
while (( core_id < CORES ));do
	taskset -c 0 /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id)) > server_$((core_id)).log& 
        #taskset -c 0 /home/qizhe/dcpim_kernel/util/server --ip 192.168.10.125 --port $((4000 + core_id))
      	(( core_id++ ))
done
