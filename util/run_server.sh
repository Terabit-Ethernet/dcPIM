CORES=$1
core_id=0
while (( core_id < CORES ));do
	taskset -c $core_id ./server --ip 192.168.10.125 --port $((4000 + core_id)) > result_$((core_id))  &
        (( core_id++ ))
done
