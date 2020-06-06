CORES=$1
core_id=0
while (( core_id < CORES ));do
	taskset -c $core_id ./homa_test 192.168.10.115:6000 --sp $(( 4000 + core_id )) --count 40 dcacpping &
        (( core_id++ ))
done
