CORES=$1
score=$2
core_id=0
while (( core_id < CORES ));do
	taskset -c $core_id ./homa_test 192.168.10.115:$((4000+score)) --sp $(( 4000 + core_id )) --count 40 dcacpping &
        (( core_id++ ))
done
