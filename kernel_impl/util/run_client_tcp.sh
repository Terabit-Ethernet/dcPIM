CORES=$1
score=$2
core_id=0
while (( core_id < CORES ));do
	taskset -c $((core_id*4)) /home/qizhe/dcpim_kernel/util/dcpim_test 192.168.10.125:$((4000+score)) --sp $(( 10000 * (1 + score) +  core_id )) --count 1 tcpping &
        (( core_id++ ))
done
