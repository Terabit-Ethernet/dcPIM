host=$1

# ping the number of end hosts
for (( c=1; c<=$host; c++ ))
do
   ping 10.10.1.$c  -w 5
done

# reserve the numa memory

sudo sh -c 'for i in /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages; do echo 4096 > $i; done'

# config
pip install netifaces
python config.py 1 $host
# compile the code
export RTE_SDK=/usr/local/src/dpdk-stable-18.11.10/

make clean
make

