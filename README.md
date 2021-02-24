# pipeline-pim
DPDK implementation for pipelined PIM

1. Config the addresses of devices and NUMA memories;

  To do that
   ```
   sudo ./run.sh $num_server
   ```
   
2. Compile and Load net-driver kernel module:
 
   ```
   make
   sudo insmod nd_module.ko
   ```

 ```
 
 
 
if you are using Cornell clusters, you need to do following changes:

1. change line 6 to the correct end host addresses in config.sh:
```
ping 10.10.1.$c  -w 5
```
The correct IP addresses are from (5.0.0.10 to 12.0.0.10) depending on the number of servers you are using.

2. Also, you need to change config.py line 7 for the correct IP prefix/surfix. The current is for cloudlab clusters.

3
