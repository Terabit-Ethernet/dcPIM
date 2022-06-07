#!/bin/bash
ssh_array=(
ms1301
ms1302
ms1303
ms1304
ms1305
ms1306
ms1307
ms1308
ms1309
ms1310
ms1311
ms1312
ms1313
ms1314
ms1315
ms1316
ms1317
ms1318
ms1319
ms1320
ms1321
ms1322
ms1323
ms1324
ms1325
ms1326
ms1327
ms1328
ms1329
ms1330
ms1331
ms1332)

workload=$1
num_hosts=$2
# run experiment
for addr in  "${ssh_array[@]: 1 : $num_hosts}";
	do 
	 	ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p 22 artifact@$addr.utah.cloudlab.us "sudo killall pim; cd ~/dcPIM/implementation;sudo ./build/pim -- send CDF_$workload.txt > result_$workload.txt" &
	done

sleep 20

ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p 22 artifact@ms1301.utah.cloudlab.us "sudo killall pim; cd ~/dcPIM/implementation;sudo ./build/pim -- start CDF_$workload.txt > result_$workload.txt" &

sleep 120

for addr in  "${ssh_array[@]: 0 : $num_hosts}";
	do 
	 	ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p 22 artifact@$addr.utah.cloudlab.us "sudo killall pim" &
	done
