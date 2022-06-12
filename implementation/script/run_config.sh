#!/bin/bash
num_host=$1
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

# set up the server
for addr in  "${ssh_array[@]}";
	do 
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p 22 artifact@$addr.utah.cloudlab.us "git clone https://github.com/Terabit-Ethernet/dcPIM.git; cd ~/dcPIM/implementation;"
	done

for addr in  "${ssh_array[@]}";
	do 
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p 22 artifact@$addr.utah.cloudlab.us "cd ~/dcPIM/implementation; chmod +x run.sh;bash ./run.sh $num_host" &
	done

sleep 240
