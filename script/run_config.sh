eval `ssh-agent`
ssh-add
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
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "git config --global credential.helper 'cache --timeout=2628000'"
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "cd /usr/local/src/pipeline-pim; git pull https://qizhe:Shinyway88!@github.com/qizhe/pipeline-pim.git"
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "cd /usr/local/src/pipeline-pim; git pull"
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@$addr.utah.cloudlab.us "git clone https://qizhe@github.com/qizhe/pipeline-pim.git; cd ~/pipeline-pim;git checkout cloudlab; git checkout -b cloudlab origin/cloudlab;git pull;" &
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "git clone https://qizhe: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@github.com/qizhe/tcp_baseline.git; cd ~/tcp_baseline;git pull; make" &
# 		# scp -o StrictHostKeyChecking=no -p 22 ttcs-agent.cfg caiqizhe@$addr.utah.cloudlab.us:~/ &
# 		# scp -o StrictHostKeyChecking=no -p 22 ttcs-agent_1.0.12_amd64.deb caiqizhe@$addr.utah.cloudlab.us:~/ &
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "sudo dpkg -i ttcs-agent_1.0.12_amd64.deb" &
# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "sudo sysctl -w net.ipv4.tcp_congestion_control=dctcp;sudo sysctl -w net.ipv4.tcp_ecn_fallback=0;" &

# 		# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "cd ~/pipeline-pim; ./run.sh 32" &
	done

for addr in  "${ssh_array[@]}";
	do 
		ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa -p 22 caiqizhe@$addr.utah.cloudlab.us "cd pipeline-pim; chmod +x run.sh;bash ./run.sh $num_host" &
	done



# run experiment
# for addr in  "${ssh_array[@]: 1}";
# 	do 
# 	 	ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "sudo killall pim; cd /usr/local/src/pipeline-pim;sudo ./build/pim -- send CDF_aditya.txt > result_aditya.txt" &
# 	done

# sleep 3

# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@ms0817.utah.cloudlab.us "sudo killall pim; cd /usr/local/src/pipeline-pim;sudo ./build/pim -- send CDF_aditya.txt > result_aditya.txt" &


# for addr in  "${ssh_array[@]}";
# 	do 
# 	 	ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "sudo killall pim" &
# 	done
