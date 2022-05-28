eval `ssh-agent`
ssh-add
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
ms1332
)

# set up the server
# for addr in  "${ssh_array[@]}";
# 	do 
# 		echo addr;
# 		ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "cd /usr/local/src/pipeline-pim; /usr/local/src/pipeline-pim/run.sh 16" &
# 	done

num_hosts=$1
mkdir ../result
mkdir ../result/"$num_hosts"

i=0
# run experiment
for addr in  "${ssh_array[@]: 0: $num_hosts}";
	do 
	 	scp -r caiqizhe@$addr.utah.cloudlab.us:~/pipeline-pim/result_imc10.txt ../result/"$num_hosts"/result_imc10_$i.txt
	 	scp -r caiqizhe@$addr.utah.cloudlab.us:~/pipeline-pim/result_websearch.txt ../result/"$num_hosts"/result_websearch_$i.txt
	 	scp -r caiqizhe@$addr.utah.cloudlab.us:~/pipeline-pim/result_datamining.txt ../result/"$num_hosts"/result_datamining_$i.txt
	 	# scp -r caiqizhe@$addr.utah.cloudlab.us:~/tcp_baseline/result_"$workload"_"$i" result/result_"$workload"_$i.txt

		i=$((i+1))
	done

# sleep 3

# ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@ms0817.utah.cloudlab.us "sudo killall pim; cd /usr/local/src/pipeline-pim;sudo ./build/pim -- send CDF_aditya.txt > result_aditya.txt" &


# for addr in  "${ssh_array[@]}";
# 	do 
# 	 	ssh -o StrictHostKeyChecking=no -p 22 caiqizhe@$addr.utah.cloudlab.us "sudo killall pim" &
# 	done
