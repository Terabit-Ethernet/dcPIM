conf_str_pfabric = '''init_cwnd: 7
max_cwnd: 10
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 2
num_flow: {0}
flow_trace: ../../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 1
traffic_imbalance: 0
load: 0.8
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 7
capability_window: 7
capability_window_timeout: 25
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
capability_third_level: 1
capability_fourth_level: 0
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''

conf_str_phost = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 112
num_flow: {0}
flow_trace: ../../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 12
traffic_imbalance: 0
load: 0.8
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 7
capability_window: 7
capability_window_timeout: 25
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
capability_third_level: 1
capability_fourth_level: 0
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''

conf_str_fastpass = '''init_cwnd: 6
max_cwnd: 12
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 114
num_flow: {0}
flow_trace: ../../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 14
traffic_imbalance: 0
load: 0.8
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
fastpass_epoch_pkts: 7
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 7
capability_window: 7
capability_window_timeout: 25
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
capability_third_level: 1
capability_fourth_level: 0
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''

conf_str_random = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 112
num_flow: {0}
flow_trace: ../../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 16
traffic_imbalance: 0
load: 0.8
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 7
capability_window: 7
capability_window_timeout: 25
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
capability_third_level: 1
capability_fourth_level: 0
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''

conf_str_ruf = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 115
num_flow: {0}
flow_trace: ../../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 15
traffic_imbalance: 0
load: 0.8
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
token_initial: 2
token_third_level: 1
token_timeout: 2
token_resend_timeout: 1
token_window: 1
token_window_timeout: 1.1
rufhost_idle_timeout: 5.5
ruf_max_tokens: 10
ruf_min_tokens: 5
ruf_controller_epoch: 5
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''
conf_str_pim = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 116
num_flow: 1000000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 17
traffic_imbalance: 0
load: 0.7
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
pim_iter_limit: 5
pim_beta: 4
pim_alpha: 1
token_initial: 1
token_resend_timeout: 1
token_window: 1
token_window_timeout: 1.1
pim_select_min_iters: 1
ddc: 0
ddc_cpu_ratio: 0.33
ddc_mem_ratio: 0.33
ddc_disk_ratio: 0.34
ddc_normalize: 2
ddc_type: 0
deadline: 0
schedule_by_deadline: 0
avg_deadline: 0.0001
magic_inflate: 1
interarrival_cdf: none
num_host_types: 13
incast_tm: {0}
'''

runs = ['pfabric', 'phost', 'fastpass', 'random', 'ruf']
workloads = ['aditya', 'dctcp', 'datamining', 'constant']
incasts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
size = 100 #MB
size_in_pkts = 100 * 1024 * 1024 / 1460 
# for i in incasts:
# 	file_name = "best_case/" + "CDF_constant_" + str(i) + ".txt"
# 	per_flow_size = size_in_pkts / i
# 	with open(file_name, 'w') as f:
# 		f.write("{0} 1 0\n".format(per_flow_size)) 
# 		f.write("{0} 1 1\n".format(per_flow_size))

for r in runs:
    for w in workloads:
        #  generate conf file
        for incast in incasts:
	        if r == 'pfabric':
	            conf_str = conf_str_pfabric.format(incast, w)
	        elif r == 'phost':
	            conf_str = conf_str_phost.format(incast, w)
	        elif r == 'fastpass':
	            conf_str = conf_str_fastpass.format(incast, w)
	        elif r == 'random':
	            conf_str = conf_str_random.format(incast, w)
	        elif r == 'ruf':
	        	conf_str = conf_str_ruf.format(incast, w)
	        confFile = w + "/conf_{0}_{1}_{2}.txt".format(r, w, incast)
	        with open(confFile, 'w') as f:
                    print confFile
	            f.write(conf_str)
