conf_str_pfabric = '''init_cwnd: 11
max_cwnd: 14
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 2
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 1
traffic_imbalance: 0
load: {0}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 11
capability_window: 11
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
'''

conf_str_phost = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 112
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 12
traffic_imbalance: 0
load: {0}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 11
capability_window: 11
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
'''

conf_str_fastpass = '''init_cwnd: 6
max_cwnd: 12
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 114
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 14
traffic_imbalance: 0
load: {0}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 11
capability_window: 11
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
'''

conf_str_random = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 112
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 16
traffic_imbalance: 0
load: {0}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 11
capability_window: 11
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
'''

conf_str_ranking = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 115
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 15
traffic_imbalance: 0
load: {0}
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
rankinghost_idle_timeout: 0.5
ranking_reset_epoch: 1
ranking_max_tokens: 1
ranking_controller_epoch: 0.25
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
'''

conf_str_multiround = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 116
num_flow: 200000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 17
traffic_imbalance: 0
load: {0}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
mr_iter_limit: 4
mr_epoch: 10
mr_window_size: 1
mr_small_flow: 1
mr_window_timeout: 1e-0.6
mr_resend_timeout: 1
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
'''


runs = ['pfabric', 'phost', 'fastpass', 'random', 'ranking', 'multi_round']
workloads = ['aditya', 'dctcp', 'datamining', 'constant']
loads = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
for r in runs:
    for w in workloads:
        #  generate conf file
        for load in loads:
	        if r == 'pfabric':
	            conf_str = conf_str_pfabric.format(load, w)
	        elif r == 'phost':
	            conf_str = conf_str_phost.format(load, w)
	        elif r == 'fastpass':
	            conf_str = conf_str_fastpass.format(load, w)
	        elif r == 'random':
	            conf_str = conf_str_random.format(load, w)
	        elif r == 'ranking':
	        	conf_str = conf_str_ranking.format(load, w)
	        elif r == 'multi_round':
	        	conf_str = conf_str_multiround.format(load, w)
	        confFile = "conf_{0}_{1}_{2}.txt".format(r, w, int(load * 10))
	        with open(confFile, 'w') as f:
	            print confFile
	            f.write(conf_str)
