conf_str_pfabric = '''init_cwnd: 12
max_cwnd: 15
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 2
num_flow: 100000
flow_trace: ../CDF_{1}.txt
cut_through: 1
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
capability_initial: 8
capability_window: 8
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
incast_tm: 20
'''

conf_str_phost = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 112
num_flow: 100000
flow_trace: ../CDF_{1}.txt
cut_through: 1
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
capability_initial: 8
capability_window: 8
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
incast_tm: 20
'''

conf_str_fastpass = '''init_cwnd: 6
max_cwnd: 12
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 114
num_flow: 100000
flow_trace: ../CDF_{1}.txt
cut_through: 1
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
capability_initial: 8
capability_window: 8
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
incast_tm: 20
'''

conf_str_random = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 112
num_flow: 100000
flow_trace: ../CDF_{1}.txt
cut_through: 1
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
capability_initial: 8
capability_window: 8
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
incast_tm: 20
'''

conf_str_ranking = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 40000000000.0
queue_type: 2
flow_type: 115
num_flow: 100000
flow_trace: ../CDF_{1}.txt
cut_through: 1
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
token_initial: 16
token_timeout: 1.5
token_resend_timeout: 9
token_window: 8
token_window_timeout: 25
token_third_level: 1
rankinghost_idle_timeout: 12
ranking_reset_epoch: 50
ranking_max_tokens: {0}
ranking_controller_epoch: 1
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

runs = ['ranking']
workloads = ['aditya', 'dctcp', 'datamining', 'constant']
epochs= [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
#epochs = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
for r in runs:
    for w in workloads:
        #  generate conf file
        for epoch in epochs:
	        if r == 'pfabric':
	            conf_str = conf_str_pfabric.format(epoch, w)
	        elif r == 'phost':
	            conf_str = conf_str_phost.format(epoch, w)
	        elif r == 'fastpass':
	            conf_str = conf_str_fastpass.format(epoch, w)
	        elif r == 'random':
	            conf_str = conf_str_random.format(epoch, w)
	        elif r == 'ranking':
	        	conf_str = conf_str_ranking.format(epoch, w)
	        confFile = "conf_{0}_{1}_{2}.txt".format(r, w, int(epoch))
	        with open(confFile, 'w') as f:
	            print confFile
	            f.write(conf_str)
