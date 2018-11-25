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
token_fourth_level: 0
rankinghost_idle_timeout: {0}
ranking_reset_epoch: 50
ranking_max_tokens: 80
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
idle_time = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
#epochs = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
for r in runs:
    for w in workloads:
        #  generate conf file
        for idle in idle_time:
	        if r == 'ranking':
	        	conf_str = conf_str_ranking.format(idle * 0.3 * 8, w)
	        confFile = "conf_{0}_{1}_{2}.txt".format(r, w, int(idle))
	        with open(confFile, 'w') as f:
	            print confFile
	            f.write(conf_str)
