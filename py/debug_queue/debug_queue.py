conf_str_ruf = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 115
topology: FatTree
k: 16
num_flow: 1000000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 15
traffic_imbalance: 0
load: 0.6
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
rufhost_idle_timeout: {2}
ruf_max_tokens: 10
ruf_min_tokens: 5
ruf_controller_epoch: {0}
debug_controller_queue: 1
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

runs = ['ruf']
workloads = ['aditya', 'dctcp', 'datamining', 'constant']
tokens = [10]
control_epochs = [5, 6]
#epochs = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
for r in runs:
    for w in workloads:
        #  generate conf file
        for token in tokens:
        	for control_epoch in control_epochs:
	        # if r == 'pfabric':
	        #     conf_str = conf_str_pfabric.format(token, w)
	        # elif r == 'phost':
	        #     conf_str = conf_str_phost.format(token, w)
	        # elif r == 'fastpass':
	        #     conf_str = conf_str_fastpass.format(token, w)
	        # elif r == 'random':
	        #     conf_str = conf_str_random.format(token, w)
		        c_time = control_epoch
		        idle_time = 0.5 + c_time
	    		conf_str = conf_str_ruf.format(c_time, w, idle_time)
		        confFile = "conf_{0}_{1}_{2}_{3}.txt".format(r, w, int(token), control_epoch)
		        with open(confFile, 'w') as f:
		            print confFile
		            f.write(conf_str)
