conf_str_pim = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 500000
propagation_delay: 0.00000065
bandwidth: 100000000000.0
queue_type: 2
flow_type: 116
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 17
traffic_imbalance: 0
load: {3}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
pim_iter_limit: {2}
pim_beta: 1.3
pim_alpha: 1
pim_k: {1}
token_initial: 1
token_timeout: 8
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
'''

runs = ["pim"]
pim_k = [1, 2, 4, 8]
rounds = [1, 2, 3, 4, 5]
loads = [0.54, 0.56, 0.72, 0.74, 0.76, 0.78, 0.80, 0.82, 0.84]
workloads = ['imc10']
#incasts = [1,143]
for k in pim_k:
	for r in rounds:
		for l in loads:
		    for w in workloads:
		        #  generate conf file
		        conf_str = conf_str_pim.format(w, k, r, l)
		        confFile = "conf_{0}_{1}_{2}_{3}.txt".format(w, k, r, l)
		        with open(confFile, 'w') as f:
		            f.write(conf_str)
