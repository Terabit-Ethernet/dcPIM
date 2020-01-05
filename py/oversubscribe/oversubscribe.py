conf_str_pfabric = '''init_cwnd: 19
max_cwnd: 22
retx_timeout: 1.54e-05
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 2
os_ratio: 0.5
num_hosts: 288
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 1
traffic_imbalance: 0
load: 0.5
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
'''

conf_str_phost = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 100000000000.0
queue_type: 2
flow_type: 112
os_ratio: 0.5
num_hosts: 288
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 12
traffic_imbalance: 0
load: 0.5
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
'''

conf_str_fastpass = '''init_cwnd: 6
max_cwnd: 12
retx_timeout: 45e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
os_ratio: 0.5
num_hosts: 288
flow_type: 114
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 14
traffic_imbalance: 0
load: 0.5
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
'''

conf_str_random = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 100000000000.0
queue_type: 2
flow_type: 112
os_ratio: 0.5
num_hosts: 288
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 16
traffic_imbalance: 0
load: 0.5
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
'''

conf_str_ruf = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 100000000000.0
queue_type: 2
flow_type: 115
os_ratio: 0.5
num_hosts: 288
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 15
traffic_imbalance: 0
load: 0.5
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
ruf_localize: {1}
ruf_limit_conns: {2}
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

conf_str_pim = '''init_cwnd: 2
max_cwnd: 6
retx_timeout: 9.50003e-06
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 100000000000.0
queue_type: 2
flow_type: 116
os_ratio: 0.5
num_hosts: 288
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 17
traffic_imbalance: 0
load: 0.5
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
pim_iter_limit: 4
pim_beta: 1.3
pim_alpha: 1
token_initial: 1
token_timeout: 2
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

runs = ['pfabric', 'phost', 'fastpass', 'random', 'ruf', "pim", "ruf_local"]
workloads = ['aditya', 'dctcp', 'datamining', 'constant']
#incasts = [1,143]
for r in runs:
    for w in workloads:
        #  generate conf file
        if r == "ruf":
            for i in range(2):
                for j in range(2):
                    conf_str = conf_str_ruf.format(w, i, j)
                    confFile = "conf_{0}_{1}_{2}_{3}.txt".format(r, w, i, j)
                    with open(confFile, 'w') as f:
                        f.write(conf_str)
            continue
        if r == 'pfabric':
            conf_str = conf_str_pfabric.format(w)
        elif r == 'phost':
            conf_str = conf_str_phost.format(w)
        elif r == 'fastpass':
            conf_str = conf_str_fastpass.format(w)
        elif r == 'random':
            conf_str = conf_str_random.format(w)
        elif r == 'pim':
            conf_str = conf_str_pim.format(w)
        confFile = "conf_{0}_{1}.txt".format(r, w)
        with open(confFile, 'w') as f:
            f.write(conf_str)
