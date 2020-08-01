conf_str_pfabric = '''init_cwnd: {4}
max_cwnd: {5}
retx_timeout: {6}
queue_size: 36864
propagation_delay: 0.0000002
bandwidth: 100000000000.0
queue_type: 2
flow_type: 2
os_ratio: {3}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 1
traffic_imbalance: 0
local_load: {1}
remote_load: {2}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: 19
capability_window: 19
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
os_ratio: {3}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 12
traffic_imbalance: 0
local_load: {1}
remote_load: {2}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: {5}
capability_initial: {4}
capability_window: {4}
capability_window_timeout: {6}
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
queue_size: 500000
propagation_delay: 0.0000002
bandwidth: 10000000000.0
queue_type: 2
flow_type: 114
os_ratio: {3}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 14
traffic_imbalance: 0
local_load: {1}
remote_load: {2}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
capability_timeout: 1.5
capability_resend_timeout: 9
capability_initial: {4}
capability_window: {4}
fastpass_epoch_pkts: {4}
fastpass_limit_conns: {5}
fastpass_localize: {5}
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
os_ratio: {2}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{1}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 16
traffic_imbalance: 0
local_load: {0}
remote_load: {4}
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
os_ratio: {3}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 15
traffic_imbalance: 0
local_load: {1}
remote_load: {2}
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
ruf_controller_epoch: 5.0
ruf_localize: {4}
ruf_limit_conns: {5}
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
queue_size: 500000
propagation_delay: 0.00000065
bandwidth: 100000000000.0
queue_type: 2
flow_type: 116
os_ratio: {3}
num_hosts: 144
num_flow: 1000000
flow_trace: ../CDF_{0}.txt
cut_through: 0
mean_flow_size: 0
load_balancing: 0
preemptive_queue: 0
big_switch: 0
host_type: 17
traffic_imbalance: 0
local_load: {1}
remote_load: {2}
reauth_limit: 3
magic_trans_slack: 1.1
magic_delay_scheduling: 1
use_flow_trace: 0
smooth_cdf: 1
burst_at_beginning: 0
pim_iter_limit: 4
pim_beta: 1.3
pim_alpha: 1
pim_k: 4
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

import math
#runs = ['pfabric', 'phost', 'fastpass', 'ruf', 'pim']
runs = ['fastpass']
workloads = ['aditya', 'dctcp', 'datamining']
#precentage = [  0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.46, 0.47, 0.48, 0.49, 0.50, 0.51, 0.52, 0.53, 0.54, 0.55, 0.56, 0.57, 0.58, 0.59, 0.60, 0.61, 0.62, 0.63, 0.64, 0.65, 0.66, 0.67, 0.68, 0.69, 0.70, 0.71, 0.72, 0.73, 0.74, 0.75, 0.76, 0.77, 0.78, 0.79, 0.80, 0.81, 0.82, 0.83, 0.84, 0.85, 0.86, 0.87, 0.88, 0.89]
over_subscription = [2]
#remote_load = [0.6, 0.8]
remote_loads = [0.2, 0.4, 0.6, 0.8, 1.0]
for r in runs:
    for w in workloads:
        #  generate conf file
        # for r_load in remote_load:
        #     for o in over_subscription:
        #         os_ratio = 1.0 / o
        #         load = 0.0
        #         first_time = False
        #         propagation_delay = 0.0000002
        #         access_bw = 100000000000.0
        #         core_bw = 4 * access_bw * os_ratio
        #         rtt = (4 * propagation_delay + (1500 * 8 / access_bw +  1500 * 8 / core_bw) * 2) * 2
        #         bdp = int(math.ceil(rtt * access_bw / 8 / 1500))
        #         while load <= 1.0 - os_ratio * r_load:
        #             if r == "ruf":
        #                 for i in range(2):
        #                     for j in range(2):
        #                         conf_str = conf_str_ruf.format(w, load, r_load, os_ratio, i, j)
        #                         confFile = "conf_{0}_{1}_{2}_{3}_{4}_{5}_{6}.txt".format(r, w, i, j, o, load, r_load)
        #                         with open(confFile, 'w') as f:
        #                             f.write(conf_str)
        #             else:
        #                 if r == 'pfabric':
        #                     conf_str = conf_str_pfabric.format(w, load, r_load, os_ratio, bdp,  bdp + 3, rtt * 7)
        #                 elif r == 'phost':
        #                     conf_str = conf_str_phost.format(w, load, r_load, os_ratio,bdp, bdp + 2, bdp * 3 + 4)
        #                 elif r == 'fastpass':
        #                     conf_str = conf_str_fastpass.format(w, load, r_load, os_ratio, bdp)
        #                 elif r == 'random':
        #                     conf_str = conf_str_random.format(w, load, r_load, os_ratio, bdp)

        #                 elif r == 'pim':
        #                     conf_str = conf_str_pim.format(w, load, r_load, os_ratio)
        #                 confFile = "conf_{0}_{1}_{2}_{3}_{4}.txt".format(r, w, o, load, r_load)
        #                 with open(confFile, 'w') as f:
        #                     print confFile
        #                     f.write(conf_str)
        #             load += 0.1
        for rl in remote_loads:
            for o in over_subscription:
                os_ratio = 1.0 / o
                first_time = False
                propagation_delay = 0.0000002
                access_bw = 10000000000.0
                core_bw = 4 * access_bw * os_ratio
                rtt = (4 * propagation_delay + (1500 * 8 / access_bw +  1500 * 8 / core_bw) * 2) * 2
                bdp = int(math.ceil(rtt * access_bw / 8 / 1500))
                r_load = rl
                l_load = 0.4
                print o
                if r == "ruf":
                    for i in range(2):
                        for j in range(2):
                            conf_str = conf_str_ruf.format(w, l_load, r_load, os_ratio, i, j)
                            confFile = "conf_{0}_{1}_{2}_{3}_{4}_{5}_{6}.txt".format(r, w, i, j, o, l_load, r_load)
                            with open(confFile, 'w') as f:
                                f.write(conf_str)
                elif r == 'fastpass':
                    for i in range(2):
                        conf_str = conf_str_fastpass.format(w, l_load, r_load, os_ratio, bdp, i)
                        confFile = "conf_{0}_{1}_{2}_{3}_{4}.txt".format(r, w, o, l_load, r_load, i)
                        with open(confFile, 'w') as f:
                            f.write(conf_str)
                else:
                    if r == 'pfabric':
                        conf_str = conf_str_pfabric.format(w, l_load, r_load, os_ratio, bdp,  bdp + 3, rtt * 7)
                    elif r == 'phost':
                        conf_str = conf_str_phost.format(w, l_load, r_load, os_ratio,bdp, bdp + 2, bdp * 3 + 4)
                    elif r == 'random':
                        conf_str = conf_str_random.format(w, l_load, r_load, os_ratio, bdp)

                    elif r == 'pim':
                        conf_str = conf_str_pim.format(w, l_load, r_load, os_ratio)
                    confFile = "conf_{0}_{1}_{2}_{3}_{4}.txt".format(r, w, o, l_load, r_load)
                    with open(confFile, 'w') as f:
                        print confFile
                        f.write(conf_str)
