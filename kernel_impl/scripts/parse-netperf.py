#!/usr/bin/env python3
import os
import re
import sys
import numpy as np
# Parse args
if len(sys.argv) < 3:
    print("usage: parse-netperf.py DIR NUM_APPS")
    exit(1)

DIR = sys.argv[1]
N = int(sys.argv[2])

# Parse netperf files
results = []
total_thpt = 0


# client_sched_dict, server_sched_dict = sched_latency()


# client_netperf_dict, server_netperf_dict = netfilter_output()
# e2e_netfilter_dict = get_e2e_netfilter(thread_dict, client_netperf_dict, server_netperf_dict)

# client_netfilter2_dict, server_netfilter2_dict = netfilter_output_2()
# print ('''port, client_core, server_core, client_pid, server_pid, thpt, latency, total_netfilter_pkt''')
f = os.path.join(DIR, "latency.log")
lines = []
with open(f, "r") as file:
        lines = file.readlines()
        params = lines[0].split()
        mean = params[0]
        p99 = params[1]
        p999 = params[2]
for i in range(0, N):
    f = os.path.join(DIR, "netperf-{}.log".format(i))
    lines = []
    with open(f, "r") as file:
        lines = file.readlines()
        num = 0
        temp_result = []
        for line in lines:
            params = line.split()
            if len(params) <= 2:
                break
            time = float(params[2])
            if num > 10000000:
                break
            results.append(time)
            temp_result.append(time)
            num += 1
    f = os.path.join(DIR, "netperf-{}.log".format(i))
    temp_result.sort()
    with open(f, "r") as file:
        lines = file.readlines()
        for line in lines:
            params = line.split()
            port = int(params[0])
            thpt = float(params[4])
            latency = np.percentile(temp_result, 99.9)
            total_thpt += thpt

results.sort()
# Print the netperf latencies
categories = ['m_lat', 'p99_lat', 'p999_lat']
print("{}\t{}\t{}\t{}".format('m_lat','p99_lat',  'p999_lat', "thpt"))

# print("{}\t{}\t{}".format(sum(results) / len(results), np.percentile(results, 99),  np.percentile(results, 99.9)), total_thpt)
print("{}\t{}\t{}\t{}".format(mean, p99, p999, total_thpt))
