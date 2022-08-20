#!/usr/local/bin/python
import errno
import numpy as np
import os
import sys

# matplotlib.rcParams['figure.figsize'] = [3.125, 1.93]
# matplotlib.rcParams['mathtext.fontset'] = u'stix'
# matplotlib.rcParams['pdf.fonttype'] = 42
# matplotlib.rcParams['ps.fonttype'] = 42

marker = [".", "o", "x", "s", "*"]

algos = ["pim"]
# epochs = [3]
workloads = ['imc10']
load = 0.8
#tokens = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]
pim_k = [1, 2, 4, 8]
rounds = [1, 2, 3, 4, 5]
loads = [[0.54, 0.72, 0.76, 0.74, 0.72], [0.56, 0.76, 0.80, 0.80, 0.78],
[0.56, 0.78, 0.82, 0.82, 0.82], [0.56, 0.78, 0.84, 0.84, 0.84]]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5
RATIO = 6
FIRST_THRESHOLD = 6000
SECOND_THRESHOLD = 12000
THIRD_THRESHOLD = 24000
FOURTH_THRESHOLD = 48000
FIFTH_THRESHOLD = 96000

set_dst = {}

def get_oracle_fct(src_addr, dst_addr, flow_size, bandwidth):
    num_hops = 8
    if (src_addr / 16 == dst_addr / 16):
        num_hops = 4

    propagation_delay = num_hops * 0.00000065
    b = bandwidth * 1000000000.0
    # pkts = (float)(flow_size) / 1460.0
    # np = math.floor(pkts)
    # # leftover = (pkts - np) * 1460
    # incl_overhead_bytes = 1500 * np
    # incl_overhead_bytes = 1500 * np + leftover
    # if(leftover != 0): 
    #     incl_overhead_bytes += 40

    # bandwidth = 10000000000.0 #10Gbps
    transmission_delay = 0

    # transmission_delay = (incl_overhead_bytes + 40) * 8.0 / bandwidth
    transmission_delay = flow_size * 8.0 / b
    if (num_hops == 8):
        # 1 packet and 1 ack
        # if (leftover != 1460 and leftover != 0):
        #     # less than mss sized flow. the 1 packet is leftover sized.
        #     transmission_delay += 2 * (leftover + 2 * 40) * 8.0 / (4 * bandwidth)

        # else:
        # # 1 packet is full sized
        #     transmission_delay += 2 * (1460 + 2 * 40) * 8.0 / (4 * bandwidth)
        transmission_delay += 1.5 * 1500 * 8.0 / b
        transmission_delay += 2.5 * 40 * 8.0 / b
    # if (leftover != 1460 and leftover != 0):
    #     # less than mss sized flow. the 1 packet is leftover sized.
    #     transmission_delay += (leftover + 2 * 40) * 8.0 / (bandwidth)

   # else:
         # 1 packet is full sized
    #     transmission_delay += (1460 + 2 * 40) * 8.0 / (bandwidth)
    else:
        transmission_delay += 1 * 1500 * 8.0 / b
        transmission_delay += 2 * 40 * 8.0 / b
    return transmission_delay + propagation_delay



def read_file(filename):
    output = []
    total_sent_packets = 0
    total_pkt = 0
    finish_time = 0
    s_time = 1.0
    reach_check_point = 0

    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if "queue" in line:
                continue
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
                total_pkt = int(params[9])
                finish_time = float(params[1])
                reach_check_point += 1
            elif reach_check_point < 10:
                flowId = int(params[0])
                size = float(params[1])
                src = int(params[2])
                dst = int(params[3])
                start_time = float(params[4])
                end_time = float(params[5])
                fct = float(params[6]) / 1000000.0
                orct = get_oracle_fct(src, dst, size, 100.0)
                ratio = fct / orct
                assert(ratio >= 1.0)
                if reach_check_point < 10:
                    output.append([flowId, size, start_time, end_time, fct, orct, ratio])
    return output, total_sent_packets, total_pkt, finish_time, s_time

def output_file(output, filename, format_str):
    file = open(filename, "w+")
    file.write(format_str)
    for i in range(len(pim_k)):
        string = ""
        string += str(float(pim_k[i]))
        for j in range(len(rounds)):
            string += " " + str(output[workloads[0]][i][j])
        string += "\n"
        file.write(string)

def get_mean_fct_oct_ratio(output):
    total = 0
    for line in output:
        total += line[FCT] / line[ORCT]
    return total / float(len(output))

def get_99_fct_oct_ratio(output):
    total = []
    for line in output:
        total.append(line[FCT] / line[ORCT])

    return np.percentile(np.array(total), 99)
def get_utilization(output, end_time, bandwidth, num_nodes):
    total = 0
    for line in output:
        total += line[SIZE]

    return total * 8 / bandwidth / end_time / num_nodes

def get_mean_fct_oct_ratio_by_size(output, segments):
    total = []
    for i in range(segments):
        total.append([])

    num_elements = [0] * segments
    for line in output:
        size = line[SIZE]
        ratio = line[RATIO]
        if size < FIRST_THRESHOLD:
            total[0].append(ratio)
            num_elements[0] += 1
        elif size < SECOND_THRESHOLD:
            total[1].append(ratio)
            num_elements[1] += 1
        elif size < THIRD_THRESHOLD:
            total[2].append(ratio)
            num_elements[2] += 1
        elif size < FOURTH_THRESHOLD:
            total[3].append(ratio)
            num_elements[3] += 1
        elif size < FIFTH_THRESHOLD:
            total[4].append(ratio)
            num_elements[4] += 1
        else:
            total[5].append(ratio)
            num_elements[5] += 1
    return total, num_elements

def read_util_outputs(direc):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    stats = {}

    for i in workloads:
        util[i] = {}
        fct_oct_ratio[i] = {}
        for j in range(len(pim_k)):
            util[i][j] = {}
            fct_oct_ratio[i][j] = {}
            for k in range(len(rounds)):
                util[i][j][k] = {}
                fct_oct_ratio[i][j][k] = {}
            # stats[j] = {}
                # total, num_elements = get_mean_fct_oct_ratio_by_size(output, 6)
                # stats[j]['median'] = [ np.median(total[i]) for i in range(len(total))]
                # stats[j]['std'] =  [ np.std(total[i]) for i in range(len(total))]
    return fct_oct_ratio, stats

def read_slowdown_outputs(direc):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    stats = {}

    for i in workloads:
        fct_oct_ratio[i] = {}
        for j in range(len(pim_k)):
            fct_oct_ratio[i][j] = {}
            for k in range(len(rounds)):
                fct_oct_ratio[i][j][k] = {}
            # stats[j] = {}
    for i in workloads:
        for j in range(len(pim_k)):
            for k in range(len(rounds)):
                file = input_prefix + str(i) + "_" + str(pim_k[j]) + "_" + str(rounds[k]) + "_" + str(0.54) + ".txt"
                output, total_sent_packets, total_pkt, finish_time, start_time = read_file(file)
                fct_oct_ratio[i][j][k] = get_99_fct_oct_ratio(output)
                # total, num_elements = get_mean_fct_oct_ratio_by_size(output, 6)
                # stats[j]['median'] = [ np.median(total[i]) for i in range(len(total))]
                # stats[j]['std'] =  [ np.std(total[i]) for i in range(len(total))]
    return  fct_oct_ratio, stats


def main():
    date = str(sys.argv[1])
#    util, fct_oct_ratio, stats =  read_util_outputs("../result/pim_k_iterations/" + date)
#    output_file(util, "../result/pim_k_iterations/pim_k_iteration_util.dat", "k/r   1   2   3   4   5\n")
    fct_oct_ratio, stats =  read_slowdown_outputs("../result/pim_k_iterations/" + date)
    output_file(fct_oct_ratio, "../result/pim_k_iterations/pim_k_iteration_slowdown.dat", "k/r   1   2   3   4   5\n")

    # output_file(fct_oct_ratio, "../result/pim_k_iterations/pim_k_iteration_slowdown.dat")
main()
