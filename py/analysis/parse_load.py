#!/usr/local/bin/python
import errno
import numpy as np
import os
import sys
import json

# algos = ["homa_aeolus", "ndp","hpcc", "pim"]
#algos = ["pfabric", "homa", "pim"]
algos=["pim"]
loads = [5, 6, 7, 8]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5
RATIO = 6
set_dst = {}

bandwidth = 100
def get_oracle_fct(src_addr, dst_addr, flow_size):
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
    s_time = 0
    reach_check_point = 0

    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()

            if "queue pos" in line:
                continue
            if "queue " in line:
                continue
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
                total_pkt = int(params[9])
                finish_time = float(params[1])
                reach_check_point += 1
            elif reach_check_point < 4:
                flowId = int(params[0])
                size = float(params[1])
                src = int(params[2])
                dst = int(params[3])
                start_time = float(params[4])
                end_time = float(params[5])
                fct = float(params[6]) / 1000000.0
                orct = get_oracle_fct(src, dst, size)
                ratio = fct / orct 
                if ratio < 1.0:
                    assert False
                if flowId == 0:
                    s_time = start_time / 1000000.0
                if reach_check_point < 10:
                    output.append([flowId, size, start_time, end_time, fct, orct, ratio])
    return output, total_sent_packets, total_pkt, finish_time, s_time

def output_file(output, filename):
    workload = ""
    file = open(filename, "w+")
    for i in loads:
        string = ""
        string += str(float(i) / 10)
        for j in algos:
            string += " " + str(output[j][i])
        string += "\n"
        file.write(string)

def get_mean_fct_oct_ratio(output):
    total = 0
    for line in output:
        total += line[RATIO]
    return total / float(len(output))

def get_utilization(output, end_time, bandwidth, num_nodes):
    total = 0
    for line in output:
        total += line[SIZE]

    return total * 8 / bandwidth / end_time / num_nodes

def get_99_fct_oct_ratio(output):
    data = []
    for line in output:
        data.append(line[FCT] / line[ORCT])
        #if line[FCT] / line[ORCT] > 8.0:
         #   print line[SIZE] / 1460
    return np.percentile(data, 99)

# def read_ndp_files(trace, direc = "../../result/ndp/"):
#     file = direc + "result_ndp_{}.txt".format("load")
#     output = {}
#     with open(file) as json_file:
#         output = json.load(json_file)
#     return output

# def read_hpcc_files(trace, direc = "../../result/hpcc/"):
#     file = direc + "result_hpcc_{}.txt".format("load")
#     output = {}
#     with open(file) as json_file:
#         output = json.load(json_file)
#     return output

# def read_homa_files(queue, direc = "../../result/homa/"):
#     file = direc + "result_homa_{}_{}_{}.txt".format(queue,"load", bandwidth)
#     output = {}
#     with open(file) as json_file:
#         output = json.load(json_file)
#     return output

# def read_homa_aeolus_files(queue, direc = "../../result/homa_aeolus/"):
#     file = direc + "result_homa_{}_{}_{}.txt".format(queue,"load", bandwidth)
#     output = {}
#     with open(file) as json_file:
#         output = json.load(json_file)
#     return output

def read_outputs(direc, trace):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    n_ratio = {}
    stats = {}
    for i in algos:
        util[i] = {}
        fct_oct_ratio[i] = {}
        n_ratio[i] = {}
        for j in loads:
            util[i][j] = 0
            fct_oct_ratio[i][j] = 0
            n_ratio[i][j] = 0
    for i in algos:
        for j in loads:
            if i == "ndp":
                output = read_ndp_files(trace)
                util[i][j] = output[trace][str(j)]['util']
                fct_oct_ratio[i][j] = output[trace][str(j)]["mean"]
                n_ratio[i][j] = output[trace][str(j)]["99"]
            elif i == "hpcc":
                output = read_hpcc_files(trace)
                util[i][j] = output[trace][str(j)]['util']
                fct_oct_ratio[i][j] = output[trace][str(j)]["mean"]
                n_ratio[i][j] = output[trace][str(j)]["99"]
            elif i == "homa_limit":
                output = read_homa_files("limit")
                load = "{:.1f}".format(float(j) / 10)
                util[i][j] = output[trace][load]['util']
                fct_oct_ratio[i][j] = output[trace][load]["mean"]
                n_ratio[i][j] = output[trace][load]["99"]
            elif i == "homa_unlimit":
                output = read_homa_files("unlimit")
                load = "{:.1f}".format(float(j) / 10)
                util[i][j] = output[trace][load]['util']
                fct_oct_ratio[i][j] = output[trace][load]["mean"]
                n_ratio[i][j] = output[trace][load]["99"]
            elif i == "homa_aeolus":
                output = read_homa_aeolus_files("500")
                load = "{:.1f}".format(float(j) / 10)
                util[i][j] = output[trace][load]['util']
                fct_oct_ratio[i][j] = output[trace][load]["mean"]
                n_ratio[i][j] = output[trace][load]["99"]
            else:
                file = input_prefix  + str(i) +  "_" + trace + "_" + str(j) +".txt"
                output, total_sent_packets, total_pkt, finish_time, start_time = read_file(file)
                util[i][j] = total_sent_packets  / float(total_pkt)
                fct_oct_ratio[i][j] = get_mean_fct_oct_ratio(output)
                n_ratio[i][j] = get_99_fct_oct_ratio(output)
            # if i == "ranking":
            #     total, num_elements = get_mean_fct_oct_ratio_by_size(output, 6)
            #     stats[j]['median'] = [ np.median(total[k]) for k in range(len(total))]
                # stats[j]['std'] =  [ np.std(total[k]) for k in range(len(total))]
    return util, fct_oct_ratio, n_ratio

def main():
    global bandwidth
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    bandwidth = int(sys.argv[3])
    util, fct_oct_ratio,n_ratio =  read_outputs("../result/load/" + date, trace)
    output_file(util, "../result/load/{}_load_util.dat".format( trace))
    output_file(fct_oct_ratio, "../result/load/{}_load_slowdown.dat".format(trace))
    output_file(n_ratio, "../result/load/{}_load_99_slowdown.dat".format(trace))
main()

