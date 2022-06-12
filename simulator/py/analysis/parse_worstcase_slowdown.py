#!/usr/local/bin/python
import errno
import numpy as np
import os
import sys
import json
# matplotlib.rcParams['figure.figsize'] = [3.125, 1.93]
marker = [".", "o", "x", "s", "*"]
#algos = ["ranking"]
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4", "p2+p3+p4+p5"]
#algos = ["homa", "ndp", "hpcc", "pim"]
algos = ['pim']
#algos = ["phost"]
#traces = ["aditya"]
traces = ["worstcase2"]
# traces = ['aditya', 'dctcp']
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]
load = 0.8

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5

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

def read_ndp_file(filename):
    output = []
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split(',')
            flowId = int(params[0])
            size = int(params[3])
            src = int(params[1])
            dst = int(params[2])
            fct = float(params[5][:-3]) / 1000000.0
            orct = get_oracle_fct(src, dst, size, 100)
            if size > 200000:
                continue
            output.append([flowId, size, 0, 0, fct, orct, orct / fct])
    return output

def ipToNode(ip):
    return (int(ip, 16)-int('0b000001', 16))/int('00000100', 16)

def read_hpcc_file(filename):
    output = []
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            # flowId = int(params[0])
            size = int(params[4])
            src = ipToNode((params[0]))
            dst = ipToNode((params[1]))
            fct = float(params[6]) / 1000000000.0
            orct = get_oracle_fct(src, dst, size, 100)
            if size > 200000:
                continue
            output.append([0, size, 0 ,0, fct, orct, orct / fct])
    return output

def read_homa_file(filename):
    output = []
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if params[0] == "##":
                continue
            flowId = int(params[0])
            size = int(params[1])
            if size > 200000:
                continue
            # src = int(params[1])
            # dst = int(params[2])
            fct = float(params[4])
            if(flowId == 0):
                orct = get_oracle_fct(0, 16, size, 100)
            else:
                orct = get_oracle_fct(0, 0, size, 100)

            output.append([flowId, size, 0, 0, fct, orct, orct / fct])
    return output

def read_file(filename):
    output = []
    total_sent_packets = 0
    total_packets = 0
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
                total_packets = int(params[9])
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
                orct = get_oracle_fct(src, dst, size, 100)
                assert(fct > orct)
                # ratio = float(params[8])
                # if reach_check_point < 10:
                if size > 200000:
                    continue
                output.append([flowId, size, start_time, end_time, fct, orct])
    return output, total_sent_packets,total_packets, finish_time, s_time

def output_file(output, output_99, filename, format_str):
    workload = ""
    file = open(filename, "w+")
    file.write(format_str)
    for i in traces:
        string = "\"Mean Slowdown\""
        for j in algos:
            string += " " + str(output[i][j])
        string += "\n"
        file.write(string)
    for i in traces:
        string = "\"99 Slowdown\""
        for j in algos:
            string += " " + str(output_99[i][j])
        string += "\n"
        file.write(string)

def get_mean_fct_oct_ratio(output):
    total = 0
    for line in output:
        total += line[FCT] / line[ORCT]
    return total / float(len(output))

def get_99_fct_oct_ratio(output):
    data = []
    for line in output:
        data.append(line[FCT] / line[ORCT])
        #if line[FCT] / line[ORCT] > 8.0:
         #   print line[SIZE] / 1460
    return np.percentile(data, 99)

def get_utilization(output, end_time, bandwidth, num_nodes):
    total = 0
    for line in output:
        total += line[SIZE]

    return total * 8 / bandwidth / end_time / num_nodes
def read_ndp_files(trace, direc = "../../result/ndp/"):
    file = direc + "result_ndp_{}.txt".format(trace)
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output
def read_hpcc_files(trace, direc = "../../result/hpcc/"):
    file = direc + "result_hpcc_{}.txt".format(trace)
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_homa_files(trace, direc = "../../result/homa/"):
    file = direc + "result_homa_{}.txt".format("load")
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_homa_aeolus_files(trace, direc = "../../result/homa_aeolus/"):
    file = direc + "result_homa_500_{}_100.txt".format("load")
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_outputs(direc, t):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    fct_oct_ratio_99 = {}
    for k in traces:
        util[k] = {}
        fct_oct_ratio[k] = {}
        fct_oct_ratio_99[k] = {}
        for i in algos:
            util[k][i] = 0
            fct_oct_ratio[k][i] = 0
            fct_oct_ratio_99[k][i] = 0
    for k in traces:
        for i in algos:
            file = input_prefix  + i +  "_{}.txt".format(k)
            if i == 'ndp':
                output = read_ndp_file(file)
                # util[k][i] = output[k]['util']
                fct_oct_ratio[k][i] = get_mean_fct_oct_ratio(output)
                fct_oct_ratio_99[k][i] = get_99_fct_oct_ratio(output)
                # fct_oct_ratio[k][i] = output[k]['mean']
                # fct_oct_ratio_99[k][i] = output[k]['99']
            elif i == 'hpcc':
                output = read_hpcc_file(file)
                # util[k][i] = output[k]['util']
                fct_oct_ratio[k][i] = get_mean_fct_oct_ratio(output)
                fct_oct_ratio_99[k][i] = get_99_fct_oct_ratio(output)
                # fct_oct_ratio[k][i] = output[k]['mean']
                # fct_oct_ratio_99[k][i] = output[k]['99']
            elif i == "homa":
                output = read_homa_file(file)
                fct_oct_ratio[k][i] = get_mean_fct_oct_ratio(output)
                fct_oct_ratio_99[k][i] = get_99_fct_oct_ratio(output)
                # fct_oct_ratio[k][i] = output[k]['mean']
                # fct_oct_ratio_99[k][i] = output[k]['99']
                # load = "{:.1f}".format(float(6) / 10)
                # util[k][i] = output[k][load]['util']
                # fct_oct_ratio[k][i] = output[k][load]["mean"]
                # fct_oct_ratio_99[k][i] = output[k][load]["99"]
            elif i == "homa_aeolus":
                print k
                # output = read_homa_aeolus_files(t)
                # load = "{:.1f}".format(float(6) / 10)
                # util[k][i] = output[k][load]['util']
                # fct_oct_ratio[k][i] = output[k][load]["mean"]
                # fct_oct_ratio_99[k][i] = output[k][load]["99"]
                # fct_oct_ratio[k][i] = output[k]['mean']
                # fct_oct_ratio_99[k][i] = output[k]['99']
            else:
                output, total_sent_packets, total_packets, finish_time, start_time = read_file(file)
                # util[k][i] = total_sent_packets  / float(total_packets)
                fct_oct_ratio[k][i] = get_mean_fct_oct_ratio(output)
                fct_oct_ratio_99[k][i] = get_99_fct_oct_ratio(output)
    return util, fct_oct_ratio, fct_oct_ratio_99


def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    util, fct_oct_ratio, fct_oct_ratio_99 =  read_outputs("../result/worst_case/" + date, trace)
    # draw_graph(util, trace + " Utilization")
    # draw_graph(fct_oct_ratio, trace + " Slowdown")
    # print util, fct_oct_ratio, fct_oct_ratio_99
    # output_file(util, "../gnuplot/data/{0}_util.dat".format(trace))
    output_file(fct_oct_ratio,fct_oct_ratio_99, "../result/worst_case/{0}_slowdown.txt".format(trace), "<ATTRIBUTE> <VALUE>\n")
    # output_file(fct_oct_ratio_99, "../gnuplot/data/{0}_99_slowdown.dat".format(trace))

main()
