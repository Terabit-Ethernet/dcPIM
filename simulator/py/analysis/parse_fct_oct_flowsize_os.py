#!/usr/local/bin/python
import errno
import numpy as np
import os
import sys
import json
import math

marker = [".", "o", "x", "s", "*"]
algos = ["pim"]
#algos = [ "ndp" , "hpcc", "pim"]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
RATIO = 4

BDP = 0
FIRST_THRESHOLD = 0
SECOND_THRESHOLD = 0
THIRD_THRESHOLD = 0
FOURTH_THRESHOLD = 0
FIFTH_THRESHOLD = 0
bandwidth = 0

def get_oracle_fct(src_addr, dst_addr, flow_size):
    num_hops = 8
    if (src_addr / 16 == dst_addr / 16):
        num_hops = 4

    propagation_delay = num_hops * 0.00000065

   
    # pkts = (float)(flow_size) / 1460.0
    # np = math.floor(pkts)
    # # leftover = (pkts - np) * 1460
    # incl_overhead_bytes = 1500 * np
    # incl_overhead_bytes = 1500 * np + leftover
    # if(leftover != 0): 
    #     incl_overhead_bytes += 40
    
    # bandwidth = 10000000000.0 #10Gbps
    transmission_delay = 0
    b = bandwidth * 1e9
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
        transmission_delay += 2 * 1500 * 8.0 / b
        transmission_delay += 40 * 8.0 * 4 / b
    # if (leftover != 1460 and leftover != 0):
    #     # less than mss sized flow. the 1 packet is leftover sized.
    #     transmission_delay += (leftover + 2 * 40) * 8.0 / (bandwidth)
        
    # else:
    #     # 1 packet is full sized
    #     transmission_delay += (1460 + 2 * 40) * 8.0 / (bandwidth)
    else:
        transmission_delay += 1 * 1500 * 8.0 / b
        transmission_delay += 40 * 8 * 2 / b
    return transmission_delay + propagation_delay

def read_file(filename):
    output = []
    total_sent_packets = 0
    finish_time = 0
    s_time = 0
    reach_check_point = 0
    large_flow = 0
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if "queue" in line:
                continue
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
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
                orct = get_oracle_fct(src, dst, size)
                ratio = fct / orct
                if ratio < 1.0:
                    print line, orct
                assert(fct > orct)
                if flowId == 0:
                    s_time = start_time / 1000000.0
                output.append([flowId, size, start_time, end_time, ratio])
    return output, total_sent_packets, finish_time, s_time

def get_mean_fct_oct_ratio(output, segments):
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
            # if ratio > 10:
            #     print line 
            num_elements[2] += 1
        elif size < FOURTH_THRESHOLD:
            total[3].append(ratio)
            # if ratio > 30:
            #     print line 
            num_elements[3] += 1
        elif size < FIFTH_THRESHOLD:
            total[4].append(ratio)
            num_elements[4] += 1
        else:
            total[5].append(ratio)
            num_elements[5] += 1
    return total, num_elements

def output_file(output, filename):
    workload = ""
    file = open(filename, "w+")
    x = ['<1BDP', '<2BDP', '<4BDP','<8BDP', '<16BDP', "infi"]
    for i in range(len(x)):
        string = ""
        string += x[i]
        for j in algos:
            string += " " + str(output[j]['mean'][i])
            string += " " + str(output[j]['std'][i])
        string += "\n"
        file.write(string)

def read_ndp_files(trace, direc = "../../result/ndp/"):
    file = direc + "result_ndp_local_traffic.txt"
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_hpcc_files(trace, direc = "../../result/hpcc/"):
    file = direc + "result_hpcc_local_traffic.txt"
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_homa_limit_files(direc = "../../result/homa/"):
    file = direc + "result_homa_limit_load_{}.txt".format(int(bandwidth))
    output = {}
    print file
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_homa_aeolus_files(direc = "../../result/homa_aeolus/"):
    file = direc + "result_homa_500_load_{}.txt".format(int(bandwidth))
    output = {}
    print file
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_homa_unlimit_files(direc = "../../result/homa/"):
    file = direc + "result_homa_unlimit_load_{}.txt".format(int(bandwidth))
    output = {}
    with open(file) as json_file:
        output = json.load(json_file)
    return output

def read_outputs(direc, workload, trace):
    stats = {}
    input_prefix = direc + "/result_"
    num_elements = []
    for i in algos:
        stats[i] = {}
        if i == 'ndp':
            output = read_ndp_files(trace)
            stats[i]['mean'] = output[trace]["6"]['mean_flow_size']
            stats[i]['std'] = output[trace]["6"]["std"]
        elif i == 'hpcc':
            output = read_hpcc_files(trace)
            stats[i]['mean'] = output[trace]['mean_flow_size']
            stats[i]['std'] = output[trace]["std"]
        elif i == "homa_limit":
            output = read_homa_limit_files()
            stats[i]['mean'] = output[workload]["0.6"]['mean_flow_size']
            stats[i]['std'] = output[workload]["0.6"]["std"]
        elif i == "homa_aeolus":
            output = read_homa_aeolus_files()
            stats[i]['mean'] = output[trace]["0.6"]['mean_flow_size']
            stats[i]['std'] = output[trace]["0.6"]["std"]
        elif i == "homa_unlimit":
            output = read_homa_unlimit_files()
            stats[i]['mean'] = output[workload]["0.6"]['mean_flow_size']
            stats[i]['std'] = output[workload]["0.6"]["std"]
        else:
            file = input_prefix  + i +  "_" + trace + "_2_0.4_0.4" + ".txt"
            output, total_sent_packets, finish_time, start_time = read_file(file)
            total, num_elements = get_mean_fct_oct_ratio(output, 6)
            stats[i]['mean'] = [ np.mean(total[j]) for j in range(len(total))]
            stats[i]['std'] =  [ np.percentile(total[j], 99) - np.mean(total[j]) for j in range(len(total))]
    return stats, num_elements

def main():
    global bandwidth, FIRST_THRESHOLD, SECOND_THRESHOLD, THIRD_THRESHOLD, FOURTH_THRESHOLD,FIFTH_THRESHOLD
    date = str(sys.argv[1])
    workload = str(sys.argv[2])
    trace = str(sys.argv[3])
    bandwidth = float(sys.argv[4])
    b = bandwidth * 1e9
    rtt = (0.65 * 4 + 1500.0 * 8 / b * 1000000.0 * 2.5) * 2
    BDP = int(math.ceil(rtt / (1500.0 * 8 / b * 1000000.0)))
    FIRST_THRESHOLD = BDP * 1460 
    SECOND_THRESHOLD = BDP * 2 * 1460
    THIRD_THRESHOLD = BDP * 4 * 1460
    FOURTH_THRESHOLD = BDP * 8 * 1460
    FIFTH_THRESHOLD = BDP * 16 * 1460
    stats, num_elements =  read_outputs("../result/" + workload + "/" + date, workload, trace)
    # draw_graph(average, "FCT_OCT_Ratio" + "_" + workload + "_" + alg)
    # draw_graph(stats, num_elements, workload + " FCT_OCT_ratio")
    output_file(stats, "../result/{0}/{1}_{2}_{3}_slowdown_size.dat".format(workload, workload, trace, int(bandwidth)))
main()
