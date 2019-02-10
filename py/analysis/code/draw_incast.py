#!/usr/local/bin/python
import errno
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import os
from matplotlib import cm
import sys
import json
# matplotlib.rcParams['figure.figsize'] = [3.125, 1.93]
matplotlib.rcParams['font.family'] = 'sans serif'
matplotlib.rcParams['font.family'] = 'serif'
matplotlib.rcParams['font.serif'] = 'Times New Roman'
matplotlib.rcParams['font.size'] = 8
matplotlib.rcParams['xtick.minor.size'] = 0
matplotlib.rcParams['xtick.minor.width'] = 0
# matplotlib.rcParams['mathtext.fontset'] = u'stix'
# matplotlib.rcParams['pdf.fonttype'] = 42
# matplotlib.rcParams['ps.fonttype'] = 42

marker = [".", "o", "x", "s", "*"]
#algos = ["ranking"]
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4", "p2+p3+p4+p5"]
algos = ["pfabric","fastpass", "phost", "ranking"]
incasts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]
load = 0.8
ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5
SENT_PACKET = 6
DROP_PACKET = 7

def get_oracle_fct(flowsize, bandwidth):
    return float(flowsize) * 8.0 / bandwidth * 1000000.0 

def read_file(filename):
    with open(filename) as f:
        lines = f.readlines()
        drop_rate = json.loads(lines[0])
        fct_oct_ratio = json.loads(lines[1])
        request_complete_time = json.loads(lines[2])
        # print drop_rate, fct_oct_ratio
        return drop_rate, fct_oct_ratio, request_complete_time

def output_file(output, filename, factor = 1.0):
    workload = ""
    file = open(filename, "w+")
    for i in range(len(incasts)):
        string = ""
        string += str(incasts[i])
        for j in algos:
            string += " " + str(float(output[j][i]) * factor)
        string += "\n"
        file.write(string)
# def read_file(filename):
#     output = []
#     total_sent_packets = 0
#     finish_time = 0
#     s_time = 1.0 
#     reach_check_point = False
#     with open(filename) as f:
#         lines = f.readlines()
#         for i in range(len(lines) - 1):
#             line = lines[i]
#             params = line.split()
#             if params[0] == "##":
#                 total_sent_packets = int(params[9]) - int(params[3])
#                 finish_time = float(params[1])
#                 reach_check_point = True
#             else:
#                 flowId = int(params[0])
#                 size = float(params[1])
#                 src = int(params[2])
#                 dst = int(params[3])
#                 start_time = float(params[4])
#                 end_time = float(params[5])
#                 fct = float(params[6])
#                 orct = float(params[7])
#                 ratio = float(params[8])
#                 sent_packet = float(params[9].split('/')[0])
#                 drop_packet = float(params[10].split('/')[0])
#                 if reach_check_point == False:
#                     output.append([flowId, size, start_time, end_time, fct, orct, sent_packet, drop_packet])
#     return output, total_sent_packets, finish_time, s_time

def get_mean_fct_oct_ratio(output):
    total = 0
    for line in output:
        total += line[FCT] / line[ORCT]
    return total / float(len(output))

def get_utilization(output, end_time, bandwidth, num_nodes):
    total = 0
    for line in output:
        total += line[SIZE]

    return total * 8 / bandwidth / end_time / num_nodes

def get_drop_rate(output):
    total_sent = 0.0
    drop = 0.0
    for line in output:
        total_sent += line[SENT_PACKET]
        drop += line[DROP_PACKET]
    return drop / total_sent

def read_outputs(direc, bandwidth, num_nodes, trace):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    drop_rate = {}
    for i in algos:
        util[i] = {}
        fct_oct_ratio[i] = {}
        drop_rate[i] = {}
        for j in incasts:
            util[i][j] = 0
            fct_oct_ratio[i][j] = 0
            drop_rate[i][j] = 0

    for i in algos:
        for j in incasts:
            file = input_prefix  + i + "_" + str(j) +"_1.txt"
            output, total_sent_packets, finish_time, start_time = read_file(file)
            util[i][j] = total_sent_packets  * 1500 * 8 / (( finish_time - start_time) * bandwidth * num_nodes) / load * num_nodes
            fct_oct_ratio[i][j] = get_mean_fct_oct_ratio(output)
            drop_rate[i][j] = get_drop_rate(output)

    return util, fct_oct_ratio, drop_rate

def draw_graph(dicts, name, min = 0, max = 1.1):
    fig, ax = plt.subplots()
    i = 0
    values = {}
    for j in algos:
        values[j] = []
    for i in algos:
        for j in incasts:
            values[i].append(dicts[i][j])
    i = 0
    print dicts
    for j in algos:
        eb = plt.errorbar(incasts, values[j], marker = marker[i], label = j, alpha = 0.5)
        i += 1
        # eb[-1][0].set_linestyle('--')

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)
    ax.set_xticks(incasts)
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.set_ylim(min ,max)
    plt.xlabel('incast')
    plt.ylabel(name)
    ## add a legend
    plt.show()
    plt.savefig(name)

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    drop_rate, fct_oct_ratio, request_complete_time = read_file('../../result/incast/{}/result_{}.txt'.format(trace, date))
    output_file(drop_rate, "../gnuplot/data/incast_drop_rate.dat")
    output_file(fct_oct_ratio, "../gnuplot/data/incast_slowdown.dat")
    output_file(request_complete_time, "../gnuplot/data/incast_request_complete_time.dat", 1000)

    # util, fct_oct_ratio, drop_rate =  read_outputs("../../../data/incast/" + trace + '/' + date, 40000000000, 144 , trace)
    # draw_graph(drop_rate, trace + " " + "Incast Drop Rate", min = 0.0, max = 0.5)
    # draw_graph(fct_oct_ratio, trace + " " + "Incast FCT_OCT_ratio", min = 1, max = 10)
    # draw_graph(util, trace + " " + "Incast Utilization", min = 0.9, max = 1.1)

main()
# def draw_histogram(data):
            
#     fig, ax1 = plt.subplots()
#     ax2 = ax1.twinx()
#     ax1.set_ylim(0,0.7)
#     ax2.set_ylim(0,1.02)
#     axes = plt.gca()

# lns1 = ax1.plot(x0, y1, 'y--', label = "Maximum", alpha = 0.3)
# lns2 = ax1.plot(x0, y0, 'b', label = "Distributed Ranking", alpha = 0.2)
# lns3 = ax2.plot(x0, per, 'g--', label = "Percentage of Utilization", alpha = 0.3)
# # plt.plot(x1, y1, 'r--', label = input_file2, alpha = 0.5)
# # plt.plot(x0, y0, 'g--', label = input_file1, alpha = 0.5)
# # plt.scatter(x1,y1, c=cm.hot(np.abs(y1)), edgecolor='r')
# lns = lns1+lns2+lns3
# labs = [l.get_label() for l in lns]
# ax1.legend(lns, labs, loc='best')
# ax1.set_xlabel('time (ms)')
# ax1.set_ylabel('Utilization')
# ax2.set_ylabel('Utilization Percentage')

# plt.show()
# plt.savefig(output_file)