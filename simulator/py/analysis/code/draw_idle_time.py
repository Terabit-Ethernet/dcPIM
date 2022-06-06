#!/usr/local/bin/python
import errno
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import os
from matplotlib import cm
import sys

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

algos = ["ranking"]
idle_time = [0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5]
unit = 2.4
load = 0.8
#tokens = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5

set_dst = {}
def read_file(filename):
    output = []
    total_sent_packets = 0
    finish_time = 0
    s_time = 0
    reach_check_point = False

    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
                finish_time = float(params[1])
                reach_check_point = True
            else:
                flowId = int(params[0])
                size = float(params[1])
                start_time = float(params[4])
                end_time = float(params[5])
                fct = float(params[6])
                orct = float(params[7])
                ratio = float(params[8])
                if flowId == 0:
                    s_time = start_time / 1000000.0
                if reach_check_point == False:
                    output.append([flowId, size, start_time, end_time, fct, orct])
    return output, total_sent_packets, finish_time, s_time

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

def read_outputs(direc, matric, lastFlowID, bandwidth, num_nodes, trace):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    for i in algos:
        util[i] = {}
        fct_oct_ratio[i] = {}
        for j in idle_time:
            util[i][j] = 0
            fct_oct_ratio[i][j] = 0
    for i in algos:
        for j in idle_time:
            file = input_prefix  + i +  "_" + trace + "_" + str(j) +".txt"
            output, total_sent_packets, finish_time, start_time = read_file(file)
            util[i][j] = total_sent_packets  * 1460 * 8 / (( finish_time - start_time) * bandwidth * num_nodes) / load
            fct_oct_ratio[i][j] = get_mean_fct_oct_ratio(output)
    return util, fct_oct_ratio

def draw_graph(dicts, name):
    fig, ax = plt.subplots()

    values = {}
    for j in algos:
        values[j] = []
    for i in algos:
        for j in idle_time:
            values[i].append(dicts[i][j])
    i = 0
    for j in algos:
        eb = plt.errorbar(np.array(idle_time), values[j], marker = marker[0], label = j, alpha = 0.5)
        # eb[-1][0].set_linestyle('--')
    print values

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)
    ax.set_xticks(np.array(idle_time))
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

    plt.xlabel('idle time (BDP Transimission Time)')
    plt.ylabel(name)
    ## add a legend
    plt.show()
    plt.savefig(name)

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    util, fct_oct_ratio =  read_outputs("../../../data/idle_time/" + date, "", 99999, 40000000000, 144, trace)
    draw_graph(util, trace + " Idle Time Utilization")
    draw_graph(fct_oct_ratio,  trace + " Idle Time FCT_OCT_ratio")
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