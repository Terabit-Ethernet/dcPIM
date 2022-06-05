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
#algos = ["ranking"]
algos = ["ranking"]
max_tokens = [10, 100, 1000, 10000]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
NUM_SENDER = 1
RATIO = 2

def read_data_file(filename):
    output_ratio = []
    output_size = []
    total_sent_packets = 0
    finish_time = 0
    s_time = 0
    reach_check_point = False
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i]
            params = line.split()

            id = int(params[ID])
            num_sender = int(params[NUM_SENDER])
            ratio = float(params[RATIO])
            output_ratio.append(ratio)
            output_size.append(num_sender)
    return output_ratio, output_size



def draw_graph_ratio(outputs):
    fig, ax = plt.subplots()
    x = [i for i in range(0, 144)]     
    print x
    for i in range(len(outputs)):
        print len(outputs[i])
        eb = plt.errorbar(x, outputs[i], marker = marker[0], alpha = 0.5, label = str(max_tokens[i]))
        # eb[-1][0].set_linestyle('--')

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)
    ax.set_yscale('log')
    ax.set_yticks([1, 2, 4, 8, 16, 32, 64, 128, 256, 512])
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

    plt.xlabel('max_tokens')
    plt.ylabel('max min fairness ratio')
    ## add a legend
    plt.show()
    plt.savefig("max_min_fairness")

def draw_graph_size(outputs):
    fig, ax = plt.subplots()
    x = [i for i in range(0, 144)]     
    print x
    for i in range(len(outputs)):
        print len(outputs[i])
        eb = plt.errorbar(x, outputs[i], marker = marker[0], alpha = 0.5, label = str(max_tokens[i]))
        # eb[-1][0].set_linestyle('--')

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)

    plt.xlabel('max_tokens')
    plt.ylabel('number of senders')
    ## add a legend
    plt.show()
    plt.savefig("num_senders")

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    outputs_ratio = []
    outputs_size = []
    for i in max_tokens:
        ratio, size = read_data_file("../../../data/scheduling_analysis/" + date + "/result_ranking_" + trace + "_" + str(i) +  ".txt")
        outputs_ratio.append(ratio)
        outputs_size.append(size)
    draw_graph_ratio(outputs_ratio)
    draw_graph_size(outputs_size)
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