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
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4", "p2+p3+p4+p5"]
algos = ["pfabric", "fastpass", "phost", "ranking"]
traces = ["aditya", "dctcp", "datamining"]
#traces = ['aditya', 'dctcp']
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]
load = 0.8

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5

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
                fct = float(params[6])
                orct = float(params[7])
                ratio = float(params[8])
                if reach_check_point < 10:
                    output.append([flowId, size, start_time, end_time, fct, orct])
    return output, total_sent_packets,total_packets, finish_time, s_time

def output_file(output, filename):
    workload = ""
    file = open(filename, "w+")
    for i in traces:
        string = ""
        if i == "aditya":
            workload = "IMC10"
        elif i == "dctcp":
            workload = "\"Web Search\""
        elif i == "datamining":
            workload = "\"Data Mining \""
        elif i == "constant":
            workload = "Constant"
        else:
            workload = i
        string += workload
        for j in algos:
            string += " " + str(output[i][j])
        string += "\n"
        file.write(string)
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

def read_outputs(direc):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    for k in traces:
        util[k] = {}
        fct_oct_ratio[k] = {}
        for i in algos:
            util[k][i] = 0
            fct_oct_ratio[k][i] = 0

    for k in traces:
        for i in algos:
            file = input_prefix  + i +  "_" + k + ".txt"
            output, total_sent_packets, total_packets, finish_time, start_time = read_file(file)
            util[k][i] = total_sent_packets  / float(total_packets)
            fct_oct_ratio[k][i] = get_mean_fct_oct_ratio(output)
    return util, fct_oct_ratio

# def draw_graph(dicts, name):
#     fig, ax = plt.subplots()

#     values = {}
#     for j in algos:
#         values[j] = []
#     for i in algos:
#         for j in incasts:
#             values[i].append(dicts[i][j])
#     i = 0
#     print values
#     for j in algos:
#         eb = plt.errorbar(incasts, values[j], marker = marker[0], label = j, alpha = 0.5)
#         # eb[-1][0].set_linestyle('--')

#     ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)
#     ax.set_xscale('log')
#     ax.set_xticks([1, 2, 4, 9, 18, 36, 72, 143])
#     ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

#     plt.xlabel('incast')
#     plt.ylabel(name)
#     ## add a legend
#     plt.show()
#     plt.savefig(name)

def draw_graph(dicts, name):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ind = np.arange(len(traces))                # the x locations for the groups
    width = 0.15                                # the width of the bars
    rects = []
    values = {}
    colors = ["salmon", "khaki", "lightskyblue", "lightgreen", "yellow"]
    for j in algos:
        values[j] = []
    for i in traces:
        for j in algos:
            values[j].append(dicts[i][j])
    i = 0
    for j in algos:
        rects.append(ax.bar(ind, values[j], width,
                    color= colors[i], alpha = 0.4))
        ind = ind + width
        i += 1
    print values
    # axes and labels
    ax.set_xlim(-width,len(ind)+width)
    # ax.set_ylim(0,45)
    ax.set_ylabel(name)
    xTickMarks = ['IMC10', 'Web Search', 'Data Mining']
    ind = np.arange(len(traces))                # the x locations for the groups

    ax.set_xticks(ind + 1.5 * width)
    xtickNames = ax.set_xticklabels(xTickMarks)
    plt.setp(xtickNames, rotation=0, fontsize=10)

    ## add a legend
    ax.legend( (rects[0][0], rects[1][0], rects[2][0], rects[3][0]), (algos[0], algos[1], algos[2], algos[3]) )

    plt.show()
    plt.savefig(name)
def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    util, fct_oct_ratio =  read_outputs("../../result/" + trace + '/' + date)
    # draw_graph(util, trace + " Utilization")
    # draw_graph(fct_oct_ratio, trace + " Slowdown")
    print util, fct_oct_ratio
    output_file(util, "../gnuplot/data/{0}_util.dat".format(trace))
    output_file(fct_oct_ratio, "../gnuplot/data/{0}_slowdown.dat".format(trace))

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
