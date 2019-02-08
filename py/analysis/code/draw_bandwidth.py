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

algos = ["pfabric", "phost", "ranking", "fastpass"]
bandwidths = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5
RATIO = 6
load = 0.8
FIRST_THRESHOLD = 6000
SECOND_THRESHOLD = 12000
THIRD_THRESHOLD = 24000
FOURTH_THRESHOLD = 48000
FIFTH_THRESHOLD = 96000
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
            if params[0] == "##" :
                total_sent_packets = int(params[9]) - int(params[3])
                finish_time = float(params[1])
                reach_check_point = True
                break
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
                    output.append([flowId, size, start_time, end_time, fct, orct, ratio])
    return output, total_sent_packets, finish_time, s_time

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
    stats = {}
    for i in algos:
        util[i] = {}
        fct_oct_ratio[i] = {}
        for j in bandwidths:
            util[i][j] = 0
            fct_oct_ratio[i][j] = 0
            if i == 'ranking':
                stats[j] = {}
    for i in algos:
        for j in bandwidths:
            file = input_prefix  + str(i) +  "_" + trace + "_" + str(j) +".txt"
            output, total_sent_packets, finish_time, start_time = read_file(file)
            util[i][j] = total_sent_packets  * 1500 * 8 / (( finish_time - start_time) * j * 1000000000 * num_nodes) / load
            fct_oct_ratio[i][j] = get_mean_fct_oct_ratio(output)
            if i == "ranking":
                total, num_elements = get_mean_fct_oct_ratio_by_size(output, 6)
                stats[j]['median'] = [ np.median(total[k]) for k in range(len(total))]
                stats[j]['std'] =  [ np.std(total[k]) for k in range(len(total))]
    return util, fct_oct_ratio, stats, num_elements

def draw_bar_graph(stats,num_elements, name):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_width = 0.08                            # the width of the bars
    opacity = 0.4
    rects = []
    error_config = {'ecolor': '0.3'}
    index = np.arange(len(stats[bandwidths[0]]['median']))                # the x locations for the groups
    c_index = 0
    for bandwidth in bandwidths:
        # print index + bar_width / 2 + c_index * bar_width
        # print len(stats[alg]['median'])
        # print len(stats[alg]['std'])
        # print len(index + bar_width / 2 + c_index * bar_width)
        # print alg
        ax.bar(index + bar_width / 2 + c_index * bar_width, stats[bandwidth]['median'], bar_width,
                    alpha=opacity,
                    yerr= stats[bandwidth]['std'], error_kw=error_config, label=bandwidth)
        c_index += 1

    # axes and labels
    # ax.set_xlim(-width,len(ind)+width)

    ax.set_ylim(0,12)
    ax.set_xlabel("kB")
    ax.set_ylabel(name)
    xTickMarks = ['<6', '<12', '<24','<48', '<96', "infi"]
    ax.set_xticks(index + bar_width * 3)
    xtickNames = ax.set_xticklabels(xTickMarks)
    plt.setp(xtickNames, rotation=0, fontsize=10)

    for i in range(len(index)):
        ax.text(i + 0.5, 60, num_elements[i], 
          horizontalalignment='center', verticalalignment='center', fontsize = 13)
    ax.legend()

    ## add a legend
    plt.show()
    plt.savefig(name)

def draw_graph(dicts, name):
    fig, ax = plt.subplots()

    values = {}
    print dicts
    for j in algos:
        values[j] = []
    for i in algos:
        for j in bandwidths:
            values[i].append(dicts[i][j])
    i = 0
    for j in algos:
        eb = plt.errorbar(bandwidths, values[j], marker = marker[i], label = j, alpha = 0.5)
        # eb[-1][0].set_linestyle('--')

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)
    # ax.set_xticks([0.5, 2, 4, 9, 18, 36])
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

    plt.xlabel('bandwidths (Gbps)')
    plt.ylabel(name)
    ## add a legend
    plt.show()
    plt.savefig(name)

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    util, fct_oct_ratio, stats, num_elements =  read_outputs("../../../data/bandwidth/" + date, "", 99999, 40000000000, 144, trace)
    draw_graph(util, trace + " bandwidth Utilization")
    draw_graph(fct_oct_ratio,  trace + " bandwidth FCT_OCT_ratio")
    draw_bar_graph(stats, num_elements, trace + " bar chart for Slowdown")

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