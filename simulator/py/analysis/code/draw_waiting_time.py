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
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4"]
#incast_ratio = [1, 2, 4, 9, 18, 36, 72, 143]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
RATIO = 4

FIRST_THRESHOLD = 6000
SECOND_THRESHOLD = 12000
THIRD_THRESHOLD = 24000
FOURTH_THRESHOLD = 48000
FIFTH_THRESHOLD = 96000
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
                waiting_time = float(params[11]) / orct
                if flowId == 0:
                    s_time = start_time / 1000000.0
                if reach_check_point == False:
                    output.append([flowId, size, start_time, end_time, waiting_time])
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

def read_outputs(direc, matric, lastFlowID, bandwidth, num_nodes, trace):
    stats = {}
    input_prefix = direc + "/result_"
    for i in algos:
        stats[i] = {}
        file = input_prefix  + str(i) +  "_" + trace + "_" + str(30) +".txt"
        output, total_sent_packets, finish_time, start_time = read_file(file)
        total, num_elements = get_mean_fct_oct_ratio(output, 6)
        stats[i]['median'] = [ np.median(total[j]) for j in range(len(total))]
        stats[i]['std'] =  [ np.std(total[j]) for j in range(len(total))]
    return stats, num_elements

def draw_graph(stats,num_elements, name):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_width = 0.1                           # the width of the bars
    opacity = 0.4
    rects = []
    colors = ["purple", "red", "blue", "green", "orange", "yellow"]
    error_config = {'ecolor': '0.3'}
    index = np.arange(len(stats[algos[0]]['median']))                # the x locations for the groups
    print stats
    c_index = 0
    for i in algos:
        # print index + bar_width / 2 + c_index * bar_width
        # print len(stats[alg]['median'])
        # print len(stats[alg]['std'])
        # print len(index + bar_width / 2 + c_index * bar_width)
        # print alg
        ax.bar(index + bar_width / 2 + c_index * bar_width, stats[i]['median'], bar_width,
                    alpha=opacity, 
                    yerr= stats[i]['std'], error_kw=error_config, label=i)
        c_index += 1

    # axes and labels
    # ax.set_xlim(-width,len(ind)+width)

    ax.set_ylim(0,100)
    ax.set_xlabel("kB")
    ax.set_ylabel(name)
    xTickMarks = ['<6', '<12', '<24','<48', '<96', "infi"]
    ax.set_xticks(index + bar_width * 2)
    xtickNames = ax.set_xticklabels(xTickMarks)
    plt.setp(xtickNames, rotation=0, fontsize=10)

    for i in range(len(index)):
        ax.text(i + 0.5, 60, num_elements[i], 
          horizontalalignment='center', verticalalignment='center', fontsize = 13)
    ax.legend()

    ## add a legend
    plt.show()
    plt.savefig(name)

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    stats, num_elements =  read_outputs("../../../data/max_token/" + date, "", 99999, 40000000000, 144,trace)
    # draw_graph(average, "FCT_OCT_Ratio" + "_" + trace + "_" + alg)
    draw_graph(stats, num_elements, trace + " waiting_time")
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