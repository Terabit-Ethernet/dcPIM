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
tokens = [1, 2, 3, 4, 5, 6, 7, 8, 9]
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4"]
#algos = ["pfabric", "phost", "ranking", "fastpass"]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
RATIO = 4

BDP = 7
FIRST_THRESHOLD = BDP * 1460 
SECOND_THRESHOLD = BDP * 2 * 1460
THIRD_THRESHOLD = BDP * 4 * 1460
FOURTH_THRESHOLD = BDP * 8 * 1460
FIFTH_THRESHOLD = BDP * 16 * 1460
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
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
                finish_time = float(params[1])
                reach_check_point += 1
            elif reach_check_point < 2:
                flowId = int(params[0])
                size = float(params[1])
                start_time = float(params[4])
                end_time = float(params[5])
                fct = float(params[6])
                orct = float(params[7])
                ratio = float(params[8])
                if flowId == 0:
                    s_time = start_time / 1000000.0
                if reach_check_point < 2:
                    output.append([flowId, size, start_time, end_time, ratio])
    print large_flow
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
    print num_elements
    return total, num_elements

def output_file(output, filename):
    workload = ""
    file = open(filename, "w+")
    x = ['<BDP', '<2BDP', '<4BDP','<8BDP', '<16BDP', "infi"]
    for i in range(len(x)):
        string = ""
        string += x[i]
        for j in tokens:
            string += " " + str(output[j]['mean'][i])
            string += " " + str(output[j]['std'][i])
        string += "\n"
        file.write(string)

def read_outputs(direc, workload):
    stats = {}
    input_prefix = direc + "/result_"
    for i in tokens:
        stats[i] = {}
        file = input_prefix  + "ranking_{}_{}.txt".format(workload, i)
        output, total_sent_packets, finish_time, start_time = read_file(file)
        total, num_elements = get_mean_fct_oct_ratio(output, 6)
        stats[i]['mean'] = [ np.mean(total[j]) for j in range(len(total))]
        stats[i]['std'] =  [ np.std(total[j]) for j in range(len(total))]
    return stats, num_elements

def draw_graph(stats,num_elements, name):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_width = 0.15                           # the width of the bars
    opacity = 0.4
    rects = []
    colors = ["purple", "red", "blue", "green", "orange"]
    error_config = {'ecolor': '0.3'}
    index = np.arange(len(stats[algos[0]]['mean']))                # the x locations for the groups
    print stats
    c_index = 0
    for alg in algos:
        # print index + bar_width / 2 + c_index * bar_width
        # print len(stats[alg]['mean'])
        # print len(stats[alg]['std'])
        # print len(index + bar_width / 2 + c_index * bar_width)
        # print alg
        ax.bar(index + bar_width / 2 + c_index * bar_width, stats[alg]['mean'], bar_width,
                    alpha=opacity, color= colors[c_index],
                    yerr= stats[alg]['std'], error_kw=error_config, label=alg)
        c_index += 1

    # axes and labels
    # ax.set_xlim(-width,len(ind)+width)

    ax.set_ylim(0,15)
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
    workload = str(sys.argv[2])
    stats, num_elements =  read_outputs("../../result/rand_min_token/" + date, workload)
    # draw_graph(average, "FCT_OCT_Ratio" + "_" + workload + "_" + alg)
    # draw_graph(stats, num_elements, workload + " FCT_OCT_ratio")
    print stats
    output_file(stats, "../gnuplot/data/{0}_rand_min_token_slowdown_size.dat".format(workload))
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
