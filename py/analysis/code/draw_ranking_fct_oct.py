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
algos = ["pfabric", "phost", "random", "ranking", "fastpass"]
incasts = [1, 2, 4, 9, 18, 36, 72, 143]
# input_file1 = sys.argv[1]
# output_file = sys.argv[2]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5

def read_data_file(filename):
    output = {}
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
                dst = int(params[3])
                ratio = float(params[8])
                if reach_check_point == False:
                    if dst not in output:
                        output[dst] = []
                    output[dst].append(ratio)
    return output

def read_ranking_file(filename = 'ranking.txt'):
    ranking = []
    with open(filename) as f:
        lines = f.readlines()
        for line in lines:
            ranking.append(int(line))
    return ranking

def get_mean_fct_oct_ratio(output):
    average = []
    for i in range(144):
        average.append(np.sum(output[i]) / float(len(output[i])))
    return average

def draw_graph(average, ranking):
    fig, ax = plt.subplots()
     
    average = [x for _, x in sorted(zip(ranking,average), key=lambda pair: pair[0])]
    ranking = [x for x, _ in sorted(zip(ranking,average), key=lambda pair: pair[0])]
    print ranking


    eb = plt.errorbar(ranking, average, marker = marker[0], alpha = 0.5)
        # eb[-1][0].set_linestyle('--')

    ax.legend(fancybox=False, shadow=False, frameon=False, loc = 1)

    plt.xlabel('ranking')
    plt.ylabel('fct/oct ratio')
    ## add a legend
    plt.show()
    plt.savefig("ranking_fct_oct")

def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    output = read_data_file("../../../data/incast/" + date + "/result_ranking_" + trace + "_2.txt")
    ranking = read_ranking_file()
    average = get_mean_fct_oct_ratio(output)
    draw_graph(average, ranking)
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