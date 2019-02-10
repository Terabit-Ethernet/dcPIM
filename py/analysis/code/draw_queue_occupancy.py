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
tokens = [10]
epochs = [5, 6]
# traces = ['aditya', 'dctcp', 'datamining']
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
RATIO = 6
FIRST_THRESHOLD = 6000
SECOND_THRESHOLD = 12000
THIRD_THRESHOLD = 24000
FOURTH_THRESHOLD = 48000
FIFTH_THRESHOLD = 96000

set_dst = {}
def read_file(filename):
    output = []
    total_sent_packets = 0
    total_pkt = 0
    finish_time = 0
    s_time = 1.0
    reach_check_point = 0

    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if params[0] == "##":
                continue
            else:
                time = str(params[0])
                queue = str(params[1])
                output.append([time, queue])
    return output

def output_file(outputs, filename):
    string = ''
    file = open(filename, "w+")
    max_size = 0
    for i in outputs:
        if len(outputs[i]) > max_size:
            max_size = len(outputs[i])
    for i in range(0, max_size):
        default_time = ""
        for j in epochs:
            if len(outputs[j]) > i:
                default_time = str(outputs[j][i][0])
        for j in epochs:
            if len(outputs[j]) > i:
                string += outputs[j][i][0] + " " + outputs[j][i][1] + " "
            else:
                string += default_time + " " + "0" + " "
        string += '\n'
    file.write(string)


def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    outputs = {}
    for e in epochs:
        for t in tokens:
            output =  read_file("../../result/debug_queue/" + date + '/result_ranking_{}_{}_{}.txt'.format(trace, t, e))
            outputs[e] = output
    output_file(outputs, "../gnuplot/data/{0}_queue_occupancy.dat".format(trace))

    # draw_graph(util, trace + " Max Token Utilization")
    # draw_graph(fct_oct_ratio,  trace + " Max Token FCT_OCT_ratio")
    # draw_bar_graph(stats, num_elements, trace + " bar chart for Slowdown")
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
