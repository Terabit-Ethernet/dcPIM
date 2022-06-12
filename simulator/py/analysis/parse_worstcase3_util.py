#!/usr/local/bin/python
import errno
import numpy as np
import os
import sys
import json
# matplotlib.rcParams['figure.figsize'] = [3.125, 1.93]
marker = [".", "o", "x", "s", "*"]
#algos = ["ranking"]
#algos = ["p1", "p2", "p2+p3", "p2+p3+p4", "p2+p3+p4+p5"]
#algos = ["homa", "ndp", "hpcc", "pim"]
algos = ['pim']
#algos = ["phost"]
#traces = ["aditya"]
traces = ["worstcase2"]
# traces = ['aditya', 'dctcp']
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
            output.append([params[0], float(params[1]) / 14400,])
    return output

def output_file(output, filename, format_str):
    workload = ""
    file = open(filename, "w+")
    file.write(format_str)
    i = 0
    for line in output:
        string = ""
        string += line[0] + " " + str(line[1])
        string += "\n"
        file.write(string)
        i += 1
        if i > 60:
            break
     
def main():
    output =  read_file("../result/worst_case/pim_util_worstcase3.txt" )
    # draw_graph(util, trace + " Utilization")
    # draw_graph(fct_oct_ratio, trace + " Slowdown")
    # print util, fct_oct_ratio, fct_oct_ratio_99
    # output_file(util, "../gnuplot/data/{0}_util.dat".format(trace))
    output_file(output, "../result/worst_case/pim_util_worstcase3_result.txt", "<TIME> <UTILIZATION>\n")
    # output_file(fct_oct_ratio_99, "../gnuplot/data/{0}_99_slowdown.dat".format(trace))

main()
