#!/usr/local/bin/python
import errno
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import os
from matplotlib import cm
import sys
import json

algos = ["pfabric", "phost", "fastpass", "ranking"]
incasts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]

ID = 0
SIZE = 1
START_TIME = 2
END_TIME = 3
FCT = 4
ORCT = 5
RATIO = 6
SENT_PACKET = 7
DROP_PACKET = 8

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
                src = int(params[2])
                dst = int(params[3])
                start_time = float(params[4])
                end_time = float(params[5])
                fct = float(params[6])
                orct = float(params[7])
                ratio = float(params[8])
                sent_packet = float(params[9].split('/')[0])
                drop_packet = float(params[10].split('/')[0])
                if flowId == 0:
                    s_time = start_time / 1000000.0
                if reach_check_point == False:
                    output.append([flowId, size, start_time, end_time, fct, orct, ratio, sent_packet, drop_packet])
    return output
def get_mean_fct_oct_ratio(output):
    total = 0
    for line in output:
        total += line[RATIO]
    return total / float(len(output))

def get_drop_rate(output):
    total_sent = 0.0
    drop = 0.0
    for line in output:
        total_sent += line[SENT_PACKET]
        drop += line[DROP_PACKET]
    return drop / total_sent

def read_outputs(direc, repeat_time = 10000):
    input_prefix = direc + "/result_"
    util = {}
    fct_oct_ratio = {}
    drop_rate = {}
    for i in algos:
        util[i] = {}
        fct_oct_ratio[i] = {}
        drop_rate[i] = {}
        for j in incasts:
            fct_oct_ratio[i][j] = []
            drop_rate[i][j] = []
    for i in algos:
        print i
        for j in incasts:
            for k in range(1, repeat_time + 1):
                file = input_prefix  + i + "_" + str(j) + "_" + str(k) + ".txt"
                output = read_file(file)
                #util[i][j] = total_sent_packets  * 1460 * 8 / (( finish_time - start_time) * bandwidth * num_nodes)
                fct_oct_ratio[i][j].append(get_mean_fct_oct_ratio(output))
                drop_rate[i][j].append(get_drop_rate(output))

    average_fct_oct = {}
    average_drop_rate = {}
    for i in algos:
        average_fct_oct[i] = []
        average_drop_rate[i] = []
        for j in incasts:
            average_fct_oct[i].append(np.mean(fct_oct_ratio[i][j]))
            average_drop_rate[i].append(np.mean(drop_rate[i][j]))
    return average_fct_oct, average_drop_rate

def write_to_file(average_drop_rate, average_fct_oct, filename):
    f = open(filename, 'w+')
    f.write(json.dumps(average_drop_rate) + '\n')
    f.write(json.dumps(average_fct_oct) + '\n')
    f.close()
def main():
    date = str(sys.argv[1])
    trace = str(sys.argv[2])
    average_fct_oct, average_drop_rate =  read_outputs("../result/incast/" + trace + '/' + date)
    filename = "../result/incast/" + trace + '/'+ "result" + "_" + date + ".txt"
    write_to_file(average_drop_rate, average_fct_oct, filename)

main()