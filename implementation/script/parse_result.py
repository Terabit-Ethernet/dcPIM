import errno
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import os
from matplotlib import cm
import sys
import json

dst_large = {}

BDP = 20
FIRST_THRESHOLD = BDP * 1460 
SECOND_THRESHOLD = BDP * 2 * 1460
THIRD_THRESHOLD = BDP * 4 * 1460
FOURTH_THRESHOLD = BDP * 8 * 1460
FIFTH_THRESHOLD = BDP * 16 * 1460


algos = {"pim"}
def get_mean_fct_oct_ratio(output, segments):
    total = []
    for i in range(segments):
        total.append([])
    RATIO = 4
    SIZE = 1
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
    return total, num_elements

def read_pim_file(filename):
    output = []
    start = False
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if(len(params) == 0):
                continue
            if params[0] == "Signal":
                start = True
                continue
            if len(output) == 5000:
                break
            if params[0] == "Finished":
                break
            if start:
                flowId = int(params[0])
                src = int(params[1])
                dst = int(params[2])
                size = float(params[3])
                fct = float(params[4])
                orct = size * 8.0 * 1500 / 1460 / 10000000000.0 + 0.00001
                start_time = float(params[11])
                finish_time = float(params[12])
                # if size > 2000000:
                #     print fct / orct
                # ratio = float(params[8])
                # if src not in dst_large:
                #     dst_large[src] = 0
                # if fct / orct > 100.0:
                #     dst_large[src] += 1
                #     print line
#                    print flowId, size,params[1], params[2], fct, orct, fct / orct, start_time, finish_time
                # if reach_check_point < 10:
                output.append([flowId, size, fct, orct, fct / orct])
    return output

def read_pim_sim_file(filename):
    output = []
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            slowdown = float(lines[i])
            output.append(slowdown)
    return output
            # src = int(params[1])
                    # dst = int(params[2])

def read_tcp_file(filename):
    output = []
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            flowId = int(params[1])
            size = float(params[2].split(":")[1])
            fct = float(params[4])
            orct = size * 8.0 * 1500 / 1460 / 10000000000.0 + 0.00001
            if fct < orct:
                #print fct
                #print orct
                #print line
                #return
                fct = orct
            # ratio = float(params[8])
            #if fct / orct > 10.0:
             #   print flowId, size, fct / orct
            # if reach_check_point < 10:
            output.append([flowId, size, fct, orct, fct / orct])
    return output
def read_files(num_nodes, trace):
    pim_output = []
    stats = {}
    for i in range(num_nodes):
        pim_file = "../result/{}/result_{}_{}.txt".format(num_nodes, trace, i)
        output = read_pim_file(pim_file)

        # sorted_pim_file = sorted(output, key = lambda tup: tup[7])
        # f = open("pim_result/{}/result_{}_{}.old".format(pim_date, trace, i + 5), 'w+')
        # for k in sorted_pim_file:
        #     f.write(str(k))
        #     f.write('\n')
        # f.close()

        pim_output += output
    # pim_sim_output = read_pim_sim_file("pim/pim_sim.txt")

    # return pim_output, pim_sim_output, tcp_output
    total, num_elements = get_mean_fct_oct_ratio(pim_output, 6)
    stats['pim'] = {}
    stats['pim']['mean'] = [ np.mean(total[j]) for j in range(len(total))]
    stats['pim']['std'] =  [ np.percentile(total[j], 99) - np.mean(total[j]) for j in range(len(total))]

#    print stats
    # return pim_output, tcp_output
    return stats

def output_file(output, filename, format_str):
    workload = ""
    file = open(filename, "w+")
    file.write(format_str)
    x = ['<1BDP', '<2BDP', '<4BDP','<8BDP', '<16BDP', "infi"]
    for i in range(len(x)):
        string = ""
        string += x[i]
        for j in algos:
            string += " " + str(output[j]['mean'][i])
            string += " " + str(output[j]['std'][i])
        string += "\n"
        file.write(string)

def write_cdf_slowdown(pim_output, cdf_pim_mean_file, cdf_pim_99_file):

    pfile = open(cdf_pim_mean_file, "w+")
    pfile_99 = open(cdf_pim_99_file, "w+")
    # tfile = open(cdf_pim_sim_file, "w+")
    # merge_file = open("6c.csv", "w+")
    pim_slowdown = {}
    # pim_sim_slowdown = pim_sim_output
    for i in range(len(pim_output)):
        if pim_output[i][1] not in pim_slowdown:
            pim_slowdown[pim_output[i][1]] = []
        pim_slowdown[pim_output[i][1]].append(pim_output[i][2] / pim_output[i][3])
    
    # for i in range(len(pim_sim_output)):
    #     pim_sim_slowdown.append(pim_sim_output[i][0] / pim_sim_output[i][3])

    size_sorted = np.sort(pim_slowdown.keys())
    # pim_sim_slowdown_sorted = np.sort(pim_sim_slowdown)
    # pim_p = 1. * np.arange(len(pim_slowdown)) / (len(pim_slowdown) - 1)
    # # pim_sim_p = 1. * np.arange(len(pim_sim_slowdown)) / (len(pim_sim_slowdown) - 1)
    # print np.mean(np.array(pim_slowdown))
    # for i in range(len(pim_p)):
    #     if i % 100 == 0:
    #         pfile.write("{} {}\n".format(pim_slowdown_sorted[i], pim_p[i]))

    for size in size_sorted:
        pfile.write("{} {}\n".format(size, np.mean(pim_slowdown[size])))
        pfile_99.write("{} {}\n".format(size, np.percentile(pim_slowdown[size], 99)))
    # for j in range(len(pim_sim_p)):
    #     if j % 100 == 0:
    #         tfile.write("{} {}\n".format(pim_sim_slowdown_sorted[j], pim_sim_p[j]))

    # i = 0
    # j = 0
    # p_i = 0
    # p_j = 0
    # max_x = 22
    # while i < len(pim_p) and j < len(pim_sim_p):
    #     if pim_slowdown_sorted[i] < pim_sim_slowdown_sorted[j]:
            
    #         merge_file.write("{}, {}, {} \n".format(pim_slowdown_sorted[i], pim_p[i], p_j))
    #         p_i = pim_p[i]
    #         i += 50
    #     elif pim_slowdown_sorted[i]  > pim_sim_slowdown_sorted[j]:
    #         merge_file.write("{}, {}, {} \n".format(pim_sim_slowdown_sorted[j], p_i, pim_sim_p[j]))
    #         p_j = pim_sim_p[j]
    #         j += 50
    #     else :
    #         merge_file.write("{}, {}, {} \n".format(pim_slowdown_sorted[i], pim_p[i], pim_sim_p[j]))
    #         p_i = pim_p[i]
    #         i += 50
    #         p_j = pim_sim_p[j]
    #         j += 50
    # while i < len(pim_p):
    #     merge_file.write("{}, {}, {} \n".format(pim_slowdown_sorted[i], pim_p[i], p_j))
    #     i += 50
    # while j < len(pim_sim_p):
    #     merge_file.write("{}, {}, {} \n".format(pim_sim_slowdown_sorted[j], p_i, pim_sim_p[j]))
    #     j += 50

def main():
    num_nodes = int(sys.argv[1])
    trace = str(sys.argv[2])
    stats = read_files(num_nodes, trace)
    output_file(stats,  "../result/{0}_{1}_slowdown_size.dat".format(trace, num_nodes), "<FLOW_SIZE> <MEAN_SLOWDOWN> <DIFF_BETWEEN_TAIL_AND_MEAN>\n")
    # tcp_output = read_files(tcp_date, num_nodes, trace)
    # write_cdf_slowdown(pim_output, "parse_cdf_pim_{}.dat".format(trace), "parse_cdf_pim_{}_99.dat".format(trace))
    # write_cdf_slowdown(tcp_output, "parse_cdf_tcp_{}.dat".format(trace), "parse_cdf_tcp_{}_99.dat".format(trace))

# def get_cdf_fct(pim_output, tcp_output):
#     pim_

main()
