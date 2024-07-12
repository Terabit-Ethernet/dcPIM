import sys
import os
from statistics import mean, median
def calc_thpt(file):
    throughput_sum = 0
    num_lines = 0
    avg_throughput = 0
    # Open the file for reading
    with open(file, 'r') as file:
        start = False
        end = False
        # Loop through each line in the file
        for line in file:
            if "sec" not in line:
                continue
            # Split the line into its components
            components = line.split()

            throughput = float(components[6])
            if "Mbits" in line:
                throughput /= 1000.0
            # bytes = float(components[1].split(': ')[1])
            # time = float(components[2].split(': ')[1])

            avg_throughput = throughput
    
    return avg_throughput

def calc_cpu(file, total_cpu):
    server_cpu_sum = 0
    client_cpu_sum = 0
    matching_cpu = 0
    num_lines = 0
    # Open the file for reading
    with open(file, 'r') as file:
        start = False
        end = False
        # Loop through each line in the file
        for line in file:
            if "CPU" in line:
                continue
            if "Average" not in line:
                continue
            if "all" in line:
                continue
            # Split the line into its components
            components = line.split()
            if(len(components) < 7):
                continue
            cpu = int(components[1])
            usage = float(components[4])
            if(cpu % 2 == 1):
                if cpu == 7:
                    matching_cpu = usage
                    # break
                # if cpu % 2 > total_cpu:
                #     continue
                if cpu <= 48: 
                    server_cpu_sum += usage
                else:
                    client_cpu_sum += usage

    return client_cpu_sum, server_cpu_sum, matching_cpu

def main():
    # Get command line arguments
    # flows = [1, 4,  15]
    dire = str(sys.argv[1])
    flows = int(sys.argv[2])
    num_hosts = int(sys.argv[3])
    # protocol = str(sys.argv[3])
    thpts = []
    client_cpu_usages = []
    server_cpu_usages = []
    matching_cpu_usages = []
    client_cpu = 0
    server_cpu = 0
    matching_cpu = 0
    # directory = str(sys.argv[1])
    # server = int(sys.argv[2])

    total_thpt = 0.0    
    directory = "{}/{}/{}/".format(dire, num_hosts, flows)
    cpu_file_name = "cpu.log"
    client_cpu_arr = []
    server_cpu_arr = []
    matching_cpu_arr = []
    thpt_arr = []
    for h in range(num_hosts):
        total_thpt = 0
        directory2 = directory + "{}/".format(h)
#        if h == 1 or h == 5:
#            continue
        for file in os.listdir(directory2):
             filename = os.fsdecode(file)
             # print(filename)
             if filename.startswith("server_"): 
                total_thpt += calc_thpt(directory2+ filename)
             if filename.startswith("cpu"):
                client_cpu, server_cpu, matching_cpu = calc_cpu(directory2 + filename, flows)
                client_cpu_arr.append(client_cpu)
                server_cpu_arr.append(server_cpu)
                matching_cpu_arr.append(matching_cpu)
        thpt_arr.append(total_thpt)
    print(thpt_arr)
    print(flows, min(thpt_arr), mean(thpt_arr), max(thpt_arr), min(client_cpu_arr)/ 100.0, mean(client_cpu_arr) / 100.0, max(client_cpu_arr) / 100.0,
      min(server_cpu_arr)/ 100.0, mean(server_cpu_arr) / 100.0, max(server_cpu_arr) / 100.0, min(matching_cpu_arr) / 100.0, mean(matching_cpu_arr) / 100.0, max(matching_cpu_arr) / 100.0)
        # thpts.append(total_thpt)
        # flow_cpu_usages.append(flow_cpu)
        # matching_cpu_usages.append(matching_cpu)
            # for f in range(len(flows)):
    # print("{} {}".format(flows[f], thpts[f]))
    # for f in range(len(flows)):
        # print("{} {} {}".format(flows[f], flow_cpu_usages[f] / 100.0, matching_cpu_usages[f] / 100.0))

main()
