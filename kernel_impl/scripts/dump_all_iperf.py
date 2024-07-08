import sys

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
            # bytes = float(components[1].split(': ')[1])
            # time = float(components[2].split(': ')[1])

            avg_throughput = throughput
    return avg_throughput

def calc_cpu(file, total_cpu):
    cpu_sum = 0
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
            if(cpu % 4 == 0):
                if cpu == 60:
                    matching_cpu = usage
                    break
                if cpu / 4 > total_cpu:
                    continue
                cpu_sum += usage

    return cpu_sum, matching_cpu

def main():
    # Get command line arguments
    flows = [1, 2, 4, 6, 8, 10, 12, 15]
    dim = int(sys.argv[1])
    protocol = str(sys.argv[2])
    thpts = []
    flow_cpu_usages = []
    matching_cpu_usages = []
    # directory = str(sys.argv[1])
    # server = int(sys.argv[2])
    
    for f in flows:
        total_thpt = 0.0
        directory = "temp/{}_a2a_{}_2_0_{}/".format(protocol, dim, f)
        cpu_file_name = "cpu-server-{}.log".format(f)
        for i in range(f):
            file_name = directory + "server_{}.log".format(i)
            total_thpt += calc_thpt(file_name)
        thpts.append(total_thpt)
        flow_cpu, matching_cpu = calc_cpu(directory + cpu_file_name, i)
        flow_cpu_usages.append(flow_cpu)
        matching_cpu_usages.append(matching_cpu)
        
    print("total_throughput: ")
    for f in range(len(flows)):
        print("{} {}".format(flows[f], thpts[f]))
    
    print("cpu util: ")
    for f in range(len(flows)):
        print("{} {} {}".format(flows[f], flow_cpu_usages[f] / 100.0, matching_cpu_usages[f] / 100.0))

main()
