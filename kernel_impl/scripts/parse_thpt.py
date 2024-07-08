import sys

def calc_thpt(file):
    throughput_sum = 0
    num_lines = 0
    # Open the file for reading
    with open(file, 'r') as file:
        start = False
        end = False
        # Loop through each line in the file
        for line in file:
            if "start connection" in line:
                start = True
                continue
            if "done!" in line:
                break
            if start == False:
                continue
            if 'Gbps' not in line: 
                continue
            # Split the line into its components
            components = line.split()

            throughput = float(components[1])
            # bytes = float(components[1].split(': ')[1])
            # time = float(components[2].split(': ')[1])

            # Calculate the throughput in bytes per second
            throughput_bytes = throughput

            # Calculate the average throughput so far
            throughput_sum += throughput_bytes
            num_lines += 1
        if num_lines == 0:
            return 0
        avg_throughput = throughput_sum / num_lines
        print(avg_throughput)
    return avg_throughput
def main():
    # Get command line arguments
    directory = str(sys.argv[1])
    server = int(sys.argv[2])
    
    total_thpt = 0.0
    for i in range(server):
        file_name = directory + "server_{}.log".format(i)
        total_thpt += calc_thpt(file_name)
    print("total_throughput: ", total_thpt)
    # Open a file for writing
    with open("temp/thpt.log", "w") as file:
    # Write output to the file
        file.write("Throughput: {} Gbps\n".format(total_thpt))

main()
