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
    local_load = {}
    remote_load = {}
    with open(filename) as f:
        lines = f.readlines()
        for i in range(len(lines) - 1):
            line = lines[i]
            params = line.split()
            if params[0] == "##":
                total_sent_packets = int(params[9]) - int(params[3])
                total_packets = int(params[9])
                finish_time = float(params[1])
                reach_check_point += 1
            elif reach_check_point < 10:
                flowId = int(params[0])
                size = float(params[1])
                src = int(params[2])
                dst = int(params[3])
                start_time = float(params[4])
                if src / 64 == dst / 64:
                    if src not in local_load:
                        local_load[src] = size
                    else:
                        local_load[src] += size

                else:
                    if src not in remote_load:
                        remote_load[src] = size
                    else:
                        remote_load[src] += size


        total = 10000000000.0 / 8 * (start_time / 1000000.0 - 1.00)
        for i in range(720):
            print i, "local: ", local_load[i] / total
            print i, "remote: ", remote_load[i] / total

read_file("debug")
