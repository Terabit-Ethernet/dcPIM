import sys
num_hosts=int(sys.argv[1])
host_index = int(sys.argv[2])
loc = 0
for j in range(num_hosts):
    for i in range(16):
        src_port = 4000 * (host_index) + (j + 1) * 256 + i
        dst_port = 4000 * (host_index) + (j + 1) * 256 + i
        action = i % (3) + j * 3 
        command = "sudo ethtool -U ens2f0np0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
        loc = loc + 1
        print(command)

for j in range(num_hosts):
    for i in range(16):
        src_port = 4000 * (j + 1) + (host_index) * 256 + i
        dst_port = 4000 * (j + 1) + (host_index) * 256 + i
        action =  i % (3) + (j + num_hosts) * 3
        command = "sudo ethtool -U ens2f0np0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
        loc = loc + 1
        print(command)


for i in range(16):
    src_port = i
    dst_port = i
    action = i
    command = "sudo ethtool -U ens2f0np0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    loc = loc + 1
    print(command)
