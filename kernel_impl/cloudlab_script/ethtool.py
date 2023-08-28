import sys
num_hosts=int(sys.argv[1])
loc = 0
for j in range(num_hosts):
    for i in range(15):
        src_port = 4000 * j + i
        dst_port = 4000 * j + i
        action = i
        command = "sudo ethtool -U ens3f0np0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
        loc = loc + 1
        print(command)

for i in range(15):
    src_port = i
    dst_port = i
    action = i
    command = "sudo ethtool -U ens3f0np0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    loc = loc + 1
    print(command)
