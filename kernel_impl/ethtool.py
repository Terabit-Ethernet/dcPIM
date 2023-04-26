for i in range(15):
    src_port = 10000 + i
    dst_port = 10000 + i
    action = i
    loc = i
#    command = "sudo ethtool -U ens2f0 flow-type tcp4 src-ip 192.168.10.125 dst-ip 192.168.10.124 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    command = "sudo ethtool -U ens2f0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    print(command)

for i in range(15):
    src_port = i
    dst_port = i
    action = i
    loc = i + 15
#    command = "sudo ethtool -U ens2f0 flow-type tcp4 src-ip 192.168.10.125 dst-ip 192.168.10.124 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    command = "sudo ethtool -U ens2f0 flow-type tcp4 src-port {} dst-port {} action {} loc {}".format(src_port, dst_port, action, loc)
    print(command)
