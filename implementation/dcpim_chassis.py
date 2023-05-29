"""
Reserve an entire chassis worth of m510 machines.
"""

import geni.portal as portal
import geni.rspec.pg as RSpec
import geni.urn as urn
import geni.aggregate.cloudlab as cloudlab

pc = portal.Context()

# images = [ ("UBUNTU16-64-STD", "Ubuntu 16.04") ]

types  = [ ("m510", "m510 (Intel Xeon-D)")]

chassis = range(1,13+1)

# pc.defineParameter("image", "Disk Image",
#                   portal.ParameterType.IMAGE, images[0], images)

pc.defineParameter("type", "Node Type",
                   portal.ParameterType.NODETYPE, types[0], types)

pc.defineParameter("chassis", "Which chassis to request",
                   portal.ParameterType.INTEGER,1,chassis)

pc.defineParameter("skip", "Comma-separated list of nodes to skip",
                   portal.ParameterType.STRING,"")

params = pc.bindParameters()

rspec = RSpec.Request()

lan = RSpec.LAN()
rspec.addResource(lan)

skiplist = ["ms%02d%02d" % (params.chassis, int(x)) for x in params.skip.split(",") if x]

nodes_per_chassis = 45
num_nodes = nodes_per_chassis - len(skiplist)

rc_aliases = ["rcmaster", "rcnfs"]
for i in range(num_nodes - 2):
    rc_aliases.append("rc%02d" % (i + 1))

n = 0
for i in range(nodes_per_chassis):
    name = "ms%02d%02d" % (params.chassis, i + 1)

    if name in skiplist:
        continue

    rc_alias = rc_aliases[n]
    node = RSpec.RawPC(rc_alias)
    n = n + 1

    if rc_alias == "rcnfs":
        # Ask for a 150GB file system mounted at /shome on rcnfs
        bs = node.Blockstore("bs", "/shome")
        bs.size = "150GB"

    node.hardware_type = params.type
    node.disk_image =  'urn:publicid:IDN+utah.cloudlab.us+image+dcpim-PG0:dcpim-m510'
    node.component_id = urn.Node(cloudlab.Utah, name)

    # node.addService(RSpec.Execute(
    #         shell="sh", command="sudo /local/repository/startup.sh"))

    rspec.addResource(node)

    iface = node.addInterface("eth0")
    lan.addInterface(iface)

pc.printRequestRSpec(rspec)
