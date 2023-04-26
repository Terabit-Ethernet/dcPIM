# dcPIM
Datacenter Parallel Iterative Matching (dcPIM) is a transport design that realizes the classical Parallel Iterative Matching (PIM) protocol 
from switch scheduling literature on datacenter networks without using any specialized hardware. Our key technical result is an extension of 
PIM’s theoretical analysis to the datacenter context. dcPIM design builds upon insights gained from this analysis, by extending PIM to overcome 
the unique challenges introduced by datacenter environments (much larger scales and round trip times). Using theoretical analysis and evaluation, 
we show that dcPIM maintains near-optimal latency of state-of-the-art data center transport designs, sustains 6 − 10% higher loads on evaluated workloads,
and guarantees near-optimal network utilization.

## Repository overview

- `implementation/` includes the DPDK implementation of dcPIM.
- `simulator/` includes the simulator of dcPIM.
- `kernel_impl/` includes the kernel implementation of dcPIM (ongoing).
README in each sub repository contains instructions for running implementation/simulation experiments and reproducing our SIGCOMM results. 
