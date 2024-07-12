# Cloudlab experiments

## Config experiments

Experiments use 8 servers in r650 clusters in Cloudlab.
1. Using this [profile](https://www.cloudlab.us/p/dcPIM/dcPIM-100Gbps) to instantiate experiments. Please specify the number of nodes to 8 and the physical node type to r650.
2. Run:
   ```
   cd local_scripts/
   ```
3. On your local machine, change the `env.sh` file to set the correct username and server addresses. Four addresses should be in the server array, and the remaining four should be in the client array.
4. Run run_config.sh,
```
  ./run_config.sh
```

## Run experiments

On your local machine, under `/local_scripts` folder:

1. Run permutation workloads where four servers serve as senders and the other four servers serve as receivers; each sender will send data to only one receiver.

Run dcPIM,
```
./run_exp.sh dcpim 0 permutation
```

Run TCP,
```
./run_exp.sh tcp 1 permutation
```

Results will be printed out as the standard output.

2. Run all-to-all workloads where four servers serve as senders and the other four servers serve as receivers; each sender will send data to all four receivers.

Run dcPIM,
```
./run_exp.sh dcpim 0 a2a
```

Run TCP,
```
./run_exp.sh tcp 1 a2a
```

3. Run real all-to-all workloads where 8 server serves as senders and receivers; each server will send/receive data to/from other servers.
Each server will use 3 CPU cores to send data and another 3 CPU cores to receive data to/from one host. In total, each server will use 3 * 8 * 2 = 48 cores.

Run dcPIM,
```
./run_exp_sep.sh dcpim 0 a2a_real
```

Run TCP,
```
./run_exp_sep.sh tcp 1 a2a_real
```

## Note

clnode281 and clnode265 have some hardware configuration issues, leading to performance degradation. Try to avoid using them if you can.
