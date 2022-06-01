# dcPIM Simulator

Datacenter Parallel Iterative Matching (dcPIM) is a transport design that realizes the classical Parallel Iterative Matching (PIM) protocol from switch scheduling literature on datacenter networks without using any specialized hardware. Our key technical result is an extension of PIM’s theoretical analysis to the datacenter context. dcPIM design builds upon insights gained from this analysis, by extending PIM to overcome the unique challenges introduced by datacenter environments (much larger scales and round trip times). Using theoretical analysis and evaluation, we show that dcPIM maintains near-optimal latency of state-of-the-art data center transport designs, sustains 6 − 10% higher loads on evaluated workloads, and guarantees near-optimal network utilization.

## 1. Overview
### Repository overview
The simulator is built upon pHost simulator.
- `coresim/` includes the main event loop and the default class of events, topology, queues, flows and packets.
- `ext/` includes protocols, including dcPIM, pHost, pFabric and Fastpass.
- `run/` includes experiment setup, flow generation and parameteres read/write.
- `py/` includes scripts for running SIGCOMM 2022 artifact evaluation.

### Getting Started Guide
Through the following three sections, we provide getting started instructions to install NetChannel and to run experiments.

   - **Compile Simulator (2 compute-mins):**  
This section covers how to compile the simulator.
   - **SIGCOMM 2022 Artifact Evaluation (6 days):**  
This section provides the detailed instructions to reproduce all individual results of dcPIM presented in our SIGCOMM 2022 paper.


## 2. Compile the Simulator
```
aclocal
automake --add-missing
autoconf
./configure 
make
mkdir py/result
```

## 3. SIGCOMM 2021 Artifact Evaluation

###  Run Simulation Results

Running different workloads takes different amount of time. Here is the estimation of running time for each workload:
```
IMC10 (aditya):   ~20 mins
Web Search: 4 hours
Datamining: ~17 hours
```
After running scripts, simulators will be run in background.
Several tips for running experiments:
 First, making sure the total number of simulator processes <= total number of CPU cores. 
 Second, running too many datamining experiments in parallel may use too much memory.
 For example, if the server has 12GB memory, we recommend having at most 8 datamining experiments.

1. Reproduce Figure 3 results (Evaulation results for the default setup) (Running time: ~17 hours)

   ```
   cd py/load_100Gbps/
   ./run.sh
   ```
   The logs are stored in directory `py/result/load/5.15/`.

2. Reproduce Figure 4 results (Microscopic view into dcPIM performance) (Running time: ~30 mins)

   ```
   cd py/worst_case/
   ./run.sh
   ```
   The logs are stored in directory `py/result/worst_case/5.15/`.

3. Reproduce Figure 5 results (Oversubscribed topology and Fat-Tree topology) (Running time: 17 hours + 31 hours)

   To run workloads on oversubscribed topology,
   
   ```
   cd py/oversubscribe/
   ./run.sh
   ```
   run.py will run IMC10, Web Search and Datamining workloads one by one. The logs are stored in directory `py/result/oversubscribe/5.15/`.

   To run workoloads on Fat-Tree topology,
   ```
   cd py/fat_tree/
   ./run.sh
   ```
   The logs are stored in directory `py/result/fat_tree/5.15/`.

4. Reproduce Figure 6 results (dcPIM Sensitivity Analysis) (running time: 1 hours)

   For 6a and 6b, the maximum sustained loads for each (r, k) are:

   ```
   r\k  1  2  4  8
   1.0 54 56 56 56
   2.0 74 76 78 78
   3.0 76 80 82 84
   4.0 74 80 82 84
   5.0 72 78 82 84
   ```
 
   To get results for figure 6a and 6b (Max sustained load and mean slowdown for different (r, k)), run:
 
   ```
   cd py/pim_k_iterations
   ./run.sh
   ```
  
   The logs are stored in directory `py/result/pim_k_iterations/5.15/`.
   To get results for 6c (the effect of beta), run:
  
   ```
   cd py/pim_beta
   ./run.sh
   ```
  
   The logs are stored in directory `py/result/pim_beta/5.15/`.


5. Reproduce Figure 8 results (Bursty workload) (running time: ~17 hours)

   ```
   cd py/bursty_workload/
   ./run.sh
   ```
   
   The logs are stored in directory `py/result/bursty/5.15/`.

   
### Parse simulation results

All parsing scripts are located at `py/analysis`. And the parsing results are located at `py/result/path/to/result`.

   ```
   cd py/analysis
   ```
1. Parse Figure 3 results (Evaulation results for the default setup).

   Parse results of network utilization and mean slowdown (Figure 3a and 3b).
  
   ```
   python parse_load.py 5.15 imc10 100
   python parse_slowdown.py 5.15 100
   ```
   
   For Figure 3a, the result is at: `py/result/load/imc10_load_util.dat`. The format of files are `<LOAD> <UTIL>`. For Figure 3b, the results are located at `py/result/load/mean_slowdown.dat`; the mean slowdown when the load is 0.6, is corresponding to the second row in the `$WORKLOAD_load_slowdown.dat`. 
   
   Parse results of slowdown versus flow size(Figure 3c, 3d, 3e) with the IMC10 workload.
   
   ```
   python parse_fct_oct_flowsize.py 5.15 all-to-all imc10 100
   python parse_fct_oct_flowsize.py 5.15 all-to-all websearch 100
   python parse_fct_oct_flowsize.py 5.15 all-to-all datamining 100

   ```
   
   The corresponding file is at `py/result/load/$WORKLOAD_load_slowdown.dat`. The format of the file is `<FLOW_SIZE> <MEAN_SLOWDOWN> <DIFF_BETWEEN_TAIL_AND_MEAN>`.
   
2. Parse Figure 4 results (Microscopic view into dcPIM performance)

   The result of Figure 4a is located at `py/result/worst_case/pim_util_worstcase1.txt`. The format of file is  `<TIME> <Throughput>`. The network utilization is `THROUGHPUT / 1600`.
   
   Parse results for Figure 4b.
   
   ```
   python parse_worstcast_slowdown.py 5.15 worstcase2
   ```
   
   The file is located at `py/result/worst_case/worstcase2_slowdown.txt`.
   
   The result of Figure 4c is located at `py/result/worst_case/pim_util_worstcase3.txt`. The format of file is  `<TIME> <Throughput>`. The network utilization is `THROUGHPUT / 14400`. 
   
3. Parse Figure 5 results (Oversubscribed topology and Fat-Tree topology)

   Parse results of mean slowdown in the oversubscribed topology (Figure 5a)
   
   ```
   python parse_oversubscribe.py 5.15 oversubscribe 100
   ```

   The file is located at `py/result/oversubscribed/oversubscribe_slowdown.dat`.

   Parse results of slowdown versus flow size in oversubscribed topology with IMC10 workload (Figure 5b).
   
   ```
   python parse_fct_oct_flowsize_os.py 5.15 oversubscribe imc10 100
   ```
   
   The file is located at `py/result/oversubscribed/oversubscribe_imc10_100_slowdown_size.dat`.

   Parse results of mean slowdown in the Fat-tree topology (Figure 5c)
   
   ```
   python parse_fat_tree.py 5.15
   ```

   The file is located at `py/result/fat_tree/fat_tree_slowdown.dat`.
   
   Parse results of slowdown versus flow size in Fat-tree topology with IMC10 workload (Figure 5d).
   
   ```
   python parse_fct_oct_flowsize_fat.py 5.15 fat_tree imc10 100
   ```
     
   The file is located at `py/result/fat_tree/fat_tree_aditya_100_slowdown_size.dat`.

   
 4. Parse Figure 6 results (dcPIM Sensitivity Analysis)
 
    Parse results of maximum sustained load (r,k) and mean slowdown (r,k)
    
    ```
    python parse_pim_k_iter_util.py 5.15
    ```
    
    The files are located at `py/result/pim_k_iterations/pim_k_iteration_slowdown.dat` and `pim_k_iteration_util.dat`.
    In the `pim_k_iteration_util.dat`, 1 means the dcPIM can sustain the load for a given (r,k).
    
    Parse results of sustained load & mean slowdown of beta,
    
    ```
    python parse_pim_beta.py 5.15
    ```
    
    The files are located at `py/result/pim_beta/pim_beta_slowdown.dat` and `pim_beta_util.dat`.
 5. Parse Figure 8 Appendix results (Bursty Workload)    
    ```
    python parse_bursty_load.py 5.15 imc10 100
    ```
    

## Authors

* Qizhe Cai

