# dcPIM Simulator

## 1. Overview
### Repository overview
The simulator is built upon pFabric simulator.
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
The first subsection describes how to get simulation results and the second subsection describes how to parse each result.

## 2. Compile the Simulator

Assume the current directory is `simulator/`, run:

```
aclocal
automake --add-missing
autoconf
./configure 
make
mkdir py/result
```
Note if GCC version > 6, then it may have some issues. To avoid that, 

```
CC='gcc-6' CXX='g++-6' ./configure 
CC='gcc-6' CXX='g++-6' make
```
## 3. SIGCOMM 2022 Artifact Evaluation

###  Run Simulation Results

#### Caveats of Our Work
First, simulation will be run in background and you can check if simulation is finished by using `htop`.
Second, you can run multiple simulation in parallel but please make sure the total number of simulator processes <= total number of CPU cores. 
Third, running too many datamining experiments in parallel may use too much memory.
For example, if the server has 120GB memory, we recommend having at most 8 datamining experiments.

Running different workloads takes different amount of time. Here is the estimation of running time for each workload:
```
IMC10 (aditya):   ~25 mins
Web Search: ~3.3 hours
Datamining: ~17 hours
```

1. Reproduce Figure 3 results (Evaulation results for the default setup) (Running time: ~17 hours)

   ```
   cd py/load_100Gbps/
   ./run.sh
   ```
   The results are stored in directory `py/result/load/5.15/`.

2. Reproduce Figure 4 results (Microscopic view into dcPIM performance) (Running time: ~8 hours)

   ```
   cd py/worst_case/
   ./run.sh
   ```
   The results are stored in directory `py/result/worst_case/5.15/`.

3. Reproduce Figure 5 results (Oversubscribed topology and Fat-Tree topology) (Running time: 21 hours + 31 hours)

   To run experiments on oversubscribed topology,
   
   ```
   cd py/oversubscribe/
   ./run.py
   ```
   run.py will run IMC10, Web Search and Datamining workloads one by one. The logs are stored in directory `py/result/oversubscribe/5.15/`.

   To run experiments on Fat-Tree topology,
   ```
   cd py/fat_tree/
   ./run.sh
   ```
   The results are stored in directory `py/result/fat_tree/5.15/`.

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
  
   The results are stored in directory `py/result/pim_k_iterations/5.15/`.
   To get results for 6c (the effect of beta), run:
  
   ```
   cd py/pim_beta
   ./run.sh
   ```
  
   The results are stored in directory `py/result/pim_beta/5.15/`.


5. Reproduce Figure 8 results (Bursty workload) (running time: ~30 mins)

   ```
   cd py/bursty_workload/
   git clone https://github.com/Terabit-Ethernet/workload_generator.git
   cd workload_generator
   ./run_script.sh imc10
   cd ../
   mv workload_generator/result/bursty_workload/pim/ trace/
   ./run.sh
   ```
   
   The results are stored in directory `py/result/bursty/5.15/`.

   
### Parse simulation results

All parsing scripts are located at `py/analysis`. And the parsing results are located at `py/result/path/to/result`.

   ```
   cd py/analysis
   ```
1. Parse Figure 3 results (Evaulation results for the default setup).

   Parse results of network utilization and mean slowdown (Figure 3a and 3b).
  
   ```
   python parse_load.py 5.15 imc10 100
   cat ../result/load/imc10_load_util.dat
   python parse_slowdown.py 5.15 100
   cat ../result/load/mean_slowdown.dat
   ```
   
   For Figure 3a, the results are at: `py/result/load/imc10_load_util.dat`. The format of files are `<LOAD> <UTIL>`. 
   
   For Figure 3b, the results are at `py/result/load/mean_slowdown.dat`.
   
   Parse results of slowdown versus flow size(Figure 3c, 3d, 3e) with the IMC10 workload.
   
   ```
   python parse_fct_oct_flowsize.py 5.15 all-to-all imc10 100
   cat ../result/load/all-to-all_imc10_load_slowdown_size.dat
   python parse_fct_oct_flowsize.py 5.15 all-to-all websearch 100
   cat ../result/load/all-to-all_websearch_load_slowdown_size.dat
   python parse_fct_oct_flowsize.py 5.15 all-to-all datamining 100
   cat ../result/load/all-to-all_datamining_load_slowdown_size.dat
   ```
   
   The format of the file is `<FLOW_SIZE> <MEAN_SLOWDOWN> <DIFF_BETWEEN_TAIL_AND_MEAN>`.
   
2. Parse Figure 4 results (Microscopic view into dcPIM performance)
   
   ```
   python parse_worstcase1_util.py 
   cat ../result/worst_case/pim_util_worstcase1_result.txt
   python parse_worstcase_slowdown.py 5.15 worstcase2
   cat ../result/worst_case/worstcase2_slowdown.txt
   python parse_worstcase3_util.py 
   cat ../result/worst_case/pim_util_worstcase3_result.txt
   ```
    The result of Figure 4a is located at `py/result/worst_case/pim_util_worstcase1_result.txt`, Figure 4b is located at `py/result/worst_case/worstcase2_slowdown.txt` and Figure 4c is located `py/result/worst_case/pim_util_worstcase3.txt`.
   
3. Parse Figure 5 results (Oversubscribed topology and Fat-Tree topology)

   Parse results of mean slowdown in the oversubscribed topology (Figure 5a)
   
   ```
   python parse_oversubscribe.py 5.15 oversubscribe 100
   cat ../result/oversubscribe/oversubscribe_slowdown.dat
   ```

   The results are at `py/result/oversubscribed/oversubscribe_slowdown.dat`.

   Parse results of slowdown versus flow size in oversubscribed topology with IMC10 workload (Figure 5b).
   
   ```
   python parse_fct_oct_flowsize_os.py 5.15 oversubscribe imc10 100
   cat ../result/oversubscribe/oversubscribe_imc10_100_slowdown_size.dat
   ```
   
   The results are at `py/result/oversubscribed/oversubscribe_imc10_100_slowdown_size.dat`.

   Parse results of mean slowdown in the Fat-tree topology (Figure 5c)
   
   ```
   python parse_fat_tree.py 5.15
   cat ../result/fat_tree/fat_tree_slowdown.dat
   ```

   The results are at `py/result/fat_tree/fat_tree_slowdown.dat`.
   
   Parse results of slowdown versus flow size in Fat-tree topology with IMC10 workload (Figure 5d).
   
   ```
   python parse_fct_oct_flowsize_fat.py 5.15 fat_tree imc10 100
   cat ../result/fat_tree/fat_tree_imc10_100_slowdown_size.dat
   ```
     
   The results are at `py/result/fat_tree/fat_tree_aditya_100_slowdown_size.dat`.

   
 4. Parse Figure 6 results (dcPIM Sensitivity Analysis)
 
    Parse results of mean slowdown (r,k)
    
    ```
    python parse_pim_k_iter_util.py 5.15
    cat ../result/pim_k_iterations/pim_k_iteration_slowdown.dat
    ```
  
    The results are at `py/result/pim_k_iterations/pim_k_iteration_slowdown.dat`.
  5. Parse Figure 8 Appendix results (Bursty Workload)    
    ```
    python parse_bursty_load.py 5.15 imc10 100
    cat ../result/bursty/imc10_bursty_load_util.dat
    cat ../result/bursty/imc10_bursty_load_slowdown.dat
    cat ../result/bursty/imc10_bursty_load_99_slowdown.dat
    ```
    The results are at `py/result/bursty/imc10_bursty_load_util.dat`, `imc10_bursty_load_slowdown.dat` and `imc10_bursty_load_99_slowdown.dat`.

### Getting Baseline Results(Optional)
In case you are interested in getting baseline results shown in the paper, we provide repos for each protocol including [NDP](https://github.com/qizhe/NDP) and [HPCC](https://github.com/qizhe/High-Precision-Congestion-Control) except Homa with Aeolus since the repo is not public. The instructions are in the READMEs of repos.



## Authors

* Qizhe Cai

