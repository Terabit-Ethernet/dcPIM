# TEPS = Terabit nEtwork Packet Simulator

## Organization

### Core stuff is in `coresim/` 

Normally these files shouldn't change. This directory includes implementations of the following:
* Main event loop and related helper functions, global variables, main() function to determine which experiment to run: `main.cpp`
    * Note: deciding which experiment to run will eventually be moved to the `run/` directory, probably to `experiment.cpp`.
* Core event implementations (`Event`, `FlowArrivalEvent`, `FlowFinishedEvent`, etc): `event.cpp`.
* Representation of the topology: `node.cpp`, `topology.cpp`
* Queueing behavior. This is a basis for extension; the default implementation is FIFO-dropTail: `queue.cpp`.
* Flows and packets. This is also a basis for extension; default is TCP: `packet.cpp` and `flow.cpp`.
* Random variables used in flow generation. Used as a library by the flow generation code: `random_variable.cpp`.

### Extensions are in `ext/`

This is where you implement your favorite protocol.
* Generally extensions are created by subclassing one or more aspects of classes defined in `coresim/`.
* Once an extension is defined, it should be added to `factory.cpp` so it can be run. 
    * Currently, `factory.cpp` supports changing the flow, queue, and host-scheduling implementations.
* Methods in `coresim/` call the `get_...` methods in `factory.cpp` to initialize the simulation with the correct implementation.
* Which implementation to use from `factory.cpp` is determined by the config file, parsed by `run/params.cpp`.
    * You should give your extension an identifier in `factory.h` so it can be uniquely identified in the config file.

### Stuff related to actually running the simulator is in `run/`

* Experiment setup, running, and post-analysis: `experiment.cpp`
* Flow generation models: `flow_generator.cpp`
* Parsing of config file: `params.cpp`
    * Configuration parameters for your extension should be added to `params.h` and `params.cpp`.
    * These can then be accessed with `params.<your_parameter>`

### Helper scripts to run experiments are in `py/`

This can be useful if:
* You are running many experiments in parallel.
* You want to easily generate configuration files.

To compile, the Automake and Autoconf files are included: `configure.ac` and `Makefile.am`. The makefile will produce two targets: `simulator` and `simdebug`. 
`simdebug` is equivalent to `simulator`, except compiler optimzations are turned off to make debugging easier.

## SIGCOMM 2021 Artifact Evaluation

### Compile the Simulator

```
aclocal
automake --add-missing
autoconf
./configure 
make
```
###  Run Simulation Results

Running different workloads takes different amount of time. Here is the estimation of running time for each workload:

```
IMC10 (aditya):   20-30 mins
Web Search: 5-6 hours
Datamining: 2-3 days
```

1. Create a result folder inside `py/`: `mkdir py/result`

2. Reproduce Figure 3 results (Evaulation results for the default setup)

   ```
   cd py/load_100Gbps/
   python load.py
   ./run_script.sh 5.15 imc10
   ./run_script.sh 5.15 websearch
   ./run_script.sh 5.15 datamining
   ```
   The logs are stored in directory `py/result/load/5.15/`.

3. Reproduce Figure 4 results (Microscopic view into dcPIM performance)

   ```
   cd py/worst_case/
   ./run_script.sh 5.15 worstcase1
   ./run_script.sh 5.15 worstcase2
   ./run_script.sh 5.15 worstcase3
   ```
   The logs are stored in directory `py/result/worst_case/5.15/`.

4. Reproduce Figure 5 results (Oversubscribed topology and Fat-Tree topology)

   To run workloads on oversubscribed topology,
   
   ```
   cd py/oversubscribed/
   python oversubscribe.py
   python run.py
   ```
   run.py will run IMC10, Web Search and Datamining workloads one by one. The logs are stored in directory `py/result/oversubscribe/5.15/`.

   To run workoloads on Fat-Tree topology,
   ```
   cd py/fat_tree/
   python fat_tree.py
   ./run_script.sh 5.15 imc10
   ./run_script.sh 5.15 websearch
   ./run_script.sh 5.15 datamining
   ```
   The logs are stored in directory `py/result/fat_tree/5.15/`.

5. Reproduce Figure 6 results (dcPIM Sensitivity Analysis)

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
   python pim_k_iterations.py
   python run.py
   ```
  
   The logs are stored in directory `py/result/pim_k_iterations/5.15/`.
   To get results for 6c (the effect of beta), run:
  
   ```
   cd py/pim_beta
   python pim_beta.py
   ./run_script.sh 5.15 imc10
   ```
  
   The logs are stored in directory `py/result/pim_beta/5.15/`.


6. Reproduce Figure 8 results (Bursty workload)

   ```
   cd py/bursty_workload/
   python bursty.py
   ./run_script.sh 5.15 imc10
   ./run_script.sh 5.15 websearch
   ./run_script.sh 5.15 datamining
   ```
   
   The logs are stored in directory `py/result/bursty/5.15/`.

   
### Parse simulation results

All parsing scripts are located at `py/analysis`. And the parsing results are located at `py/result/path/to/result`.

1. Parse Figure 3 results (Evaulation results for the default setup).

   Parse results of network utilization and mean slowdown (Figure 3a and 3b).
  
   ```
   python parse_load.py 5.15 imc10 100
   python parse_load.py 5.15 websearch 100
   python parse_load.py 5.15 datamining 100
   ```
   
   The network utilization/slodown result is at: `py/result/load/$WORKLOAD_load_util.dat`and `py/result/load/$WORKLOAD_load_slowdown.dat`. The format of files are `<LOAD> <MEAN_SLOWDOWN_OR_UTIL>`. For Figure 3b, the default load is 0.6, corresponding to the second row in the `$WORKLOAD_load_slowdown.dat`. 
   
   Parse results of slowdown versus flow size(Figure 3c, 3d, 3e) with the IMC10 workload.
   
   ```
   python parse_fct_oct_flowsize.py 5.15 all-to-all IMC10 100
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
   python parse_fct_oct_flowsize_os.py 5.15 all-to-all imc10 100
   ```
   
   The file is located at `py/result/oversubscribed/oversubscribe_imc10_100_slowdown_size.dat`.

   Parse results of mean slowdown in the Fat-tree topology (Figure 5c)
   
   ```
   python parse_fat_tree.py 5.15
   ```

   The file is located at `py/result/fat_tree/fat_tree_slowdown.dat`.
   
   Parse results of slowdown versus flow size in Fat-tree topology with IMC10 workload (Figure 5d).
   
   ```
   python parse_fct_oct_flowsize_fat.py 5.15 all-to-all imc10 100
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

## Authors

* Qizhe Cai

