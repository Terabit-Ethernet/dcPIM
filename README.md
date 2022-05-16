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
IMC10 (aditya):   15 mins
Web Search: 5-6 hours
Datamining: 2-3 days
```

1. Create a result folder inside `py/`: `mkdir py/result`

2. Reproduce Figure 3 results (Evaulation results for the default setup)

   ```
   cd py/load_100Gbps/
   python load.py
   ```

   To run each workload, 

   ```
   ./run_script.sh $DATE $WORKLOAD
   ```
   Eg. `./run_script.sh 5.15 imc10`, `./run_script.sh 5.15 websearch`, `./run_script.sh 5.15 datamining`

3. Reproduce Figure 4 results (Microscopic view into dcPIM performance)

   ```
   cd py/worst_case/
   ```

   To run each workload, 

   ```
   ./run_script.sh $DATE $WORSTCASE
   ```
   Eg. `./run_script.sh 5.15 worstcase1`, `./run_script.sh 5.15 worstcase2`, `./run_script.sh 5.15 worstcase3`

4. Reproduce Figure 5 results (Oversubscribed topology and Fat-Tree topology)

   To run workloads on oversubscribed topology,
   ```
   cd py/oversubscribed/
   python oversubscribe.py
   python run.py
   ```
   run.py will run IMC10, Web Search and Datamining workloads one by one.
   
   To run workoloads on Fat-Tree topology,
   ```
   cd py/fat_tree/
   python fat_tree.py
   ```

   To run each workload, 
   ```
   ./run_script.sh $DATE $WORSTCASE
   ```
   Eg. `./run_script.sh 5.15 imc10`, `./run_script.sh 5.15 websearch`, `./run_script.sh 5.15 datamining`
   
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
   To get results for figure 6a and 6b, run:
   ```
   cd py/pim_k_iterations
   python pim_k_iterations.py
   python run.py
   ```
   To get results for 6c, run:
   ```
   cd py/pim_beta
   python pim_beta.py
   ./run_script.sh $DATE imc10
   ```
   Eg.  `./run_script.sh $5.15 imc10`
## Authors

* Qizhe Cai

