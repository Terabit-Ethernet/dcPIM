# Cloudlab experiments


## Run experiments

1. Run permutation workloads where 4 servers serves as senders and the other 4 servers serves as receivers; each sender will only send data to one receiver.

Run dcPIM,
```
./run_exp.sh dcpim 0 permutation
```

Run TCP,
```
./run_exp.sh tcp 1 permutation
```

Results will be printed out as the standard output.

2. Run all-to-all workloads where 4 servers serves as senders and the other 4 servers serves as receivers; each sender will only send data to all 4 receivers.

Run dcPIM,
```
./run_exp.sh dcpim 0 a2a
```

Run TCP,
```
./run_exp.sh tcp 1 a2a
```


## Note

clnode281 and 265 have some hardware configuration issues, leading to performance degradation. Trying to avoid them if you can.
