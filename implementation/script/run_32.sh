#!/bin/bash

./run_config.sh 32
./run_exp.sh websearch 32
./get_result.sh 32
python3 parse_result.py 32 websearch
