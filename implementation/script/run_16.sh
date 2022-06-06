#!/bin/bash

./run_config.sh 16
./run_exp.sh websearch 16
./get_result.sh 16
python3 parse_result.py 16 websearch
