#!/bin/bash

# Array of numbers to replace the {} in the directory pattern
numbers=(64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072)
#numbers=(1 2 4 8 16 32)
# Loop through the numbers and cat the second line of the result.log file in each directory
for i in "${numbers[@]}"; do
  dir="temp/tcp_flow_a2a_1_"$i"_0_1_6"
  if [ -d "$dir" ]; then # Check if directory exists
    if [ -f "${dir}/result.log" ]; then # Check if the result.log file exists
      # echo "Second line of ${dir}/result.log:"
      sed -n '2p' "${dir}/result.log" # Print the second line of the file
    else
      echo "File ${dir}/result.log does not exist."
    fi
  else
    echo "Directory ${dir} does not exist."
  fi
done
