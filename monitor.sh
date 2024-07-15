#!/bin/bash

# Create a directory with the current time and date for the strace output
current_time=$(date +"%d%b%Y-%I:%M:%S%p")
output_dir="strace_outputs/${current_time}"
mkdir -p $output_dir

# File to keep track of traced processes
traced_pids_file="traced_pids.txt"
touch $traced_pids_file

# Function to trace a process and its children
trace_process() {
    local pid=$1
    echo "Tracing process $pid and its children..."
    sudo strace -f -ff -o "${output_dir}/strace_output_${pid}" -s 4096 -t -v -p "$pid" &
    echo $pid >> $traced_pids_file
}

# Function to check if a process is already being traced
is_traced() {
    local pid=$1
    grep -q "^$pid$" $traced_pids_file
    return $?
}

# Main loop
while true; do
    # Find all relevant processes
    for proc in python python3 pip pip3; do
        for pid in $(pgrep -x $proc); do
            # Check if this process is not already being traced
            if ! is_traced $pid; then
                trace_process $pid
            fi
        done
    done
    # No sleep interval here, continuous monitoring
done

# Clean-up code for script termination
trap 'rm -f $traced_pids_file; exit 0' INT TERM
