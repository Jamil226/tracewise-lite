#!/bin/bash
# TRACEWISE-Lite Real Telemetry Execution Script
#
# This script orchestrates the real execution of binaries using AFL++ and DynamoRIO.
# It replaces the simulated trace generator with real provenance data.
#
# Prerequisites:
# 1. AFL++ installed (afl-fuzz, afl-gcc)
# 2. DynamoRIO installed
# 3. Target binaries (Juliet or LAVA-M) compiled with AFL instrumentation

set -e

echo "=========================================================="
echo " TRACEWISE-Lite: Real Telemetry Experiment Pipeline"
echo "=========================================================="

if [ -z "$DYNAMORIO_HOME" ]; then
    echo "[!] DYNAMORIO_HOME is not set. Please set it to your DynamoRIO installation."
    echo "    Example: export DYNAMORIO_HOME=/opt/dynamorio"
    exit 1
fi

if [ -z "$AFL_HOME" ]; then
    echo "[!] AFL_HOME is not set. Assuming AFL++ is in PATH."
fi

TARGET_BIN=$1
INPUT_DIR=$2
CRASH_DIR=$3

if [ -z "$CRASH_DIR" ]; then
    echo "Usage: ./run_real_experiments.sh <target_binary> <afl_input_dir> <afl_crash_dir>"
    echo "Example: ./run_real_experiments.sh ./benchmarks/lava-m/base64 ./inputs ./out/default/crashes"
    exit 1
fi

echo "[*] Step 1: Compiling DynamoRIO Client"
# The C-based DynamoRIO client that tracks instructions, memory, and syscalls
CLIENT_DIR="src/instrumentation/dr_client"
if [ ! -f "$CLIENT_DIR/libtracewise_dr.so" ]; then
    echo "    Compiling libtracewise_dr.so..."
    mkdir -p $CLIENT_DIR/build && cd $CLIENT_DIR/build
    cmake -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake ..
    make
    cd ../../../..
fi
CLIENT_LIB="$(pwd)/$CLIENT_DIR/build/libtracewise_dr.so"

echo "[*] Step 2: Processing AFL++ Crashes"
CRASH_FILES=$(ls $CRASH_DIR/id:* 2>/dev/null | head -n 10)

if [ -z "$CRASH_FILES" ]; then
    echo "[!] No AFL crashes found in $CRASH_DIR"
    exit 1
fi

mkdir -p ./experiments/real_traces

for CRASH_INPUT in $CRASH_FILES; do
    CRASH_ID=$(basename $CRASH_INPUT | cut -d',' -f1)
    echo "    -> Generating trace for crash: $CRASH_ID"
    
    TRACE_OUT="./experiments/real_traces/trace_${CRASH_ID}.json"
    
    # (We expect the binary to crash, so we use || true to ignore the exit code)
    $DYNAMORIO_HOME/bin64/drrun -c $CLIENT_LIB $TRACE_OUT -- $TARGET_BIN < $CRASH_INPUT || true
    
    echo "    -> Trace saved: $TRACE_OUT"
done

echo "[*] Step 3: Running TRACEWISE-Lite Pipeline on Real Traces"
for TRACE_OUT in ./experiments/real_traces/*.json; do
    python3 experiments/process_real_trace.py "$TRACE_OUT"
done

echo "=========================================================="
echo " Real Telemetry Evaluation Complete."
echo " Results available in: experiments/results/real/"
echo "=========================================================="
