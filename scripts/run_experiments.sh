#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "[*] Running 3 iterations of real CVE evaluation..."

python3 experiments/run_pipeline.py \
    --manifest ~/tracewise_cvs/magma_manifest.json \
    --model qwen2.5-coder:1.5b \
    --logs ./experiments/dynamorio_logs \
    --output ./results/real_cve_run1

python3 experiments/run_pipeline.py \
    --manifest ~/tracewise_cvs/magma_manifest.json \
    --model qwen2.5-coder:1.5b \
    --logs ./experiments/dynamorio_logs \
    --output ./results/real_cve_run2

python3 experiments/run_pipeline.py \
    --manifest ~/tracewise_cvs/magma_manifest.json \
    --model qwen2.5-coder:1.5b \
    --logs ./experiments/dynamorio_logs \
    --output ./results/real_cve_run3

echo "[*] Computing statistics for Real CVEs..."
python3 scripts/compute_final_stats.py real_cve

echo "[*] Running 3 iterations of Juliet evaluation..."
for i in 1 2 3; do
    python3 experiments/run_pipeline.py \
        --manifest ~/tracewise_cvs/juliet_manifest.json \
        --model qwen2.5-coder:1.5b \
        --logs ./experiments/dynamorio_logs \
        --output ./results/juliet_run${i}
done

echo "[*] Computing statistics for Juliet..."
python3 scripts/compute_final_stats.py juliet
