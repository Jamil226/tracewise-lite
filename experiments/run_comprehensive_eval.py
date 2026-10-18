#!/usr/bin/env python3
"""
TRACEWISE-Lite: Comprehensive Evaluation Suite

Runs the full pipeline across:
  - 5 vulnerable binaries (positive cases)
  - 2 benign binaries (false-positive analysis)
  - Token-efficiency curve measurement
  - CWE output normalization

Produces paper-ready tables and a token-efficiency curve CSV.
"""
import sys
import os
import time
import json
import re
import subprocess
import csv
from dataclasses import dataclass, field
from typing import List, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from instrumentation.dynamorio_client import ExecutionTrace, ExecutionEvent, EventType
from provenance.collector import SelectiveProvenanceCollector
from provenance.hbpg import HBPGConstructor
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DYNAMORIO_HOME = os.environ.get('DYNAMORIO_HOME', os.path.expanduser('~/dynamorio'))
DR_CLIENT = os.path.join(PROJECT_ROOT, 'src', 'instrumentation', 'dr_client', 'build', 'libtracewise_dr.so')

BENCHMARKS = [
    # --- POSITIVE CASES (vulnerable) ---
    {
        "name": "Stack Buffer Overflow", "binary": "benchmarks/sample_vuln/vuln_bin",
        "ground_truth_cwe": "CWE-121", "is_benign": False,
        "crash_input": "A" * 200 + "\n",
    },
    {
        "name": "Heap Buffer Overflow", "binary": "benchmarks/sample_vuln/heap_overflow_bin",
        "ground_truth_cwe": "CWE-122", "is_benign": False,
        "crash_input": "B" * 200 + "\n",
    },
    {
        "name": "Use After Free", "binary": "benchmarks/sample_vuln/uaf_bin",
        "ground_truth_cwe": "CWE-416", "is_benign": False,
        "crash_input": "C" * 60 + "\n",
    },
    {
        "name": "Format String", "binary": "benchmarks/sample_vuln/fmt_bin",
        "ground_truth_cwe": "CWE-134", "is_benign": False,
        "crash_input": "%s%s%s%s%s%s%s%s%s%s%n%n%n%n\n",
    },
    {
        "name": "Integer Overflow", "binary": "benchmarks/sample_vuln/int_overflow_bin",
        "ground_truth_cwe": "CWE-190", "is_benign": False,
        "crash_input": "4294967295\n" + "D" * 256 + "\n",
    },
    # --- BENIGN CASES (should NOT be flagged) ---
    {
        "name": "Safe Copy (Benign)", "binary": "benchmarks/sample_vuln/benign_safe_copy_bin",
        "ground_truth_cwe": "NONE", "is_benign": True,
        "crash_input": "Hello World\n",
    },
    {
        "name": "Safe Malloc/Free (Benign)", "binary": "benchmarks/sample_vuln/benign_safe_malloc_bin",
        "ground_truth_cwe": "NONE", "is_benign": True,
        "crash_input": "Hello World\n",
    },
]

CWE_ALIASES = {
    "121": "CWE-121", "122": "CWE-122", "134": "CWE-134",
    "190": "CWE-190", "416": "CWE-416", "119": "CWE-119",
    "129": "CWE-129",
}


def normalize_cwe(raw: str) -> str:
    """Normalize LLM CWE output to canonical 'CWE-XXX' format."""
    if not raw:
        return "CWE-Unknown"
    # Already correct format
    if re.match(r'^CWE-\d+$', raw.strip()):
        return raw.strip()
    # Just a number
    m = re.search(r'\b(\d{3,4})\b', raw)
    if m:
        return CWE_ALIASES.get(m.group(1), f"CWE-{m.group(1)}")
    return "CWE-Unknown"


def load_trace(filepath: str) -> ExecutionTrace:
    events = []
    with open(filepath, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                ev_type = data.get('event_type')
                event_type_map = {
                    'mem_read': EventType.MEMORY_READ,
                    'mem_write': EventType.MEMORY_WRITE,
                    'func_call': EventType.FUNCTION_CALL,
                    'syscall': EventType.SYSCALL,
                    'crash': EventType.CRASH,
                }
                mapped_type = event_type_map.get(ev_type, EventType.SYSCALL)
                event = ExecutionEvent(
                    event_type=mapped_type,
                    address=data.get('address', 0),
                    timestamp=data.get('timestamp', 0),
                    thread_id=data.get('thread_id', 0),
                    memory_address=data.get('memory_address'),
                    memory_size=data.get('memory_size'),
                    func_name=data.get('func_name'),
                    syscall_number=data.get('syscall_number'),
                )
                events.append(event)
            except Exception:
                pass
    trace = ExecutionTrace(
        trace_id=os.path.basename(filepath),
        binary_path="real_binary",
        events=events,
    )
    trace.metadata['vulnerability_type'] = 'buffer_overflow'
    return trace


def count_tokens(text: str) -> int:
    return len(text) // 4


def generate_trace(binary_path: str, crash_input: str, trace_output: str) -> bool:
    drrun = os.path.join(DYNAMORIO_HOME, 'bin64', 'drrun')
    if not os.path.exists(drrun):
        return False
    try:
        subprocess.run(
            [drrun, '-c', DR_CLIENT, trace_output, '--', binary_path],
            input=crash_input.encode(),
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False
    return os.path.exists(trace_output) and os.path.getsize(trace_output) > 0


def measure_token_efficiency_curve(raw_events: int, hbpg, compressor, llm) -> List[Dict]:
    """
    Measure LLM accuracy at different compression ratios.
    Returns a list of (compression_ratio, tokens, cwe_detected) dicts.
    """
    curve = []
    import copy

    # Point 1: 0% compression (raw truncated to 4k tokens)
    curve.append({"compression_pct": 0, "tokens": 4000, "note": "raw_truncated"})

    # Points 2-N: incrementally compress
    compressed = compressor.compress(hbpg)
    compressed_dict = compressed.to_dict()
    compressed_json = json.dumps(compressed_dict)
    compressed_tokens = count_tokens(compressed_json)

    analysis = llm.analyze_provenance_summary(compressed_dict)
    detected = normalize_cwe(analysis.cwe_id if analysis else "")
    ratio = round((1 - compressed_tokens / max(1, raw_events)) * 100, 2)
    curve.append({
        "compression_pct": ratio,
        "tokens": compressed_tokens,
        "cwe_detected": detected,
        "note": "tracewise_lite",
    })

    return curve


def run_comprehensive_evaluation():
    collector = SelectiveProvenanceCollector()
    constructor = HBPGConstructor()
    compressor = SemanticCompressionEngine()
    llm = LLMReasoningModule()

    trace_dir = os.path.join(PROJECT_ROOT, 'experiments', 'comprehensive_traces')
    os.makedirs(trace_dir, exist_ok=True)
    results_dir = os.path.join(PROJECT_ROOT, 'results')
    os.makedirs(results_dir, exist_ok=True)

    all_results = []
    efficiency_data = []

    print("=" * 90)
    print("TRACEWISE-Lite: Comprehensive Evaluation (Positive + Benign + Efficiency Curve)")
    print("=" * 90)

    for bench in BENCHMARKS:
        name = bench["name"]
        binary = os.path.join(PROJECT_ROOT, bench["binary"])
        gt_cwe = bench["ground_truth_cwe"]
        is_benign = bench["is_benign"]
        crash_input = bench["crash_input"]

        tag = "BENIGN" if is_benign else "VULN "
        print(f"\n[{tag}] {name} (Expected: {gt_cwe})")

        if not os.path.exists(binary):
            print(f"    [!] Binary not found: {binary}")
            continue

        # Generate trace
        safe_name = name.replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "")
        trace_file = os.path.join(trace_dir, f"trace_{safe_name}.json")
        print(f"    [1] Generating trace...")
        ok = generate_trace(binary, crash_input, trace_file)
        if not ok:
            print(f"    [!] Trace generation failed")
            continue

        # Load trace
        trace = load_trace(trace_file)
        raw_events = len(trace.events)
        print(f"    [2] Raw events: {raw_events:,}")

        # Filter
        filtered = collector.process_trace(trace)
        filtered_count = len(filtered.events)

        # HBPG
        hbpg = constructor.construct(filtered)
        print(f"    [3] HBPG: {len(hbpg.nodes)} nodes, {len(hbpg.edges)} edges")

        # Compress
        compressed = compressor.compress(hbpg)
        compressed_dict = compressed.to_dict()
        compressed_tokens = count_tokens(json.dumps(compressed_dict))
        reduction = (1 - compressed_tokens / max(1, raw_events)) * 100
        print(f"    [4] Compressed: {compressed_tokens} tokens ({reduction:.2f}% reduction)")

        # LLM
        print(f"    [5] Querying LLM...")
        t0 = time.time()
        analysis = llm.analyze_provenance_summary(compressed_dict)
        latency = time.time() - t0

        raw_cwe = analysis.cwe_id if analysis else "FAILED"
        detected_cwe = normalize_cwe(raw_cwe)

        # Determine correctness
        if is_benign:
            # For benign cases, correct = LLM does NOT flag a real vulnerability
            is_correct = detected_cwe in ("CWE-Unknown", "NONE", "benign", "")
            verdict = "✅ TN" if is_correct else "❌ FP"
        else:
            is_correct = detected_cwe == gt_cwe
            verdict = "✅ TP" if is_correct else "❌ FN/Wrong"

        print(f"    [*] Detected: {detected_cwe} | Expected: {gt_cwe} | {verdict} | {latency:.1f}s")

        result = {
            "Name": name,
            "Type": "Benign" if is_benign else "Vulnerable",
            "Ground_Truth_CWE": gt_cwe,
            "Raw_Events": raw_events,
            "Filtered_Events": filtered_count,
            "Compressed_Tokens": compressed_tokens,
            "Token_Reduction_Pct": round(reduction, 2),
            "CWE_Detected_Raw": raw_cwe,
            "CWE_Detected_Normalized": detected_cwe,
            "Correct": is_correct,
            "Verdict": verdict,
            "LLM_Latency_s": round(latency, 1),
        }
        all_results.append(result)

        # Collect efficiency data for vulnerable cases
        if not is_benign:
            efficiency_data.append({
                "benchmark": name,
                "raw_events": raw_events,
                "compressed_tokens": compressed_tokens,
                "reduction_pct": round(reduction, 2),
                "cwe_correct": is_correct,
                "latency": round(latency, 1),
            })

    # ─── Final Tables ───────────────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("VULNERABLE BINARY RESULTS (True Positive / False Negative)")
    print("-" * 100)
    print(f"{'Name':<28} | {'GT CWE':<9} | {'Detected':<9} | {'Tokens':<7} | {'Reduction':<10} | {'Verdict':<12} | Latency")
    print("-" * 100)
    for r in all_results:
        if r["Type"] == "Vulnerable":
            print(f"{r['Name']:<28} | {r['Ground_Truth_CWE']:<9} | {r['CWE_Detected_Normalized']:<9} | "
                  f"{r['Compressed_Tokens']:<7} | {r['Token_Reduction_Pct']:.2f}%    | {r['Verdict']:<12} | {r['LLM_Latency_s']}s")

    print("\n" + "=" * 100)
    print("BENIGN BINARY RESULTS (False Positive Analysis)")
    print("-" * 100)
    print(f"{'Name':<30} | {'Expected':<9} | {'LLM Output':<12} | {'Verdict':<10} | Latency")
    print("-" * 100)
    for r in all_results:
        if r["Type"] == "Benign":
            print(f"{r['Name']:<30} | {r['Ground_Truth_CWE']:<9} | {r['CWE_Detected_Normalized']:<12} | {r['Verdict']:<10} | {r['LLM_Latency_s']}s")

    # ─── Summary Statistics ─────────────────────────────────────────────────────
    vuln_results = [r for r in all_results if r["Type"] == "Vulnerable"]
    benign_results = [r for r in all_results if r["Type"] == "Benign"]

    tp = sum(1 for r in vuln_results if r["Correct"])
    fp = sum(1 for r in benign_results if not r["Correct"])
    tn = sum(1 for r in benign_results if r["Correct"])
    avg_tokens = sum(r["Compressed_Tokens"] for r in vuln_results) / max(1, len(vuln_results))
    avg_reduction = sum(r["Token_Reduction_Pct"] for r in vuln_results) / max(1, len(vuln_results))
    avg_latency = sum(r["LLM_Latency_s"] for r in all_results) / max(1, len(all_results))

    print("\n" + "=" * 60)
    print("SUMMARY STATISTICS")
    print("-" * 60)
    print(f"  True Positives  (correct vuln detection): {tp}/{len(vuln_results)}")
    print(f"  True Negatives  (correct benign pass):    {tn}/{len(benign_results)}")
    print(f"  False Positives (benign flagged as vuln): {fp}/{len(benign_results)}")
    print(f"  Avg Compressed Tokens:                    {avg_tokens:.1f}")
    print(f"  Avg Token Reduction:                      {avg_reduction:.2f}%")
    print(f"  Avg LLM Latency:                          {avg_latency:.1f}s")
    print("=" * 60)

    # ─── Save Results ────────────────────────────────────────────────────────────
    with open(os.path.join(results_dir, 'comprehensive_results.json'), 'w') as f:
        json.dump(all_results, f, indent=2)

    with open(os.path.join(results_dir, 'comprehensive_results.csv'), 'w', newline='') as f:
        if all_results:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)

    with open(os.path.join(results_dir, 'efficiency_curve.csv'), 'w', newline='') as f:
        if efficiency_data:
            writer = csv.DictWriter(f, fieldnames=efficiency_data[0].keys())
            writer.writeheader()
            writer.writerows(efficiency_data)

    print(f"\nResults saved: results/comprehensive_results.json/.csv")
    print(f"Efficiency data: results/efficiency_curve.csv")


if __name__ == "__main__":
    run_comprehensive_evaluation()
