#!/usr/bin/env python3
"""
TRACEWISE-Lite: Multi-CWE Evaluation Runner

Runs the full pipeline (DynamoRIO → HBPG → Compression → LLM) across
multiple vulnerability classes and produces a paper-ready results table.
"""
import sys
import os
import time
import json
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from instrumentation.dynamorio_client import ExecutionTrace, ExecutionEvent, EventType
from provenance.collector import SelectiveProvenanceCollector
from provenance.hbpg import HBPGConstructor
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DYNAMORIO_HOME = os.environ.get('DYNAMORIO_HOME', os.path.expanduser('~/dynamorio'))
DR_CLIENT = os.path.join(PROJECT_ROOT, 'src', 'instrumentation', 'dr_client', 'build', 'libtracewise_dr.so')

# Define our benchmark suite
BENCHMARKS = [
    {
        "name": "Stack Buffer Overflow",
        "binary": "benchmarks/sample_vuln/vuln_bin",
        "ground_truth_cwe": "CWE-121",
        "crash_input_gen": lambda: "A" * 200 + "\n",
    },
    {
        "name": "Heap Buffer Overflow",
        "binary": "benchmarks/sample_vuln/heap_overflow_bin",
        "ground_truth_cwe": "CWE-122",
        "crash_input_gen": lambda: "B" * 200 + "\n",
    },
    {
        "name": "Use After Free",
        "binary": "benchmarks/sample_vuln/uaf_bin",
        "ground_truth_cwe": "CWE-416",
        "crash_input_gen": lambda: "C" * 60 + "\n",
    },
    {
        "name": "Format String",
        "binary": "benchmarks/sample_vuln/fmt_bin",
        "ground_truth_cwe": "CWE-134",
        "crash_input_gen": lambda: "%s%s%s%s%s%s%s%s%s%s%n%n%n%n\n",
    },
    {
        "name": "Integer Overflow",
        "binary": "benchmarks/sample_vuln/int_overflow_bin",
        "ground_truth_cwe": "CWE-190",
        "crash_input_gen": lambda: "4294967295\n" + "D" * 256 + "\n",
    },
]


def load_trace(filepath: str) -> ExecutionTrace:
    """Load a DynamoRIO JSON trace into our pipeline format."""
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
                    'crash': EventType.CRASH
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
                    syscall_number=data.get('syscall_number')
                )
                events.append(event)
            except Exception:
                pass
    trace = ExecutionTrace(
        trace_id=os.path.basename(filepath),
        binary_path="real_binary",
        events=events
    )
    trace.metadata['vulnerability_type'] = 'buffer_overflow'
    return trace


def count_tokens(text: str) -> int:
    return len(text) // 4


def generate_trace(binary_path: str, crash_input: str, trace_output: str) -> bool:
    """Run a binary under DynamoRIO and capture the trace."""
    drrun = os.path.join(DYNAMORIO_HOME, 'bin64', 'drrun')
    if not os.path.exists(drrun):
        print(f"    [!] drrun not found at {drrun}")
        return False

    try:
        proc = subprocess.run(
            [drrun, '-c', DR_CLIENT, trace_output, '--', binary_path],
            input=crash_input.encode(),
            capture_output=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        print("    [!] DynamoRIO timed out")
        return False

    return os.path.exists(trace_output) and os.path.getsize(trace_output) > 0


def run_full_evaluation():
    collector = SelectiveProvenanceCollector()
    constructor = HBPGConstructor()
    compressor = SemanticCompressionEngine()
    llm = LLMReasoningModule()

    os.makedirs(os.path.join(PROJECT_ROOT, 'experiments', 'multi_cwe_traces'), exist_ok=True)

    all_results = []

    print("=" * 80)
    print("TRACEWISE-Lite: Multi-CWE Live Evaluation")
    print("=" * 80)

    for bench in BENCHMARKS:
        name = bench["name"]
        binary = os.path.join(PROJECT_ROOT, bench["binary"])
        gt_cwe = bench["ground_truth_cwe"]
        crash_input = bench["crash_input_gen"]()

        print(f"\n--- {name} ({gt_cwe}) ---")

        if not os.path.exists(binary):
            print(f"    [!] Binary not found: {binary}")
            continue

        # Step 1: Generate trace
        trace_file = os.path.join(
            PROJECT_ROOT, 'experiments', 'multi_cwe_traces',
            f"trace_{gt_cwe.replace('-', '_')}.json"
        )
        print(f"    [1] Generating DynamoRIO trace...")
        ok = generate_trace(binary, crash_input, trace_file)
        if not ok:
            print(f"    [!] Trace generation failed for {name}")
            all_results.append({
                "Vulnerability": name, "Ground Truth": gt_cwe,
                "Raw Events": "N/A", "Filtered": "N/A",
                "Compressed Tokens": "N/A", "CWE Detected": "FAILED",
                "Latency": "N/A"
            })
            continue

        # Step 2: Load & process trace
        trace = load_trace(trace_file)
        raw_events = len(trace.events)
        print(f"    [2] Raw events captured: {raw_events}")

        # Step 3: Selective provenance
        filtered = collector.process_trace(trace)
        filtered_count = len(filtered.events)
        print(f"    [3] After selective filtering: {filtered_count} events")

        # Step 4: HBPG construction
        hbpg = constructor.construct(filtered)
        print(f"    [4] HBPG: {len(hbpg.nodes)} nodes, {len(hbpg.edges)} edges")

        # Step 5: Semantic compression
        compressed = compressor.compress(hbpg)
        compressed_dict = compressed.to_dict()
        compressed_json = json.dumps(compressed_dict)
        compressed_tokens = count_tokens(compressed_json)
        print(f"    [5] Compressed: {len(compressed.nodes)} nodes, {compressed_tokens} tokens")

        # Step 6: LLM reasoning
        print(f"    [6] Querying LLM (qwen2.5-coder:1.5b)...")
        start_time = time.time()
        analysis = llm.analyze_provenance_summary(compressed_dict)
        latency = time.time() - start_time

        detected_cwe = analysis.cwe_id if analysis else "FAILED"
        match = "✅" if detected_cwe == gt_cwe else "❌"
        print(f"    [*] Result: {detected_cwe} {match} (expected {gt_cwe}) — {latency:.1f}s")

        all_results.append({
            "Vulnerability": name,
            "Ground Truth": gt_cwe,
            "Raw Events": raw_events,
            "Filtered": filtered_count,
            "Compressed Tokens": compressed_tokens,
            "CWE Detected": detected_cwe,
            "Match": match,
            "Latency": f"{latency:.1f}s"
        })

    # Print final results table
    print("\n" + "=" * 95)
    print(f"{'Vulnerability':<22} | {'Ground Truth':<12} | {'Raw Events':<11} | {'Tokens':<7} | {'CWE Detected':<13} | {'Match':<5} | {'Latency':<8}")
    print("-" * 95)
    for r in all_results:
        print(f"{r['Vulnerability']:<22} | {r['Ground Truth']:<12} | {str(r['Raw Events']):<11} | {str(r['Compressed Tokens']):<7} | {r['CWE Detected']:<13} | {r.get('Match',''):<5} | {r['Latency']:<8}")
    print("=" * 95)

    # Save results
    results_dir = os.path.join(PROJECT_ROOT, 'results')
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, 'multi_cwe_results.json'), 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to results/multi_cwe_results.json")


if __name__ == "__main__":
    run_full_evaluation()
