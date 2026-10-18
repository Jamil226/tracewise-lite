#!/usr/bin/env python3
"""
TRACEWISE-Lite: Large-Scale Benchmark Runner

This script automates the full real TRACEWISE-Lite pipeline over dozens/hundreds 
of compiled binaries. It generates synthetic Juliet-like test cases on the fly,
compiles them, and evaluates them with real DynamoRIO instrumentation and the local LLM.

It produces the large-scale CSV results matrix and confusion matrix statistics.
"""
import sys
import os
import time
import json
import re
import subprocess
import csv
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

CWE_ALIASES = {
    "121": "CWE-121", "122": "CWE-122", "134": "CWE-134",
    "190": "CWE-190", "416": "CWE-416", "119": "CWE-119",
    "129": "CWE-129",
}

def normalize_cwe(raw: str) -> str:
    if not raw:
        return "CWE-Unknown"
    if re.match(r'^CWE-\d+$', raw.strip()):
        return raw.strip()
    m = re.search(r'\b(\d{3,4})\b', raw)
    if m:
        return CWE_ALIASES.get(m.group(1), f"CWE-{m.group(1)}")
    return "CWE-Unknown"

def generate_juliet_like_suite(output_dir: str, num_cases: int = 50) -> List[Dict]:
    """Generates real compilable C files spanning vulnerable and benign cases."""
    os.makedirs(output_dir, exist_ok=True)
    benchmarks = []
    
    # Templates for auto-generation
    cwe_121_tmpl = """#include <stdio.h>\n#include <string.h>\nvoid func_{id}() {{\n    char buf[64];\n    char input[256];\n    if (fgets(input, sizeof(input), stdin)) {{\n        strcpy(buf, input); // VULNERABLE\n        printf("%s", buf);\n    }}\n}}\nint main() {{ func_{id}(); return 0; }}"""
    cwe_416_tmpl = """#include <stdio.h>\n#include <stdlib.h>\nvoid func_{id}() {{\n    char *buf = malloc(64);\n    fgets(buf, 64, stdin);\n    free(buf);\n    printf("UAF: %s\\n", buf); // VULNERABLE\n}}\nint main() {{ func_{id}(); return 0; }}"""
    benign_tmpl = """#include <stdio.h>\n#include <string.h>\nvoid func_{id}() {{\n    char buf[256];\n    if (fgets(buf, sizeof(buf), stdin)) {{\n        printf("%s", buf); // SAFE\n    }}\n}}\nint main() {{ func_{id}(); return 0; }}"""
    
    for i in range(num_cases):
        is_benign = (i % 3 == 0)
        cwe_type = "CWE-121" if (i % 3 == 1) else "CWE-416"
        cwe_type = "NONE" if is_benign else cwe_type
        
        tmpl = benign_tmpl if is_benign else (cwe_121_tmpl if cwe_type == "CWE-121" else cwe_416_tmpl)
        src_code = tmpl.format(id=i)
        
        src_file = os.path.join(output_dir, f"testcase_{i}.c")
        bin_file = os.path.join(output_dir, f"testcase_{i}_bin")
        
        with open(src_file, "w") as f:
            f.write(src_code)
            
        # Compile
        subprocess.run(["gcc", "-O0", "-g", "-fno-stack-protector", src_file, "-o", bin_file])
        
        benchmarks.append({
            "name": f"Juliet_Mock_{i}",
            "binary": bin_file,
            "ground_truth_cwe": cwe_type,
            "is_benign": is_benign,
            "crash_input": "A" * 200 + "\\n"
        })
        
    return benchmarks

def generate_trace(binary_path: str, crash_input: str, trace_output: str) -> bool:
    drrun = os.path.join(DYNAMORIO_HOME, 'bin64', 'drrun')
    if not os.path.exists(drrun): return False
    try:
        subprocess.run(
            [drrun, '-c', DR_CLIENT, trace_output, '--', binary_path],
            input=crash_input.encode(), capture_output=True, timeout=15
        )
    except subprocess.TimeoutExpired:
        return False
    return os.path.exists(trace_output) and os.path.getsize(trace_output) > 0

def load_trace(filepath: str) -> ExecutionTrace:
    events = []
    with open(filepath, 'r') as f:
        for line in f:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                mapped_type = {
                    'mem_read': EventType.MEMORY_READ, 'mem_write': EventType.MEMORY_WRITE,
                    'func_call': EventType.FUNCTION_CALL, 'syscall': EventType.SYSCALL,
                    'crash': EventType.CRASH
                }.get(data.get('event_type'), EventType.SYSCALL)
                events.append(ExecutionEvent(
                    event_type=mapped_type, address=data.get('address', 0),
                    timestamp=data.get('timestamp', 0), thread_id=data.get('thread_id', 0),
                    memory_address=data.get('memory_address'), memory_size=data.get('memory_size'),
                    func_name=data.get('func_name'), syscall_number=data.get('syscall_number')
                ))
            except Exception: pass
    return ExecutionTrace(trace_id=os.path.basename(filepath), binary_path="binary", events=events)

def run_large_scale():
    print("=" * 80)
    print("TRACEWISE-Lite: Large-Scale Benchmark Runner")
    print("Generating 50 real C binaries for Juliet/LAVA-M style evaluation...")
    
    benchmark_dir = os.path.join(PROJECT_ROOT, "benchmarks", "generated_suite")
    benchmarks = generate_juliet_like_suite(benchmark_dir, num_cases=50)
    
    collector = SelectiveProvenanceCollector()
    constructor = HBPGConstructor()
    compressor = SemanticCompressionEngine()
    llm = LLMReasoningModule()
    
    results = []
    trace_dir = os.path.join(PROJECT_ROOT, 'experiments', 'large_scale_traces')
    os.makedirs(trace_dir, exist_ok=True)
    
    print(f"Starting real DynamoRIO instrumentation & LLM reasoning over {len(benchmarks)} binaries...")
    
    for idx, bench in enumerate(benchmarks):
        print(f"  [{idx+1}/{len(benchmarks)}] Analyzing {bench['name']} (Expected: {bench['ground_truth_cwe']})")
        
        trace_file = os.path.join(trace_dir, f"trace_{idx}.json")
        if not generate_trace(bench['binary'], bench['crash_input'], trace_file):
            continue
            
        trace = load_trace(trace_file)
        raw_events = len(trace.events)
        
        filtered = collector.process_trace(trace)
        hbpg = constructor.construct(filtered)
        compressed = compressor.compress(hbpg)
        
        compressed_dict = compressed.to_dict()
        compressed_tokens = len(json.dumps(compressed_dict)) // 4
        
        t0 = time.time()
        analysis = llm.analyze_provenance_summary(compressed_dict)
        latency = time.time() - t0
        
        detected_cwe = normalize_cwe(analysis.cwe_id if analysis else "FAILED")
        
        if bench['is_benign']:
            is_correct = detected_cwe in ("CWE-Unknown", "NONE", "benign", "")
        else:
            is_correct = detected_cwe == bench['ground_truth_cwe']
            
        results.append({
            "TestID": bench['name'],
            "Type": "Benign" if bench['is_benign'] else "Vulnerable",
            "Expected": bench['ground_truth_cwe'],
            "Detected": detected_cwe,
            "Raw_Events": raw_events,
            "Tokens": compressed_tokens,
            "Correct": is_correct,
            "Latency": round(latency, 1)
        })

    # Save scale results
    results_dir = os.path.join(PROJECT_ROOT, 'results')
    with open(os.path.join(results_dir, 'scale_results.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print("\\nLarge-scale evaluation complete. Matrix saved to results/scale_results.csv")

if __name__ == "__main__":
    run_large_scale()
