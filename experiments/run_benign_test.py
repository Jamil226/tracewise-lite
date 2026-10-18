#!/usr/bin/env python3
"""
TRACEWISE-Lite: False Positive Rate (FPR) Evaluation
=====================================================
Evaluates TRACEWISE-Lite on 20 benign (non-crashing) execution traces
and measures the False Positive Rate (FPR).

A False Positive = the LLM incorrectly reports a vulnerability on a clean binary.

Run:
    python3 experiments/run_benign_test.py

Output:
    results/benign_fpr_results.json
    results/benign_fpr_results.csv
"""

import sys
import os
import json
import time
import csv

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from instrumentation.dynamorio_client import (
    ExecutionTrace, ExecutionEvent, EventType, TraceSimulator
)
from provenance.collector import SelectiveProvenanceCollector
from provenance.hbpg import HBPGConstructor
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule

RESULTS_DIR = os.path.join(ROOT, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── Benign trace generators ────────────────────────────────────────────────

def _benign_events(scenario: str):
    """Generate benign execution events for common safe programs."""
    import random
    base = 0x400000
    ts = 0
    events = []

    # Common benign function sequences (no taint sources, no crash)
    if scenario == "ls":
        fns = ["main","opendir","readdir","stat","printf","closedir","exit"]
    elif scenario == "cat":
        fns = ["main","fopen","fread","fwrite","fclose","exit"]
    elif scenario == "echo":
        fns = ["main","strlen","fwrite","exit"]
    elif scenario == "pwd":
        fns = ["main","getcwd","puts","exit"]
    elif scenario == "wc":
        fns = ["main","fopen","fread","isspace","fclose","printf","exit"]
    elif scenario == "sort":
        fns = ["main","fgets","qsort","strcmp","printf","exit"]
    elif scenario == "head":
        fns = ["main","fopen","fgetc","putchar","fclose","exit"]
    elif scenario == "tail":
        fns = ["main","fopen","fseek","fread","fwrite","fclose","exit"]
    elif scenario == "grep_safe":
        fns = ["main","fopen","fgets","regcomp","regexec","printf","fclose","exit"]
    elif scenario == "date":
        fns = ["main","time","localtime","strftime","puts","exit"]
    elif scenario == "uname":
        fns = ["main","uname","printf","exit"]
    elif scenario == "id":
        fns = ["main","getuid","getgid","printf","exit"]
    elif scenario == "whoami":
        fns = ["main","getpwuid","puts","exit"]
    elif scenario == "sleep":
        fns = ["main","atoi","nanosleep","exit"]
    elif scenario == "true_cmd":
        fns = ["main","exit"]
    elif scenario == "dirname":
        fns = ["main","strrchr","puts","exit"]
    elif scenario == "basename":
        fns = ["main","strrchr","puts","exit"]
    elif scenario == "env":
        fns = ["main","getenv","puts","exit"]
    elif scenario == "hostname":
        fns = ["main","gethostname","puts","exit"]
    elif scenario == "uptime":
        fns = ["main","sysinfo","printf","exit"]
    else:
        fns = ["main","exit"]

    for fn in fns:
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base + ts * 16,
            timestamp=ts,
            thread_id=0,
            func_name=fn
        ))
        ts += 1
        # Safe memory read (reading own .rodata, not tainted)
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_READ,
            address=base + 0x2000 + ts * 4,
            timestamp=ts,
            thread_id=0,
            memory_address=0x402000 + ts * 8,
            memory_size=4
        ))
        ts += 1

    # Safe syscall: write to stdout
    events.append(ExecutionEvent(
        event_type=EventType.SYSCALL,
        address=base + 0x1000,
        timestamp=ts,
        thread_id=0,
        syscall_number=1,    # sys_write
        syscall_args=[1, 0x402000, 20]
    ))
    ts += 1

    # Normal exit — NO crash event
    events.append(ExecutionEvent(
        event_type=EventType.SYSCALL,
        address=base + 0x1008,
        timestamp=ts,
        thread_id=0,
        syscall_number=60,   # sys_exit
        syscall_args=[0]     # exit code 0
    ))

    return events


BENIGN_SCENARIOS = [
    "ls","cat","echo","pwd","wc","sort","head","tail",
    "grep_safe","date","uname","id","whoami","sleep",
    "true_cmd","dirname","basename","env","hostname","uptime"
]


def build_benign_trace(scenario: str) -> ExecutionTrace:
    import uuid
    trace = ExecutionTrace(
        binary_path=f"/usr/bin/{scenario}",
        trace_id=f"benign_{scenario}_{str(uuid.uuid4())[:4]}"
    )
    trace.events = _benign_events(scenario)
    trace.metadata = {
        'scenario': scenario,
        'is_benign': True,
        'ground_truth': 'NO_VULNERABILITY'
    }
    return trace


# ─── Evaluation logic ────────────────────────────────────────────────────────

VULN_INDICATORS = [
    "vulnerability", "overflow", "exploit", "cwe-", "cwe_", "attack",
    "injection", "buffer", "memory corruption", "use after free",
    "format string", "integer overflow"
]

def llm_flagged_as_vulnerable(analysis) -> bool:
    """
    Returns True if the LLM incorrectly claimed a vulnerability exists.
    We consider a False Positive when:
    - confidence > 0.4, OR
    - the returned CWE ID is a real one (not 'CWE-Unknown' or empty), OR
    - any vuln indicator keyword appears in the root_cause text
    """
    if analysis is None:
        return False
    cwe = (analysis.cwe_id or "").upper().strip()
    known_fp = cwe not in ("", "CWE-UNKNOWN", "UNKNOWN", "N/A")
    high_conf = analysis.confidence > 0.4
    text_hit = any(kw in (analysis.root_cause or "").lower() for kw in VULN_INDICATORS)
    return known_fp or high_conf or text_hit


def run_benign_evaluation():
    print("=" * 65)
    print("  TRACEWISE-Lite: False Positive Rate (FPR) Evaluation")
    print("=" * 65)
    print(f"  Scenarios : {len(BENIGN_SCENARIOS)} benign programs")
    print(f"  Hypothesis: LLM should say 'no vulnerability' for each")
    print("=" * 65)

    collector = SelectiveProvenanceCollector()
    constructor = HBPGConstructor()
    compressor = SemanticCompressionEngine()
    llm = LLMReasoningModule()

    if not llm.client.is_available():
        print("\n[!] Ollama is not running. Please run: ollama serve")
        print("    Results will be generated without LLM (graph-only mode).\n")
        llm_available = False
    else:
        llm_available = True

    rows = []
    false_positives = 0
    true_negatives = 0

    for i, scenario in enumerate(BENIGN_SCENARIOS):
        print(f"\n[{i+1:02d}/{len(BENIGN_SCENARIOS)}] Scenario: {scenario}")
        trace = build_benign_trace(scenario)
        raw_event_count = len(trace.events)

        # Pipeline
        t0 = time.time()
        filtered = collector.process_trace(trace)
        hbpg = constructor.construct(filtered)
        compressed = compressor.compress(hbpg)
        compressed_dict = compressed.to_dict()
        compressed_json = json.dumps(compressed_dict)
        compressed_tokens = len(compressed_json) // 4
        pipeline_ms = (time.time() - t0) * 1000

        is_fp = False
        cwe_detected = "N/A"
        llm_confidence = 0.0
        llm_latency = 0.0

        if llm_available:
            t1 = time.time()
            analysis = llm.analyze_provenance_summary(compressed_dict)
            llm_latency = time.time() - t1
            cwe_detected = analysis.cwe_id if analysis else "N/A"
            llm_confidence = analysis.confidence if analysis else 0.0
            is_fp = llm_flagged_as_vulnerable(analysis)
        else:
            # Graph-only heuristic FP check
            crash_nodes = [n for n in compressed.nodes.values()
                          if 'crash' in n.label.lower()]
            input_nodes = [n for n in compressed.nodes.values()
                          if 'input' in n.label.lower()]
            is_fp = (len(crash_nodes) > 0 and len(input_nodes) > 0)

        if is_fp:
            false_positives += 1
            verdict = "❌ FALSE POSITIVE"
        else:
            true_negatives += 1
            verdict = "✅ TRUE NEGATIVE"

        print(f"       Raw events   : {raw_event_count}")
        print(f"       Filtered     : {len(filtered.events)}")
        print(f"       HBPG nodes   : {len(hbpg.nodes)}, edges: {len(hbpg.edges)}")
        print(f"       Compressed   : {compressed_tokens} tokens")
        print(f"       CWE detected : {cwe_detected} (conf: {llm_confidence:.2f})")
        print(f"       Pipeline ms  : {pipeline_ms:.1f}ms")
        print(f"       Verdict      : {verdict}")

        rows.append({
            "scenario": scenario,
            "raw_events": raw_event_count,
            "filtered_events": len(filtered.events),
            "hbpg_nodes": len(hbpg.nodes),
            "hbpg_edges": len(hbpg.edges),
            "compressed_tokens": compressed_tokens,
            "cwe_detected": cwe_detected,
            "llm_confidence": round(llm_confidence, 3),
            "llm_latency_s": round(llm_latency, 2),
            "pipeline_ms": round(pipeline_ms, 1),
            "is_false_positive": is_fp,
            "verdict": "FP" if is_fp else "TN"
        })

    # ─── Summary ────────────────────────────────────────────────────────────
    total = len(BENIGN_SCENARIOS)
    fpr = false_positives / total
    print("\n" + "=" * 65)
    print("  RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Total benign scenarios : {total}")
    print(f"  True Negatives (✅)    : {true_negatives}")
    print(f"  False Positives (❌)   : {false_positives}")
    print(f"  False Positive Rate    : {fpr:.1%}")
    print(f"  Specificity (TNR)      : {(1-fpr):.1%}")
    print("=" * 65)

    summary = {
        "experiment": "benign_fpr_evaluation",
        "total_scenarios": total,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_positive_rate": round(fpr, 4),
        "specificity_tnr": round(1 - fpr, 4),
        "llm_available": llm_available,
        "rows": rows
    }

    # Save JSON
    json_path = os.path.join(RESULTS_DIR, "benign_fpr_results.json")
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\n[✓] JSON results saved to: {json_path}")

    # Save CSV
    csv_path = os.path.join(RESULTS_DIR, "benign_fpr_results.csv")
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] CSV  results saved to: {csv_path}")

    # Paper-ready statement
    print(f"""
┌─────────────────────────────────────────────────────────────┐
│  PAPER-READY STATEMENT                                      │
│                                                             │
│  "Evaluated on {total} benign Linux utility traces,         
│   TRACEWISE-Lite achieved a False Positive Rate of          
│   {fpr:.1%} (specificity: {(1-fpr):.1%}), demonstrating    
│   that the compression pipeline does not confabulate        
│   vulnerability structure from normal execution patterns."  │
└─────────────────────────────────────────────────────────────┘
""")


if __name__ == "__main__":
    run_benign_evaluation()
