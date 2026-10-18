"""
run_pipeline.py
TRACEWISE-Lite — Full Pipeline Runner

Connects compression + ASan baseline + result logging into one
script you can run against your manifest.

Usage:
    python run_pipeline.py --manifest ~/tracewise_cvs/magma_manifest.json
    python run_pipeline.py --manifest ~/tracewise_cvs/magma_manifest.json \
                           --model mistral:7b-instruct-q4_0

The script:
  1. Loads the manifest
  2. For each binary: runs ASan baseline (if source available) OR GDB
  3. Runs your compression pipeline on the HBPG you already generate
  4. Calls the local LLM
  5. Logs results to results.json and results.csv

NOTE: This script assumes your existing DynamoRIO + HBPG builder
produces an nx.DiGraph per binary. Replace the stub at the bottom
with your actual graph builder call.
"""

import csv
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import requests

# ── Resolve repo root so we can import from src/ ─────────────────────────────
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if os.path.join(REPO_ROOT, 'src') not in sys.path:
    sys.path.insert(0, os.path.join(REPO_ROOT, 'src'))

# Adaptive k-hop compression engine
from src.provenance.hbpg_compression import (
    compress, build_llm_prompt, NodeType, EdgeType
)
# ASAN / GDB baseline
from src.evaluation.asan_baseline import (
    asan_source_baseline, stripped_binary_baseline, compare_with_tracewise
)
from src.evaluation.angr_baseline import angr_triage
# Existing TRACEWISE-Lite pipeline stages (Stages 1-3)
from src.instrumentation.dynamorio_client import TraceSimulator
from src.provenance.collector import SelectiveProvenanceCollector
from src.provenance.hbpg import HBPGConstructor

import networkx as nx

log = logging.getLogger("tracewise.pipeline")
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s | %(name)s | %(message)s")


# ─── Configuration ────────────────────────────────────────────────────────────

OLLAMA_URL    = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5-coder:1.5b"


# ─── LLM call ────────────────────────────────────────────────────────────────

def wait_for_ollama(max_retries: int = 10) -> bool:
    """Verify Ollama is alive before sending LLM request."""
    for attempt in range(max_retries):
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=15)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
        log.warning(f"Ollama not ready (attempt {attempt+1}/{max_retries}), waiting...")
    return False

def extract_json_from_llm_response(raw_text: str):
    if not raw_text or not raw_text.strip():
        return None
    text = raw_text.strip()
    import re
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE)
    text = text.strip()
    
    start = text.find('{')
    if start == -1: return None
    
    depth = 0
    end = -1
    in_string = False
    escape_next = False
    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string: continue
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        open_braces = depth
        repaired = text[start:] + ('}' * open_braces)
        try: return json.loads(repaired)
        except json.JSONDecodeError: return None
    try: return json.loads(text[start:end])
    except json.JSONDecodeError: return None

def extract_cwe_fallback(raw_text: str):
    import re
    match = re.search(r'CWE[-–](\d+)', raw_text, re.IGNORECASE)
    if match: return f"CWE-{match.group(1)}"
    return None

def call_local_llm(prompt: str, model: str = DEFAULT_MODEL, timeout: int = 60):
    if not wait_for_ollama():
        log.error("Ollama unreachable after retries — skipping this binary")
        return None, ""
    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 512,
        },
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        raw_text = resp.json().get("response", "")
        parsed = extract_json_from_llm_response(raw_text)
        return parsed, raw_text
    except Exception as e:
        log.warning("Ollama call failed or unparseable: %s", e)
        return None, ""


# ─── Stub: replace with your real graph builder ──────────────────────────────

def _load_real_trace_log(log_path: str) -> nx.DiGraph:
    """
    Parse a real JSON trace log produced by experiments/run_real_traces.py.
    Returns an nx.DiGraph with proper node/edge types for hbpg_compression.
    """
    with open(log_path) as f:
        data = json.load(f)

    G = nx.DiGraph()
    prev_id = None

    for i, ev in enumerate(data.get("events", [])):
        etype = ev.get("event_type", "")
        nid   = f"ev_{i}"

        if etype == "function_call":
            fn = ev.get("func_name", "")
            # Determine node type
            if ev.get("is_taint_source") or fn in ("read", "recv", "fread", "fgets", "scanf"):
                ntype = NodeType.SOURCE
            elif fn in ("malloc", "calloc", "realloc", "free"):
                ntype = NodeType.CALL
            else:
                ntype = NodeType.CALL
            G.add_node(nid, type=ntype, label=fn,
                       address=hex(ev.get("memory_address", 0) or 0),
                       cwe_hint=ev.get("cwe_hint"))

        elif etype == "syscall":
            sname = ev.get("syscall_name", f"sys_{ev.get('syscall_number',0)}")
            ntype = NodeType.SOURCE if ev.get("is_taint_source") else NodeType.CALL
            G.add_node(nid, type=ntype, label=f"syscall:{sname}",
                       address=None, cwe_hint=None)

        elif etype == "crash":
            G.add_node(nid, type=NodeType.CRASH,
                       label=f"CRASH:{ev.get('crash_type','unknown')}",
                       address=None,
                       cwe_hint=ev.get("cwe_hint"))

        elif etype == "memory":
            addr = ev.get("memory_address", 0) or 0
            G.add_node(nid, type=NodeType.MEMORY, label="mem_access",
                       address=hex(addr), cwe_hint=ev.get("cwe_hint"))
        else:
            continue  # skip unknown

        # Connect to previous node with semantically correct edge type.
        # TAINT propagates from SOURCE; PROPAGATE continues through tainted nodes;
        # CONTROL is used for non-tainted branches and calls.
        if prev_id and G.has_node(prev_id):
            prev_type = G.nodes[prev_id].get("type")
            is_taint_event = (ev.get("taint_source") is not None
                              or etype == "taint_prop"
                              or prev_type in {NodeType.SOURCE, NodeType.MEMORY})
            etype_edge = (EdgeType.TAINT if prev_type == NodeType.SOURCE
                          else EdgeType.PROPAGATE if is_taint_event
                          else EdgeType.CONTROL)
            G.add_edge(prev_id, nid, type=etype_edge)

        prev_id = nid

    # NOTE: Do NOT add a direct SOURCE→CRASH shortcut edge.
    # It collapses the full taint chain to 2 nodes before compression runs,
    # making CWE classification impossible. Taint must flow through
    # intermediate MEMORY/CALL nodes for Algorithm 1 to preserve them.

    log.info("Real trace log: %d nodes, %d edges from %s",
             G.number_of_nodes(), G.number_of_edges(), os.path.basename(log_path))
    return G


def build_hbpg_from_dynamorio_log(log_path: str, vuln_type: str = "buffer_overflow") -> nx.DiGraph:
    """
    Build an nx.DiGraph from a trace log.
    Priority:
      1. Real JSON trace log (from run_real_traces.py) → _load_real_trace_log()
      2. TraceSimulator synthetic fallback (no SelectiveProvenanceCollector)
    """
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                peek = f.read(1)
            if peek == "{":
                log.info("Real JSON trace log found: %s", os.path.basename(log_path))
                return _load_real_trace_log(log_path)
        except Exception as e:
            log.warning("Could not read %s: %s — using simulator", log_path, e)

    log.warning("Trace log missing: %s — using TraceSimulator (%s). "
                "Run: python3 experiments/run_real_traces.py", log_path, vuln_type)

    raw_trace = TraceSimulator.generate_vulnerable_trace(
        binary_path=os.path.basename(log_path),
        vulnerability_type=vuln_type
    )
    # Build graph directly — bypass SelectiveProvenanceCollector (designed for
    # real DynamoRIO address ranges that synthetic events don't satisfy)
    G = nx.DiGraph()
    prev_id = None
    tainted_flow = False
    
    for i, ev in enumerate(raw_trace.events):
        nid = f"sim_{i}"
        fn  = getattr(ev, 'func_name', '') or ''
        is_src   = fn in ('read', 'recv', 'fread', 'fgets', 'scanf', 'getchar')
        is_crash = ev.event_type.value == 'crash'
        is_mem   = ev.event_type.value in ('mem_read', 'mem_write')
        
        if is_src or ev.event_type.value == 'taint_prop' or getattr(ev, "taint_source", None) is not None:
            tainted_flow = True
            
        ntype = (NodeType.CRASH if is_crash else
                 NodeType.SOURCE if is_src else 
                 NodeType.MEMORY if is_mem else NodeType.CALL)
                 
        G.add_node(nid, type=ntype, label=fn or ev.event_type.value,
                   address=hex(ev.address) if ev.address else None,
                   cwe_hint=None)
        
        if prev_id:
            prev_type = G.nodes[prev_id].get("type")
            etype_edge = (EdgeType.TAINT if prev_type == NodeType.SOURCE
                          else EdgeType.PROPAGATE if tainted_flow
                          else EdgeType.CONTROL)
            G.add_edge(prev_id, nid, type=etype_edge)
        prev_id = nid
        
    # NOTE: No shortcut SOURCE→CRASH edge added.
    log.info("Synthetic graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G


# ─── Per-binary pipeline ─────────────────────────────────────────────────────

import tiktoken
try:
    enc = tiktoken.get_encoding("cl100k_base")
except Exception:
    enc = None

def count_tokens(text: str) -> int:
    return len(enc.encode(text)) if enc else 0

def run_one(
    entry:    dict,
    model:    str,
    dynamorio_log_dir: str,
) -> dict:
    """
    Run the full pipeline for one manifest entry.
    Returns a result dict suitable for CSV/JSON logging.
    """
    bug_id        = entry["bug_id"]
    binary_path   = entry.get("binary_path")
    input_path    = entry.get("input_path")
    ground_truth  = entry.get("ground_truth", "UNKNOWN")
    source_path   = entry.get("source_path")      # optional — from manifest

    log.info("=== Processing: %s (GT: %s) ===", bug_id, ground_truth)

    result = {
        "bug_id":                  bug_id,
        "ground_truth":            ground_truth,
        "asan_prediction":         None,
        "asan_correct":            None,
        "asan_requires_source":    True,
        "tracewise_prediction":    None,
        "tracewise_correct":       None,
        "tracewise_confidence":    None,
        "taint_chain_found":       None,
        "k_used":                  None,
        "nodes_before":            None,
        "nodes_after":             None,
        "raw_instruction_count":   None,
        "stage2_event_count":      None,
        "hbpg_nodes_initial":      None,
        "hbpg_nodes_compressed":   None,
        "llm_token_count":         None,
        "true_compression_ratio":  None,
        "compression_ratio":       None,
        "pipeline_latency_s":      None,
        "parse_status":            None,
        "llm_raw":                 None,
        "error":                   None,
    }

    # Guard: skip if files missing
    if not input_path or not os.path.exists(input_path):
        result["error"] = f"input_path missing or not found: {input_path}"
        log.error(result["error"])
        return result

    # ── ASan / GDB baseline ──────────────────────────────────────────────────
    input_mode    = entry.get("input_mode", "stdin")
    argv_template = entry.get("argv_template", None)

    # Resolve @@_content: read the input file and substitute as a string arg
    if argv_template:
        resolved = []
        for arg in argv_template:
            if arg == "@@_content":
                with open(input_path, 'rb') as f:
                    resolved.append(f.read().decode('utf-8', errors='replace').strip())
            else:
                resolved.append(arg)
        argv_template = resolved
        input_mode = "argv"   # force argv once resolved

    if source_path and os.path.exists(source_path):
        log.info("Running ASan baseline (source, mode=%s)…", input_mode)
        
        # Juliet-specific ASan compilation flags
        extra_flags = []
        if "juliet" in str(source_path).lower():
            juliet_root = os.path.join(REPO_ROOT, "juliet")
            import glob
            support_files = glob.glob(f"{juliet_root}/C/testcasesupport/*.c")[:3]
            extra_flags = [
                "-I", f"{juliet_root}/C/testcasesupport",
                "-DINCLUDEMAIN",
                "-w", "-lm", "-ldl"
            ] + support_files
            
        asan_res = asan_source_baseline(
            source_path, input_path,
            input_mode=input_mode,
            argv_template=argv_template,
            extra_flags=extra_flags,
        )
    elif binary_path and os.path.exists(binary_path):
        log.info("Running GDB baseline (stripped binary)…")
        asan_res = stripped_binary_baseline(binary_path, input_path)
    else:
        log.warning("No binary or source path — skipping baseline.")
        asan_res = None

    if asan_res:
        result["asan_prediction"] = asan_res.predicted_cwe
        result["asan_correct"]    = (
            asan_res.predicted_cwe == ground_truth
            if asan_res.predicted_cwe else False
        )

    # --- angr Baseline ---
    try:
        angr_res = angr_triage(binary_path, timeout_s=60)
        result["angr_status"] = "timeout" if angr_res.timed_out else ("error" if angr_res.error else "completed")
        result["angr_timed_out"] = angr_res.timed_out
        result["angr_latency_s"] = angr_res.wall_time_s
        result["angr_states"] = angr_res.states_explored
        result["angr_error"] = angr_res.error
    except Exception as e:
        log.warning("angr baseline failed for %s: %s", bug_id, e)
        result["angr_status"] = "error"
        result["angr_timed_out"] = False
        result["angr_latency_s"] = 0.0

    # ── TRACEWISE-Lite pipeline ──────────────────────────────────────────────
    t_start = time.time()
    try:
        # Stage 1-3: build HBPG from DynamoRIO log
        dynamorio_log = os.path.join(
            dynamorio_log_dir, f"{bug_id}_trace.log"
        )
        graph = build_hbpg_from_dynamorio_log(dynamorio_log)
        
        # Extract raw counts from JSON
        raw_instr_count = 0
        stage2_count = 0
        if os.path.exists(dynamorio_log):
            try:
                with open(dynamorio_log) as f:
                    log_data = json.load(f)
                    raw_instr_count = log_data.get("dr_instructions", 0)
                    stage2_count = log_data.get("events_total", 0)
            except Exception:
                pass

        # Stage 4: semantic compression
        cr = compress(graph, max_k=30)

        result["taint_chain_found"] = cr.taint_chain_found
        result["k_used"]            = cr.k_used
        result["nodes_before"]      = cr.nodes_before
        result["nodes_after"]       = cr.nodes_after
        result["compression_ratio"] = round(cr.compression_ratio, 4)
        
        # New True Compression Metrics
        result["raw_instruction_count"] = raw_instr_count
        result["stage2_event_count"]    = stage2_count
        result["hbpg_nodes_initial"]    = cr.nodes_before
        result["hbpg_nodes_compressed"] = cr.nodes_after

        # Stage 5: LLM reasoning
        prompt    = build_llm_prompt(cr)
        tokens    = count_tokens(prompt)
        result["llm_token_count"]   = tokens
        
        if raw_instr_count > 0:
            result["true_compression_ratio"] = round(1.0 - (tokens / raw_instr_count), 6)
        else:
            result["true_compression_ratio"] = 0.0
        llm_output, raw_response = call_local_llm(prompt, model=model)

        if llm_output:
            tw_cwe  = llm_output.get("cwe_id")
            result["tracewise_prediction"]  = tw_cwe
            result["tracewise_confidence"]  = llm_output.get("confidence")
            result["tracewise_correct"]     = (tw_cwe == ground_truth)
            result["parse_status"]          = "success"
            result["llm_raw"]               = json.dumps(llm_output)
        else:
            cwe_fallback = extract_cwe_fallback(raw_response)
            if cwe_fallback:
                result["tracewise_prediction"]  = cwe_fallback
                result["tracewise_correct"]     = (cwe_fallback == ground_truth)
                result["tracewise_confidence"]  = 0.1
                result["parse_status"]          = "fallback_regex"
                result["llm_raw"]               = raw_response
            else:
                result["parse_status"]          = "total_failure"
                result["error"]                 = "LLM produced no parseable output"
                result["llm_raw"]               = raw_response

    except Exception as e:
        result["error"] = str(e)
        log.exception("Pipeline error for %s: %s", bug_id, e)

    result["pipeline_latency_s"] = round(time.time() - t_start, 2)
    log.info(
        "Done: GT=%s  ASAN=%s  TW=%s  latency=%.1fs",
        ground_truth,
        result["asan_prediction"],
        result["tracewise_prediction"],
        result["pipeline_latency_s"],
    )
    return result


# ─── Aggregate metrics ────────────────────────────────────────────────────────

def compute_summary(results: list) -> dict:
    """
    Compute the numbers that go into your evaluation tables.
    Only reports on entries that completed without error or have partial data.
    """
    valid = []
    for r in results:
        if r.get("nodes_after") is not None:
            valid.append(r)

    if not valid:
        return {"error": "No valid results"}

    n = len(valid)

    asan_correct = [r for r in valid if r.get("asan_correct")]
    tw_correct   = [r for r in valid if r.get("tracewise_correct")]
    taint_found  = [r for r in valid if r.get("taint_chain_found")]

    latencies     = [r["pipeline_latency_s"] for r in valid
                     if r.get("pipeline_latency_s")]
    comp_ratios   = [r["compression_ratio"] for r in valid
                     if r.get("compression_ratio") is not None]
    true_comp_ratios = [r["true_compression_ratio"] for r in valid
                        if r.get("true_compression_ratio") is not None]
    nodes_before  = [r["nodes_before"] for r in valid if r.get("nodes_before") is not None]
    nodes_after   = [r["nodes_after"] for r in valid if r.get("nodes_after") is not None]
    
    total_failures = len([r for r in valid if r.get("parse_status") == "total_failure"])

    summary = {
        "total_binaries":           n,
        "asan_accuracy":            round(len(asan_correct) / n, 4) if n else 0,
        "tracewise_accuracy":       round(len(tw_correct) / n, 4) if n else 0,
        "taint_chain_found_pct":    round(len(taint_found) / n, 4) if n else 0,
        "mean_latency_s":           round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "mean_compression_ratio":   round(sum(comp_ratios) / len(comp_ratios), 4) if comp_ratios else 0,
        "mean_true_compression":    round(sum(true_comp_ratios) / len(true_comp_ratios), 4) if true_comp_ratios else 0,
        "mean_nodes_before":        round(sum(nodes_before) / len(nodes_before)) if nodes_before else 0,
        "mean_nodes_after":         round(sum(nodes_after) / len(nodes_after)) if nodes_after else 0,
        "parse_failure_rate":       round(total_failures / n, 4) if n else 0,
        "errors":                   len(results) - n,
    }

    # Per-CWE breakdown
    cwe_groups = {}
    for r in valid:
        gt = r["ground_truth"]
        cwe_groups.setdefault(gt, {"n": 0, "tw_correct": 0, "asan_correct": 0})
        cwe_groups[gt]["n"]           += 1
        cwe_groups[gt]["tw_correct"]  += int(bool(r["tracewise_correct"]))
        cwe_groups[gt]["asan_correct"] += int(bool(r["asan_correct"]))

    summary["per_cwe"] = {
        cwe: {
            "n":                v["n"],
            "tracewise_acc":    round(v["tw_correct"] / v["n"], 3),
            "asan_acc":         round(v["asan_correct"] / v["n"], 3),
        }
        for cwe, v in sorted(cwe_groups.items())
    }

    # Prediction distribution
    from collections import Counter
    preds = [r.get("tracewise_prediction") for r in valid if r.get("tracewise_prediction")]
    summary["prediction_distribution"] = dict(Counter(preds).most_common())

    return summary


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="TRACEWISE-Lite full pipeline runner")
    parser.add_argument("--manifest",  required=True, help="Path to magma_manifest.json")
    parser.add_argument("--model",     default=DEFAULT_MODEL)
    parser.add_argument("--logs",      default="./dynamorio_logs",
                        help="Directory containing DynamoRIO trace logs")
    parser.add_argument("--output",    default="./results",
                        help="Output directory for results")
    parser.add_argument("--limit",     type=int, default=None,
                        help="Process only first N entries (for quick testing)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    os.makedirs(args.logs, exist_ok=True)

    with open(args.manifest) as f:
        manifest = json.load(f)

    if args.limit:
        manifest = manifest[:args.limit]
        log.info("Limiting to %d entries", args.limit)

    # Skip build_pending entries
    runnable = [e for e in manifest if e.get("status") != "build_pending"]
    log.info("Running pipeline on %d/%d entries", len(runnable), len(manifest))

    all_results = []
    for entry in runnable:
        r = run_one(entry, model=args.model, dynamorio_log_dir=args.logs)
        all_results.append(r)

        # Write intermediate JSON after every binary — safe if interrupted
        with open(os.path.join(args.output, "results.json"), "w") as f:
            json.dump(all_results, f, indent=2)

    # Write CSV
    if all_results:
        csv_path = os.path.join(args.output, "results.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)
        log.info("Results written to %s", csv_path)

    # Write summary
    summary = compute_summary(all_results)
    summary_path = os.path.join(args.output, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n=== EVALUATION SUMMARY ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
