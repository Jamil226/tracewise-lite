#!/usr/bin/env python3
"""
TRACEWISE-Lite Baseline Comparison Runner
Evaluates LLM performance across different telemetry representations.
"""
import sys
import os
import time
import json
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from instrumentation.dynamorio_client import ExecutionTrace
from provenance.collector import SelectiveProvenanceCollector
from provenance.hbpg import HBPGConstructor
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule

# Setup pipeline components
collector = SelectiveProvenanceCollector()
constructor = HBPGConstructor()
compressor = SemanticCompressionEngine()
llm = LLMReasoningModule()

def load_real_trace(filepath: str) -> ExecutionTrace:
    from instrumentation.dynamorio_client import EventType, ExecutionEvent
    events = []
    with open(filepath, 'r') as f:
        for line in f:
            if not line.strip(): continue
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
    
    trace = ExecutionTrace(trace_id=os.path.basename(filepath), binary_path="real_binary", events=events)
    trace.metadata['vulnerability_type'] = 'buffer_overflow' 
    return trace

def count_tokens(text: str) -> int:
    # Simple heuristic: 1 token ~= 4 chars
    return len(text) // 4

def evaluate_baseline(trace_path: str):
    print(f"[*] Evaluating Baselines for: {trace_path}")
    trace = load_real_trace(trace_path)
    
    results = []
    
    # 1. Raw Trace (Naive Truncation to 4k tokens)
    print("    -> Running Baseline 1: Naive Truncation")
    raw_list = [e.__dict__ for e in trace.events]
    raw_json = json.dumps(raw_list, default=str)
    raw_tokens = count_tokens(raw_json)
    
    if raw_tokens > 4000:
        # Convert back to a list of primitive dicts to avoid Enum serialization errors later
        primitive_list = json.loads(raw_json)
        truncated_list = primitive_list[:50]
        start_time = time.time()
        analysis = llm.analyze_provenance_summary(truncated_list)
        latency = time.time() - start_time
        results.append({
            "Method": "Naive Truncation",
            "Tokens": 4000,
            "Accuracy": 1 if (analysis and analysis.confidence > 0) else 0,
            "CWE": analysis.cwe_id if analysis else "Failed",
            "Latency": latency
        })
    
    # 2. HBPG No Compression
    print("    -> Running Baseline 2: Uncompressed HBPG")
    filtered = collector.process_trace(trace)
    hbpg = constructor.construct(filtered)
    uncompressed_dict = hbpg.to_dict()
    uncompressed_json = json.dumps(uncompressed_dict)
    uncompressed_tokens = count_tokens(uncompressed_json)
    
    start_time = time.time()
    analysis = llm.analyze_provenance_summary(uncompressed_dict)
    latency = time.time() - start_time
    results.append({
        "Method": "HBPG (Uncompressed)",
        "Tokens": uncompressed_tokens,
        "Accuracy": 1 if (analysis and analysis.cwe_id == 'CWE-121') else 0,
        "CWE": analysis.cwe_id if analysis else "Failed",
        "Latency": latency
    })

    # 3. TRACEWISE-Lite (Compressed)
    print("    -> Running Baseline 3: TRACEWISE-Lite (Compressed HBPG)")
    compressed_hbpg = compressor.compress(hbpg)
    compressed_dict = compressed_hbpg.to_dict()
    compressed_json = json.dumps(compressed_dict)
    compressed_tokens = count_tokens(compressed_json)
    
    start_time = time.time()
    analysis = llm.analyze_provenance_summary(compressed_dict)
    latency = time.time() - start_time
    results.append({
        "Method": "TRACEWISE-Lite",
        "Tokens": compressed_tokens,
        "Accuracy": 1 if (analysis and analysis.cwe_id == 'CWE-121') else 0,
        "CWE": analysis.cwe_id if analysis else "Failed",
        "Latency": latency
    })

    # Print Table
    print("\n=================================================================")
    print(f"{'Method':<25} | {'CWE Detected':<15} | {'Tokens':<8} | {'Latency':<8}")
    print("-----------------------------------------------------------------")
    for r in results:
        print(f"{r['Method']:<25} | {str(r['CWE']):<15} | {r['Tokens']:<8} | {r['Latency']:.2f}s")
    print("=================================================================\n")


if __name__ == "__main__":
    if not llm.client.is_available():
        print("[!] ERROR: Ollama is not running on localhost:11434")
        print("    Please start ollama: `ollama serve` and ensure you have pulled `qwen2.5-coder`")
        sys.exit(1)
        
    if len(sys.argv) < 2:
        print("Usage: python3 run_baselines.py <trace.json>")
        sys.exit(1)
        
    evaluate_baseline(sys.argv[1])
