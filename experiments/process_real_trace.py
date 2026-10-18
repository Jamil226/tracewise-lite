#!/usr/bin/env python3
"""
Process a real DynamoRIO JSON trace through the TRACEWISE-Lite pipeline.

Phase 1 Fix: Now uses RealTraceShadowHBPGConstructor which implements
Shadow Memory taint tracking to generate real TAINT_FLOW edges,
fixing the 0-edges bug on real DynamoRIO traces.
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from provenance.hbpg import RealTraceShadowHBPGConstructor, NodeType, EdgeType
from compression.engine import SemanticCompressionEngine


def load_dr_raw_events(filepath: str) -> list:
    """
    Load raw events from a DynamoRIO JSON log file.
    Supports two formats:
      1. Newline-delimited JSON (one event per line)
      2. A single JSON object with an 'events' list (from run_real_traces.py)
    """
    raw_events = []
    with open(filepath, 'r') as f:
        content = f.read().strip()

    # Try JSON object format first
    if content.startswith('{'):
        try:
            data = json.loads(content)
            raw_events = data.get('events', [])
            print(f"[*] Loaded JSON-object format: {len(raw_events)} events")
            return raw_events
        except json.JSONDecodeError:
            pass

    # Fall back to newline-delimited format
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    print(f"[*] Loaded newline-delimited format: {len(raw_events)} events")
    return raw_events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 process_real_trace.py <trace.json>")
        sys.exit(1)

    trace_path = sys.argv[1]
    print(f"[*] Loading real DynamoRIO trace: {trace_path}")
    raw_events = load_dr_raw_events(trace_path)
    print(f"[*] Loaded {len(raw_events)} raw CPU events.")

    # 1. HBPG Construction with Shadow Memory Taint Tracking
    #    (Fixes the 0-edges bug — generates real TAINT_FLOW edges)
    binary_path = os.path.splitext(os.path.basename(trace_path))[0]
    constructor = RealTraceShadowHBPGConstructor(binary_path=binary_path)
    hbpg = constructor.construct_from_raw_log(
        raw_events,
        trace_id=os.path.basename(trace_path)
    )
    print(f"[*] HBPG Constructed: {len(hbpg.nodes)} nodes, {len(hbpg.edges)} edges.")
    print(f"    Tainted addresses tracked: {len(constructor.shadow._tainted)}")

    # Show edge type breakdown
    edge_types = {}
    for e in hbpg.edges:
        t = e.edge_type.value
        edge_types[t] = edge_types.get(t, 0) + 1
    print(f"    Edge breakdown: {edge_types}")

    # Show if taint path exists (INPUT_SOURCE → ... → CRASH_SITE)
    input_nodes = hbpg.get_nodes_by_type(NodeType.INPUT_SOURCE)
    crash_nodes = hbpg.get_nodes_by_type(NodeType.CRASH_SITE)
    if input_nodes and crash_nodes:
        paths = hbpg.find_taint_paths(input_nodes[0].node_id, crash_nodes[0].node_id)
        print(f"    Taint paths (INPUT_SOURCE → CRASH_SITE): {len(paths)} found")
        if paths:
            print(f"    Shortest path length: {min(len(p) for p in paths)} nodes")
    else:
        missing = []
        if not input_nodes: missing.append("INPUT_SOURCE")
        if not crash_nodes: missing.append("CRASH_SITE")
        print(f"    [!] Missing nodes: {missing} — check trace coverage")

    # 2. Semantic Compression
    engine = SemanticCompressionEngine()
    compressed = engine.compress(hbpg)

    print("\n=======================================================")
    print(" TRACEWISE-Lite Real Telemetry Compression Results")
    print("=======================================================")
    print(f" Original Nodes:        {engine.stats.original_nodes}")
    print(f" Compressed Nodes:      {engine.stats.compressed_nodes} ({(1 - engine.stats.compressed_nodes/max(1, engine.stats.original_nodes))*100:.1f}% reduction)")
    print(f" Original Edges:        {engine.stats.original_edges}")
    print(f" Compressed Edges:      {engine.stats.compressed_edges} ({(1 - engine.stats.compressed_edges/max(1, engine.stats.original_edges))*100:.1f}% reduction)")
    print(f" Semantic Preservation: {engine.stats.semantic_preservation_score:.3f}")
    print("=======================================================\n")

