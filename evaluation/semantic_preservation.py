"""
Semantic Preservation Evaluator for TRACEWISE-Lite

Computes formal metrics that validate the core claim:
"semantic-preserving provenance compression enabling lightweight
local LLM vulnerability reasoning on commodity hardware."

All algorithms are implemented from first principles for
reproducibility and transparency.
"""

import os
import sys
import json
import math
import hashlib
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from provenance.hbpg import (
    HybridBinaryProvenanceGraph, HBPGNode, HBPGEdge,
    NodeType, EdgeType
)
from evaluation.metrics import SemanticPreservationMetrics, CompressionMetrics


# ---------------------------------------------------------------------------
# Graph Similarity Algorithms
# ---------------------------------------------------------------------------

def compute_graph_edit_distance(
    G1: HybridBinaryProvenanceGraph,
    G2: HybridBinaryProvenanceGraph,
    max_cost: float = 1000.0
) -> float:
    """
    Approximate Graph Edit Distance (GED) using node/edge type-aware costs.

    We use a heuristic approximation suitable for security provenance graphs:
    - Node substitution cost = 0 if same type, 1 if different type
    - Node deletion/insertion cost = 1 per node
    - Edge deletion/insertion cost = 0.5 per edge

    This is an upper-bound approximation. Exact GED is NP-hard.
    """
    # Node-based cost
    nodes1 = set(G1.nodes.keys())
    nodes2 = set(G2.nodes.keys())

    common = nodes1 & nodes2
    only_in_1 = nodes1 - nodes2
    only_in_2 = nodes2 - nodes1

    cost = 0.0

    # Substitution cost for common nodes
    for nid in common:
        n1 = G1.nodes[nid]
        n2 = G2.nodes[nid]
        if n1.node_type != n2.node_type:
            cost += 1.0
        elif n1.label != n2.label:
            cost += 0.5

    # Deletions
    cost += len(only_in_1) * 1.0
    # Insertions
    cost += len(only_in_2) * 1.0

    # Edge costs
    edges1 = set((e.source, e.target, e.edge_type.value) for e in G1.edges)
    edges2 = set((e.source, e.target, e.edge_type.value) for e in G2.edges)

    edge_common = edges1 & edges2
    edge_only_1 = edges1 - edges2
    edge_only_2 = edges2 - edges1

    cost += len(edge_only_1) * 0.5
    cost += len(edge_only_2) * 0.5

    return min(cost, max_cost)


def compute_weisfeiler_lehman_similarity(
    G1: HybridBinaryProvenanceGraph,
    G2: HybridBinaryProvenanceGraph,
    iterations: int = 5
) -> float:
    """
    Weisfeiler-Lehman graph kernel similarity.

    Iteratively aggregates neighbor labels to compute graph "fingerprints."
    The similarity is the cosine similarity between final label histograms.

    This captures structural similarity even when node IDs differ.
    """
    def wl_fingerprint(G: HybridBinaryProvenanceGraph, iters: int) -> Counter:
        # Initialize labels with node types
        labels = {}
        for nid, node in G.nodes.items():
            labels[nid] = f"{node.node_type.value}:{node.label[:20]}"

        for _ in range(iters):
            new_labels = {}
            for nid in G.nodes:
                # Collect neighbor labels
                neighbor_labels = []
                for edge in G.edges:
                    if edge.source == nid:
                        neighbor_labels.append(labels.get(edge.target, ""))
                    elif edge.target == nid:
                        neighbor_labels.append(labels.get(edge.source, ""))

                # Sort for canonical ordering
                neighbor_labels.sort()
                # Hash the combined label
                combined = labels[nid] + "|" + ",".join(neighbor_labels)
                new_labels[nid] = hashlib.md5(combined.encode()).hexdigest()[:8]
            labels = new_labels

        return Counter(labels.values())

    fp1 = wl_fingerprint(G1, iterations)
    fp2 = wl_fingerprint(G2, iterations)

    # Cosine similarity between histograms
    all_keys = set(fp1.keys()) | set(fp2.keys())
    dot = sum(fp1[k] * fp2[k] for k in all_keys)
    norm1 = math.sqrt(sum(v ** 2 for v in fp1.values()))
    norm2 = math.sqrt(sum(v ** 2 for v in fp2.values()))

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return dot / (norm1 * norm2)


def compute_jaccard_similarity(set1: Set, set2: Set) -> float:
    """Jaccard similarity between two sets."""
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Taint-Path Preservation
# ---------------------------------------------------------------------------

def find_taint_paths(G: HybridBinaryProvenanceGraph) -> List[List[str]]:
    """
    Find all taint propagation paths from input sources to sinks/crashes.
    
    Returns list of paths (each path is list of node IDs).
    """
    # Find all input source nodes
    sources = [nid for nid, n in G.nodes.items()
               if n.node_type == NodeType.INPUT_SOURCE]

    # Find all sink/crash nodes
    sinks = [nid for nid, n in G.nodes.items()
             if n.node_type in (NodeType.CRASH_SITE, NodeType.FUNCTION)
             and any(kw in n.label for kw in ['strcpy', 'memcpy', 'system', 'sprintf'])]

    if not sources or not sinks:
        return []

    # Find paths via BFS
    paths = []
    for source in sources:
        for sink in sinks:
            # BFS from source to sink following taint/data edges
            queue = [(source, [source])]
            visited = {source}
            while queue and len(paths) < 100:  # limit for efficiency
                current, path = queue.pop(0)
                if current == sink and len(path) > 1:
                    paths.append(path)
                    break
                for edge in G.edges:
                    if edge.source == current and edge.target not in visited:
                        if edge.edge_type in (EdgeType.TAINT_FLOW, EdgeType.DATA_DEPENDENCY,
                                             EdgeType.MEMORY_PROPAGATION, EdgeType.CONTROL_FLOW):
                            visited.add(edge.target)
                            queue.append((edge.target, path + [edge.target]))

    return paths


def compute_taint_path_preservation(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph
) -> Tuple[float, float, float]:
    """
    Measure taint path preservation between original and compressed graphs.

    Returns:
        (path_preservation_rate, source_retention, sink_retention)
    """
    orig_paths = find_taint_paths(original)
    comp_paths = find_taint_paths(compressed)

    # Path preservation: fraction of original paths still present
    preserved = 0
    for op in orig_paths:
        # Check if a similar path exists in compressed
        for cp in comp_paths:
            # Check if compressed path contains the key nodes
            op_set = set(op)
            cp_set = set(cp)
            if len(op_set & cp_set) >= max(2, len(op_set) * 0.5):
                preserved += 1
                break

    path_rate = preserved / max(len(orig_paths), 1)

    # Source retention
    orig_sources = {nid for nid, n in original.nodes.items()
                    if n.node_type == NodeType.INPUT_SOURCE}
    comp_sources = {nid for nid, n in compressed.nodes.items()
                    if n.node_type == NodeType.INPUT_SOURCE}
    source_retention = compute_jaccard_similarity(
        {original.nodes[s].label for s in orig_sources},
        {compressed.nodes[s].label for s in comp_sources}
    ) if orig_sources else 1.0

    # Sink retention
    orig_sinks = {nid for nid, n in original.nodes.items()
                  if n.node_type == NodeType.FUNCTION
                  and any(kw in n.label for kw in ['strcpy', 'memcpy', 'system'])}
    comp_sinks = {nid for nid, n in compressed.nodes.items()
                  if n.node_type == NodeType.FUNCTION
                  and any(kw in n.label for kw in ['strcpy', 'memcpy', 'system'])}
    sink_retention = compute_jaccard_similarity(
        {original.nodes[s].label for s in orig_sinks},
        {compressed.nodes[s].label for s in comp_sinks}
    ) if orig_sinks else 1.0

    return path_rate, source_retention, sink_retention


# ---------------------------------------------------------------------------
# Attack Chain Preservation
# ---------------------------------------------------------------------------

def find_attack_chain(G: HybridBinaryProvenanceGraph) -> List[str]:
    """
    Extract the attack chain: input source -> ... -> crash site.
    
    Returns node IDs along the critical attack path.
    """
    inputs = [nid for nid, n in G.nodes.items() if n.node_type == NodeType.INPUT_SOURCE]
    crashes = [nid for nid, n in G.nodes.items() if n.node_type == NodeType.CRASH_SITE]

    if not inputs or not crashes:
        return []

    # Find shortest path from any input to any crash
    shortest = None
    for inp in inputs:
        for crash in crashes:
            path = _bfs_path(G, inp, crash)
            if path and (shortest is None or len(path) < len(shortest)):
                shortest = path

    return shortest or []


def _bfs_path(G: HybridBinaryProvenanceGraph, start: str, goal: str) -> List[str]:
    """BFS to find shortest path."""
    from collections import deque
    queue = deque([(start, [start])])
    visited = {start}

    while queue:
        current, path = queue.popleft()
        if current == goal:
            return path
        for edge in G.edges:
            if edge.source == current and edge.target not in visited:
                visited.add(edge.target)
                queue.append((edge.target, path + [edge.target]))
    return []


def compute_attack_chain_preservation(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph
) -> Tuple[float, bool]:
    """
    Measure attack chain preservation.

    Returns:
        (jaccard_similarity, chain_preserved_boolean)
    """
    orig_chain = find_attack_chain(original)
    comp_chain = find_attack_chain(compressed)

    if not orig_chain:
        return 1.0, True  # no chain in original, trivially preserved

    if not comp_chain:
        return 0.0, False  # chain lost

    # Jaccard similarity of node labels along chains
    orig_labels = {original.nodes[nid].label for nid in orig_chain}
    comp_labels = {compressed.nodes[nid].label for nid in comp_chain}

    jaccard = compute_jaccard_similarity(orig_labels, comp_labels)
    preserved = jaccard >= 0.5  # at least half the chain preserved

    return jaccard, preserved


def compute_shortest_path_ratio(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph
) -> float:
    """
    Ratio of compressed shortest path length to original.

    Values near 1.0 indicate good path preservation.
    Values < 1.0 may indicate shortcuts (acceptable if semantic).
    Values >> 1.0 indicate path dilation.
    """
    orig_chain = find_attack_chain(original)
    comp_chain = find_attack_chain(compressed)

    if not orig_chain:
        return 1.0
    if not comp_chain:
        return float('inf')

    orig_len = len(orig_chain)
    comp_len = len(comp_chain)

    # Ideal: compressed path is similar length or shorter
    if comp_len <= orig_len:
        return 1.0  # compressed path is as good or better
    else:
        return orig_len / comp_len


# ---------------------------------------------------------------------------
# Crash Context Preservation
# ---------------------------------------------------------------------------

def compute_crash_context_preservation(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph,
    context_depth: int = 3
) -> Tuple[float, bool]:
    """
    Measure how well crash neighborhood is preserved.

    context_depth: number of hops around crash to consider
    """
    # Find crash nodes
    orig_crashes = [nid for nid, n in original.nodes.items()
                    if n.node_type == NodeType.CRASH_SITE]
    comp_crashes = [nid for nid, n in compressed.nodes.items()
                    if n.node_type == NodeType.CRASH_SITE]

    if not orig_crashes:
        return 1.0, True

    crash_present = len(comp_crashes) > 0

    if not crash_present:
        return 0.0, False

    # Get neighborhood around crash in original
    orig_neighbors = _get_neighborhood(original, orig_crashes[0], context_depth)
    comp_neighbors = _get_neighborhood(compressed, comp_crashes[0], context_depth)

    # Compare by node labels
    orig_labels = {original.nodes[nid].label for nid in orig_neighbors}
    comp_labels = {compressed.nodes[nid].label for nid in comp_neighbors}

    jaccard = compute_jaccard_similarity(orig_labels, comp_labels)

    return jaccard, crash_present


def _get_neighborhood(G: HybridBinaryProvenanceGraph, node_id: str, depth: int) -> Set[str]:
    """Get nodes within `depth` hops of `node_id`."""
    neighborhood = {node_id}
    current = {node_id}

    for _ in range(depth):
        next_level = set()
        for nid in current:
            for edge in G.edges:
                if edge.source == nid:
                    next_level.add(edge.target)
                if edge.target == nid:
                    next_level.add(edge.source)
        current = next_level - neighborhood
        neighborhood.update(next_level)

    return neighborhood


# ---------------------------------------------------------------------------
# Critical Node Retention
# ---------------------------------------------------------------------------

def compute_critical_node_retention(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph
) -> Dict[str, float]:
    """
    Measure retention of security-critical node types.

    Returns per-type retention rates.
    """
    critical_types = [
        NodeType.INPUT_SOURCE,
        NodeType.CRASH_SITE,
        NodeType.TAINT_LABEL,
        NodeType.HEAP_OBJECT,
        NodeType.SYSCALL,
    ]

    retention = {}
    for node_type in critical_types:
        orig_count = sum(1 for n in original.nodes.values() if n.node_type == node_type)
        comp_count = sum(1 for n in compressed.nodes.values() if n.node_type == node_type)

        if orig_count == 0:
            retention[node_type.value] = 1.0
        else:
            retention[node_type.value] = min(comp_count / orig_count, 1.0)

    # Overall critical retention (weighted average)
    weights = {
        'input_source': 0.30,
        'crash_site': 0.30,
        'taint_label': 0.20,
        'heap_object': 0.10,
        'syscall': 0.10,
    }

    overall = sum(retention.get(k, 0) * w for k, w in weights.items())
    retention['overall'] = overall

    return retention


# ---------------------------------------------------------------------------
# Token Count Estimation
# ---------------------------------------------------------------------------

def estimate_token_count(graph_dict: Dict) -> int:
    """
    Estimate LLM token count for a graph serialized as JSON.

    Uses a rough heuristic: ~0.75 tokens per word (GPT-style).
    """
    json_str = json.dumps(graph_dict)
    # Rough token estimate: 1 token ≈ 4 chars for JSON
    return len(json_str) // 4


# ---------------------------------------------------------------------------
# Main Evaluation Function
# ---------------------------------------------------------------------------

def evaluate_semantic_preservation(
    original: HybridBinaryProvenanceGraph,
    compressed: HybridBinaryProvenanceGraph,
    compression_time_ms: float = 0.0
) -> Tuple[SemanticPreservationMetrics, CompressionMetrics]:
    """
    Full semantic preservation evaluation.

    This is the PRIMARY evaluation function for TRACEWISE-Lite's
    core contribution.
    """
    spm = SemanticPreservationMetrics()
    cm = CompressionMetrics()

    # --- Compression metrics ---
    cm.original_nodes = len(original.nodes)
    cm.original_edges = len(original.edges)
    cm.compressed_nodes = len(compressed.nodes)
    cm.compressed_edges = len(compressed.edges)
    cm.original_tokens_est = estimate_token_count(original.to_dict())
    cm.compressed_tokens_est = estimate_token_count(compressed.to_dict())
    cm.compression_time_ms = compression_time_ms

    spm.node_retention_rate = cm.compressed_nodes / max(cm.original_nodes, 1)
    spm.edge_retention_rate = cm.compressed_edges / max(cm.original_edges, 1)

    # --- Taint path preservation ---
    taint_rate, source_ret, sink_ret = compute_taint_path_preservation(original, compressed)
    spm.taint_path_preservation_rate = taint_rate
    spm.taint_source_retention = source_ret
    spm.taint_sink_retention = sink_ret

    # --- Attack chain preservation ---
    attack_jaccard, chain_preserved = compute_attack_chain_preservation(original, compressed)
    spm.attack_chain_jaccard = attack_jaccard
    spm.attack_chain_preserved = chain_preserved
    spm.shortest_path_ratio = compute_shortest_path_ratio(original, compressed)

    # --- Crash context ---
    crash_retention, crash_present = compute_crash_context_preservation(original, compressed)
    spm.crash_context_retention = crash_retention
    spm.crash_node_present = crash_present

    # --- Critical node retention ---
    critical_retention = compute_critical_node_retention(original, compressed)
    spm.critical_node_retention = critical_retention.get('overall', 0.0)

    # Per-type retention
    spm.function_node_retention = critical_retention.get('function', 0.0)
    spm.memory_node_retention = critical_retention.get('memory_region', 0.0)
    spm.syscall_node_retention = critical_retention.get('syscall', 0.0)
    spm.heap_node_retention = critical_retention.get('heap_object', 0.0)

    # --- Graph similarity ---
    spm.graph_edit_distance = compute_graph_edit_distance(original, compressed)
    spm.graph_edit_distance_normalized = spm.graph_edit_distance / max(cm.original_nodes, 1)
    spm.weisfeiler_lehman_similarity = compute_weisfeiler_lehman_similarity(original, compressed)

    # --- Composite score ---
    spm.compute_composite()

    return spm, cm


if __name__ == '__main__':
    # Test with simulated data
    from instrumentation.dynamorio_client import TraceSimulator
    from provenance.collector import SelectiveProvenanceCollector
    from provenance.hbpg import HBPGConstructor
    from compression.engine import SemanticCompressionEngine

    trace = TraceSimulator.generate_vulnerable_trace(vulnerability_type='buffer_overflow')
    collector = SelectiveProvenanceCollector()
    filtered = collector.process_trace(trace)

    constructor = HBPGConstructor()
    hbpg = constructor.construct(filtered)

    engine = SemanticCompressionEngine()
    compressed = engine.compress(hbpg)

    spm, cm = evaluate_semantic_preservation(hbpg, compressed)

    print("=" * 60)
    print("SEMANTIC PRESERVATION RESULTS")
    print("=" * 60)
    print(f"Node retention:          {spm.node_retention_rate:.3f}")
    print(f"Edge retention:          {spm.edge_retention_rate:.3f}")
    print(f"Taint path preservation: {spm.taint_path_preservation_rate:.3f}")
    print(f"Attack chain Jaccard:    {spm.attack_chain_jaccard:.3f}")
    print(f"Crash node present:      {spm.crash_node_present}")
    print(f"Crash context retention: {spm.crash_context_retention:.3f}")
    print(f"Critical node retention: {spm.critical_node_retention:.3f}")
    print(f"WL similarity:           {spm.weisfeiler_lehman_similarity:.3f}")
    print(f"GED (normalized):        {spm.graph_edit_distance_normalized:.3f}")
    print("-" * 60)
    print(f"OVERALL SEMANTIC SCORE:  {spm.overall_semantic_score:.3f}")
    print("-" * 60)
    print(f"Compression: {cm.original_nodes} nodes -> {cm.compressed_nodes} nodes ({cm.node_reduction_ratio*100:.1f}% reduction)")
    print(f"Tokens: {cm.original_tokens_est} -> {cm.compressed_tokens_est} ({cm.token_reduction_ratio*100:.1f}% reduction)")