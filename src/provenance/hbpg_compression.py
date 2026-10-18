"""
hbpg_compression.py
TRACEWISE-Lite — Semantic Compression Pipeline (Stage 4)

Drop this file into your /hbpg/ directory.
Replaces any fixed k=5 hop logic you currently have.

Requirements:
    pip install networkx
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import networkx as nx

logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s | %(name)s | %(message)s")
log = logging.getLogger("tracewise.compression")


# ─── Node / Edge type enums ───────────────────────────────────────────────────

class NodeType(str, Enum):
    SOURCE = "SOURCE"
    MEMORY = "MEMORY"
    CALL   = "CALL"
    CRASH  = "CRASH"

class EdgeType(str, Enum):
    TAINT     = "TAINT"
    PROPAGATE = "PROPAGATE"
    CONTROL   = "CONTROL"

# ─── Result container ─────────────────────────────────────────────────────────

@dataclass
class CompressionResult:
    graph:               nx.DiGraph
    k_used:              int
    taint_chain_found:   bool
    fallback_reason:     Optional[str]   # populated when taint_chain_found=False
    nodes_before:        int
    nodes_after:         int
    edges_before:        int
    edges_after:         int
    compression_ratio:   float           # fraction of nodes removed

    def to_llm_json(self) -> dict:
        """
        Serialise the compressed graph to the dict that gets
        embedded in the LLM prompt.  Token count stays small.
        """
        return {
            "meta": {
                "taint_chain_found": self.taint_chain_found,
                "fallback_reason":   self.fallback_reason,
                "k_used":            self.k_used,
                "compression_ratio": round(self.compression_ratio, 4),
            },
            "nodes": [
                {
                    "id":       n,
                    "type":     self.graph.nodes[n].get("type"),
                    "label":    self.graph.nodes[n].get("label"),
                    "address":  self.graph.nodes[n].get("address"),
                    "cwe_hint": self.graph.nodes[n].get("cwe_hint"),
                }
                for n in self.graph.nodes
            ],
            "edges": [
                {
                    "src":  u,
                    "dst":  v,
                    "type": self.graph[u][v].get("type"),
                }
                for u, v in self.graph.edges
            ],
        }


# ─── Helper: find the CRASH node ─────────────────────────────────────────────

def _find_crash_node(graph: nx.DiGraph) -> Optional[str]:
    for n, attrs in graph.nodes(data=True):
        if attrs.get("type") == NodeType.CRASH:
            return n
    return None


def _find_source_nodes(graph: nx.DiGraph) -> list:
    return [n for n, a in graph.nodes(data=True)
            if a.get("type") == NodeType.SOURCE]


# ─── Algorithm 1: Taint-Centric Reduction  O(V+E) ────────────────────────────

def taint_centric_reduction(graph: nx.DiGraph) -> nx.DiGraph:
    """
    Remove every node NOT reachable from a SOURCE node via
    TAINT or PROPAGATE edges (forward BFS).

    EXCEPTION: If no CRASH node exists in the graph, skip pruning
    entirely and return the full graph. Pruning without a crash anchor
    destroys semantic content in programs where the fault signal was
    not captured as a formal CRASH node (e.g. Juliet bad() functions).
    """
    # NEW: if no crash node, return full graph — do not prune
    crash_check = _find_crash_node(graph)
    if crash_check is None:
        log.info("Algorithm 1: no CRASH node found — "
                 "skipping taint reduction to preserve graph content.")
        return graph.copy()

    # Original logic — only runs when CRASH node exists
    taint_edge_types = {EdgeType.TAINT, EdgeType.PROPAGATE}
    taint_subgraph = nx.DiGraph()
    taint_subgraph.add_nodes_from(graph.nodes(data=True))

    for u, v, data in graph.edges(data=True):
        if data.get("type") in taint_edge_types:
            taint_subgraph.add_edge(u, v, **data)

    sources = _find_source_nodes(graph)
    if not sources:
        log.warning("Algorithm 1: no SOURCE nodes found — graph unchanged.")
        return graph.copy()

    reachable = set()
    for s in sources:
        reachable |= nx.descendants(taint_subgraph, s)
        reachable.add(s)

    # Always keep CRASH node even if unreachable from sources
    crash = _find_crash_node(graph)
    if crash:
        reachable.add(crash)

    reduced = graph.subgraph(reachable).copy()
    log.info("Algorithm 1 | %d → %d nodes", graph.number_of_nodes(),
             reduced.number_of_nodes())
    return reduced


# ─── Algorithm 2: Adaptive Crash-Context Preservation  O(k·E) ────────────────

def crash_context_preservation(
    graph: nx.DiGraph,
    base_k: int = 5,
    max_k: int = 12,
) -> tuple[nx.DiGraph, int, bool, Optional[str]]:
    """
    Adaptive k-hop backward BFS from CRASH node.

    Strategy
    --------
    1. Start at k=2.  Expand until a SOURCE node enters the
       predecessor window — that k is the minimal sufficient depth.
    2. If no SOURCE is found up to max_k, the vulnerability likely
       has no input taint chain (typical for CWE-476, CWE-190).
       Fall back to CONTROL-edge-only context with k=3.
    3. Always retain the CRASH node itself.

    Returns
    -------
    (subgraph, k_used, taint_chain_found, fallback_reason)
    """
    crash = _find_crash_node(graph)
    if crash is None:
        log.warning("Algorithm 2: no CRASH node — returning full graph.")
        return graph.copy(), base_k, False, "no_crash_node"

    reversed_graph = graph.reverse(copy=True)

    # ── Phase 1: grow k until a SOURCE is enclosed ──────────────────────────
    taint_reverse = nx.DiGraph()
    for u, v, d in reversed_graph.edges(data=True):
        if d.get("type") in {EdgeType.TAINT, EdgeType.PROPAGATE}:
            taint_reverse.add_edge(u, v, **d)
    taint_reverse.add_nodes_from(reversed_graph.nodes(data=True))

    found_k      = None
    found_nodes  = None

    for k in range(2, max_k + 1):
        try:
            reachable_at_k = nx.single_source_shortest_path_length(
                taint_reverse, crash, cutoff=k
            )
        except nx.NetworkXError:
            break

        has_source = any(
            graph.nodes[n].get("type") == NodeType.SOURCE
            for n in reachable_at_k
        )
        if has_source:
            found_k     = k
            found_nodes = set(reachable_at_k.keys())
            log.info("Algorithm 2 | taint chain enclosed at k=%d", k)
            break

    # ── Phase 2: taint chain found — return taint-context subgraph ──────────
    if found_nodes is not None:
        # Also pull in all original edges between retained nodes
        subgraph = graph.subgraph(found_nodes).copy()
        log.info("Algorithm 2 | k=%d | %d → %d nodes",
                 found_k, graph.number_of_nodes(), subgraph.number_of_nodes())
        return subgraph, found_k, True, None

    # ── Phase 3: no taint chain — fall back to CONTROL-edge context ──────────
    log.warning(
        "Algorithm 2 | no SOURCE found within k=%d hops via TAINT/PROPAGATE. "
        "Falling back to CONTROL-edge context (k=3). "
        "Likely CWE-476 / CWE-190 / uninitialised variable.", max_k
    )
    control_reverse = nx.DiGraph()
    for u, v, d in reversed_graph.edges(data=True):
        if d.get("type") == EdgeType.CONTROL:
            control_reverse.add_edge(u, v, **d)
    control_reverse.add_nodes_from(reversed_graph.nodes(data=True))

    try:
        control_predecessors = nx.single_source_shortest_path_length(
            control_reverse, crash, cutoff=3
        )
        fallback_nodes = set(control_predecessors.keys())
    except nx.NetworkXError:
        fallback_nodes = {crash}

    subgraph = graph.subgraph(fallback_nodes).copy()
    reason   = "no_taint_source_found_control_fallback"
    log.info("Algorithm 2 fallback | %d nodes retained", subgraph.number_of_nodes())
    return subgraph, max_k, False, reason


# ─── Algorithm 3: Semantic Deduplication  O(V²) ──────────────────────────────

def semantic_deduplication(graph: nx.DiGraph) -> nx.DiGraph:
    """
    Merge nodes that are structurally identical:
      same type + same label hash + isomorphic incident edge-type sets.

    After Algorithms 1 & 2 the graph is small, so O(V²) is cheap.
    """
    if graph.number_of_nodes() == 0:
        return graph.copy()

    nodes   = list(graph.nodes(data=True))
    mapping = {}   # old_id → canonical_id

    def _signature(node_id, attrs):
        in_types  = frozenset(
            graph[u][node_id].get("type") for u in graph.predecessors(node_id)
        )
        out_types = frozenset(
            graph[node_id][v].get("type") for v in graph.successors(node_id)
        )
        return (attrs.get("type"), attrs.get("label"), in_types, out_types)

    canonical = {}   # signature → first node_id with that signature

    for node_id, attrs in nodes:
        sig = _signature(node_id, attrs)
        if sig in canonical:
            mapping[node_id] = canonical[sig]
        else:
            canonical[sig]   = node_id
            mapping[node_id] = node_id

    merged = nx.DiGraph()
    for node_id, attrs in nodes:
        cid = mapping[node_id]
        if not merged.has_node(cid):
            merged.add_node(cid, **attrs)

    for u, v, data in graph.edges(data=True):
        cu, cv = mapping[u], mapping[v]
        if cu != cv:
            merged.add_edge(cu, cv, **data)

    log.info("Algorithm 3 | %d → %d nodes",
             graph.number_of_nodes(), merged.number_of_nodes())
    return merged


# ─── Algorithm 4: Path Abstraction  O(V+E) ───────────────────────────────────

def path_abstraction(graph: nx.DiGraph) -> nx.DiGraph:
    """
    Collapse maximal linear chains (in-degree=1, out-degree=1 via TAINT)
    into single meta-nodes.  Endpoints are always preserved.
    """
    if graph.number_of_nodes() == 0:
        return graph.copy()

    def _is_interior(n):
        """True iff node is a chain interior — not a SOURCE or CRASH."""
        if graph.nodes[n].get("type") in {NodeType.SOURCE, NodeType.CRASH}:
            return False
        preds = [
            p for p in graph.predecessors(n)
            if graph[p][n].get("type") in {EdgeType.TAINT, EdgeType.PROPAGATE}
        ]
        succs = [
            s for s in graph.successors(n)
            if graph[n][s].get("type") in {EdgeType.TAINT, EdgeType.PROPAGATE}
        ]
        return len(preds) == 1 and len(succs) == 1

    # Find all interior nodes
    interior = {n for n in graph.nodes if _is_interior(n)}

    # Build chains: connected sets of interior nodes
    interior_subgraph = graph.subgraph(interior)
    chains = list(nx.weakly_connected_components(interior_subgraph))

    # For each chain, find head/tail and collapse
    abstract = graph.copy()
    collapsed = 0

    for chain_set in chains:
        if len(chain_set) < 2:
            continue

        chain_graph = graph.subgraph(chain_set)
        # Head: node with an external predecessor
        heads = [
            n for n in chain_set
            if any(p not in chain_set for p in graph.predecessors(n))
        ]
        tails = [
            n for n in chain_set
            if any(s not in chain_set for s in graph.successors(n))
        ]

        if not heads or not tails:
            continue

        head, tail = heads[0], tails[0]
        meta_id    = f"META_{head}_{tail}"

        # Aggregate labels
        chain_labels = [
            graph.nodes[n].get("label", "") for n in chain_set
        ]
        meta_attrs = {
            "type":       NodeType.MEMORY,
            "label":      f"chain({len(chain_set)} nodes): {chain_labels[0]}…{chain_labels[-1]}",
            "address":    graph.nodes[head].get("address"),
            "cwe_hint":   next(
                (graph.nodes[n].get("cwe_hint") for n in chain_set
                 if graph.nodes[n].get("cwe_hint")), None
            ),
        }

        abstract.add_node(meta_id, **meta_attrs)

        # Re-wire external edges
        for p in list(abstract.predecessors(head)):
            if p not in chain_set:
                abstract.add_edge(p, meta_id, **abstract[p][head])
        for s in list(abstract.successors(tail)):
            if s not in chain_set:
                abstract.add_edge(meta_id, s, **abstract[tail][s])

        abstract.remove_nodes_from(chain_set)
        collapsed += len(chain_set)

    log.info("Algorithm 4 | collapsed %d interior nodes into meta-nodes", collapsed)
    return abstract


# ─── Algorithm 5: Criticality Scoring  O(V log V) ────────────────────────────

def criticality_scoring(
    graph:   nx.DiGraph,
    theta:   float = 0.30,
    alpha:   float = 0.50,   # proximity to crash weight
    beta:    float = 0.30,   # node type weight
    gamma:   float = 0.20,   # CWE hint weight
) -> nx.DiGraph:
    """
    Score each node and prune those below threshold theta.
    CRASH and SOURCE nodes are always retained (score forced to 1.0).
    """
    crash = _find_crash_node(graph)
    if crash is None or graph.number_of_nodes() == 0:
        return graph.copy()

    type_weight = {
        NodeType.SOURCE: 1.0,
        NodeType.CALL:   0.8,
        NodeType.CRASH:  1.0,
        NodeType.MEMORY: 0.4,
    }

    # Shortest-path distances from crash (reversed)
    try:
        dist_from_crash = nx.single_source_shortest_path_length(
            graph.reverse(copy=True), crash
        )
    except Exception:
        return graph.copy()

    max_dist = max(dist_from_crash.values()) if dist_from_crash else 1

    def _score(node_id):
        node_type = graph.nodes[node_id].get("type", NodeType.MEMORY)
        # Protected nodes
        if node_type in {NodeType.SOURCE, NodeType.CRASH}:
            return 1.0
        d       = dist_from_crash.get(node_id, max_dist + 1)
        prox    = 1.0 - (d / (max_dist + 1))          # 1.0 = adjacent to crash
        w_type  = type_weight.get(node_type, 0.4)
        has_cwe = 1.0 if graph.nodes[node_id].get("cwe_hint") else 0.0
        return alpha * prox + beta * w_type + gamma * has_cwe

    scores  = {n: _score(n) for n in graph.nodes}
    keep    = {n for n, s in scores.items() if s >= theta}
    pruned  = graph.subgraph(keep).copy()

    log.info(
        "Algorithm 5 | theta=%.2f | %d → %d nodes (pruned %d)",
        theta, graph.number_of_nodes(), pruned.number_of_nodes(),
        graph.number_of_nodes() - pruned.number_of_nodes(),
    )
    return pruned


# ─── Public entry point ───────────────────────────────────────────────────────

def compress(
    graph:   nx.DiGraph,
    base_k:  int   = 5,
    max_k:   int   = 12,
    theta:   float = 0.30,
    min_nodes_for_pruning: int = 8,
) -> CompressionResult:
    """
    Apply all five compression algorithms in sequence and return
    a CompressionResult with full provenance metadata.

    Parameters
    ----------
    graph   : HBPG as a networkx DiGraph.
              Node attributes expected: type, label, address, cwe_hint
              Edge attributes expected: type
    base_k  : starting k for adaptive hop search (ignored — search starts at 2)
    max_k   : maximum k before falling back to CONTROL-edge context
    theta   : criticality pruning threshold (0.0–1.0)

    Returns
    -------
    CompressionResult
    """
    n_before = graph.number_of_nodes()
    e_before = graph.number_of_edges()

    log.info("=== TRACEWISE-Lite Compression START | %d nodes %d edges ===",
             n_before, e_before)

    # Stage 4.1
    g1 = taint_centric_reduction(graph)

    # Stage 4.2
    g2, k_used, taint_found, fallback = crash_context_preservation(
        g1, base_k=base_k, max_k=max_k
    )

    # Stage 4.3
    g3 = semantic_deduplication(g2)

    # Stage 4.4
    g4 = path_abstraction(g3)

    # Stage 4.5: only prune if graph is rich enough
    if g4.number_of_nodes() >= min_nodes_for_pruning:
        g5 = criticality_scoring(g4, theta=theta)
    else:
        g5 = g4   # skip pruning — graph too sparse already
        log.info("Algorithm 5 skipped — graph has only %d nodes "
                 "(below floor of %d)", g4.number_of_nodes(), 
                 min_nodes_for_pruning)

    n_after = g5.number_of_nodes()
    e_after = g5.number_of_edges()
    ratio   = 1.0 - (n_after / n_before) if n_before > 0 else 0.0

    log.info("=== Compression DONE | %d→%d nodes | ratio=%.4f | "
             "taint_chain=%s | k=%d ===",
             n_before, n_after, ratio, taint_found, k_used)

    return CompressionResult(
        graph             = g5,
        k_used            = k_used,
        taint_chain_found = taint_found,
        fallback_reason   = fallback,
        nodes_before      = n_before,
        nodes_after       = n_after,
        edges_before      = e_before,
        edges_after       = e_after,
        compression_ratio = ratio,
    )


# ─── LLM prompt builder ──────────────────────────────────────────────────────

def build_llm_prompt(result: CompressionResult) -> str:
    """
    Build the prompt string sent to the local model via Ollama.
    The taint_chain_found flag changes the instruction to the LLM,
    which is the key fix for CWE-476 and CWE-190 accuracy.
    """
    graph_json = json.dumps(result.to_llm_json(), indent=2)

    if result.taint_chain_found:
        context_instruction = (
            "A direct user-input taint chain IS present in this trace. "
            "Focus on data-flow from SOURCE nodes to the CRASH site."
        )
    else:
        context_instruction = (
            f"NOTE: No direct user-input taint chain was found "
            f"(reason: {result.fallback_reason}). "
            "This pattern is consistent with CWE-476 (NULL Pointer Dereference) "
            "or CWE-190 (Integer Overflow) where the root cause is not "
            "direct user input. "
            "Focus on the CONTROL-flow context near the CRASH node and "
            "look for uninitialised pointer dereferences or arithmetic "
            "boundary violations."
        )

    prompt = f"""You are a binary vulnerability analysis expert.
Below is a compressed execution provenance graph in JSON format.

{context_instruction}

Graph:
{graph_json}

Before classifying, reason step by step:
1. What functions are present in the graph nodes?
2. What is the edge type connecting them (TAINT/PROPAGATE/CONTROL)?
3. Which CWE pattern does this most closely match?

Only after reasoning, respond with a JSON object:
{{
  "reasoning": "<your step-by-step analysis>",
  "cwe_id":    "<e.g. CWE-121>",
  "cwe_name":  "<full CWE name>",
  "confidence": <float 0.0-1.0>,
  "root_cause": "<one paragraph>",
  "exploit_score": <integer 0-10>,
  "key_nodes": ["<node_id>", ...]
}}

IMPORTANT: If the graph has fewer than 3 nodes and no clear taint chain,
set confidence below 0.4 and explain what information is missing.
Do not default to CWE-476 unless the evidence specifically shows a null
pointer dereference pattern.
"""
    return prompt


# ─── Minimal smoke test ──────────────────────────────────────────────────────

if __name__ == "__main__":
    # Build a toy HBPG that mimics a stack buffer overflow
    G = nx.DiGraph()

    G.add_node("src_read",    type=NodeType.SOURCE, label="read(fd,buf,256)",
               address="0x401020", cwe_hint=None)
    G.add_node("mem_buf",     type=NodeType.MEMORY, label="stack_buf[64]",
               address="0x7ffe1000", cwe_hint="CWE-121")
    G.add_node("call_strcpy", type=NodeType.CALL,   label="strcpy(dest,src)",
               address="0x401080", cwe_hint="CWE-121")
    G.add_node("mem_dest",    type=NodeType.MEMORY, label="dest_buf[32]",
               address="0x7ffe1080", cwe_hint=None)
    # loop nodes — should be deduplicated / abstracted
    for i in range(5):
        G.add_node(f"loop_{i}", type=NodeType.MEMORY,
                   label="loop_iter", address="0x401090", cwe_hint=None)
    G.add_node("crash",       type=NodeType.CRASH,  label="SIGSEGV@0x4010b0",
               address="0x4010b0", cwe_hint=None)

    G.add_edge("src_read",    "mem_buf",     type=EdgeType.TAINT)
    G.add_edge("mem_buf",     "call_strcpy", type=EdgeType.TAINT)
    G.add_edge("call_strcpy", "mem_dest",   type=EdgeType.PROPAGATE)
    for i in range(5):
        prev = "mem_dest" if i == 0 else f"loop_{i-1}"
        G.add_edge(prev, f"loop_{i}", type=EdgeType.TAINT)
    G.add_edge("loop_4", "crash", type=EdgeType.CONTROL)

    result = compress(G)

    print("\n=== LLM JSON (what gets sent to model) ===")
    print(json.dumps(result.to_llm_json(), indent=2))

    print("\n=== LLM Prompt ===")
    print(build_llm_prompt(result))
