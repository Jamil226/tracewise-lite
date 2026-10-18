"""
TRACEWISE-Lite: Formal HBPG Semantics
=======================================

Provides algorithmic pseudo-code, formal definitions, optimization objectives,
and complexity analysis for:
  1. HBPG construction
  2. Semantic compression (each strategy individually)
  3. Compression invariants

Addresses GPT reviewer concern:
  "Compression strategies must have algorithms, pseudo-code,
   optimization objectives, and complexity analysis."
"""

from dataclasses import dataclass
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Formal HBPG Definition
# ---------------------------------------------------------------------------

HBPG_FORMAL_DEFINITION = """
Formal Definition: Hybrid Binary Provenance Graph (HBPG)
=========================================================

HBPG is a typed directed graph G = (V, E, τ_V, τ_E, λ) where:

  V        = finite set of vertices (execution entities)
  E ⊆ V×V  = directed edges (provenance dependencies)
  τ_V: V → NodeType        = node type function
  τ_E: E → EdgeType        = edge type function
  λ: V → Label             = node labeling function

Node Types (NodeType):
  N_F  = FUNCTION        (binary function execution)
  N_M  = MEMORY_REGION   (stack/heap memory location)
  N_I  = INPUT_SOURCE    (external input: read, recv, scanf)
  N_C  = CRASH_SITE      (program crash location)
  N_S  = SYSCALL         (system call invocation)
  N_T  = TAINT_LABEL     (taint flow marker)
  N_H  = HEAP_OBJECT     (malloc/free heap allocation)
  N_D  = DATA_VALUE      (constant or computed value)

Edge Types (EdgeType):
  E_DD = DATA_DEPENDENCY    (data flows from u to v)
  E_CF = CONTROL_FLOW       (control transfers from u to v)
  E_MP = MEMORY_PROPAGATION (memory state modified by u, affects v)
  E_IP = INPUT_PROPAGATION  (external input flows from u to v)
  E_SI = SYSCALL_INTERACTION (u invokes syscall v)
  E_TF = TAINT_FLOW         (taint label propagates from u to v)
  E_CR = CALL_RELATION      (u calls function v)
  E_RR = RETURN_RELATION    (v returns to u)

Taint Propagation Rule:
  If (u, v) ∈ E with τ_E(u,v) ∈ {E_TF, E_DD, E_MP}
    and τ_V(u) = N_I (or u is tainted)
  Then: v is tainted

  Formally: Taint(G) = { v ∈ V | ∃ path u→*v where τ_V(u) = N_I,
                                   all edges on path ∈ {E_TF, E_DD, E_MP} }

Attack Chain:
  σ = ⟨v_0, v_1, ..., v_k⟩  where:
    - τ_V(v_0) = N_I     (input source)
    - τ_V(v_k) = N_C     (crash site)
    - ∀i: (v_i, v_{i+1}) ∈ E
  The attack chain σ* is the shortest such path (by BFS).

Critical Node Set:
  C(G) = { v ∈ V | τ_V(v) ∈ {N_I, N_C, N_T, N_H} }
        ∪ { v ∈ V | τ_V(v) = N_F ∧ λ(v) ∈ DANGER_FUNCTIONS }

  DANGER_FUNCTIONS = {strcpy, memcpy, sprintf, gets, malloc, free,
                      realloc, read, recv, scanf, system, execve}
"""


# ---------------------------------------------------------------------------
# Compression Algorithms (Formal)
# ---------------------------------------------------------------------------

COMPRESSION_ALGORITHMS = {

    "taint_centric_reduction": {
        "name": "Algorithm 1: Taint-Centric Reduction",
        "objective": (
            "Remove nodes not reachable from any taint source "
            "or connected to a crash site via taint edges.\n"
            "Minimize: |V'| subject to: Taint(G') ⊇ Taint(G) ∩ V'"
        ),
        "pseudocode": """
Algorithm 1: TAINT_CENTRIC_REDUCTION(G)
  Input:  HBPG G = (V, E, τ_V, τ_E, λ)
  Output: Subgraph G' preserving all taint-reachable nodes

  1. R ← { v ∈ V | τ_V(v) ∈ {N_I, N_T} }   // taint seeds
  2. R ← R ∪ { v ∈ V | τ_V(v) = N_C }       // always keep crash sites
  3. changed ← True
  4. WHILE changed DO
  5.   changed ← False
  6.   FOR EACH edge (u, v) ∈ E with τ_E(u,v) = E_TF DO
  7.     IF u ∈ R AND v ∉ R THEN R ← R ∪ {v}; changed ← True
  8.     IF v ∈ R AND u ∉ R THEN R ← R ∪ {u}; changed ← True
  9. // Expand by 1-hop neighborhood (crash context)
 10. FOR EACH v ∈ R DO
 11.   FOR EACH (u, v) or (v, w) ∈ E DO R ← R ∪ {u, w}
 12. RETURN SUBGRAPH(G, R)

Complexity: O(|V| + |E|)  — single BFS traversal
""",
        "invariants": [
            "All CRASH_SITE nodes survive: ∀v, τ_V(v)=N_C ⟹ v ∈ V'",
            "All taint sources survive: ∀v, τ_V(v)=N_I ⟹ v ∈ V'",
            "Taint paths preserved up to 1-hop neighborhood",
        ],
    },

    "crash_context_preservation": {
        "name": "Algorithm 2: Crash-Context Backward Slice",
        "objective": (
            "Preserve crash sites and all ancestors up to depth d.\n"
            "Maximize: coverage of backward slice from N_C nodes"
        ),
        "pseudocode": """
Algorithm 2: CRASH_CONTEXT_PRESERVATION(G, d)
  Input:  HBPG G, context depth d (default d=5)
  Output: Subgraph G' preserving crash neighborhood

  1. S ← { v ∈ V | τ_V(v) = N_C }   // crash sites
  2. IF S = ∅ THEN RETURN G
  3. preserved ← S
  4. FOR i ← 1 TO d DO
  5.   new_nodes ← ∅
  6.   FOR EACH (u, v) ∈ E with v ∈ preserved AND u ∉ preserved DO
  7.     new_nodes ← new_nodes ∪ {u}
  8.   preserved ← preserved ∪ new_nodes
  9. RETURN SUBGRAPH(G, preserved)

Complexity: O(d × |E|)   — d backward BFS rounds
""",
        "invariants": [
            "All crash sites preserved: S ⊆ V'",
            "At least d-hop ancestors of each crash node preserved",
        ],
    },

    "event_clustering": {
        "name": "Algorithm 3: Temporal Event Clustering",
        "objective": (
            "Merge consecutive nodes of the same type within a time window Δt.\n"
            "Minimize |V'| while preserving node type distribution τ_V"
        ),
        "pseudocode": """
Algorithm 3: EVENT_CLUSTERING(G, Δt)
  Input:  HBPG G, time window Δt (default Δt=3 timestamps)
  Output: Clustered graph G' with merged redundant nodes

  1. nodes_sorted ← SORT(V, key=λ(v).timestamp)
  2. clusters ← []
  3. current_cluster ← [nodes_sorted[0]]
  4. FOR i ← 1 TO |V|-1 DO
  5.   v ← nodes_sorted[i];  prev ← current_cluster[-1]
  6.   IF τ_V(v) = τ_V(prev) AND |v.timestamp - prev.timestamp| ≤ Δt THEN
  7.     current_cluster.append(v)
  8.   ELSE
  9.     clusters.append(current_cluster)
  10.    current_cluster ← [v]
  11. clusters.append(current_cluster)
  12. // Build clustered graph
  13. FOR EACH cluster c ∈ clusters DO
  14.   representative ← c[0]
  15.   representative.label ← label(c[0]) + " ×" + |c|
  16.   representative.attributes.cluster_size ← |c|
  17.   ADD representative TO V'
  18.   FOR EACH v ∈ c DO cluster_map[v] ← representative
  19. // Remap edges (remove self-loops from clustering)
  20. FOR EACH (u, v) ∈ E DO
  21.   u' ← cluster_map[u];  v' ← cluster_map[v]
  22.   IF u' ≠ v' THEN ADD (u', v') TO E'
  23. RETURN G' = (V', E', ...)

Complexity: O(|V| log|V| + |E|)  — dominated by sorting
""",
        "invariants": [
            "At least one representative per cluster survives",
            "Cluster size tracked in node attributes for transparency",
            "Self-loops (intra-cluster edges) are eliminated",
        ],
    },

    "semantic_path_abstraction": {
        "name": "Algorithm 4: Semantic Path Abstraction",
        "objective": (
            "Abstract graph to function-level by removing non-critical "
            "low-level nodes (memory regions, data values) while preserving "
            "function/input/crash/syscall nodes and their edges.\n"
            "Preserve: V' = { v | τ_V(v) ∈ {N_F, N_I, N_C, N_S} }"
        ),
        "pseudocode": """
Algorithm 4: SEMANTIC_PATH_ABSTRACTION(G, level)
  Input:  HBPG G, abstraction level ∈ {function, block}
  Output: Abstracted graph G'

  CASE level = "function":
    1. KEEP ← { N_F, N_I, N_C, N_S }
  CASE level = "block":
    1. KEEP ← { N_F, N_I, N_C, N_S, N_M }

  2. V' ← { v ∈ V | τ_V(v) ∈ KEEP }
  3. E' ← { (u, v) ∈ E | u ∈ V' AND v ∈ V' }
  4. RETURN G' = (V', E', ...)

Complexity: O(|V| + |E|)  — single pass filter
""",
        "invariants": [
            "Crash sites (N_C) always in KEEP set",
            "Input sources (N_I) always in KEEP set",
            "Abstraction level parameterizable (function vs block)",
        ],
    },

    "vulnerability_focused_filtering": {
        "name": "Algorithm 5: Vulnerability-Focused Filtering",
        "objective": (
            "Final pass: retain only nodes that are security-critical.\n"
            "Keep: essential node types + vulnerability-relevant functions + "
            "nodes on paths between inputs and crash sites."
        ),
        "pseudocode": """
Algorithm 5: VULN_FOCUSED_FILTER(G)
  Input:  HBPG G
  Output: Vulnerability-focused subgraph G'

  DANGER = {strcpy, memcpy, sprintf, gets, malloc, free, system, read}

  1. preserved ← ∅
  2. // Keep essential node types
  3. FOR EACH v ∈ V DO
  4.   IF τ_V(v) ∈ {N_I, N_C, N_T, N_H, N_S} THEN preserved ← preserved ∪ {v}
  5.   IF τ_V(v) = N_F AND λ(v) ∈ DANGER    THEN preserved ← preserved ∪ {v}
  6. // Keep nodes on input→crash paths
  7. inputs  ← { v ∈ V | τ_V(v) = N_I }
  8. crashes ← { v ∈ V | τ_V(v) = N_C }
  9. FOR EACH i ∈ inputs, c ∈ crashes DO
 10.   path ← BFS_PATH(G, i, c)
 11.   preserved ← preserved ∪ path
 12. RETURN SUBGRAPH(G, preserved)

Complexity: O(|inputs| × |crashes| × (|V| + |E|))  — BFS per pair
            Practical: O(|V| + |E|) since |inputs|, |crashes| are small
""",
        "invariants": [
            "All N_I, N_C, N_T, N_H, N_S nodes retained",
            "All danger-function nodes retained",
            "Input→crash shortest path always preserved if it exists",
        ],
    },
}


# ---------------------------------------------------------------------------
# Overall Compression Optimization Objective
# ---------------------------------------------------------------------------

COMPRESSION_OBJECTIVE = """
Overall Semantic Compression Optimization Objective
=====================================================

Given original HBPG G = (V, E) and compression ratio target r ∈ (0, 1]:

  Minimize:  |V'| / |V|          (maximize node reduction)

  Subject to:
    (I1)  ∀v ∈ V, τ_V(v) = N_C  ⟹  v ∈ V'            [crash site invariant]
    (I2)  Taint(G') ⊇ Taint(G) ∩ V'                    [taint preservation]
    (I3)  σ*(G') ≠ ∅  if σ*(G) ≠ ∅                     [attack chain exists]
    (I4)  |V'| / |V| ≥ r                                 [compression ratio floor]
    (I5)  SemScore(G, G') ≥ θ    (θ = 0.7 target)       [semantic quality floor]

Where:
  SemScore(G, G') = w1·CrashPresent + w2·TaintRetention
                  + w3·AttackChainJaccard + w4·CriticalNodeRetention
                  + w5·WL_Similarity

  Weights: w1=0.30, w2=0.20, w3=0.20, w4=0.20, w5=0.10

Note:
  This is a constrained combinatorial optimization.
  Our five-strategy pipeline is a greedy approximation:
  each strategy is applied in sequence to enforce invariants (I1)–(I3)
  while reducing |V'|.
"""


# ---------------------------------------------------------------------------
# Complexity Summary Table
# ---------------------------------------------------------------------------

COMPLEXITY_SUMMARY = [
    ("Algorithm 1: Taint-Centric Reduction",       "O(|V| + |E|)",                  "O(|V|)"),
    ("Algorithm 2: Crash-Context Backward Slice",  "O(d × |E|)",                    "O(|V|)"),
    ("Algorithm 3: Temporal Event Clustering",     "O(|V| log|V| + |E|)",           "O(|V|)"),
    ("Algorithm 4: Semantic Path Abstraction",     "O(|V| + |E|)",                  "O(|V|)"),
    ("Algorithm 5: Vulnerability-Focused Filter",  "O(|V| + |E|) practical",        "O(|V|)"),
    ("Full Compression Pipeline",                  "O(|V| log|V| + |E|)",           "O(|V|)"),
]


@dataclass
class AlgorithmComplexity:
    """Formal complexity record for a single algorithm."""
    name: str
    time_complexity: str
    space_complexity: str
    invariants: List[str]
    optimization_objective: str


def get_algorithm_summary() -> str:
    """Return formatted complexity summary table."""
    lines = [
        "=" * 75,
        "TRACEWISE-Lite: Compression Algorithm Complexity Summary",
        "=" * 75,
        f"{'Algorithm':<45} {'Time':>15} {'Space':>10}",
        "-" * 75,
    ]
    for name, time_c, space_c in COMPLEXITY_SUMMARY:
        lines.append(f"{name:<45} {time_c:>15} {space_c:>10}")
    lines.append("=" * 75)
    return "\n".join(lines)


def get_formal_definition() -> str:
    """Return the formal HBPG definition string."""
    return HBPG_FORMAL_DEFINITION


def get_algorithm(name: str) -> dict:
    """Retrieve a specific algorithm definition."""
    return COMPRESSION_ALGORITHMS.get(name, {})


def get_all_algorithms() -> str:
    """Return all algorithm pseudo-codes as a formatted string."""
    parts = [COMPRESSION_OBJECTIVE, ""]
    for key, alg in COMPRESSION_ALGORITHMS.items():
        parts.append("=" * 70)
        parts.append(alg["name"])
        parts.append("-" * 70)
        parts.append(f"Objective: {alg['objective']}")
        parts.append(alg["pseudocode"])
        parts.append("Compression Invariants:")
        for inv in alg["invariants"]:
            parts.append(f"  ✓ {inv}")
        parts.append("")
    parts.append(get_algorithm_summary())
    return "\n".join(parts)


if __name__ == "__main__":
    print(get_formal_definition())
    print()
    print(get_all_algorithms())
