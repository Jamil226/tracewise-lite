import networkx as nx
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from src.provenance.hbpg_compression import compress, NodeType, EdgeType

def build_scaled_graph(n_loop_iterations: int) -> nx.DiGraph:
    """
    Simulate a binary with a large loop — many identical events.
    Tests that deduplication + abstraction work at scale.
    """
    G = nx.DiGraph()
    G.add_node("src",   type=NodeType.SOURCE, label="fgets()", address="0x401010", cwe_hint=None)
    G.add_node("crash", type=NodeType.CRASH,  label="SIGSEGV", address="0x4010ff", cwe_hint=None)
    
    prev = "src"
    for i in range(n_loop_iterations):
        nid = f"mem_{i}"
        G.add_node(nid, type=NodeType.MEMORY, 
                   label="buf_access",    # identical label — will be deduplicated
                   address="0x7ffe1000",  # identical address
                   cwe_hint=None)
        G.add_edge(prev, nid, type=EdgeType.TAINT)
        prev = nid
    
    G.add_edge(prev, "crash", type=EdgeType.CONTROL)
    return G

if __name__ == "__main__":
    print(f"{'Scale':>10} {'Before':>10} {'After':>8} {'Ratio':>8}")
    print("-" * 40)
    for scale in [100, 1_000, 10_000, 50_000, 100_000]:
        G = build_scaled_graph(scale)
        cr = compress(G)
        print(f"{scale:>10,} {cr.nodes_before:>10,} {cr.nodes_after:>8} "
              f"{cr.compression_ratio:>8.4%}")
