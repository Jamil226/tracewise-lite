"""
Semantic Compression Engine for TRACEWISE-Lite

Implements compression strategies that reduce telemetry complexity
while preserving exploitability-critical semantics:
- Taint-centric reduction
- Vulnerability-focused filtering
- Semantic path abstraction
- Event clustering
"""

import os
import sys
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from utils.config import get_config
from provenance.hbpg import (
    HybridBinaryProvenanceGraph, HBPGNode, HBPGEdge,
    NodeType, EdgeType
)

logger = setup_logger("compression")


@dataclass
class CompressionStats:
    """Statistics from compression operation"""
    original_nodes: int
    original_edges: int
    compressed_nodes: int
    compressed_edges: int
    node_reduction: float
    edge_reduction: float
    strategies_applied: List[str]
    semantic_preservation_score: float


class SemanticCompressionEngine:
    """
    Semantic Compression Engine

    Reduces graph complexity while preserving vulnerability-relevant
    semantics through multiple compression strategies.
    """

    def __init__(self, config=None):
        self.config = config or get_config().compression
        self.strategies_applied: List[str] = []
        self.stats = None

    def compress(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Apply semantic compression to HBPG

        Args:
            graph: Original Hybrid Binary Provenance Graph

        Returns:
            Compressed graph preserving exploitability semantics
        """
        logger.info(f"Starting semantic compression on graph with "
                   f"{len(graph.nodes)} nodes, {len(graph.edges)} edges")

        original_nodes = len(graph.nodes)
        original_edges = len(graph.edges)
        strategies = []

        compressed = graph

        # Apply compression strategies in order
        if self.config.preserve_taint_paths:
            compressed = self._taint_centric_reduction(compressed)
            strategies.append("taint_centric_reduction")

        if self.config.preserve_crash_context:
            compressed = self._crash_context_preservation(compressed)
            strategies.append("crash_context_preservation")

        if self.config.cluster_similar_events:
            compressed = self._event_clustering(compressed)
            strategies.append("event_clustering")

        # Always apply abstraction
        compressed = self._semantic_path_abstraction(compressed)
        strategies.append("semantic_path_abstraction")

        # Final vulnerability-focused filtering
        compressed = self._vulnerability_focused_filtering(compressed)
        strategies.append("vulnerability_focused_filtering")

        # Calculate statistics
        compressed_nodes = len(compressed.nodes)
        compressed_edges = len(compressed.edges)

        self.stats = CompressionStats(
            original_nodes=original_nodes,
            original_edges=original_edges,
            compressed_nodes=compressed_nodes,
            compressed_edges=compressed_edges,
            node_reduction=1.0 - (compressed_nodes / max(original_nodes, 1)),
            edge_reduction=1.0 - (compressed_edges / max(original_edges, 1)),
            strategies_applied=strategies,
            semantic_preservation_score=self._calculate_semantic_preservation(
                graph, compressed
            )
        )

        logger.info(f"Compression complete: "
                   f"nodes {original_nodes} -> {compressed_nodes} "
                   f"({self.stats.node_reduction*100:.1f}% reduction), "
                   f"edges {original_edges} -> {compressed_edges} "
                   f"({self.stats.edge_reduction*100:.1f}% reduction)")

        return compressed

    def _taint_centric_reduction(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Remove nodes not on taint propagation paths

        Keeps only nodes that are part of taint flow from
        input sources to sinks/crashes.
        """
        # Find all taint-related nodes
        taint_nodes = set()
        for node_id, node in graph.nodes.items():
            if node.node_type in (NodeType.TAINT_LABEL, NodeType.INPUT_SOURCE):
                taint_nodes.add(node_id)

        # Find nodes reachable via taint edges
        reachable = set(taint_nodes)
        changed = True
        while changed:
            changed = False
            for edge in graph.edges:
                if edge.edge_type == EdgeType.TAINT_FLOW:
                    if edge.source in reachable and edge.target not in reachable:
                        reachable.add(edge.target)
                        changed = True
                    if edge.target in reachable and edge.source not in reachable:
                        reachable.add(edge.source)
                        changed = True

        # Also include crash nodes
        for node_id, node in graph.nodes.items():
            if node.node_type == NodeType.CRASH_SITE:
                reachable.add(node_id)

        # Include neighbors of crash and taint nodes
        extended = set(reachable)
        for node_id in reachable:
            for edge in graph.edges:
                if edge.source == node_id:
                    extended.add(edge.target)
                if edge.target == node_id:
                    extended.add(edge.source)

        # Create reduced graph
        return self._create_subgraph(graph, extended)

    def _crash_context_preservation(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Preserve complete context around crash sites

        Ensures crash site and its predecessors are retained.
        """
        # Find crash nodes
        crash_nodes = {nid for nid, n in graph.nodes.items()
                      if n.node_type == NodeType.CRASH_SITE}

        if not crash_nodes:
            return graph

        # Build backward slice from crashes
        preserved = set(crash_nodes)

        # Include ancestors up to depth limit
        for _ in range(self.config.min_path_length + 2):
            new_nodes = set()
            for edge in graph.edges:
                if edge.target in preserved and edge.source not in preserved:
                    new_nodes.add(edge.source)
            preserved.update(new_nodes)

        return self._create_subgraph(graph, preserved)

    def _event_clustering(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Cluster similar sequential events

        Groups consecutive function calls of the same type
        or operating on the same memory region.
        """
        # Group nodes by type and proximity
        clusters = []
        current_cluster = []

        sorted_nodes = sorted(graph.nodes.values(), key=lambda n: n.timestamp)

        for node in sorted_nodes:
            if not current_cluster:
                current_cluster = [node]
            else:
                last = current_cluster[-1]
                # Check if similar and close in time
                if (node.node_type == last.node_type and
                    abs(node.timestamp - last.timestamp) <= 3):
                    current_cluster.append(node)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [node]

        if current_cluster:
            clusters.append(current_cluster)

        # Create clustered graph
        new_graph = HybridBinaryProvenanceGraph(
            binary_path=graph.binary_path,
            trace_id=f"{graph.trace_id}_clustered"
        )

        cluster_map = {}  # old_node_id -> new_cluster_id

        for cluster in clusters:
            if len(cluster) == 1:
                # Single node, add directly
                node = cluster[0]
                new_id = new_graph.add_node(
                    node_type=node.node_type,
                    address=node.address,
                    label=node.label,
                    attributes=node.attributes,
                    timestamp=node.timestamp
                )
                for n in cluster:
                    cluster_map[n.node_id] = new_id
            else:
                # Cluster nodes
                first = cluster[0]
                new_id = new_graph.add_node(
                    node_type=first.node_type,
                    address=first.address,
                    label=f"{first.label} (x{len(cluster)})",
                    attributes={
                        **first.attributes,
                        'cluster_size': len(cluster),
                        'clustered': True,
                        'timestamps': [n.timestamp for n in cluster]
                    },
                    timestamp=first.timestamp
                )
                for n in cluster:
                    cluster_map[n.node_id] = new_id

        # Remap edges
        for edge in graph.edges:
            if edge.source in cluster_map and edge.target in cluster_map:
                new_source = cluster_map[edge.source]
                new_target = cluster_map[edge.target]
                # Avoid self-loops from clustering
                if new_source != new_target:
                    new_graph.add_edge(
                        source=new_source,
                        target=new_target,
                        edge_type=edge.edge_type,
                        attributes=edge.attributes,
                        weight=edge.weight
                    )

        return new_graph

    def _semantic_path_abstraction(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Abstract semantic paths to higher-level representations

        Replaces sequences of low-level operations with semantic summaries.
        """
        abstraction_level = self.config.abstraction_level

        if abstraction_level == "function":
            # Abstract to function-level
            return self._abstract_to_function_level(graph)
        elif abstraction_level == "block":
            # Abstract to basic block level
            return self._abstract_to_block_level(graph)

        return graph

    def _abstract_to_function_level(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """Abstract graph to function-level representation"""
        new_graph = HybridBinaryProvenanceGraph(
            binary_path=graph.binary_path,
            trace_id=f"{graph.trace_id}_func_abstract"
        )

        # Keep only function, input, crash, and syscall nodes
        important_types = {NodeType.FUNCTION, NodeType.INPUT_SOURCE,
                          NodeType.CRASH_SITE, NodeType.SYSCALL}

        for node_id, node in graph.nodes.items():
            if node.node_type in important_types:
                new_graph.nodes[node_id] = node

        # Add edges between preserved nodes
        for edge in graph.edges:
            if edge.source in new_graph.nodes and edge.target in new_graph.nodes:
                new_graph.edges.append(edge)

        return new_graph

    def _abstract_to_block_level(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """Abstract graph to basic block level"""
        # For now, similar to function level but with memory nodes
        new_graph = HybridBinaryProvenanceGraph(
            binary_path=graph.binary_path,
            trace_id=f"{graph.trace_id}_block_abstract"
        )

        important_types = {NodeType.FUNCTION, NodeType.INPUT_SOURCE,
                          NodeType.CRASH_SITE, NodeType.SYSCALL,
                          NodeType.MEMORY_REGION}

        for node_id, node in graph.nodes.items():
            if node.node_type in important_types:
                new_graph.nodes[node_id] = node

        for edge in graph.edges:
            if edge.source in new_graph.nodes and edge.target in new_graph.nodes:
                new_graph.edges.append(edge)

        return new_graph

    def _vulnerability_focused_filtering(self, graph: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """
        Final filtering focused on vulnerability indicators

        Removes nodes that don't contribute to vulnerability understanding.
        """
        # Essential node types for vulnerability analysis
        essential_types = {
            NodeType.INPUT_SOURCE, NodeType.CRASH_SITE,
            NodeType.TAINT_LABEL, NodeType.HEAP_OBJECT
        }

        # Vulnerability-relevant functions
        vuln_functions = {
            'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf',
            'memcpy', 'memmove', 'malloc', 'free', 'realloc',
            'read', 'recv', 'scanf', 'gets', 'system'
        }

        preserved = set()

        # Keep essential nodes
        for node_id, node in graph.nodes.items():
            if node.node_type in essential_types:
                preserved.add(node_id)
            elif node.node_type == NodeType.FUNCTION:
                if any(vf in node.label for vf in vuln_functions):
                    preserved.add(node_id)
            elif node.node_type == NodeType.SYSCALL:
                preserved.add(node_id)

        # Keep nodes on paths between input and crash
        input_nodes = {nid for nid, n in graph.nodes.items()
                      if n.node_type == NodeType.INPUT_SOURCE}
        crash_nodes = {nid for nid, n in graph.nodes.items()
                      if n.node_type == NodeType.CRASH_SITE}

        # Find connecting paths
        for inp in input_nodes:
            for crash in crash_nodes:
                path_nodes = self._find_path_nodes(graph, inp, crash)
                preserved.update(path_nodes)

        return self._create_subgraph(graph, preserved)

    def _find_path_nodes(self, graph: HybridBinaryProvenanceGraph,
                         source: str, target: str) -> Set[str]:
        """Find all nodes on paths between source and target"""
        # BFS to find all paths
        visited = set()
        queue = [(source, [source])]
        all_nodes = set()

        while queue:
            current, path = queue.pop(0)

            if current == target:
                all_nodes.update(path)
                continue

            if current in visited:
                continue
            visited.add(current)

            for edge in graph.edges:
                if edge.source == current and edge.target not in visited:
                    queue.append((edge.target, path + [edge.target]))

        return all_nodes

    def _create_subgraph(self, graph: HybridBinaryProvenanceGraph,
                         node_ids: Set[str]) -> HybridBinaryProvenanceGraph:
        """Create subgraph from set of node IDs"""
        new_graph = HybridBinaryProvenanceGraph(
            binary_path=graph.binary_path,
            trace_id=f"{graph.trace_id}_compressed"
        )

        # Copy nodes
        for node_id in node_ids:
            if node_id in graph.nodes:
                node = graph.nodes[node_id]
                new_graph.nodes[node_id] = node
                new_graph._node_counter = max(new_graph._node_counter,
                                             int(node_id[1:]) + 1)

        # Copy edges between preserved nodes
        for edge in graph.edges:
            if edge.source in node_ids and edge.target in node_ids:
                new_graph.edges.append(edge)

        return new_graph

    def _calculate_semantic_preservation(self,
                                         original: HybridBinaryProvenanceGraph,
                                         compressed: HybridBinaryProvenanceGraph) -> float:
        """
        Calculate semantic preservation score

        Measures how well the compressed graph preserves
        vulnerability-relevant semantics.
        """
        scores = []

        # Check if input sources are preserved
        orig_inputs = len(original.get_nodes_by_type(NodeType.INPUT_SOURCE))
        comp_inputs = len(compressed.get_nodes_by_type(NodeType.INPUT_SOURCE))
        if orig_inputs > 0:
            scores.append(comp_inputs / orig_inputs)
        else:
            scores.append(1.0)

        # Check if crash sites are preserved
        orig_crashes = len(original.get_nodes_by_type(NodeType.CRASH_SITE))
        comp_crashes = len(compressed.get_nodes_by_type(NodeType.CRASH_SITE))
        if orig_crashes > 0:
            scores.append(comp_crashes / orig_crashes)
        else:
            scores.append(1.0)

        # Check if taint labels are preserved
        orig_taints = len(original.get_nodes_by_type(NodeType.TAINT_LABEL))
        comp_taints = len(compressed.get_nodes_by_type(NodeType.TAINT_LABEL))
        if orig_taints > 0:
            scores.append(comp_taints / orig_taints)
        else:
            scores.append(1.0)

        # Check attack path preservation
        orig_path = original.get_attack_propagation_path()
        comp_path = compressed.get_attack_propagation_path()
        if orig_path:
            scores.append(len(comp_path) / max(len(orig_path), 1))
        else:
            scores.append(1.0)

        return sum(scores) / len(scores)

    def get_compression_summary(self) -> Dict:
        """Get summary of compression results"""
        if not self.stats:
            return {}

        return {
            'original_size': {
                'nodes': self.stats.original_nodes,
                'edges': self.stats.original_edges
            },
            'compressed_size': {
                'nodes': self.stats.compressed_nodes,
                'edges': self.stats.compressed_edges
            },
            'reduction': {
                'nodes': f"{self.stats.node_reduction*100:.1f}%",
                'edges': f"{self.stats.edge_reduction*100:.1f}%"
            },
            'strategies': self.stats.strategies_applied,
            'semantic_preservation': f"{self.stats.semantic_preservation_score*100:.1f}%"
        }


if __name__ == "__main__":
    print("Semantic Compression Engine")
    print("Usage: Import and use SemanticCompressionEngine")