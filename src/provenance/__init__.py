"""
TRACEWISE-Lite Provenance Module

Selective provenance collection and HBPG construction for vulnerability analysis.
"""

from .collector import SelectiveProvenanceCollector, ProvenanceFilter, ProvenanceGraphBuilder
from .hbpg import (
    HBPGConstructor,
    ShadowMemory,
    RealTraceShadowHBPGConstructor,
    HybridBinaryProvenanceGraph,
    HBPGNode, HBPGEdge,
    NodeType, EdgeType
)

__all__ = [
    'SelectiveProvenanceCollector', 'ProvenanceFilter', 'ProvenanceGraphBuilder',
    'HBPGConstructor', 'ShadowMemory', 'RealTraceShadowHBPGConstructor',
    'HybridBinaryProvenanceGraph',
    'HBPGNode', 'HBPGEdge', 'NodeType', 'EdgeType'
]