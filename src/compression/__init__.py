"""
TRACEWISE-Lite Compression Module

Semantic compression engine for reducing HBPG complexity while preserving
vulnerability-relevant semantics.
"""

from .engine import SemanticCompressionEngine, CompressionStats

__all__ = ['SemanticCompressionEngine', 'CompressionStats']