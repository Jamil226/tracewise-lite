"""
Evaluation Metrics for TRACEWISE-Lite

Comprehensive metrics for assessing:
- Semantic preservation during compression
- Vulnerability detection accuracy
- LLM reasoning quality
- Performance and scalability
- Baseline comparisons

All metrics are designed to be measurable, reproducible, and publishable.
"""

import os
import sys
import json
import time
import math
import hashlib
import statistics
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ---------------------------------------------------------------------------
# Semantic Preservation Metrics
# ---------------------------------------------------------------------------

@dataclass
class SemanticPreservationMetrics:
    """
    Measures how well compression preserves vulnerability-relevant semantics.
    These are the CORE metrics validating TRACEWISE-Lite's main contribution.
    """

    # Graph structure preservation
    node_retention_rate: float = 0.0           # |compressed_nodes| / |original_nodes|
    edge_retention_rate: float = 0.0           # |compressed_edges| / |original_edges|
    critical_node_retention: float = 0.0       # crash/input/sink nodes preserved

    # Taint-path preservation
    taint_path_preservation_rate: float = 0.0  # taint paths preserved after compression
    taint_source_retention: float = 0.0        # input source nodes retained
    taint_sink_retention: float = 0.0          # sink function nodes retained

    # Attack-chain preservation
    attack_chain_preserved: bool = False       # full input->crash path exists
    attack_chain_jaccard: float = 0.0          # Jaccard similarity of attack paths
    shortest_path_ratio: float = 0.0           # |compressed_sp| / |original_sp|

    # Crash-context preservation
    crash_context_retention: float = 0.0       # nodes around crash retained
    crash_node_present: bool = False           # crash node survived compression

    # Semantic similarity
    graph_edit_distance: float = 0.0           # GED between original and compressed
    graph_edit_distance_normalized: float = 0.0 # GED / |original_nodes|
    weisfeiler_lehman_similarity: float = 0.0  # WL graph kernel similarity

    # Node-type specific
    function_node_retention: float = 0.0
    memory_node_retention: float = 0.0
    syscall_node_retention: float = 0.0
    heap_node_retention: float = 0.0

    # Composite score
    overall_semantic_score: float = 0.0        # weighted composite (see compute)

    def compute_composite(self, weights: Dict[str, float] = None) -> float:
        """
        Compute weighted composite semantic preservation score.

        Weights reflect importance for vulnerability analysis:
        - Crash node presence: 0.25 (must detect crash)
        - Taint path preservation: 0.25 (must track data flow)
        - Attack chain: 0.20 (must reconstruct attack)
        - Critical node retention: 0.15 (key security nodes)
        - Graph similarity: 0.15 (overall structural integrity)
        """
        if weights is None:
            weights = {
                'crash_node_present': 0.25,
                'taint_path_preservation': 0.25,
                'attack_chain_jaccard': 0.20,
                'critical_node_retention': 0.15,
                'weisfeiler_lehman_similarity': 0.15,
            }

        self.overall_semantic_score = (
            weights['crash_node_present'] * (1.0 if self.crash_node_present else 0.0) +
            weights['taint_path_preservation'] * self.taint_path_preservation_rate +
            weights['attack_chain_jaccard'] * self.attack_chain_jaccard +
            weights['critical_node_retention'] * self.critical_node_retention +
            weights['weisfeiler_lehman_similarity'] * self.weisfeiler_lehman_similarity
        )

        # Ensure crash node presence is a hard requirement
        if not self.crash_node_present:
            self.overall_semantic_score *= 0.5

        return self.overall_semantic_score

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CompressionMetrics:
    """Raw compression statistics."""
    original_nodes: int = 0
    original_edges: int = 0
    compressed_nodes: int = 0
    compressed_edges: int = 0
    original_tokens_est: int = 0          # estimated LLM tokens (raw JSON)
    compressed_tokens_est: int = 0         # estimated LLM tokens (compressed)
    compression_time_ms: float = 0.0
    memory_before_mb: float = 0.0
    memory_after_mb: float = 0.0

    @property
    def node_reduction_ratio(self) -> float:
        return 1.0 - (self.compressed_nodes / max(self.original_nodes, 1))

    @property
    def edge_reduction_ratio(self) -> float:
        return 1.0 - (self.compressed_edges / max(self.original_edges, 1))

    @property
    def token_reduction_ratio(self) -> float:
        return 1.0 - (self.compressed_tokens_est / max(self.original_tokens_est, 1))

    @property
    def compression_ratio(self) -> float:
        """Overall compression ratio (geometric mean of node and edge)."""
        return math.sqrt(self.node_reduction_ratio * self.edge_reduction_ratio)


# ---------------------------------------------------------------------------
# Vulnerability Detection Metrics
# ---------------------------------------------------------------------------

@dataclass
class DetectionMetrics:
    """Metrics for vulnerability detection accuracy."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0


@dataclass
class CWEClassificationMetrics:
    """Metrics for CWE classification accuracy."""

    total_cases: int = 0
    correct_cwe_top1: int = 0
    correct_cwe_top3: int = 0
    correct_cwe_family: int = 0  # correct CWE category (e.g., any buffer overflow CWE)
    cwe_predictions: List[Tuple[str, str]] = field(default_factory=list)  # (predicted, ground_truth)
    per_cwe_accuracy: Dict[str, float] = field(default_factory=dict)

    @property
    def top1_accuracy(self) -> float:
        return self.correct_cwe_top1 / max(self.total_cases, 1)

    @property
    def top3_accuracy(self) -> float:
        return self.correct_cwe_top3 / max(self.total_cases, 1)

    @property
    def family_accuracy(self) -> float:
        return self.correct_cwe_family / max(self.total_cases, 1)

    def record_prediction(self, predicted_cwe: str, ground_truth_cwe: str) -> None:
        self.cwe_predictions.append((predicted_cwe, ground_truth_cwe))
        self.total_cases += 1

        # Top-1
        if predicted_cwe == ground_truth_cwe:
            self.correct_cwe_top1 += 1
            self.correct_cwe_top3 += 1
            self.correct_cwe_family += 1
            return

        # Top-3: check if ground truth in top-3 (simulated by checking family)
        pred_family = self._cwe_family(predicted_cwe)
        gt_family = self._cwe_family(ground_truth_cwe)
        if pred_family == gt_family:
            self.correct_cwe_top3 += 1
            self.correct_cwe_family += 1

    @staticmethod
    def _cwe_family(cwe: str) -> str:
        """Map CWE to family."""
        family_map = {
            'CWE-121': 'buffer_overflow', 'CWE-122': 'buffer_overflow',
            'CWE-120': 'buffer_overflow', 'CWE-124': 'buffer_overflow',
            'CWE-126': 'buffer_overflow', 'CWE-127': 'buffer_overflow',
            'CWE-416': 'use_after_free', 'CWE-415': 'double_free',
            'CWE-134': 'format_string', 'CWE-133': 'format_string',
            'CWE-190': 'integer_overflow', 'CWE-191': 'integer_underflow',
            'CWE-78': 'command_injection', 'CWE-77': 'command_injection',
            'CWE-22': 'path_traversal', 'CWE-23': 'path_traversal',
            'CWE-401': 'memory_leak', 'CWE-476': 'null_pointer',
            'CWE-362': 'race_condition', 'CWE-367': 'race_condition',
        }
        return family_map.get(cwe, 'other')


@dataclass
class RootCauseMetrics:
    """Metrics for root-cause explanation quality."""

    total_explanations: int = 0
    keyword_hits: int = 0          # expected keywords found in explanation
    keyword_misses: int = 0        # expected keywords not found
    hallucination_flags: int = 0   # detected hallucinations (contradictions)
    completeness_scores: List[float] = field(default_factory=list)  # 0.0-1.0 per explanation
    explanation_lengths: List[int] = field(default_factory=list)

    # Reference keywords per CWE family
    KEYWORD_MAP: Dict[str, List[str]] = field(default_factory=lambda: {
        'buffer_overflow': ['buffer', 'overflow', 'bounds', 'strcpy', 'memcpy', 'size'],
        'use_after_free': ['free', 'use-after-free', 'freed', 'dangling', 'heap'],
        'format_string': ['format', 'printf', 'format string', '%s', '%n'],
        'integer_overflow': ['integer', 'overflow', 'wrap', 'arithmetic', 'signed'],
        'command_injection': ['command', 'system', 'shell', 'injection', 'exec'],
        'path_traversal': ['path', 'traversal', 'directory', '../', 'canonicalize'],
    })

    def score_explanation(self, explanation: str, ground_truth_cwe: str) -> float:
        """
        Score explanation quality based on keyword presence.

        Returns a score between 0.0 and 1.0.
        """
        explanation_lower = explanation.lower()
        family = CWEClassificationMetrics._cwe_family(ground_truth_cwe)
        keywords = self.KEYWORD_MAP.get(family, [])

        if not keywords:
            return 0.5  # neutral for unknown families

        hits = sum(1 for kw in keywords if kw.lower() in explanation_lower)
        score = hits / len(keywords)

        self.keyword_hits += hits
        self.keyword_misses += len(keywords) - hits
        self.completeness_scores.append(score)
        self.explanation_lengths.append(len(explanation))
        self.total_explanations += 1

        return score

    @property
    def avg_completeness(self) -> float:
        return statistics.mean(self.completeness_scores) if self.completeness_scores else 0.0

    @property
    def avg_explanation_length(self) -> float:
        return statistics.mean(self.explanation_lengths) if self.explanation_lengths else 0.0


@dataclass
class ExploitabilityMetrics:
    """Metrics for exploitability assessment accuracy."""

    predictions: List[Tuple[float, str]] = field(default_factory=list)  # (score, label)

    def record_assessment(self, score: float, label: str) -> None:
        """
        Record exploitability assessment.

        label: 'exploitable', 'likely', 'unclear', 'unlikely', 'not_exploitable'
        """
        self.predictions.append((score, label))

    @property
    def avg_score_exploitable(self) -> float:
        """Average score for cases labeled exploitable."""
        scores = [s for s, l in self.predictions if l == 'exploitable']
        return statistics.mean(scores) if scores else 0.0

    @property
    def avg_score_not_exploitable(self) -> float:
        scores = [s for s, l in self.predictions if l == 'not_exploitable']
        return statistics.mean(scores) if scores else 0.0

    @property
    def separation(self) -> float:
        """How well scores separate exploitable from non-exploitable."""
        return self.avg_score_exploitable - self.avg_score_not_exploitable


# ---------------------------------------------------------------------------
# Performance Metrics
# ---------------------------------------------------------------------------

@dataclass
class PerformanceMetrics:
    """Performance and resource consumption metrics."""

    # Timing (in seconds)
    fuzzing_time: float = 0.0
    instrumentation_time: float = 0.0
    provenance_time: float = 0.0
    hbpg_construction_time: float = 0.0
    compression_time: float = 0.0
    llm_analysis_time: float = 0.0
    total_pipeline_time: float = 0.0

    # Memory (in MB)
    peak_ram_mb: float = 0.0
    avg_ram_mb: float = 0.0
    graph_memory_mb: float = 0.0

    # CPU
    avg_cpu_percent: float = 0.0

    # Throughput
    events_per_second: float = 0.0
    nodes_per_second: float = 0.0

    # LLM-specific
    llm_tokens_input: int = 0
    llm_tokens_output: int = 0
    llm_latency_ms: float = 0.0
    llm_tokens_per_sec: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def end_to_end_latency(self) -> float:
        """Total time from input to report."""
        return self.total_pipeline_time


# ---------------------------------------------------------------------------
# LLM Reasoning Quality Metrics
# ---------------------------------------------------------------------------

@dataclass
class LLMReasoningMetrics:
    """Comprehensive LLM reasoning quality assessment."""

    model_name: str = ""

    # CWE classification
    cwe_metrics: CWEClassificationMetrics = field(default_factory=CWEClassificationMetrics)

    # Root cause
    rc_metrics: RootCauseMetrics = field(default_factory=RootCauseMetrics)

    # Exploitability
    exp_metrics: ExploitabilityMetrics = field(default_factory=ExploitabilityMetrics)

    # Hallucination detection
    hallucination_count: int = 0
    hallucination_rate: float = 0.0       # hallucinations / total_queries
    contradiction_count: int = 0           # self-contradictions detected
    factual_error_count: int = 0           # factually incorrect statements

    # Consistency
    consistency_score: float = 0.0         # same input -> same output consistency
    consistency_trials: int = 0

    # Remediation quality
    remediation_scores: List[float] = field(default_factory=list)

    def compute_hallucination_rate(self, total_queries: int) -> float:
        self.hallucination_rate = self.hallucination_count / max(total_queries, 1)
        return self.hallucination_rate

    @property
    def avg_remediation_score(self) -> float:
        return statistics.mean(self.remediation_scores) if self.remediation_scores else 0.0

    def summary(self) -> Dict[str, float]:
        return {
            'cwe_top1_acc': self.cwe_metrics.top1_accuracy,
            'cwe_top3_acc': self.cwe_metrics.top3_accuracy,
            'cwe_family_acc': self.cwe_metrics.family_accuracy,
            'root_cause_completeness': self.rc_metrics.avg_completeness,
            'exploitability_separation': self.exp_metrics.separation,
            'hallucination_rate': self.hallucination_rate,
            'consistency': self.consistency_score,
            'remediation_score': self.avg_remediation_score,
        }


# ---------------------------------------------------------------------------
# Baseline Comparison Metrics
# ---------------------------------------------------------------------------

@dataclass
class BaselineComparison:
    """Comparison of TRACEWISE-Lite against baselines."""

    method_name: str = ""
    detection_metrics: DetectionMetrics = field(default_factory=DetectionMetrics)
    performance_metrics: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    graph_size_nodes: int = 0
    graph_size_edges: int = 0
    llm_tokens_used: int = 0
    analysis_success_rate: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'method': self.method_name,
            'precision': self.detection_metrics.precision,
            'recall': self.detection_metrics.recall,
            'f1': self.detection_metrics.f1_score,
            'nodes': self.graph_size_nodes,
            'edges': self.graph_size_edges,
            'tokens': self.llm_tokens_used,
            'pipeline_time': self.performance_metrics.total_pipeline_time,
            'success_rate': self.analysis_success_rate,
        }


# ---------------------------------------------------------------------------
# Aggregation and Reporting
# ---------------------------------------------------------------------------

class MetricsAggregator:
    """Aggregate results across multiple benchmark runs."""

    def __init__(self):
        self.runs: List[Dict] = []
        self.by_benchmark: Dict[str, List[Dict]] = defaultdict(list)
        self.by_vuln_type: Dict[str, List[Dict]] = defaultdict(list)

    def add_run(self, result: Dict, benchmark: str = "", vuln_type: str = ""):
        self.runs.append(result)
        if benchmark:
            self.by_benchmark[benchmark].append(result)
        if vuln_type:
            self.by_vuln_type[vuln_type].append(result)

    def aggregate_semantic_preservation(self) -> Dict:
        """Aggregate semantic preservation metrics."""
        metrics_list = [r.get('semantic_metrics', {}) for r in self.runs if r.get('semantic_metrics')]
        if not metrics_list:
            return {}

        return {
            'overall_semantic_score': {
                'mean': statistics.mean(m.get('overall_semantic_score', 0) for m in metrics_list),
                'std': statistics.stdev(m.get('overall_semantic_score', 0) for m in metrics_list) if len(metrics_list) > 1 else 0,
                'min': min(m.get('overall_semantic_score', 0) for m in metrics_list),
                'max': max(m.get('overall_semantic_score', 0) for m in metrics_list),
            },
            'taint_path_preservation': {
                'mean': statistics.mean(m.get('taint_path_preservation_rate', 0) for m in metrics_list),
            },
            'crash_context_retention': {
                'mean': statistics.mean(m.get('crash_context_retention', 0) for m in metrics_list),
            },
            'attack_chain_jaccard': {
                'mean': statistics.mean(m.get('attack_chain_jaccard', 0) for m in metrics_list),
            },
        }

    def aggregate_compression(self) -> Dict:
        """Aggregate compression metrics."""
        metrics_list = [r.get('compression_metrics', {}) for r in self.runs if r.get('compression_metrics')]
        if not metrics_list:
            return {}

        return {
            'node_reduction': {
                'mean': statistics.mean(m.get('node_reduction_ratio', 0) for m in metrics_list),
                'std': statistics.stdev(m.get('node_reduction_ratio', 0) for m in metrics_list) if len(metrics_list) > 1 else 0,
            },
            'edge_reduction': {
                'mean': statistics.mean(m.get('edge_reduction_ratio', 0) for m in metrics_list),
            },
            'token_reduction': {
                'mean': statistics.mean(m.get('token_reduction_ratio', 0) for m in metrics_list),
            },
        }

    def aggregate_performance(self) -> Dict:
        """Aggregate performance metrics."""
        metrics_list = [r.get('performance', {}) for r in self.runs if r.get('performance')]
        if not metrics_list:
            return {}

        keys = ['total_pipeline_time', 'compression_time', 'llm_analysis_time',
                'peak_ram_mb', 'llm_tokens_input', 'llm_tokens_output']

        result = {}
        for key in keys:
            values = [m.get(key, 0) for m in metrics_list if key in m]
            if values:
                result[key] = {
                    'mean': statistics.mean(values),
                    'std': statistics.stdev(values) if len(values) > 1 else 0,
                    'min': min(values),
                    'max': max(values),
                }
        return result

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump({
                'runs': self.runs,
                'aggregate_semantic': self.aggregate_semantic_preservation(),
                'aggregate_compression': self.aggregate_compression(),
                'aggregate_performance': self.aggregate_performance(),
                'by_benchmark': {k: len(v) for k, v in self.by_benchmark.items()},
                'by_vuln_type': {k: len(v) for k, v in self.by_vuln_type.items()},
            }, f, indent=2, default=str)


if __name__ == '__main__':
    # Quick sanity test
    spm = SemanticPreservationMetrics(
        node_retention_rate=0.3,
        edge_retention_rate=0.2,
        crash_node_present=True,
        taint_path_preservation_rate=0.85,
        attack_chain_jaccard=0.75,
        critical_node_retention=0.80,
        weisfeiler_lehman_similarity=0.70,
    )
    spm.compute_composite()
    print(f"Composite semantic score: {spm.overall_semantic_score:.3f}")

    cwe = CWEClassificationMetrics()
    cwe.record_prediction('CWE-121', 'CWE-121')
    cwe.record_prediction('CWE-122', 'CWE-121')  # same family
    cwe.record_prediction('CWE-416', 'CWE-121')  # different
    print(f"CWE Top-1: {cwe.top1_accuracy:.2f}, Top-3: {cwe.top3_accuracy:.2f}, Family: {cwe.family_accuracy:.2f}")
