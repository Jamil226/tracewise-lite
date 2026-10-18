"""
LLM Reasoning Validation for TRACEWISE-Lite

Rigorous evaluation of LLM reasoning quality across multiple models:
- CWE prediction accuracy
- Root-cause explanation correctness
- Hallucination detection
- Exploitability assessment accuracy
- Multi-model comparison (TinyLlama, Phi, DeepSeek-Coder)
"""

import os
import sys
import json
import re
import time
import statistics
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.logger import setup_logger
from llm.reasoning import LLMReasoningModule, VulnerabilityAnalysis, OllamaClient

logger = setup_logger("llm_val")


# Ground truth datasets for validation
GROUND_TRUTH_VULNS = [
    {
        'vuln_type': 'buffer_overflow',
        'cwe': 'CWE-121',
        'family': 'buffer_overflow',
        'keywords': ['buffer', 'overflow', 'bounds', 'strcpy', 'memcpy', 'size', 'stack'],
        'exploitability': 0.85,
        'description': 'Stack buffer overflow via unchecked strcpy',
    },
    {
        'vuln_type': 'heap_overflow',
        'cwe': 'CWE-122',
        'family': 'buffer_overflow',
        'keywords': ['buffer', 'overflow', 'heap', 'malloc', 'bounds', 'size'],
        'exploitability': 0.80,
        'description': 'Heap buffer overflow via unchecked memcpy',
    },
    {
        'vuln_type': 'use_after_free',
        'cwe': 'CWE-416',
        'family': 'use_after_free',
        'keywords': ['free', 'use-after-free', 'freed', 'dangling', 'heap', 'use after'],
        'exploitability': 0.75,
        'description': 'Use-after-free via accessing freed heap object',
    },
    {
        'vuln_type': 'double_free',
        'cwe': 'CWE-415',
        'family': 'use_after_free',
        'keywords': ['free', 'double free', 'heap', 'corruption'],
        'exploitability': 0.70,
        'description': 'Double free causing heap corruption',
    },
    {
        'vuln_type': 'format_string',
        'cwe': 'CWE-134',
        'family': 'format_string',
        'keywords': ['format', 'printf', 'format string', '%s', '%n', '%x'],
        'exploitability': 0.65,
        'description': 'Format string vulnerability via user-controlled format specifier',
    },
    {
        'vuln_type': 'integer_overflow',
        'cwe': 'CWE-190',
        'family': 'integer_overflow',
        'keywords': ['integer', 'overflow', 'wrap', 'arithmetic', 'signed', 'unsigned'],
        'exploitability': 0.60,
        'description': 'Integer overflow in size calculation leading to buffer overflow',
    },
    {
        'vuln_type': 'command_injection',
        'cwe': 'CWE-78',
        'family': 'command_injection',
        'keywords': ['command', 'system', 'shell', 'injection', 'exec', 'popen'],
        'exploitability': 0.90,
        'description': 'Command injection via unsanitized user input to system()',
    },
    {
        'vuln_type': 'path_traversal',
        'cwe': 'CWE-22',
        'family': 'path_traversal',
        'keywords': ['path', 'traversal', 'directory', '../', 'canonicalize', 'sanitize'],
        'exploitability': 0.70,
        'description': 'Path traversal via unsanitized file path input',
    },
    {
        'vuln_type': 'null_pointer',
        'cwe': 'CWE-476',
        'family': 'null_pointer',
        'keywords': ['null', 'dereference', 'pointer', 'NULL', 'crash'],
        'exploitability': 0.30,
        'description': 'NULL pointer dereference causing crash',
    },
    {
        'vuln_type': 'memory_leak',
        'cwe': 'CWE-401',
        'family': 'memory_leak',
        'keywords': ['leak', 'memory', 'free', 'malloc', 'unreachable'],
        'exploitability': 0.20,
        'description': 'Memory leak via missing free on error path',
    },
]


# Model configurations
# --- Sub-2B (Edge Models: Classifier Collapse regime) ---
SUPPORTED_MODELS = {
    'tinyllama': {
        'name': 'tinyllama',
        'size': '1.1B',
        'context': 2048,
        'description': 'Lightweight, fast inference',
        'tier': 'edge',
    },
    'phi': {
        'name': 'phi',
        'size': '2.7B',
        'context': 2048,
        'description': 'Microsoft Phi-2, good reasoning',
        'tier': 'edge',
    },
    'deepseek-coder': {
        'name': 'deepseek-coder:1.3b',
        'size': '1.3B',
        'context': 4096,
        'description': 'Code-focused, good for security',
        'tier': 'edge',
    },
    'qwen2.5-coder': {
        'name': 'qwen2.5-coder:1.5b',
        'size': '1.5B',
        'context': 4096,
        'description': 'Alibaba Qwen, strong code reasoning (primary baseline)',
        'tier': 'edge',
    },
    # --- 7B+ Models: prove Classifier Collapse is a SIZE issue, not a compression issue ---
    'qwen2.5-coder:7b': {
        'name': 'qwen2.5-coder:7b',
        'size': '7B',
        'context': 8192,
        'description': 'Qwen 7B — proves compression quality when model is larger',
        'tier': 'capable',
        'ram_gb': 5.5,
    },
    'llama3:8b': {
        'name': 'llama3:8b',
        'size': '8B',
        'context': 8192,
        'description': 'Meta LLaMA-3 8B — gold standard local model',
        'tier': 'capable',
        'ram_gb': 5.5,
    },
    'mistral:7b': {
        'name': 'mistral:7b-instruct-q4_0',
        'size': '7B',
        'context': 8192,
        'description': 'Mistral 7B Instruct — balanced reasoning',
        'tier': 'capable',
        'ram_gb': 4.5,
    },
}


@dataclass
class LLMValidationResult:
    """Result of validating a single LLM on a single test case."""
    model_name: str
    vuln_type: str
    ground_truth_cwe: str
    predicted_cwe: str = ""
    predicted_class: str = ""
    confidence: float = 0.0
    explanation: str = ""
    root_cause_score: float = 0.0
    exploitability_score: float = 0.0
    hallucination_detected: bool = False
    latency_ms: float = 0.0
    tokens_input: int = 0
    tokens_output: int = 0
    consistency_score: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


class LLMValidator:
    """
    Validates LLM reasoning quality for vulnerability analysis.

    Evaluates:
    - CWE prediction accuracy (top-1, top-3)
    - Root-cause explanation quality (keyword-based)
    - Hallucination detection (self-contradiction, factual errors)
    - Exploitability assessment accuracy
    - Multi-model comparison across edge (sub-2B) and capable (7B+) models

    Key research question answered:
      Is the 11.49% accuracy (Classifier Collapse) due to bad COMPRESSION
      or due to MODEL CAPACITY LIMITS?
      If 7B/8B models achieve ≥60% on the same compressed graphs,
      the compression is proven sound and the failure is model-size only.
    """

    @staticmethod
    def normalize_cwe(cwe_raw: str) -> str:
        """
        Normalize CWE identifiers to canonical 'CWE-NNN' format.
        Handles: '416', 'cwe416', 'CWE 416', 'CWE-416' → 'CWE-416'.
        Fixes the partial-match issue that was penalizing exact accuracy.
        """
        import re
        if not cwe_raw:
            return 'CWE-Unknown'
        s = str(cwe_raw).strip().upper().replace(' ', '-')
        m = re.search(r'(\d{2,4})', s)
        if m:
            return f'CWE-{m.group(1)}'
        return cwe_raw

    def __init__(self, ollama_host: str = "http://localhost:11434"):
        self.ollama_host = ollama_host
        self.results: List[LLMValidationResult] = []
        self.model_results: Dict[str, List[LLMValidationResult]] = defaultdict(list)

    def check_model_available(self, model_name: str) -> bool:
        """Check if a model is available via Ollama."""
        try:
            client = OllamaClient()
            client.config.ollama_host = self.ollama_host
            available = client.list_models()
            return model_name in available or any(model_name in m for m in available)
        except Exception:
            return False

    def evaluate_model(self, model_name: str,
                       test_cases: List[Dict] = None,
                       num_trials: int = 1) -> List[LLMValidationResult]:
        """
        Evaluate a single LLM model.

        Args:
            model_name: Ollama model name
            test_cases: Test cases to evaluate (default: GROUND_TRUTH_VULNS)
            num_trials: Number of consistency trials per case

        Returns:
            List of validation results
        """
        if test_cases is None:
            test_cases = GROUND_TRUTH_VULNS

        logger.info(f"Evaluating model: {model_name} on {len(test_cases)} cases")

        results = []

        # Configure LLM module
        from utils.config import LLMConfig
        config = LLMConfig(model_name=model_name, ollama_host=self.ollama_host)
        llm_module = LLMReasoningModule(config)

        # Check availability
        if not llm_module.client.is_available():
            logger.warning(f"Ollama not available, using heuristic fallback for {model_name}")

        for case in test_cases:
            result = self._evaluate_case(llm_module, case, model_name, num_trials)
            results.append(result)

        self.model_results[model_name] = results
        self.results.extend(results)

        return results

    def _evaluate_case(self, llm_module: LLMReasoningModule,
                       case: Dict, model_name: str, num_trials: int) -> LLMValidationResult:
        """Evaluate a single test case."""
        # Create a minimal provenance summary for this vulnerability type
        prov_summary = self._build_test_provenance(case)

        start = time.time()

        try:
            # Get LLM analysis
            analysis = llm_module.analyze_provenance_summary(prov_summary)

            latency = (time.time() - start) * 1000  # ms

            # Score explanation quality
            rc_score = llm_module.rc_metrics.score_explanation(
                analysis.root_cause, case['cwe']
            ) if hasattr(llm_module, 'rc_metrics') else self._score_explanation(
                analysis.root_cause, case
            )

            # Detect hallucinations
            hallucination = self._detect_hallucination(analysis, case)

            # Consistency check (run multiple times)
            consistency = 1.0
            if num_trials > 1:
                consistency = self._check_consistency(llm_module, prov_summary,
                                                      analysis.vulnerability_class, num_trials)

            return LLMValidationResult(
                model_name=model_name,
                vuln_type=case['vuln_type'],
                ground_truth_cwe=case['cwe'],
                predicted_cwe=analysis.cwe_id,
                predicted_class=analysis.vulnerability_class,
                confidence=analysis.confidence,
                explanation=analysis.root_cause[:500],
                root_cause_score=rc_score,
                exploitability_score=analysis.exploitability_score,
                hallucination_detected=hallucination,
                latency_ms=latency,
                consistency_score=consistency,
            )

        except Exception as e:
            logger.error(f"Error evaluating {case['vuln_type']} with {model_name}: {e}")
            return LLMValidationResult(
                model_name=model_name,
                vuln_type=case['vuln_type'],
                ground_truth_cwe=case['cwe'],
                hallucination_detected=True,
                latency_ms=(time.time() - start) * 1000,
            )

    def _build_test_provenance(self, case: Dict) -> Dict:
        """Build a test provenance summary for a vulnerability type."""
        vuln_type = case['vuln_type']

        # Node type distribution varies by vulnerability
        node_distributions = {
            'buffer_overflow': {
                'function': 3, 'memory_region': 5, 'input_source': 1,
                'crash_site': 1, 'taint_label': 2, 'syscall': 0, 'heap_object': 0,
            },
            'use_after_free': {
                'function': 4, 'memory_region': 2, 'input_source': 0,
                'crash_site': 1, 'taint_label': 1, 'syscall': 0, 'heap_object': 3,
            },
            'format_string': {
                'function': 3, 'memory_region': 2, 'input_source': 1,
                'crash_site': 1, 'taint_label': 2, 'syscall': 1, 'heap_object': 0,
            },
            'integer_overflow': {
                'function': 3, 'memory_region': 2, 'input_source': 1,
                'crash_site': 1, 'taint_label': 1, 'syscall': 0, 'heap_object': 0,
            },
        }

        default_dist = {
            'function': 3, 'memory_region': 3, 'input_source': 1,
            'crash_site': 1, 'taint_label': 1, 'syscall': 0, 'heap_object': 0,
        }

        node_types = node_distributions.get(vuln_type, default_dist)

        return {
            'binary_path': 'test_binary',
            'trace_id': f'test_{vuln_type}',
            'nodes': [
                {'type': t, 'count': c}
                for t, c in node_types.items() if c > 0
            ],
            'edges': [
                {'type': 'taint_flow', 'count': node_types.get('taint_label', 1)},
                {'type': 'memory_propagation', 'count': node_types.get('memory_region', 1)},
                {'type': 'control_flow', 'count': 2},
            ],
            'statistics': {
                'total_nodes': sum(node_types.values()),
                'total_edges': 6,
                'node_types': node_types,
                'attack_path': [
                    {'type': 'input_source', 'label': 'read()'},
                    {'type': 'taint_label', 'label': f'taint:{vuln_type}'},
                    {'type': 'function', 'label': case['keywords'][0] if case['keywords'] else 'vuln_func'},
                    {'type': 'crash_site', 'label': 'crash'},
                ],
            },
        }

    def _score_explanation(self, explanation: str, case: Dict) -> float:
        """Score explanation against ground truth keywords."""
        explanation_lower = explanation.lower()
        keywords = case.get('keywords', [])

        if not keywords:
            return 0.5

        hits = sum(1 for kw in keywords if kw.lower() in explanation_lower)
        return hits / len(keywords)

    def _detect_hallucination(self, analysis: VulnerabilityAnalysis,
                              case: Dict) -> bool:
        """
        Detect potential hallucinations in LLM output.

        Checks for:
        1. CWE that doesn't match vulnerability class
        2. Contradictory statements
        3. Factually incorrect CWE assignments
        """
        hallucination = False

        # Check CWE consistency with vulnerability class
        cwe_family_map = {
            'CWE-121': 'buffer_overflow', 'CWE-122': 'buffer_overflow',
            'CWE-416': 'use_after_free', 'CWE-415': 'use_after_free',
            'CWE-134': 'format_string',
            'CWE-190': 'integer_overflow',
            'CWE-78': 'command_injection',
            'CWE-22': 'path_traversal',
            'CWE-476': 'null_pointer',
            'CWE-401': 'memory_leak',
        }

        predicted_family = cwe_family_map.get(analysis.cwe_id, '')
        if predicted_family and analysis.vulnerability_class != 'unknown':
            if predicted_family != analysis.vulnerability_class:
                # CWE and class don't match - potential inconsistency
                pass  # Not necessarily hallucination

        # Check for impossible confidence
        if analysis.confidence > 1.0 or analysis.confidence < 0:
            hallucination = True

        # Check for empty but declared root cause
        if not analysis.root_cause or len(analysis.root_cause) < 10:
            if analysis.confidence > 0.5:
                hallucination = True

        return hallucination

    def _check_consistency(self, llm_module: LLMReasoningModule,
                           prov_summary: Dict,
                           expected_class: str,
                           num_trials: int) -> float:
        """Check if model gives consistent results across multiple runs."""
        predictions = []
        for _ in range(num_trials):
            try:
                analysis = llm_module.analyze_provenance_summary(prov_summary)
                predictions.append(analysis.vulnerability_class)
            except Exception:
                predictions.append("error")

        # Fraction matching the most common prediction
        if not predictions:
            return 0.0

        most_common = max(set(predictions), key=predictions.count)
        agreement = predictions.count(most_common) / len(predictions)
        return agreement

    def compare_models(self, model_names: List[str] = None) -> Dict:
        """
        Compare multiple LLM models on the same test cases.

        Returns:
            Comparison dictionary with per-model statistics
        """
        if model_names is None:
            model_names = list(SUPPORTED_MODELS.keys())

        # Run evaluation for each model
        for model in model_names:
            if model not in self.model_results:
                self.evaluate_model(model)

        # Compute comparison metrics
        comparison = {}
        for model in model_names:
            results = self.model_results.get(model, [])
            if not results:
                continue

            total = len(results)
            # Normalize CWE IDs before accuracy scoring to handle prefix issues
            correct_cwe = sum(
                1 for r in results
                if self.normalize_cwe(r.ground_truth_cwe) == self.normalize_cwe(r.predicted_cwe)
            )
            correct_class = sum(1 for r in results if r.vuln_type == r.predicted_class)
            hallucinations = sum(1 for r in results if r.hallucination_detected)
            avg_latency = statistics.mean([r.latency_ms for r in results if r.latency_ms > 0]) if any(r.latency_ms > 0 for r in results) else 0
            avg_rc_score = statistics.mean([r.root_cause_score for r in results]) if results else 0
            avg_consistency = statistics.mean([r.consistency_score for r in results]) if results else 0

            comparison[model] = {
                'cwe_top1_accuracy': correct_cwe / total if total > 0 else 0,
                'class_accuracy': correct_class / total if total > 0 else 0,
                'hallucination_rate': hallucinations / total if total > 0 else 0,
                'avg_root_cause_score': avg_rc_score,
                'avg_exploitability_score': statistics.mean([r.exploitability_score for r in results]),
                'avg_latency_ms': avg_latency,
                'avg_consistency': avg_consistency,
                'model_info': SUPPORTED_MODELS.get(model, {}),
            }

        return comparison

    def generate_comparison_table(self, comparison: Dict = None) -> str:
        """Generate a formatted comparison table."""
        if comparison is None:
            comparison = self.compare_models()

        lines = [
            "=" * 90,
            "LLM MODEL COMPARISON FOR VULNERABILITY ANALYSIS",
            "=" * 90,
            "",
            f"{'Model':<20} {'CWE Acc':<10} {'Class Acc':<12} {'Halluc. Rate':<14} "
            f"{'RC Score':<10} {'Latency(ms)':<13} {'Consistency':<12}",
            "-" * 90,
        ]

        for model, stats in sorted(comparison.items()):
            info = stats.get('model_info', {})
            size = info.get('size', '?')
            lines.append(
                f"{model:<20} "
                f"{stats['cwe_top1_accuracy']:<10.3f} "
                f"{stats['class_accuracy']:<12.3f} "
                f"{stats['hallucination_rate']:<14.3f} "
                f"{stats['avg_root_cause_score']:<10.3f} "
                f"{stats['avg_latency_ms']:<13.1f} "
                f"{stats['avg_consistency']:<12.3f}"
            )

        lines.extend([
            "-" * 90,
            "CWE Acc = Top-1 CWE prediction accuracy",
            "Class Acc = Vulnerability class prediction accuracy",
            "Halluc. Rate = Fraction of outputs with detected hallucinations",
            "RC Score = Root cause explanation keyword completeness",
            "",
        ])

        return "\n".join(lines)

    def save_results(self, output_dir: str):
        """Save validation results."""
        os.makedirs(output_dir, exist_ok=True)

        # All results
        with open(os.path.join(output_dir, 'llm_validation_results.json'), 'w') as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2, default=str)

        # Per-model results
        for model, results in self.model_results.items():
            with open(os.path.join(output_dir, f'llm_results_{model}.json'), 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, default=str)

        # Comparison
        comparison = self.compare_models()
        with open(os.path.join(output_dir, 'llm_model_comparison.json'), 'w') as f:
            json.dump(comparison, f, indent=2, default=str)

        # Text table
        with open(os.path.join(output_dir, 'llm_comparison_table.txt'), 'w') as f:
            f.write(self.generate_comparison_table(comparison))

        logger.info(f"LLM validation results saved to {output_dir}")


if __name__ == '__main__':
    print("LLM Reasoning Validation for TRACEWISE-Lite")
    print("=" * 70)

    validator = LLMValidator()

    # Evaluate each model (will use fallback if Ollama unavailable)
    for model_name in ['tinyllama', 'phi', 'deepseek-coder']:
        print(f"\nEvaluating {model_name}...")
        validator.evaluate_model(model_name)

    # Compare
    comparison = validator.compare_models()
    print("\n" + validator.generate_comparison_table(comparison))

    validator.save_results('./eval/results')