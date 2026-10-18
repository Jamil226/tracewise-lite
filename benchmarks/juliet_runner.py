"""
Juliet Test Suite Runner for TRACEWISE-Lite

Automates execution of Juliet test cases for CWE classification evaluation.
Juliet provides ground-truth labeled vulnerabilities with known CWE IDs.

Dataset: NIST SAMATE Juliet Test Suite for C/C++
"""

import os
import sys
import json
import re
import glob
import subprocess
import tempfile
import statistics
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'evaluation'))

from utils.logger import setup_logger
from utils.config import get_config
from instrumentation.dynamorio_client import TraceSimulator
from main_pipeline import TraceWisePipeline

logger = setup_logger("juliet")


# Juliet CWE to vulnerability type mapping
JULIET_CWE_MAP = {
    'CWE121': ('CWE-121', 'buffer_overflow', 'stack'),
    'CWE122': ('CWE-122', 'buffer_overflow', 'heap'),
    'CWE124': ('CWE-124', 'buffer_overflow', 'bounds'),
    'CWE126': ('CWE-126', 'buffer_overflow', 'overread'),
    'CWE127': ('CWE-127', 'buffer_overflow', 'underread'),
    'CWE415': ('CWE-415', 'double_free', None),
    'CWE416': ('CWE-416', 'use_after_free', None),
    'CWE134': ('CWE-134', 'format_string', None),
    'CWE190': ('CWE-190', 'integer_overflow', None),
    'CWE191': ('CWE-191', 'integer_underflow', None),
    'CWE78': ('CWE-78', 'command_injection', None),
    'CWE22': ('CWE-22', 'path_traversal', None),
    'CWE401': ('CWE-401', 'memory_leak', None),
    'CWE476': ('CWE-476', 'null_pointer', None),
    'CWE617': ('CWE-617', 'assertion', None),
    'CWE690': ('CWE-690', 'null_deref', None),
}


def extract_cwe_from_path(filepath: str) -> Optional[str]:
    """Extract CWE ID from Juliet file path."""
    match = re.search(r'CWE(\d+)', filepath)
    if match:
        cwe_id = f"CWE-{match.group(1)}"
        return cwe_id
    return None


def parse_juliet_source(source_path: str) -> Dict:
    """
    Parse Juliet test source to extract:
    - CWE ID
    - Vulnerability type (bad vs good)
    - Entry point function
    """
    with open(source_path, 'r', errors='ignore') as f:
        content = f.read()

    cwe_id = extract_cwe_from_path(source_path)

    # Determine if bad (vulnerable) or good (fixed) case
    is_bad = 'bad' in os.path.basename(source_path).lower()

    # Extract entry point
    main_match = re.search(r'void\s+(CWE\d+_\w+_\w+)\s*\(', content)
    entry_point = main_match.group(1) if main_match else 'main'

    # Extract data flow description (from comments)
    flow_match = re.search(r'/\*\s*(.*?(?:Source|Sink|Flow).*?)\*/', content, re.DOTALL)
    data_flow = flow_match.group(1).strip() if flow_match else ""

    return {
        'cwe_id': cwe_id,
        'is_bad': is_bad,
        'entry_point': entry_point,
        'data_flow': data_flow[:200],
        'filepath': source_path,
    }


@dataclass
class JulietResult:
    """Result of analyzing a single Juliet test case."""
    test_id: str
    cwe_ground_truth: str
    cwe_predicted: str = ""
    vulnerability_class: str = ""
    confidence: float = 0.0
    detected: bool = False
    root_cause: str = ""
    analysis_time: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class JulietBenchmark:
    """
    Runner for Juliet Test Suite evaluation.

    Evaluates TRACEWISE-Lite's ability to:
    1. Detect vulnerabilities in 'bad' test cases
    2. Not flag 'good' test cases as vulnerable (false positives)
    3. Correctly classify CWE IDs
    """

    def __init__(self, juliet_path: str = "./juliet"):
        self.juliet_path = Path(juliet_path)
        self.results: List[JulietResult] = []
        self.summary: Dict = {}

    def discover_test_cases(self, cwe_filter: List[str] = None, max_per_cwe: int = 10) -> List[Dict]:
        """
        Discover Juliet test cases organized by CWE.

        Args:
            cwe_filter: Only include these CWEs (e.g., ['CWE121', 'CWE122'])
            max_per_cwe: Maximum test cases per CWE to include

        Returns:
            List of test case metadata dictionaries
        """
        test_cases = []

        if not self.juliet_path.exists():
            logger.warning(f"Juliet path not found: {self.juliet_path}")
            logger.info("Using simulated Juliet-style test cases instead")
            return self._generate_simulated_cases(cwe_filter, max_per_cwe)

        # Real Juliet dataset discovery
        for cwe_dir in sorted(self.juliet_path.iterdir()):
            if not cwe_dir.is_dir():
                continue

            cwe_match = re.match(r'CWE(\d+)', cwe_dir.name)
            if not cwe_match:
                continue

            cwe_id = f"CWE{cwe_match.group(1)}"

            if cwe_filter and cwe_id not in cwe_filter:
                continue

            count = 0
            for subdir in cwe_dir.iterdir():
                if not subdir.is_dir():
                    continue

                # Find C source files
                for c_file in subdir.glob('*.c'):
                    if count >= max_per_cwe:
                        break

                    parsed = parse_juliet_source(str(c_file))
                    if parsed['cwe_id']:
                        test_cases.append(parsed)
                        count += 1

        logger.info(f"Discovered {len(test_cases)} Juliet test cases")
        return test_cases

    def _generate_simulated_cases(self, cwe_filter: List[str] = None,
                                   max_per_cwe: int = 10) -> List[Dict]:
        """Generate simulated Juliet-style test cases for evaluation."""
        cases = []
        cwe_list = cwe_filter or list(JULIET_CWE_MAP.keys())

        for cwe_code in cwe_list:
            info = JULIET_CWE_MAP.get(cwe_code)
            if not info:
                continue

            cwe_id, vuln_type, subtype = info

            for i in range(min(max_per_cwe, 5)):
                # Bad case (vulnerable)
                cases.append({
                    'cwe_id': cwe_id,
                    'is_bad': True,
                    'entry_point': f'{cwe_code}_bad_{i:02d}',
                    'data_flow': f'{vuln_type} vulnerability via {subtype or "unsafe"} operation',
                    'filepath': f'simulated/{cwe_code}/s{str(i).zfill(3)}/bad_{i}.c',
                    'simulated': True,
                    'vuln_type': vuln_type,
                })

                # Good case (fixed)
                cases.append({
                    'cwe_id': cwe_id,
                    'is_bad': False,
                    'entry_point': f'{cwe_code}_good_{i:02d}',
                    'data_flow': f'{vuln_type} safe variant with bounds checking',
                    'filepath': f'simulated/{cwe_code}/s{str(i).zfill(3)}/good_{i}.c',
                    'simulated': True,
                    'vuln_type': vuln_type,
                })

        logger.info(f"Generated {len(cases)} simulated Juliet test cases")
        return cases

    def run_evaluation(self, test_cases: List[Dict],
                       pipeline: TraceWisePipeline = None) -> List[JulietResult]:
        """
        Run TRACEWISE-Lite on all test cases and collect results.

        Args:
            test_cases: List of test case metadata
            pipeline: Optional pre-configured pipeline

        Returns:
            List of JulietResult objects
        """
        if pipeline is None:
            pipeline = TraceWisePipeline()

        results = []
        total = len(test_cases)

        for idx, case in enumerate(test_cases):
            logger.info(f"[{idx+1}/{total}] Analyzing {case['entry_point']} ({case['cwe_id']})")

            result = self._analyze_case(case, pipeline)
            results.append(result)

        self.results = results
        self._compute_summary()

        return results

    def _analyze_case(self, case: Dict, pipeline: TraceWisePipeline) -> JulietResult:
        """Analyze a single test case using the real DynamoRIO pipeline."""
        import time
        import os
        import subprocess
        start = time.time()

        test_id = f"{case['cwe_id']}_{case['entry_point']}"
        binary_path = case.get('filepath')

        if not binary_path or not os.path.exists(binary_path):
            logger.warning(f"Binary {binary_path} not found. Skipping.")
            return JulietResult(test_id=test_id, cwe_ground_truth=case['cwe_id'], detected=False)

        trace_output = f"/tmp/tracewise_juliet_{test_id}.json"
        import shutil
        dynamorio_home = os.environ.get('DYNAMORIO_HOME')
        if dynamorio_home:
            drrun = os.path.join(dynamorio_home, 'bin64', 'drrun')
        else:
            drrun = shutil.which('drrun') or 'drrun'
        dr_client = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/instrumentation/dr_client/build/libtracewise_dr.so'))

        # Run real instrumentation
        try:
            subprocess.run([drrun, '-c', dr_client, trace_output, '--', binary_path], 
                           input=b"A"*100 + b"\\n", capture_output=True, timeout=10)
        except subprocess.TimeoutExpired:
            pass

        if not os.path.exists(trace_output) or os.path.getsize(trace_output) == 0:
            return JulietResult(test_id=test_id, cwe_ground_truth=case['cwe_id'], detected=False)

        # Run TRACEWISE pipeline on the real trace
        from instrumentation.dynamorio_client import ExecutionTrace, ExecutionEvent, EventType
        from provenance.collector import SelectiveProvenanceCollector
        from provenance.hbpg import HBPGConstructor
        from compression.engine import SemanticCompressionEngine
        from llm.reasoning import LLMReasoningModule
        import json

        events = []
        with open(trace_output, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    mapped_type = {
                        'mem_read': EventType.MEMORY_READ, 'mem_write': EventType.MEMORY_WRITE,
                        'func_call': EventType.FUNCTION_CALL, 'syscall': EventType.SYSCALL,
                        'crash': EventType.CRASH
                    }.get(data.get('event_type'), EventType.SYSCALL)
                    events.append(ExecutionEvent(event_type=mapped_type, address=data.get('address', 0), timestamp=data.get('timestamp', 0), thread_id=data.get('thread_id', 0), memory_address=data.get('memory_address'), memory_size=data.get('memory_size'), func_name=data.get('func_name'), syscall_number=data.get('syscall_number')))
                except Exception: pass
                
        trace = ExecutionTrace(trace_id=test_id, binary_path=binary_path, events=events)
        
        collector = SelectiveProvenanceCollector()
        constructor = HBPGConstructor()
        compressor = SemanticCompressionEngine()
        llm = LLMReasoningModule()

        filtered = collector.process_trace(trace)
        hbpg = constructor.construct(filtered)
        compressed = compressor.compress(hbpg)
        
        analysis = llm.analyze_provenance_summary(compressed.to_dict())
        elapsed = time.time() - start

        if analysis:
            return JulietResult(
                test_id=test_id,
                cwe_ground_truth=case['cwe_id'],
                cwe_predicted=analysis.cwe_id,
                vulnerability_class=analysis.vulnerability_class,
                confidence=analysis.confidence,
                detected=True,
                root_cause=analysis.root_cause[:200],
                analysis_time=elapsed,
            )
        else:
            return JulietResult(test_id=test_id, cwe_ground_truth=case['cwe_id'], detected=False)    analysis_time=elapsed,
                error=result.error_message or "Analysis failed",
            )

    def _compute_summary(self):
        """Compute aggregate statistics."""
        if not self.results:
            return

        # Overall accuracy
        total = len(self.results)
        correct_cwe = sum(1 for r in self.results if r.cwe_ground_truth == r.cwe_predicted)
        detected = sum(1 for r in self.results if r.detected)

        # By CWE
        by_cwe = defaultdict(lambda: {'total': 0, 'correct': 0, 'detected': 0})
        for r in self.results:
            cwe = r.cwe_ground_truth
            by_cwe[cwe]['total'] += 1
            if r.cwe_ground_truth == r.cwe_predicted:
                by_cwe[cwe]['correct'] += 1
            if r.detected:
                by_cwe[cwe]['detected'] += 1

        self.summary = {
            'total_cases': total,
            'cwe_top1_accuracy': correct_cwe / total if total > 0 else 0,
            'detection_rate': detected / total if total > 0 else 0,
            'avg_confidence': statistics.mean([r.confidence for r in self.results if r.confidence > 0]) if any(r.confidence > 0 for r in self.results) else 0,
            'avg_analysis_time': statistics.mean([r.analysis_time for r in self.results]),
            'by_cwe': {k: {
                'accuracy': v['correct'] / v['total'] if v['total'] > 0 else 0,
                'detection_rate': v['detected'] / v['total'] if v['total'] > 0 else 0,
                'count': v['total'],
            } for k, v in by_cwe.items()},
        }

    def save_results(self, output_dir: str):
        """Save evaluation results."""
        os.makedirs(output_dir, exist_ok=True)

        # Raw results
        with open(os.path.join(output_dir, 'juliet_results.json'), 'w') as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2, default=str)

        # Summary
        with open(os.path.join(output_dir, 'juliet_summary.json'), 'w') as f:
            json.dump(self.summary, f, indent=2, default=str)

        # CSV
        import csv
        with open(os.path.join(output_dir, 'juliet_results.csv'), 'w', newline='') as f:
            if self.results:
                writer = csv.DictWriter(f, fieldnames=self.results[0].to_dict().keys())
                writer.writeheader()
                for r in self.results:
                    writer.writerow(r.to_dict())

        logger.info(f"Results saved to {output_dir}")

    def print_summary(self):
        """Print evaluation summary."""
        if not self.summary:
            print("No results to summarize. Run evaluation first.")
            return

        print("\n" + "=" * 70)
        print("JULIET TEST SUITE EVALUATION SUMMARY")
        print("=" * 70)
        print(f"Total Cases:    {self.summary['total_cases']}")
        print(f"CWE Accuracy:   {self.summary['cwe_top1_accuracy']:.2%}")
        print(f"Detection Rate: {self.summary['detection_rate']:.2%}")
        print(f"Avg Confidence: {self.summary['avg_confidence']:.3f}")
        print(f"Avg Time:       {self.summary['avg_analysis_time']:.2f}s")
        print("-" * 70)
        print("By CWE:")
        for cwe, stats in sorted(self.summary['by_cwe'].items()):
            print(f"  {cwe}: accuracy={stats['accuracy']:.2%}, "
                  f"detection={stats['detection_rate']:.2%}, n={stats['count']}")
        print("=" * 70)


if __name__ == '__main__':
    import statistics

    print("Juliet Test Suite Runner for TRACEWISE-Lite")
    print("=" * 60)

    benchmark = JulietBenchmark()

    # Run on key CWEs
    test_cases = benchmark.discover_test_cases(
        cwe_filter=['CWE121', 'CWE122', 'CWE415', 'CWE416', 'CWE134', 'CWE190'],
        max_per_cwe=3
    )

    results = benchmark.run_evaluation(test_cases)
    benchmark.print_summary()
    benchmark.save_results('./benchmarks/juliet/results')