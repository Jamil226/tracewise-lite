"""
TRACEWISE-Lite: Main Pipeline Orchestrator

Coordinates the complete vulnerability analysis workflow:
1. Fuzzing -> 2. Instrumentation -> 3. Provenance Collection
-> 4. HBPG Construction -> 5. Semantic Compression -> 6. LLM Analysis
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

from utils.config import TraceWiseConfig, get_config
from utils.logger import setup_logger, ProgressTracker

from fuzzing.afl_wrapper import AFLFuzzingEngine, CrashInfo, quick_fuzz
from instrumentation.dynamorio_client import (
    DynamoRIOClient, ExecutionTrace, TraceSimulator
)
from provenance.collector import SelectiveProvenanceCollector, ProvenanceGraphBuilder
from provenance.hbpg import HBPGConstructor, HybridBinaryProvenanceGraph
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule, VulnerabilityAnalysis

logger = setup_logger("main")


@dataclass
class PipelineResult:
    """Complete result from TRACEWISE-Lite pipeline"""
    success: bool
    target_binary: str
    trace_id: str
    crash_found: bool
    crash_info: Optional[Dict]
    provenance_stats: Dict
    hbpg_summary: Dict
    compression_summary: Dict
    vulnerability_analysis: Optional[VulnerabilityAnalysis]
    report_path: Optional[str]
    execution_time: float
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        if self.vulnerability_analysis:
            result['vulnerability_analysis'] = asdict(self.vulnerability_analysis)
        return result


class TraceWisePipeline:
    """
    TRACEWISE-Lite Main Pipeline

    Orchestrates the complete vulnerability analysis workflow
    from fuzzing to LLM-assisted reasoning.
    """

    def __init__(self, config: TraceWiseConfig = None):
        self.config = config or get_config()
        self.config.ensure_directories()

        # Initialize components
        self.fuzzing_engine = AFLFuzzingEngine(self.config.fuzzing)
        self.instrumentation = DynamoRIOClient(self.config.instrumentation)
        self.provenance_collector = SelectiveProvenanceCollector(self.config.provenance)
        self.hbpg_constructor = HBPGConstructor()
        self.compression_engine = SemanticCompressionEngine(self.config.compression)
        self.llm_module = LLMReasoningModule(self.config.llm)

        self.results_dir = os.path.join(self.config.workspace_dir, "results")
        os.makedirs(self.results_dir, exist_ok=True)

    def run_full_pipeline(self,
                          target_binary: str,
                          seeds: List[bytes] = None,
                          fuzzing_timeout: int = 300,
                          skip_fuzzing: bool = False,
                          existing_crash: str = None) -> PipelineResult:
        """
        Run complete TRACEWISE-Lite pipeline

        Args:
            target_binary: Path to target binary
            seeds: Optional seed inputs for fuzzing
            fuzzing_timeout: Fuzzing timeout in seconds
            skip_fuzzing: Use existing crash instead of fuzzing
            existing_crash: Path to existing crash input

        Returns:
            PipelineResult with complete analysis
        """
        start_time = time.time()
        logger.info("=" * 70)
        logger.info("TRACEWISE-Lite Pipeline Starting")
        logger.info("=" * 70)
        logger.info(f"Target: {target_binary}")
        logger.info(f"Workspace: {self.config.workspace_dir}")

        try:
            # Step 1: Fuzzing (if not skipped)
            if not skip_fuzzing:
                crash_info = self._run_fuzzing(
                    target_binary, seeds, fuzzing_timeout
                )
            else:
                crash_info = self._load_existing_crash(existing_crash)

            if not crash_info:
                logger.warning("No crashes found - analysis may be limited")

            # Step 2: Instrumentation
            trace = self._run_instrumentation(target_binary, crash_info)

            # Step 3: Selective Provenance Collection
            filtered_trace = self._collect_provenance(trace)

            # Step 4: HBPG Construction
            hbpg = self._construct_hbpg(filtered_trace)

            # Step 5: Semantic Compression
            compressed_hbpg = self._compress_hbpg(hbpg)

            # Step 6: LLM Analysis
            analysis = self._analyze_with_llm(compressed_hbpg, crash_info)

            # Generate Report
            report_path = self._generate_report(
                analysis, compressed_hbpg, crash_info
            )

            execution_time = time.time() - start_time

            result = PipelineResult(
                success=True,
                target_binary=target_binary,
                trace_id=trace.trace_id if trace else "",
                crash_found=crash_info is not None,
                crash_info=crash_info.to_dict() if crash_info else None,
                provenance_stats=filtered_trace.metadata if filtered_trace else {},
                hbpg_summary=hbpg.to_dict().get('statistics', {}) if hbpg else {},
                compression_summary=self.compression_engine.get_compression_summary(),
                vulnerability_analysis=analysis,
                report_path=report_path,
                execution_time=execution_time
            )

            # Save result
            self._save_result(result)

            logger.info("=" * 70)
            logger.info("TRACEWISE-Lite Pipeline Complete")
            logger.info(f"Total Time: {execution_time:.2f}s")
            logger.info(f"Report: {report_path}")
            logger.info("=" * 70)

            return result

        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            execution_time = time.time() - start_time
            return PipelineResult(
                success=False,
                target_binary=target_binary,
                trace_id="",
                crash_found=False,
                crash_info=None,
                provenance_stats={},
                hbpg_summary={},
                compression_summary={},
                vulnerability_analysis=None,
                report_path=None,
                execution_time=execution_time,
                error_message=str(e)
            )

    def _run_fuzzing(self,
                     target_binary: str,
                     seeds: List[bytes],
                     timeout: int) -> Optional[CrashInfo]:
        """Step 1: Run AFL++ fuzzing"""
        logger.info("-" * 70)
        logger.info("Step 1: Fuzzing with AFL++")
        logger.info("-" * 70)

        self.fuzzing_engine.create_seed_corpus(seeds)
        process = self.fuzzing_engine.start_fuzzing(target_binary, timeout=timeout)

        # Wait for fuzzing to complete
        try:
            process.wait(timeout=timeout + 30)
        except Exception:
            self.fuzzing_engine.stop_fuzzing()

        crashes = self.fuzzing_engine.collect_crashes()

        if crashes:
            logger.info(f"Found {len(crashes)} crashes")
            return crashes[0]
        else:
            logger.warning("No crashes found during fuzzing")
            return None

    def _load_existing_crash(self, crash_path: str) -> Optional[CrashInfo]:
        """Load existing crash for analysis"""
        if not crash_path or not os.path.exists(crash_path):
            return None

        logger.info(f"Using existing crash: {crash_path}")
        return CrashInfo(
            crash_id="existing",
            input_path=crash_path,
            output_path=crash_path,
            crash_type="unknown",
            signal=11,
            exec_time=0,
            crash_hash="existing"
        )

    def _run_instrumentation(self,
                            target_binary: str,
                            crash_info: CrashInfo) -> ExecutionTrace:
        """Step 2: Run DynamoRIO instrumentation"""
        logger.info("-" * 70)
        logger.info("Step 2: Dynamic Binary Instrumentation")
        logger.info("-" * 70)

        if crash_info:
            # Read crash input
            with open(crash_info.input_path, 'rb') as f:
                crash_input = f.read()

            trace = self.instrumentation.run_with_instrumentation(
                target_binary=target_binary,
                input_data=crash_input,
                timeout=30
            )
        else:
            trace = self.instrumentation.run_with_instrumentation(
                target_binary=target_binary,
                timeout=30
            )

        logger.info(f"Collected trace with {len(trace.events)} events")
        return trace

    def _collect_provenance(self, trace: ExecutionTrace) -> ExecutionTrace:
        """Step 3: Selective Provenance Collection"""
        logger.info("-" * 70)
        logger.info("Step 3: Selective Provenance Collection")
        logger.info("-" * 70)

        filtered_trace = self.provenance_collector.process_trace(trace)

        stats = filtered_trace.metadata
        logger.info(f"Original events: {stats.get('original_event_count', 0)}")
        logger.info(f"Filtered events: {stats.get('filtered_event_count', 0)}")
        logger.info(f"Reduction: {stats.get('reduction_ratio', 0)*100:.1f}%")

        return filtered_trace

    def _construct_hbpg(self, trace: ExecutionTrace) -> HybridBinaryProvenanceGraph:
        """Step 4: HBPG Construction"""
        logger.info("-" * 70)
        logger.info("Step 4: HBPG Construction")
        logger.info("-" * 70)

        hbpg = self.hbpg_constructor.construct(trace)

        # Save HBPG
        hbpg_path = os.path.join(self.results_dir, f"hbpg_{trace.trace_id}.json")
        hbpg.save(hbpg_path)

        return hbpg

    def _compress_hbpg(self, hbpg: HybridBinaryProvenanceGraph) -> HybridBinaryProvenanceGraph:
        """Step 5: Semantic Compression"""
        logger.info("-" * 70)
        logger.info("Step 5: Semantic Compression")
        logger.info("-" * 70)

        compressed = self.compression_engine.compress(hbpg)

        summary = self.compression_engine.get_compression_summary()
        logger.info(f"Compression: {summary.get('reduction', {}).get('nodes', 'N/A')} node reduction")
        logger.info(f"Semantic preservation: {summary.get('semantic_preservation', 'N/A')}")

        # Save compressed HBPG
        comp_path = os.path.join(self.results_dir, f"hbpg_{hbpg.trace_id}_compressed.json")
        compressed.save(comp_path)

        return compressed

    def _analyze_with_llm(self,
                         hbpg: HybridBinaryProvenanceGraph,
                         crash_info: CrashInfo) -> Optional[VulnerabilityAnalysis]:
        """Step 6: LLM Analysis"""
        logger.info("-" * 70)
        logger.info("Step 6: LLM-Assisted Reasoning")
        logger.info("-" * 70)

        # Check if Ollama is available
        if not self.llm_module.client.is_available():
            logger.warning("Ollama not available - using heuristic analysis")
            return self.llm_module._fallback_analysis(hbpg.to_dict())

        # Analyze
        summary = hbpg.to_dict()
        crash_dict = crash_info.to_dict() if crash_info else None

        analysis = self.llm_module.analyze_provenance_summary(summary, crash_dict)

        logger.info(f"Vulnerability Class: {analysis.vulnerability_class}")
        logger.info(f"CWE: {analysis.cwe_id}")
        logger.info(f"Confidence: {analysis.confidence:.2f}")

        return analysis

    def _generate_report(self,
                        analysis: VulnerabilityAnalysis,
                        hbpg: HybridBinaryProvenanceGraph,
                        crash_info: CrashInfo) -> str:
        """Generate final report"""
        report_path = os.path.join(
            self.results_dir,
            f"report_{hbpg.trace_id}.txt"
        )

        comp_summary = self.compression_engine.get_compression_summary()
        report = self.llm_module.generate_report(
            analysis=analysis,
            compression_summary=comp_summary,
            output_path=report_path
        )

        return report_path

    def _save_result(self, result: PipelineResult):
        """Save pipeline result to JSON"""
        result_path = os.path.join(
            self.results_dir,
            f"result_{result.trace_id or 'unknown'}.json"
        )
        with open(result_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

    def run_simulation(self, vulnerability_type: str = "buffer_overflow") -> PipelineResult:
        """
        Run pipeline with simulated trace (for testing/demo)

        Args:
            vulnerability_type: Type of vulnerability to simulate

        Returns:
            PipelineResult
        """
        start_time = time.time()
        logger.info("=" * 70)
        logger.info("TRACEWISE-Lite Simulation Mode")
        logger.info("=" * 70)
        logger.info(f"Simulating: {vulnerability_type}")

        try:
            # Generate simulated trace
            trace = TraceSimulator.generate_vulnerable_trace(
                binary_path="simulated_binary",
                vulnerability_type=vulnerability_type
            )

            # Step 3: Provenance Collection
            filtered_trace = self._collect_provenance(trace)

            # Step 4: HBPG Construction
            hbpg = self._construct_hbpg(filtered_trace)

            # Step 5: Compression
            compressed = self._compress_hbpg(hbpg)

            # Step 6: Analysis (fallback for simulation)
            analysis = self.llm_module._fallback_analysis(compressed.to_dict())
            # Override with known vulnerability
            analysis.vulnerability_class = vulnerability_type
            analysis.cwe_id = self._get_cwe_for_vuln(vulnerability_type)
            analysis.confidence = 0.9

            # Generate report
            report_path = self._generate_report(analysis, compressed, None)

            execution_time = time.time() - start_time

            result = PipelineResult(
                success=True,
                target_binary="simulated",
                trace_id=trace.trace_id,
                crash_found=True,
                crash_info=None,
                provenance_stats=filtered_trace.metadata,
                hbpg_summary=hbpg.to_dict().get('statistics', {}),
                compression_summary=self.compression_engine.get_compression_summary(),
                vulnerability_analysis=analysis,
                report_path=report_path,
                execution_time=execution_time
            )

            self._save_result(result)

            logger.info("=" * 70)
            logger.info("Simulation Complete")
            logger.info(f"Time: {execution_time:.2f}s")
            logger.info("=" * 70)

            return result

        except Exception as e:
            logger.error(f"Simulation failed: {e}", exc_info=True)
            return PipelineResult(
                success=False,
                target_binary="simulated",
                trace_id="",
                crash_found=False,
                crash_info=None,
                provenance_stats={},
                hbpg_summary={},
                compression_summary={},
                vulnerability_analysis=None,
                report_path=None,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )

    def _get_cwe_for_vuln(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            'buffer_overflow': 'CWE-121',
            'use_after_free': 'CWE-416',
            'format_string': 'CWE-134',
            'heap_overflow': 'CWE-122',
            'integer_overflow': 'CWE-190'
        }
        return cwe_map.get(vuln_type, 'CWE-Unknown')


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='TRACEWISE-Lite: Vulnerability Root Cause Analysis'
    )
    parser.add_argument('target', nargs='?',
                       help='Target binary to analyze')
    parser.add_argument('--config', '-c',
                       help='Configuration file (JSON)')
    parser.add_argument('--timeout', '-t', type=int, default=300,
                       help='Fuzzing timeout in seconds (default: 300)')
    parser.add_argument('--seeds', '-s',
                       help='Directory containing seed inputs')
    parser.add_argument('--crash', '-x',
                       help='Existing crash input file')
    parser.add_argument('--simulate', '-sim', action='store_true',
                       help='Run simulation mode')
    parser.add_argument('--vuln-type', default='buffer_overflow',
                       help='Vulnerability type for simulation')
    parser.add_argument('--workspace', '-w', default='./workspace',
                       help='Workspace directory')
    parser.add_argument('--model', '-m', default='tinyllama',
                       help='LLM model name (tinyllama, phi, deepseek-coder)')
    parser.add_argument('--skip-fuzzing', action='store_true',
                       help='Skip fuzzing, use existing crash')
    parser.add_argument('--output', '-o',
                       help='Output directory for results')

    args = parser.parse_args()

    # Load configuration
    if args.config:
        config = TraceWiseConfig.from_json(args.config)
    else:
        config = TraceWiseConfig()

    config.workspace_dir = args.workspace
    config.llm.model_name = args.model

    if args.output:
        config.fuzzing.output_dir = args.output

    # Create pipeline
    pipeline = TraceWisePipeline(config)

    if args.simulate:
        # Simulation mode
        result = pipeline.run_simulation(args.vuln_type)
    elif args.target:
        # Real analysis mode
        seeds = None
        if args.seeds:
            seeds = []
            for seed_file in Path(args.seeds).iterdir():
                if seed_file.is_file():
                    seeds.append(seed_file.read_bytes())

        result = pipeline.run_full_pipeline(
            target_binary=args.target,
            seeds=seeds,
            fuzzing_timeout=args.timeout,
            skip_fuzzing=args.skip_fuzzing,
            existing_crash=args.crash
        )
    else:
        parser.print_help()
        return

    # Print summary
    if result.success:
        print("\n" + "=" * 70)
        print("ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Target: {result.target_binary}")
        print(f"Trace ID: {result.trace_id}")
        print(f"Crash Found: {result.crash_found}")
        print(f"Execution Time: {result.execution_time:.2f}s")

        if result.vulnerability_analysis:
            analysis = result.vulnerability_analysis
            print(f"\nVulnerability: {analysis.vulnerability_class}")
            print(f"CWE: {analysis.cwe_id}")
            print(f"Severity: {analysis.severity}")
            print(f"Confidence: {analysis.confidence:.2f}")

        if result.report_path:
            print(f"\nFull Report: {result.report_path}")
    else:
        print(f"\nPipeline failed: {result.error_message}")


if __name__ == "__main__":
    main()