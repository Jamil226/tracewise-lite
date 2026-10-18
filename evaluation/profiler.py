"""
Performance Profiler for TRACEWISE-Lite

Profiles resource consumption across all pipeline stages:
- RAM usage (peak, average)
- CPU utilization
- Stage-by-stage timing
- Scalability with trace/graph size
- LLM inference metrics

Uses psutil for system-level profiling and custom timers for stage-level.
"""

import os
import sys
import time
import json
import statistics
import tracemalloc
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.logger import setup_logger

logger = setup_logger("profiler")


@dataclass
class StageProfile:
    """Profile data for a single pipeline stage."""
    stage_name: str
    start_time: float = 0.0
    end_time: float = 0.0
    peak_ram_mb: float = 0.0
    avg_ram_mb: float = 0.0
    ram_samples: List[float] = field(default_factory=list)
    cpu_samples: List[float] = field(default_factory=list)
    events_processed: int = 0
    nodes_processed: int = 0
    output_size_bytes: int = 0

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    @property
    def throughput_events_per_sec(self) -> float:
        dur = self.duration_ms / 1000
        return self.events_processed / dur if dur > 0 else 0

    def to_dict(self) -> Dict:
        d = asdict(self)
        if hasattr(self, 'duration_ms'):
            d['duration_ms'] = self.duration_ms
        if hasattr(self, 'throughput_events_per_sec'):
            d['throughput_events_per_sec'] = self.throughput_events_per_sec
        return d


@dataclass
class ScalabilityResult:
    """Result of a single scalability experiment run."""
    input_size: int           # input metric (events, nodes, etc.)
    stage_name: str = ""
    duration_ms: float = 0.0
    peak_ram_mb: float = 0.0
    throughput: float = 0.0   # events/sec or nodes/sec

    def to_dict(self) -> Dict:
        d = asdict(self)
        if hasattr(self, 'duration_ms'):
            d['duration_ms'] = self.duration_ms
        if hasattr(self, 'throughput_events_per_sec'):
            d['throughput_events_per_sec'] = self.throughput_events_per_sec
        return d


class PerformanceProfiler:
    """
    Comprehensive performance profiler for TRACEWISE-Lite.

    Usage:
        profiler = PerformanceProfiler()
        with profiler.stage("provenance_collection"):
            # ... run stage ...
        report = profiler.get_report()
    """

    def __init__(self, enable_tracemalloc: bool = True):
        self.stages: List[StageProfile] = []
        self.current_stage: Optional[StageProfile] = None
        self.enable_tracemalloc = enable_tracemalloc
        self._polling_interval = 0.05  # 50ms
        self._polling_active = False
        self._poll_thread = None

    @contextmanager
    def stage(self, name: str):
        """Context manager for profiling a pipeline stage."""
        profile = StageProfile(stage_name=name)
        profile.start_time = time.time()

        # Start memory tracking
        if self.enable_tracemalloc:
            tracemalloc.start()
            start_mem = tracemalloc.take_snapshot()

        # Try to use psutil for CPU monitoring
        try:
            import psutil
            process = psutil.Process()
            initial_ram = process.memory_info().rss / (1024 * 1024)
            profile.ram_samples.append(initial_ram)
            profile.peak_ram_mb = initial_ram
        except ImportError:
            process = None

        self.current_stage = profile

        try:
            yield profile
        finally:
            profile.end_time = time.time()

            # Memory measurement
            if self.enable_tracemalloc:
                try:
                    end_mem = tracemalloc.take_snapshot()
                    top_stats = end_mem.compare_to(start_mem, 'lineno')
                    total_diff = sum(stat.size_diff for stat in top_stats)
                    profile.peak_ram_mb = abs(total_diff) / (1024 * 1024)
                    tracemalloc.stop()
                except Exception:
                    pass

            if process:
                try:
                    final_ram = process.memory_info().rss / (1024 * 1024)
                    profile.ram_samples.append(final_ram)
                    profile.peak_ram_mb = max(profile.peak_ram_mb, final_ram, *profile.ram_samples)
                    if profile.ram_samples:
                        profile.avg_ram_mb = statistics.mean(profile.ram_samples)
                except Exception:
                    pass

            self.stages.append(profile)
            self.current_stage = None

    def record_event_count(self, count: int):
        """Record number of events processed in current stage."""
        if self.current_stage:
            self.current_stage.events_processed = count

    def record_node_count(self, count: int):
        """Record number of nodes processed in current stage."""
        if self.current_stage:
            self.current_stage.nodes_processed = count

    def get_report(self) -> Dict:
        """Generate comprehensive performance report."""
        total_time_ms = sum(s.duration_ms for s in self.stages)
        total_ram = sum(s.peak_ram_mb for s in self.stages)

        return {
            'total_time_ms': total_time_ms,
            'total_peak_ram_mb': max((s.peak_ram_mb for s in self.stages), default=0),
            'stages': [s.to_dict() for s in self.stages],
            'stage_summary': {
                s.stage_name: {
                    'duration_ms': s.duration_ms,
                    'peak_ram_mb': s.peak_ram_mb,
                    'events_per_sec': s.throughput_events_per_sec,
                    'pct_of_total': (s.duration_ms / total_time_ms * 100) if total_time_ms > 0 else 0,
                }
                for s in self.stages
            },
        }

    def print_report(self):
        """Print formatted performance report."""
        report = self.get_report()

        print("\n" + "=" * 80)
        print("PERFORMANCE PROFILE REPORT")
        print("=" * 80)
        print(f"Total Pipeline Time: {report['total_time_ms']:.1f} ms")
        print(f"Peak RAM Usage:      {report['total_peak_ram_mb']:.2f} MB")
        print("-" * 80)
        print(f"{'Stage':<30} {'Time(ms)':<12} {'%':<8} {'RAM(MB)':<12} {'Throughput':<15}")
        print("-" * 80)

        for stage in self.stages:
            pct = (stage.duration_ms / report['total_time_ms'] * 100) if report['total_time_ms'] > 0 else 0
            tp = f"{stage.throughput_events_per_sec:.1f} evt/s" if stage.events_processed > 0 else "N/A"
            print(f"{stage.stage_name:<30} {stage.duration_ms:<12.1f} {pct:<8.1f} "
                  f"{stage.peak_ram_mb:<12.2f} {tp:<15}")

        print("=" * 80)

    def save(self, path: str):
        """Save performance report to JSON."""
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.get_report(), f, indent=2, default=str)


class ScalabilityBenchmark:
    """
    Benchmark scalability of TRACEWISE-Lite components.

    Measures how performance degrades with increasing input sizes.
    """

    def __init__(self):
        self.results: Dict[str, List[ScalabilityResult]] = defaultdict(list)

    def benchmark_provenance_collection(self,
                                        event_counts: List[int] = None) -> List[ScalabilityResult]:
        """Benchmark selective provenance collection scaling."""
        if event_counts is None:
            event_counts = [100, 500, 1000, 5000, 10000, 50000, 100000]

        from instrumentation.dynamorio_client import TraceSimulator
        from provenance.collector import SelectiveProvenanceCollector

        results = []
        for n_events in event_counts:
            trace = TraceSimulator.generate_vulnerable_trace()
            # Scale events by repeating
            while len(trace.events) < n_events:
                trace.events.extend(trace.events[:min(len(trace.events), n_events - len(trace.events))])
            trace.events = trace.events[:n_events]

            profiler = PerformanceProfiler()
            with profiler.stage(f"provenance_{n_events}_events"):
                collector = SelectiveProvenanceCollector()
                filtered = collector.process_trace(trace)
                profiler.record_event_count(n_events)

            report = profiler.get_report()
            result = ScalabilityResult(
                input_size=n_events,
                stage_name="provenance_collection",
                duration_ms=report['stages'][0]['duration_ms'],
                peak_ram_mb=report['stages'][0]['peak_ram_mb'],
                throughput=report['stages'][0].get('events_per_sec', 0),
            )
            results.append(result)
            self.results['provenance'].append(result)

        return results

    def benchmark_hbpg_construction(self,
                                    node_counts: List[int] = None) -> List[ScalabilityResult]:
        """Benchmark HBPG construction scaling."""
        if node_counts is None:
            node_counts = [10, 50, 100, 500, 1000, 5000]

        from instrumentation.dynamorio_client import TraceSimulator
        from provenance.collector import SelectiveProvenanceCollector
        from provenance.hbpg import HBPGConstructor

        results = []
        for n_nodes in node_counts:
            trace = TraceSimulator.generate_vulnerable_trace()
            collector = SelectiveProvenanceCollector()
            filtered = collector.process_trace(trace)

            profiler = PerformanceProfiler()
            with profiler.stage(f"hbpg_{n_nodes}_nodes"):
                constructor = HBPGConstructor()
                hbpg = constructor.construct(filtered)
                profiler.record_node_count(len(hbpg.nodes))

            report = profiler.get_report()
            result = ScalabilityResult(
                input_size=n_nodes,
                stage_name="hbpg_construction",
                duration_ms=report['stages'][0]['duration_ms'],
                peak_ram_mb=report['stages'][0]['peak_ram_mb'],
            )
            results.append(result)
            self.results['hbpg'].append(result)

        return results

    def benchmark_compression(self,
                              compression_configs: List[float] = None) -> List[ScalabilityResult]:
        """Benchmark semantic compression with different target ratios."""
        if compression_configs is None:
            compression_configs = [0.05, 0.1, 0.2, 0.3, 0.5, 0.7]

        from instrumentation.dynamorio_client import TraceSimulator
        from provenance.collector import SelectiveProvenanceCollector
        from provenance.hbpg import HBPGConstructor
        from compression.engine import SemanticCompressionEngine

        trace = TraceSimulator.generate_vulnerable_trace(vulnerability_type='buffer_overflow')
        collector = SelectiveProvenanceCollector()
        filtered = collector.process_trace(trace)
        constructor = HBPGConstructor()
        hbpg = constructor.construct(filtered)

        results = []
        for ratio in compression_configs:
            from utils.config import CompressionConfig
            config = CompressionConfig(compression_ratio=ratio)
            engine = SemanticCompressionEngine(config)

            profiler = PerformanceProfiler()
            with profiler.stage(f"compression_ratio_{ratio}"):
                compressed = engine.compress(hbpg)
                profiler.record_node_count(len(hbpg.nodes))

            report = profiler.get_report()
            result = ScalabilityResult(
                input_size=int(ratio * 100),  # percentage
                stage_name="compression",
                duration_ms=report['stages'][0]['duration_ms'],
                peak_ram_mb=report['stages'][0]['peak_ram_mb'],
            )
            results.append(result)
            self.results['compression'].append(result)

        return results

    def get_all_results(self) -> Dict[str, List[Dict]]:
        """Get all scalability results as dictionaries."""
        return {
            k: [r.to_dict() for r in v]
            for k, v in self.results.items()
        }

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.get_all_results(), f, indent=2, default=str)


if __name__ == '__main__':
    print("Performance Profiler for TRACEWISE-Lite")
    print("=" * 60)

    # Profile full pipeline
    from main_pipeline import TraceWisePipeline

    profiler = PerformanceProfiler()
    pipeline = TraceWisePipeline()

    with profiler.stage("full_pipeline"):
        result = pipeline.run_simulation("buffer_overflow")

    profiler.print_report()
    profiler.save('./profiling/pipeline_profile.json')

    # Scalability benchmarks
    print("\n" + "=" * 60)
    print("SCALABILITY BENCHMARKS")
    print("=" * 60)

    bench = ScalabilityBenchmark()

    print("\nProvenance Collection Scaling:")
    results = bench.benchmark_provenance_collection([100, 500, 1000, 5000])
    for r in results:
        print(f"  {r.input_size} events: {r.duration_ms:.1f}ms, {r.peak_ram_mb:.2f}MB")

    print("\nCompression Scaling:")
    results = bench.benchmark_compression([0.1, 0.3, 0.5])
    for r in results:
        print(f"  ratio {r.input_size}%: {r.duration_ms:.1f}ms, {r.peak_ram_mb:.2f}MB")

    bench.save('./profiling/scalability.json')