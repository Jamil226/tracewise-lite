#!/usr/bin/env python3
"""
TRACEWISE-Lite Demo Script

Demonstrates the complete pipeline using simulated traces.
No external dependencies required (AFL++, DynamoRIO, Ollama).
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from main_pipeline import TraceWisePipeline
from utils.logger import setup_logger

logger = setup_logger("demo")


def print_banner():
    """Print demo banner"""
    print("=" * 70)
    print("  TRACEWISE-Lite Demo")
    print("  Selective Semantic Provenance Compression")
    print("  for Lightweight LLM-Assisted Vulnerability Root Cause Analysis")
    print("=" * 70)
    print()


def print_result(result):
    """Print pipeline result"""
    print("\n" + "=" * 70)
    print("  ANALYSIS RESULT")
    print("=" * 70)

    if not result.success:
        print(f"  Status: FAILED")
        print(f"  Error: {result.error_message}")
        return

    print(f"  Status: SUCCESS")
    print(f"  Target: {result.target_binary}")
    print(f"  Trace ID: {result.trace_id}")
    print(f"  Execution Time: {result.execution_time:.2f}s")
    print()

    # Provenance stats
    if result.provenance_stats:
        stats = result.provenance_stats
        orig = stats.get('original_event_count', 0)
        filt = stats.get('filtered_event_count', 0)
        reduction = stats.get('reduction_ratio', 0) * 100
        print(f"  Provenance Collection:")
        print(f"    Original Events: {orig}")
        print(f"    Filtered Events: {filt}")
        print(f"    Reduction: {reduction:.1f}%")
        print()

    # HBPG stats
    if result.hbpg_summary:
        hbpg = result.hbpg_summary
        print(f"  HBPG Statistics:")
        print(f"    Total Nodes: {hbpg.get('total_nodes', 0)}")
        print(f"    Total Edges: {hbpg.get('total_edges', 0)}")
        node_types = hbpg.get('node_types', {})
        for nt, count in node_types.items():
            print(f"      {nt}: {count}")
        print()

    # Compression stats
    if result.compression_summary:
        comp = result.compression_summary
        print(f"  Compression:")
        print(f"    Original: {comp.get('original_size', {}).get('nodes', 0)} nodes")
        print(f"    Compressed: {comp.get('compressed_size', {}).get('nodes', 0)} nodes")
        print(f"    Node Reduction: {comp.get('reduction', {}).get('nodes', 'N/A')}")
        print(f"    Edge Reduction: {comp.get('reduction', {}).get('edges', 'N/A')}")
        print(f"    Semantic Preservation: {comp.get('semantic_preservation', 'N/A')}")
        print()

    # Vulnerability analysis
    if result.vulnerability_analysis:
        analysis = result.vulnerability_analysis
        print(f"  Vulnerability Analysis:")
        print(f"    Class: {analysis.vulnerability_class}")
        print(f"    CWE: {analysis.cwe_id}")
        print(f"    Severity: {analysis.severity}")
        print(f"    Confidence: {analysis.confidence:.2f}")
        print(f"    Exploitability: {analysis.exploitability_score:.2f}/1.0")
        print()
        print(f"  Root Cause:")
        print(f"    {analysis.root_cause[:200]}...")
        print()
        print(f"  Remediation:")
        print(f"    {analysis.remediation[:200]}...")
        print()

    if result.report_path:
        print(f"  Full Report: {result.report_path}")

    print("=" * 70)


def demo_all_vulnerability_types():
    """Run demo for all vulnerability types"""
    vuln_types = [
        "buffer_overflow",
        "use_after_free",
        "format_string",
    ]

    for vuln_type in vuln_types:
        print(f"\n{'#' * 70}")
        print(f"#  Testing: {vuln_type.replace('_', ' ').title()}")
        print(f"{'#' * 70}")

        pipeline = TraceWisePipeline()
        result = pipeline.run_simulation(vuln_type)
        print_result(result)

        print("\nPress Enter to continue...")
        try:
            input()
        except KeyboardInterrupt:
            print("\nDemo interrupted.")
            break


def demo_single(vuln_type="buffer_overflow"):
    """Run single vulnerability demo"""
    print_banner()
    print(f"Running simulation for: {vuln_type}\n")

    pipeline = TraceWisePipeline()
    result = pipeline.run_simulation(vuln_type)
    print_result(result)


def main():
    """Main demo entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='TRACEWISE-Lite Demo')
    parser.add_argument('--all', action='store_true',
                       help='Demo all vulnerability types')
    parser.add_argument('--type', default='buffer_overflow',
                       help='Vulnerability type to demo')
    args = parser.parse_args()

    print_banner()

    if args.all:
        demo_all_vulnerability_types()
    else:
        demo_single(args.type)

    print("\nDemo complete!")


if __name__ == "__main__":
    main()