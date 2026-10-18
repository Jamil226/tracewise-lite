"""
Test suite for TRACEWISE-Lite components
"""

import os
import sys
import unittest
import tempfile
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.config import TraceWiseConfig, FuzzingConfig
from instrumentation.dynamorio_client import (
    ExecutionEvent, ExecutionTrace, EventType, TraceSimulator
)
from provenance.collector import SelectiveProvenanceCollector
from provenance.hbpg import HBPGConstructor, HybridBinaryProvenanceGraph, NodeType
from compression.engine import SemanticCompressionEngine
from llm.reasoning import LLMReasoningModule


class TestTraceWiseConfig(unittest.TestCase):
    """Test configuration management"""

    def test_default_config(self):
        config = TraceWiseConfig()
        self.assertEqual(config.project_name, "tracewise-lite")
        self.assertIsNotNone(config.fuzzing)
        self.assertIsNotNone(config.llm)

    def test_config_save_load(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = f.name

        config = TraceWiseConfig()
        config.workspace_dir = "/tmp/test_workspace"
        config.to_json(path)

        loaded = TraceWiseConfig.from_json(path)
        self.assertEqual(loaded.workspace_dir, "/tmp/test_workspace")

        os.unlink(path)


class TestTraceSimulator(unittest.TestCase):
    """Test trace simulation"""

    def test_buffer_overflow_trace(self):
        trace = TraceSimulator.generate_vulnerable_trace(
            vulnerability_type="buffer_overflow"
        )
        self.assertIsNotNone(trace)
        self.assertTrue(len(trace.events) > 0)

        # Should have crash event
        crashes = trace.get_crash_events()
        self.assertTrue(len(crashes) > 0)

    def test_uaf_trace(self):
        trace = TraceSimulator.generate_vulnerable_trace(
            vulnerability_type="use_after_free"
        )
        heap_events = [e for e in trace.events
                      if e.event_type in (EventType.HEAP_ALLOC, EventType.HEAP_FREE)]
        self.assertTrue(len(heap_events) >= 2)


class TestProvenanceCollector(unittest.TestCase):
    """Test selective provenance collection"""

    def test_filter_reduction(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()

        filtered = collector.process_trace(trace)

        self.assertLessEqual(
            len(filtered.events),
            len(trace.events)
        )
        self.assertIn('reduction_ratio', filtered.metadata)

    def test_crash_context_collection(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()

        crash_info = {'signal': 11}
        filtered = collector.collect_from_crash(trace, crash_info)

        self.assertTrue(len(filtered.events) > 0)


class TestHBPG(unittest.TestCase):
    """Test HBPG construction"""

    def test_graph_construction(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()
        filtered = collector.process_trace(trace)

        constructor = HBPGConstructor()
        hbpg = constructor.construct(filtered)

        self.assertGreater(len(hbpg.nodes), 0)
        self.assertIsNotNone(hbpg.to_dict())

    def test_attack_path_extraction(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()
        filtered = collector.process_trace(trace)

        constructor = HBPGConstructor()
        hbpg = constructor.construct(filtered)

        path = hbpg.get_attack_propagation_path()
        self.assertIsNotNone(path)


class TestCompression(unittest.TestCase):
    """Test semantic compression"""

    def test_compression_reduces_size(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()
        filtered = collector.process_trace(trace)

        constructor = HBPGConstructor()
        hbpg = constructor.construct(filtered)

        engine = SemanticCompressionEngine()
        compressed = engine.compress(hbpg)

        self.assertLessEqual(
            len(compressed.nodes),
            len(hbpg.nodes)
        )

    def test_semantic_preservation(self):
        trace = TraceSimulator.generate_vulnerable_trace()
        collector = SelectiveProvenanceCollector()
        filtered = collector.process_trace(trace)

        constructor = HBPGConstructor()
        hbpg = constructor.construct(filtered)

        engine = SemanticCompressionEngine()
        compressed = engine.compress(hbpg)

        summary = engine.get_compression_summary()
        self.assertIn('semantic_preservation', summary)


class TestLLMModule(unittest.TestCase):
    """Test LLM reasoning module"""

    def test_fallback_analysis(self):
        module = LLMReasoningModule()

        # Create minimal provenance summary
        summary = {
            'statistics': {
                'node_types': {
                    'memory_region': 10,
                    'function': 5,
                    'crash_site': 1
                },
                'attack_path': []
            }
        }

        analysis = module._fallback_analysis(summary)
        self.assertIsNotNone(analysis.vulnerability_class)
        self.assertGreaterEqual(analysis.confidence, 0)

    def test_report_generation(self):
        module = LLMReasoningModule()

        analysis = module._fallback_analysis({
            'statistics': {'node_types': {}, 'attack_path': []}
        })

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            path = f.name

        report = module.generate_report(analysis, output_path=path)
        self.assertTrue(os.path.exists(path))
        self.assertIn("TRACEWISE-Lite", report)

        os.unlink(path)


class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def test_full_simulation_pipeline(self):
        """Test complete pipeline with simulation"""
        from main_pipeline import TraceWisePipeline

        pipeline = TraceWisePipeline()
        result = pipeline.run_simulation("buffer_overflow")

        self.assertTrue(result.success)
        self.assertTrue(result.crash_found)
        self.assertIsNotNone(result.vulnerability_analysis)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestTraceWiseConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestTraceSimulator))
    suite.addTests(loader.loadTestsFromTestCase(TestProvenanceCollector))
    suite.addTests(loader.loadTestsFromTestCase(TestHBPG))
    suite.addTests(loader.loadTestsFromTestCase(TestCompression))
    suite.addTests(loader.loadTestsFromTestCase(TestLLMModule))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)