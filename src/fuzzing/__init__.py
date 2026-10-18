"""
TRACEWISE-Lite Fuzzing Module

AFL++ integration for coverage-guided fuzzing and crash discovery.
"""

from .afl_wrapper import AFLFuzzingEngine, CrashInfo, FuzzingStats, quick_fuzz

__all__ = ['AFLFuzzingEngine', 'CrashInfo', 'FuzzingStats', 'quick_fuzz']