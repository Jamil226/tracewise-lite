"""
AFL++ Fuzzing Engine Wrapper for TRACEWISE-Lite

This module provides integration with AFL++ for coverage-guided fuzzing
to discover crashes and abnormal execution behavior in target binaries.
"""

import os
import sys
import json
import time
import signal
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from utils.config import get_config

logger = setup_logger("fuzzing")


@dataclass
class CrashInfo:
    """Information about a discovered crash"""
    crash_id: str
    input_path: str
    output_path: str
    crash_type: str  # e.g., "heap-buffer-overflow", "stack-buffer-overflow"
    signal: int
    exec_time: float
    crash_hash: str


@dataclass
class FuzzingStats:
    """Statistics from fuzzing campaign"""
    total_execs: int
    exec_per_sec: float
    unique_crashes: int
    unique_hangs: int
    total_paths: int
    corpus_count: int
    crash_details: List[CrashInfo]
    start_time: float
    duration: float


class AFLFuzzingEngine:
    """
    Wrapper for AFL++ fuzzing engine

    Handles:
    - Coverage-guided input mutation
    - Crash discovery and collection
    - Corpus management
    - Fuzzing statistics tracking
    """

    def __init__(self, config=None):
        self.config = config or get_config().fuzzing
        self.process = None
        self._running = False
        self._crashes_found: List[CrashInfo] = []

    def setup_environment(self, target_binary: str) -> Dict[str, str]:
        """
        Setup AFL++ environment variables

        Args:
            target_binary: Path to target binary

        Returns:
            Dictionary of environment variables
        """
        env = os.environ.copy()

        # AFL++ settings
        env['AFL_SKIP_CPUFREQ'] = '1'
        env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
        env['AFL_SKIP_BINCHECK'] = '1'

        # Output directory
        env['AFL_OUT'] = os.path.abspath(self.config.output_dir)

        # Memory limit
        if self.config.memory_limit != "none":
            env['AFL_MEMORY_LIMIT'] = self.config.memory_limit

        logger.info(f"AFL++ environment configured for: {target_binary}")
        return env

    def create_seed_corpus(self, sample_inputs: List[bytes] = None):
        """
        Create initial seed corpus for fuzzing

        Args:
            sample_inputs: List of seed input bytes
        """
        seeds_path = Path(self.config.seeds_dir)
        seeds_path.mkdir(parents=True, exist_ok=True)

        # Clear existing seeds
        for f in seeds_path.iterdir():
            if f.is_file():
                f.unlink()

        if sample_inputs:
            for i, seed in enumerate(sample_inputs):
                seed_file = seeds_path / f"seed_{i:04d}"
                seed_file.write_bytes(seed)
        else:
            # Create minimal default seed
            default_seed = seeds_path / "seed_0000"
            default_seed.write_bytes(b"INIT")

        logger.info(f"Created seed corpus with {len(sample_inputs) if sample_inputs else 1} seeds")

    def start_fuzzing(self,
                      target_binary: str,
                      timeout: int = None,
                      dictionary: str = None) -> subprocess.Popen:
        """
        Start AFL++ fuzzing process

        Args:
            target_binary: Path to target binary
            timeout: Fuzzing timeout in seconds
            dictionary: Path to fuzzing dictionary

        Returns:
            subprocess.Popen: Running AFL++ process
        """
        env = self.setup_environment(target_binary)

        # Build AFL++ command
        cmd = [
            self.config.afl_path,
            '-i', self.config.seeds_dir,
            '-o', self.config.output_dir,
            '-V', str(timeout or self.config.timeout),
        ]

        # Add dictionary if provided
        if dictionary or self.config.dict_file:
            cmd.extend(['-x', dictionary or self.config.dict_file])

        # Target binary and arguments
        cmd.append('--')
        cmd.append(target_binary)

        if self.config.target_args:
            cmd.extend(self.config.target_args.split())

        logger.info(f"Starting AFL++: {' '.join(cmd)}")

        # Start fuzzing
        self._running = True
        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return self.process

    def stop_fuzzing(self):
        """Stop the fuzzing process"""
        if self.process and self._running:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self._running = False
            logger.info("Fuzzing stopped")

    def monitor_fuzzing(self, callback: Callable = None, interval: int = 5):
        """
        Monitor fuzzing progress

        Args:
            callback: Optional callback function(stats_dict)
            interval: Check interval in seconds
        """
        while self._running and self.process.poll() is None:
            stats = self._read_stats()
            if callback:
                callback(stats)
            else:
                logger.debug(f"Execs: {stats.get('execs_done', 0)}, "
                           f"Crashes: {stats.get('unique_crashes', 0)}")
            time.sleep(interval)

    def _read_stats(self) -> Dict:
        """Read AFL++ statistics file"""
        stats_file = Path(self.config.output_dir) / "default" / "fuzzer_stats"
        if not stats_file.exists():
            return {}

        stats = {}
        try:
            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        stats[key.strip()] = value.strip()
        except Exception as e:
            logger.warning(f"Could not read stats: {e}")

        return stats

    def collect_crashes(self) -> List[CrashInfo]:
        """
        Collect all discovered crashes

        Returns:
            List of CrashInfo objects
        """
        crashes_dir = Path(self.config.output_dir) / "default" / "crashes"
        if not crashes_dir.exists():
            return []

        crashes = []
        for crash_file in crashes_dir.iterdir():
            if crash_file.name == "README.txt":
                continue

            crash_info = self._analyze_crash(crash_file)
            if crash_info:
                crashes.append(crash_info)

        self._crashes_found = crashes
        logger.info(f"Collected {len(crashes)} unique crashes")
        return crashes

    def _analyze_crash(self, crash_file: Path) -> Optional[CrashInfo]:
        """Analyze a single crash file"""
        try:
            # Parse crash filename for metadata
            # Format: id:000000,sig:11,src:000000,time:12345
            filename = crash_file.name
            parts = {}
            for part in filename.split(','):
                if ':' in part:
                    k, v = part.split(':', 1)
                    parts[k] = v

            crash_info = CrashInfo(
                crash_id=parts.get('id', 'unknown'),
                input_path=str(crash_file),
                output_path=str(crash_file.with_suffix('.analysis')),
                crash_type=self._classify_crash(int(parts.get('sig', 0))),
                signal=int(parts.get('sig', 0)),
                exec_time=float(parts.get('time', 0)) / 1000,  # ms to s
                crash_hash=parts.get('id', 'unknown')
            )

            return crash_info

        except Exception as e:
            logger.warning(f"Failed to analyze crash {crash_file}: {e}")
            return None

    def _classify_crash(self, signal_num: int) -> str:
        """Classify crash based on signal number"""
        signal_map = {
            6: 'SIGABRT (Abort)',
            8: 'SIGFPE (Floating Point Exception)',
            11: 'SIGSEGV (Segmentation Fault)',
            13: 'SIGPIPE (Broken Pipe)',
            14: 'SIGALRM (Alarm Clock)',
        }
        return signal_map.get(signal_num, f'Unknown Signal ({signal_num})')

    def get_fuzzing_stats(self) -> FuzzingStats:
        """
        Get complete fuzzing statistics

        Returns:
            FuzzingStats object
        """
        stats = self._read_stats()
        crashes = self.collect_crashes()

        start_time = 0
        if 'start_time' in stats:
            start_time = int(stats['start_time'])

        return FuzzingStats(
            total_execs=int(stats.get('execs_done', 0)),
            exec_per_sec=float(stats.get('execs_per_sec', 0)),
            unique_crashes=int(stats.get('unique_crashes', 0)),
            unique_hangs=int(stats.get('unique_hangs', 0)),
            total_paths=int(stats.get('paths_total', 0)),
            corpus_count=int(stats.get('corpus_count', 0)),
            crash_details=crashes,
            start_time=start_time,
            duration=time.time() - start_time if start_time else 0
        )

    def minimize_corpus(self, target_binary: str) -> str:
        """
        Minimize corpus using AFL++ minimizer

        Args:
            target_binary: Path to target binary

        Returns:
            Path to minimized corpus directory
        """
        input_dir = Path(self.config.output_dir) / "default" / "queue"
        output_dir = Path(self.config.output_dir) / "minimized"
        output_dir.mkdir(exist_ok=True)

        cmd = [
            'afl-cmin',
            '-i', str(input_dir),
            '-o', str(output_dir),
            '--',
            target_binary
        ]

        if self.config.target_args:
            cmd.extend(self.config.target_args.split())

        logger.info(f"Minimizing corpus...")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Corpus minimized to: {output_dir}")
            return str(output_dir)
        except subprocess.CalledProcessError as e:
            logger.error(f"Corpus minimization failed: {e}")
            return str(input_dir)


def quick_fuzz(target_binary: str,
               seeds: List[bytes] = None,
               timeout: int = 60,
               output_dir: str = "./fuzzing_out") -> List[CrashInfo]:
    """
    Quick fuzzing function for simple use cases

    Args:
        target_binary: Path to target binary
        seeds: Optional seed inputs
        timeout: Fuzzing timeout in seconds
        output_dir: Output directory

    Returns:
        List of discovered crashes
    """
    config = get_config()
    config.fuzzing.output_dir = output_dir

    engine = AFLFuzzingEngine(config.fuzzing)

    # Setup and start
    engine.create_seed_corpus(seeds)
    process = engine.start_fuzzing(target_binary, timeout=timeout)

    # Wait for completion
    try:
        process.wait(timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        engine.stop_fuzzing()

    # Collect results
    return engine.collect_crashes()


if __name__ == "__main__":
    # Example usage
    print("AFL++ Fuzzing Engine Wrapper")
    print("Usage: Import and use AFLFuzzingEngine class")