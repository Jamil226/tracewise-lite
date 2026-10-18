"""
Configuration management for TRACEWISE-Lite
"""

import os
import json
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class FuzzingConfig:
    """Configuration for AFL++ fuzzing engine"""
    afl_path: str = "afl-fuzz"
    timeout: int = 3600  # seconds
    memory_limit: str = "none"
    dict_file: Optional[str] = None
    seeds_dir: str = "./workspace/seeds"
    output_dir: str = "./workspace/fuzzing_out"
    target_args: str = ""
    fork_mode: bool = True


@dataclass
class InstrumentationConfig:
    """Configuration for DynamoRIO instrumentation"""
    drrun_path: str = "drrun"
    client_path: str = "./build/libtracewise_client.so"
    trace_dir: str = "./workspace/traces"
    trace_memory: bool = True
    trace_calls: bool = True
    trace_syscalls: bool = True
    max_trace_size: int = 100 * 1024 * 1024  # 100MB


@dataclass
class ProvenanceConfig:
    """Configuration for selective provenance collection"""
    vuln_keywords: List[str] = None
    max_events: int = 100000
    taint_sources: List[str] = None
    sink_functions: List[str] = None
    memory_threshold: int = 50 * 1024 * 1024  # 50MB

    def __post_init__(self):
        if self.vuln_keywords is None:
            self.vuln_keywords = [
                "malloc", "free", "memcpy", "strcpy", "strncpy",
                "sprintf", "scanf", "gets", "read", "recv",
                "alloca", "realloc", "memmove", "strcat", "strncat"
            ]
        if self.taint_sources is None:
            self.taint_sources = ["read", "recv", "fread", "scanf", "getc", "fgets"]
        if self.sink_functions is None:
            self.sink_functions = [
                "memcpy", "strcpy", "strncpy", "sprintf", "system",
                "exec", "malloc", "free", "realloc"
            ]


@dataclass
class CompressionConfig:
    """Configuration for semantic compression"""
    compression_ratio: float = 0.1  # Target 10% of original size
    preserve_taint_paths: bool = True
    preserve_crash_context: bool = True
    cluster_similar_events: bool = True
    abstraction_level: str = "function"  # function, block, or instruction
    min_path_length: int = 3


@dataclass
class LLMConfig:
    """Configuration for LLM reasoning module"""
    model_name: str = "qwen2.5-coder:1.5b"  # tinyllama, phi, qwen2.5-coder:1.5b
    ollama_host: str = "http://localhost:11434"
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout: int = 120
    context_window: int = 4096
    prompt_template: str = "default"


@dataclass
class TraceWiseConfig:
    """Main configuration for TRACEWISE-Lite"""
    project_name: str = "tracewise-lite"
    workspace_dir: str = "./workspace"
    log_level: str = "INFO"
    max_workers: int = 4

    # Sub-configurations
    fuzzing: FuzzingConfig = None
    instrumentation: InstrumentationConfig = None
    provenance: ProvenanceConfig = None
    compression: CompressionConfig = None
    llm: LLMConfig = None

    def __post_init__(self):
        if self.fuzzing is None:
            self.fuzzing = FuzzingConfig()
        if self.instrumentation is None:
            self.instrumentation = InstrumentationConfig()
        if self.provenance is None:
            self.provenance = ProvenanceConfig()
        if self.compression is None:
            self.compression = CompressionConfig()
        if self.llm is None:
            self.llm = LLMConfig()

    @classmethod
    def from_json(cls, path: str):
        """Load configuration from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)

    def to_json(self, path: str):
        """Save configuration to JSON file"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    def ensure_directories(self):
        """Create all necessary directories"""
        dirs = [
            self.workspace_dir,
            self.fuzzing.seeds_dir,
            self.fuzzing.output_dir,
            self.instrumentation.trace_dir,
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)


# Global configuration instance
_config = None


def get_config() -> TraceWiseConfig:
    """Get global configuration instance"""
    global _config
    if _config is None:
        _config = TraceWiseConfig()
    return _config


def set_config(config: TraceWiseConfig):
    """Set global configuration instance"""
    global _config
    _config = config