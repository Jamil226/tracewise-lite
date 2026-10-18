"""
Selective Provenance Collector for TRACEWISE-Lite

Implements selective provenance tracing that captures only
vulnerability-relevant events, reducing telemetry overhead
while preserving security-critical semantics.
"""

import os
import sys
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from utils.config import get_config
from instrumentation.dynamorio_client import (
    ExecutionEvent, ExecutionTrace, EventType, DynamoRIOClient
)

logger = setup_logger("provenance")


@dataclass
class ProvenanceFilter:
    """Filter criteria for selective provenance collection"""

    # Function-level filters
    include_functions: Set[str] = field(default_factory=set)
    exclude_functions: Set[str] = field(default_factory=set)

    # Memory filters
    track_heap_operations: bool = True
    track_stack_operations: bool = True
    min_memory_size: int = 0

    # Taint filters
    track_taint_sources: bool = True
    track_taint_sinks: bool = True

    # System call filters
    track_file_operations: bool = True
    track_network_operations: bool = True

    # Vulnerability-specific patterns
    vuln_patterns: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.vuln_patterns:
            self.vuln_patterns = [
                "memcpy", "strcpy", "strncpy", "sprintf", "scanf",
                "gets", "read", "recv", "alloca", "malloc", "free",
                "realloc", "system", "exec", "popen"
            ]


class SelectiveProvenanceCollector:
    """
    Selective Provenance Collector

    Filters raw execution traces to retain only vulnerability-relevant
t    provenance information, significantly reducing trace complexity.
    """

    # High-risk functions that indicate potential vulnerabilities
    HIGH_RISK_FUNCTIONS = {
        'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
        'vsprintf', 'vsnprintf', 'gets', 'memcpy', 'memmove',
        'malloc', 'calloc', 'realloc', 'free',
        'read', 'recv', 'recvfrom', 'fread', 'fgets', 'getc',
        'scanf', 'sscanf', 'fscanf', 'vscanf',
        'system', 'execve', 'execvp', 'popen', 'dlopen',
        'alloca', 'strdup', 'strndup'
    }

    # Expanded Taint source functions
    TAINT_SOURCES = {
        # Standard I/O
        "read", "fread", "fgets", "fgetc", "getc", "getchar",
        "scanf", "fscanf", "sscanf", "vscanf",
        # Network
        "recv", "recvfrom", "recvmsg",
        # Memory-mapped / file
        "mmap", "pread", "pread64",
        # String input
        "gets",                          # always dangerous
        "getline", "getdelim",
        # argv — critical for your binaries
        "__libc_start_main",             # catches argv
        "getopt", "getopt_long",
        # Environment
        "getenv",
    }

    # Expanded Taint sink functions
    TAINT_SINKS = {
        # String operations
        "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf",
        "memcpy", "memmove", "memset",
        "strdup", "strndup",
        # Execution
        "system", "execv", "execve", "execvp", "execl",
        "popen",
        # Format string
        "printf", "fprintf", "vprintf",  # when first arg is tainted
        # Allocation / free — for UAF
        "malloc", "calloc", "realloc",
        "free",
    }
    
    ALWAYS_RETAIN = {
        "abort", "exit", "_exit",
        "__stack_chk_fail",              # this is WHY you miss CWE-121
        "raise", "kill",
        "__assert_fail",
    }

    def __init__(self, config=None, filter_criteria: ProvenanceFilter = None):
        self.config = config or get_config().provenance
        self.filter_criteria = filter_criteria or ProvenanceFilter()
        self.collected_events: List[ExecutionEvent] = []
        self.taint_map: Dict[int, str] = {}  # label -> source
        self._event_stats = defaultdict(int)

    def should_collect_event(self, event: ExecutionEvent) -> bool:
        """
        Determine if an event should be collected based on selective criteria

        Args:
            event: Execution event to evaluate

        Returns:
            True if event should be collected
        """
        # Always collect crash events
        if event.event_type == EventType.CRASH:
            return True

        # Collect taint propagation events
        if event.event_type == EventType.TAINT_PROPAGATION:
            if self.filter_criteria.track_taint_sources or \
               self.filter_criteria.track_taint_sinks:
                return True

        # Collect heap operations
        if event.event_type in (EventType.HEAP_ALLOC, EventType.HEAP_FREE):
            if self.filter_criteria.track_heap_operations:
                return True

        # Filter function calls
        if event.event_type == EventType.FUNCTION_CALL:
            return self._should_collect_function_call(event)

        # Filter memory operations
        if event.event_type in (EventType.MEMORY_READ, EventType.MEMORY_WRITE):
            return self._should_collect_memory_event(event)

        # Filter system calls
        if event.event_type == EventType.SYSCALL:
            return self._should_collect_syscall(event)

        return False

    def _should_collect_function_call(self, event: ExecutionEvent) -> bool:
        """Check if function call should be collected"""
        func_name = event.func_name or ""

        # Exclude common non-interesting functions
        if func_name in self.filter_criteria.exclude_functions:
            return False

        # Always retain critical crash indicators like stack canary failures
        if func_name in self.ALWAYS_RETAIN:
            return True

        # Include explicitly requested functions
        if func_name in self.filter_criteria.include_functions:
            return True

        # Collect high-risk functions
        if func_name in self.HIGH_RISK_FUNCTIONS:
            return True

        # Collect taint-related functions
        if func_name in self.TAINT_SOURCES or func_name in self.TAINT_SINKS:
            return True

        # Collect vulnerability pattern matches
        for pattern in self.filter_criteria.vuln_patterns:
            if pattern in func_name:
                return True

        return False

    def _should_collect_memory_event(self, event: ExecutionEvent) -> bool:
        """Check if memory event should be collected"""
        # Track heap memory operations
        if self.filter_criteria.track_heap_operations:
            # Heap addresses typically start with 0x60... on Linux
            if event.memory_address and (0x60000000 <= event.memory_address <= 0x70000000):
                return True

        # Track stack operations near potential overflows
        if self.filter_criteria.track_stack_operations:
            if event.memory_address and (0x7fff0000 <= event.memory_address <= 0x7ffffffe):
                # Large writes to stack are suspicious
                if event.event_type == EventType.MEMORY_WRITE and \
                   event.memory_size and event.memory_size > 64:
                    return True

        # Filter by minimum size
        if event.memory_size and event.memory_size < self.filter_criteria.min_memory_size:
            return False

        # Track tainted memory accesses
        if event.memory_address in self.taint_map:
            return True

        return False

    def _should_collect_syscall(self, event: ExecutionEvent) -> bool:
        """Check if system call should be collected"""
        if not event.syscall_number:
            return False

        # File operations (read, write, open, etc.)
        file_syscalls = {0, 1, 2, 3}  # read, write, open, close
        if event.syscall_number in file_syscalls and \
           self.filter_criteria.track_file_operations:
            return True

        # Network operations
        network_syscalls = {41, 42, 43, 44, 45}  # socket, connect, accept, send, recv
        if event.syscall_number in network_syscalls and \
           self.filter_criteria.track_network_operations:
            return True

        return False

    def process_trace(self, trace: ExecutionTrace) -> ExecutionTrace:
        """
        Process a full execution trace and collect only relevant events

        Args:
            trace: Full execution trace

        Returns:
            Filtered execution trace with only vulnerability-relevant events
        """
        logger.info(f"Processing trace with {len(trace.events)} events")

        filtered_events = []

        # Build taint map first pass
        for event in trace.events:
            if event.event_type == EventType.TAINT_PROPAGATION and event.taint_label:
                self.taint_map[event.taint_label] = event.taint_source or "unknown"

        # Second pass: filter events
        for event in trace.events:
            if self.should_collect_event(event):
                filtered_events.append(event)
                self._event_stats[event.event_type.value] += 1

        # Create filtered trace
        filtered_trace = ExecutionTrace(
            binary_path=trace.binary_path,
            trace_id=f"{trace.trace_id}_filtered",
            events=filtered_events,
            metadata={
                **trace.metadata,
                'original_event_count': len(trace.events),
                'filtered_event_count': len(filtered_events),
                'reduction_ratio': 1.0 - (len(filtered_events) / max(len(trace.events), 1)),
                'taint_sources_found': len(self.taint_map),
                'event_stats': dict(self._event_stats)
            }
        )

        reduction = (1.0 - len(filtered_events) / max(len(trace.events), 1)) * 100
        logger.info(f"Selective provenance: {len(trace.events)} -> {len(filtered_events)} "
                   f"events ({reduction:.1f}% reduction)")

        return filtered_trace

    def collect_from_crash(self,
                           trace: ExecutionTrace,
                           crash_info: Dict) -> ExecutionTrace:
        """
        Collect provenance specifically around a crash context

        Args:
            trace: Full execution trace
            crash_info: Crash information dictionary

        Returns:
            Crash-context-focused provenance trace
        """
        # Find crash event index
        crash_idx = -1
        for i, event in enumerate(trace.events):
            if event.event_type == EventType.CRASH:
                crash_idx = i
                break

        if crash_idx == -1:
            logger.warning("No crash event found in trace")
            return self.process_trace(trace)

        # Collect events in window around crash
        window_size = min(1000, len(trace.events) // 2)
        start_idx = max(0, crash_idx - window_size)
        end_idx = min(len(trace.events), crash_idx + window_size)

        context_events = trace.events[start_idx:end_idx]

        # Process context events with normal filtering
        context_trace = ExecutionTrace(
            binary_path=trace.binary_path,
            trace_id=f"{trace.trace_id}_crash_context",
            events=context_events,
            metadata=trace.metadata
        )

        return self.process_trace(context_trace)

    def get_collection_stats(self) -> Dict:
        """Get statistics about provenance collection"""
        return {
            'total_events_collected': len(self.collected_events),
            'taint_sources_tracked': len(self.taint_map),
            'event_type_distribution': dict(self._event_stats),
            'filter_criteria': {
                'track_heap': self.filter_criteria.track_heap_operations,
                'track_stack': self.filter_criteria.track_stack_operations,
                'track_taint': self.filter_criteria.track_taint_sources,
                'high_risk_functions': list(self.HIGH_RISK_FUNCTIONS)[:10]
            }
        }


class ProvenanceGraphBuilder:
    """
    Build provenance graph from collected events

    Creates a dependency graph showing data flow and control flow
    relationships between security-relevant events.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []
        self.node_counter = 0

    def _add_node(self, event: ExecutionEvent) -> str:
        """Add a node to the provenance graph"""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1

        node_data = {
            'id': node_id,
            'type': event.event_type.value,
            'address': hex(event.address) if event.address else None,
            'timestamp': event.timestamp,
            'details': {}
        }

        # Add type-specific details
        if event.func_name:
            node_data['details']['function'] = event.func_name
        if event.memory_address:
            node_data['details']['memory_addr'] = hex(event.memory_address)
        if event.taint_source:
            node_data['details']['taint_source'] = event.taint_source

        self.nodes[node_id] = node_data
        return node_id

    def build_from_trace(self, trace: ExecutionTrace) -> Dict:
        """
        Build provenance graph from execution trace

        Args:
            trace: Filtered execution trace

        Returns:
            Provenance graph as dictionary
        """
        logger.info(f"Building provenance graph from {len(trace.events)} events")

        prev_node = None

        for event in trace.events:
            node_id = self._add_node(event)

            # Add edge from previous node
            if prev_node:
                self.edges.append({
                    'source': prev_node,
                    'target': node_id,
                    'type': 'sequence'
                })

            # Add taint edges
            if event.event_type == EventType.TAINT_PROPAGATION and event.taint_label:
                self.edges.append({
                    'source': f"taint_{event.taint_label}",
                    'target': node_id,
                    'type': 'taint_flow'
                })

            # Add memory dependency edges
            if event.memory_address:
                mem_node = f"mem_{hex(event.memory_address)}"
                if mem_node in self.nodes:
                    self.edges.append({
                        'source': mem_node,
                        'target': node_id,
                        'type': 'memory_dep'
                    })

            prev_node = node_id

        graph = {
            'nodes': list(self.nodes.values()),
            'edges': self.edges,
            'metadata': {
                'trace_id': trace.trace_id,
                'binary': trace.binary_path,
                'node_count': len(self.nodes),
                'edge_count': len(self.edges)
            }
        }

        logger.info(f"Provenance graph: {len(self.nodes)} nodes, {len(self.edges)} edges")
        return graph


if __name__ == "__main__":
    print("Selective Provenance Collector")
    print("Usage: Import and use SelectiveProvenanceCollector")