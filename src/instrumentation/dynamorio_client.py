"""
DynamoRIO Client for TRACEWISE-Lite

This module provides a Python-based interface for DynamoRIO instrumentation.
In production, this would be a C client loaded by drrun.

For the Python implementation, we provide:
- Trace collection simulation
- Event filtering
- Trace format management
"""

import os
import sys
import json
import struct
import pickle
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from utils.config import get_config

logger = setup_logger("instrumentation")


class EventType(Enum):
    """Types of execution events"""
    FUNCTION_CALL = "func_call"
    FUNCTION_RET = "func_ret"
    MEMORY_READ = "mem_read"
    MEMORY_WRITE = "mem_write"
    SYSCALL = "syscall"
    BRANCH = "branch"
    CRASH = "crash"
    TAINT_PROPAGATION = "taint_prop"
    HEAP_ALLOC = "heap_alloc"
    HEAP_FREE = "heap_free"


@dataclass
class ExecutionEvent:
    """Single execution event from instrumentation"""
    event_type: EventType
    address: int
    timestamp: int
    thread_id: int

    # Function-specific
    func_name: Optional[str] = None
    func_args: List[int] = field(default_factory=list)
    return_value: Optional[int] = None

    # Memory-specific
    memory_address: Optional[int] = None
    memory_size: Optional[int] = None
    memory_value: Optional[bytes] = None

    # System call
    syscall_number: Optional[int] = None
    syscall_args: List[int] = field(default_factory=list)

    # Taint
    taint_source: Optional[str] = None
    taint_label: Optional[int] = None

    # Heap
    heap_size: Optional[int] = None
    heap_ptr: Optional[int] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        d = asdict(self)
        d['event_type'] = self.event_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> 'ExecutionEvent':
        """Create from dictionary"""
        data['event_type'] = EventType(data['event_type'])
        return cls(**data)


@dataclass
class ExecutionTrace:
    """Complete execution trace"""
    binary_path: str
    trace_id: str
    events: List[ExecutionEvent] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def add_event(self, event: ExecutionEvent):
        """Add event to trace"""
        self.events.append(event)

    def save(self, path: str):
        """Save trace to file"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str) -> 'ExecutionTrace':
        """Load trace from file"""
        with open(path, 'rb') as f:
            return pickle.load(f)

    def to_json(self, path: str):
        """Export trace to JSON"""
        data = {
            'binary_path': self.binary_path,
            'trace_id': self.trace_id,
            'event_count': len(self.events),
            'metadata': self.metadata,
            'events': [e.to_dict() for e in self.events]
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def get_events_by_type(self, event_type: EventType) -> List[ExecutionEvent]:
        """Filter events by type"""
        return [e for e in self.events if e.event_type == event_type]

    def get_crash_events(self) -> List[ExecutionEvent]:
        """Get crash events"""
        return self.get_events_by_type(EventType.CRASH)

    def get_memory_events(self) -> List[ExecutionEvent]:
        """Get memory-related events"""
        return [e for e in self.events
                if e.event_type in (EventType.MEMORY_READ, EventType.MEMORY_WRITE)]

    def get_taint_events(self) -> List[ExecutionEvent]:
        """Get taint propagation events"""
        return self.get_events_by_type(EventType.TAINT_PROPAGATION)


class DynamoRIOClient:
    """
    DynamoRIO instrumentation client interface

    In a real deployment, this loads a C client via drrun.
    This Python version simulates and manages trace collection.
    """

    def __init__(self, config=None):
        self.config = config or get_config().instrumentation
        self.current_trace: Optional[ExecutionTrace] = None
        self._event_count = 0
        self._max_events = 1000000  # Safety limit

    def start_trace(self, binary_path: str, trace_id: str = None):
        """
        Start collecting a new execution trace

        Args:
            binary_path: Path to target binary
            trace_id: Optional trace identifier
        """
        if trace_id is None:
            import uuid
            trace_id = str(uuid.uuid4())[:8]

        self.current_trace = ExecutionTrace(
            binary_path=binary_path,
            trace_id=trace_id
        )
        self._event_count = 0
        logger.info(f"Started trace {trace_id} for {binary_path}")

    def record_event(self, event: ExecutionEvent):
        """Record a single execution event"""
        if self.current_trace is None:
            raise RuntimeError("No active trace. Call start_trace() first.")

        if self._event_count >= self._max_events:
            logger.warning("Max events reached, stopping trace collection")
            return

        self.current_trace.add_event(event)
        self._event_count += 1

    def record_function_call(self,
                             address: int,
                             func_name: str,
                             args: List[int] = None,
                             thread_id: int = 0):
        """Record function call event"""
        event = ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=address,
            timestamp=self._event_count,
            thread_id=thread_id,
            func_name=func_name,
            func_args=args or []
        )
        self.record_event(event)

    def record_memory_access(self,
                             address: int,
                             is_write: bool,
                             mem_addr: int,
                             size: int,
                             value: bytes = None,
                             thread_id: int = 0):
        """Record memory access event"""
        event = ExecutionEvent(
            event_type=EventType.MEMORY_WRITE if is_write else EventType.MEMORY_READ,
            address=address,
            timestamp=self._event_count,
            thread_id=thread_id,
            memory_address=mem_addr,
            memory_size=size,
            memory_value=value
        )
        self.record_event(event)

    def record_syscall(self,
                       address: int,
                       syscall_num: int,
                       args: List[int],
                       thread_id: int = 0):
        """Record system call event"""
        event = ExecutionEvent(
            event_type=EventType.SYSCALL,
            address=address,
            timestamp=self._event_count,
            thread_id=thread_id,
            syscall_number=syscall_num,
            syscall_args=args
        )
        self.record_event(event)

    def record_taint_propagation(self,
                                 address: int,
                                 source: str,
                                 label: int,
                                 thread_id: int = 0):
        """Record taint propagation event"""
        event = ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=address,
            timestamp=self._event_count,
            thread_id=thread_id,
            taint_source=source,
            taint_label=label
        )
        self.record_event(event)

    def record_crash(self,
                     address: int,
                     signal: int,
                     thread_id: int = 0):
        """Record crash event"""
        event = ExecutionEvent(
            event_type=EventType.CRASH,
            address=address,
            timestamp=self._event_count,
            thread_id=thread_id
        )
        self.record_event(event)

    def save_trace(self, filename: str = None) -> str:
        """
        Save current trace to file

        Args:
            filename: Optional filename

        Returns:
            Path to saved trace file
        """
        if self.current_trace is None:
            raise RuntimeError("No active trace to save")

        if filename is None:
            filename = f"trace_{self.current_trace.trace_id}.pkl"

        path = os.path.join(self.config.trace_dir, filename)
        self.current_trace.save(path)

        # Also save as JSON for readability
        json_path = path.replace('.pkl', '.json')
        self.current_trace.to_json(json_path)

        logger.info(f"Saved trace to {path} ({len(self.current_trace.events)} events)")
        return path

    def end_trace(self):
        """End current trace collection"""
        if self.current_trace:
            logger.info(f"Ended trace {self.current_trace.trace_id} "
                       f"with {len(self.current_trace.events)} events")
            self.current_trace = None

    def run_with_instrumentation(self,
                                 target_binary: str,
                                 input_data: bytes = None,
                                 timeout: int = 30) -> ExecutionTrace:
        """
        Run target binary with DynamoRIO instrumentation

        In a real implementation, this would:
        1. Launch drrun with the C client
        2. Collect raw trace data
        3. Parse and return structured trace

        For now, we simulate with a basic execution wrapper.
        """
        import uuid
        import subprocess
        import tempfile

        trace_id = str(uuid.uuid4())[:8]
        self.start_trace(target_binary, trace_id)

        # Write input to temp file if provided
        input_file = None
        if input_data:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(input_data)
                input_file = f.name

        try:
            # Build drrun command
            cmd = [
                self.config.drrun_path,
                '-c', self.config.client_path,
                '-o', os.path.join(self.config.trace_dir, f"trace_{trace_id}"),
                '--',
                target_binary
            ]

            if input_file:
                cmd.append(input_file)

            logger.info(f"Running: {' '.join(cmd)}")

            # Run with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Add metadata
            self.current_trace.metadata = {
                'returncode': result.returncode,
                'stdout': result.stdout[:1000] if result.stdout else '',
                'stderr': result.stderr[:1000] if result.stderr else '',
                'input_size': len(input_data) if input_data else 0
            }

            # Record crash if abnormal exit
            if result.returncode != 0:
                self.record_crash(
                    address=0,
                    signal=abs(result.returncode),
                    thread_id=0
                )

        except subprocess.TimeoutExpired:
            logger.warning("Execution timed out")
            self.record_crash(address=0, signal=14, thread_id=0)  # SIGALRM

        except Exception as e:
            logger.error(f"Instrumentation failed: {e}")

        finally:
            if input_file and os.path.exists(input_file):
                os.unlink(input_file)

        trace = self.current_trace
        self.save_trace()
        self.end_trace()

        return trace


class TraceSimulator:
    """
    Simulate execution traces for testing and demonstration
    without requiring actual DynamoRIO
    """

    @staticmethod
    def generate_vulnerable_trace(binary_path: str = "test_binary",
                                   vulnerability_type: str = "buffer_overflow") -> ExecutionTrace:
        """
        Generate a simulated trace showing a vulnerability

        Args:
            binary_path: Binary name
            vulnerability_type: Type of vulnerability to simulate

        Returns:
            ExecutionTrace with simulated events
        """
        import uuid
        trace = ExecutionTrace(
            binary_path=binary_path,
            trace_id=str(uuid.uuid4())[:8]
        )

        if vulnerability_type == "buffer_overflow":
            events = TraceSimulator._generate_buffer_overflow_trace()
        elif vulnerability_type == "use_after_free":
            events = TraceSimulator._generate_uaf_trace()
        elif vulnerability_type == "format_string":
            events = TraceSimulator._generate_format_string_trace()
        elif vulnerability_type == "integer_overflow":
            events = TraceSimulator._generate_integer_overflow_trace()
        elif vulnerability_type == "command_injection":
            events = TraceSimulator._generate_command_injection_trace()
        else:
            events = TraceSimulator._generate_generic_trace()

        trace.events = events
        trace.metadata = {
            'vulnerability_type': vulnerability_type,
            'simulated': True,
            'event_count': len(events)
        }

        return trace

    @staticmethod
    def _generate_buffer_overflow_trace() -> List[ExecutionEvent]:
        """
        Generate buffer overflow trace (CWE-121: Stack Buffer Overflow).

        Attack chain:
          read() [INPUT_SOURCE] -> strcpy [TAINT_PROPAGATION]
          -> stack memory write [MEMORY_WRITE] -> crash [CRASH_SITE]

        Includes benign noise (helper functions, benign memory reads)
        so compression strategies have measurable work to do.
        """
        events = []
        base_addr = 0x400000
        ts = 0  # monotonic timestamp

        # --- Benign prologue (noise for compression to remove) ---
        for noise_fn in ["__libc_start_main", "_init", "getenv", "setlocale"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + 0x100 + ts * 4,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1
            # Benign memory reads
            events.append(ExecutionEvent(
                event_type=EventType.MEMORY_READ,
                address=base_addr + 0x200 + ts * 4,
                timestamp=ts, thread_id=0,
                memory_address=0x601000 + ts * 8, memory_size=8
            ))
            ts += 1

        # Main function entry
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x1000,
            timestamp=ts, thread_id=0, func_name="main"
        ))
        ts += 1

        # === CRITICAL: FUNCTION_CALL for read() creates INPUT_SOURCE node ===
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x1100,
            timestamp=ts, thread_id=0,
            func_name="read",          # triggers INPUT_SOURCE in HBPGConstructor
            func_args=[0, 0x7fff0000, 256]
        ))
        ts += 1

        # Underlying syscall for read
        events.append(ExecutionEvent(
            event_type=EventType.SYSCALL,
            address=base_addr + 0x1105,
            timestamp=ts, thread_id=0,
            syscall_number=0, syscall_args=[0, 0x7fff0000, 256]
        ))
        ts += 1

        # Taint tagging: input buffer is now tainted
        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x1110,
            timestamp=ts, thread_id=0,
            taint_source="read", taint_label=1
        ))
        ts += 1

        # --- More benign noise between input and sink ---
        for noise_fn in ["strlen", "toupper", "printf"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + 0x1150 + ts,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1
            events.append(ExecutionEvent(
                event_type=EventType.MEMORY_READ,
                address=base_addr + 0x1160 + ts,
                timestamp=ts, thread_id=0,
                memory_address=0x7fff0000 + ts, memory_size=4
            ))
            ts += 1

        # Dangerous sink: strcpy with tainted source
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x1200,
            timestamp=ts, thread_id=0,
            func_name="strcpy",
            func_args=[0x7fff1000, 0x7fff0000]
        ))
        ts += 1

        # Taint propagation through strcpy (source -> dest)
        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x1205,
            timestamp=ts, thread_id=0,
            taint_source="strcpy", taint_label=1
        ))
        ts += 1

        # Buffer overflow: 256-byte write into 64-byte stack buffer
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_WRITE,
            address=base_addr + 0x1210,
            timestamp=ts, thread_id=0,
            memory_address=0x7fff1000,
            memory_size=256, memory_value=b'A' * 256
        ))
        ts += 1

        # Return address overwrite
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_WRITE,
            address=base_addr + 0x1220,
            timestamp=ts, thread_id=0,
            memory_address=0x7fff1240,
            memory_size=8, memory_value=b'\x41' * 8
        ))
        ts += 1

        # Crash on return to overwritten address
        events.append(ExecutionEvent(
            event_type=EventType.CRASH,
            address=base_addr + 0x1020,
            timestamp=ts, thread_id=0
        ))

        return events

    @staticmethod
    def _generate_uaf_trace() -> List[ExecutionEvent]:
        """
        Generate use-after-free trace (CWE-416).

        Attack chain:
          recv() [INPUT_SOURCE] -> malloc [HEAP_ALLOC]
          -> free [HEAP_FREE] -> memory_read on freed ptr -> crash
        """
        events = []
        base_addr = 0x400000
        ts = 0

        # Benign prologue noise
        for noise_fn in ["__libc_start_main", "_init", "getopt", "fprintf"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + ts * 8,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x2000,
            timestamp=ts, thread_id=0, func_name="main"
        ))
        ts += 1

        # === INPUT_SOURCE: recv() ===
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x2050,
            timestamp=ts, thread_id=0,
            func_name="recv",
            func_args=[3, 0x7fff0000, 128, 0]
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x2055,
            timestamp=ts, thread_id=0,
            taint_source="recv", taint_label=2
        ))
        ts += 1

        # malloc — allocate object
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x2100,
            timestamp=ts, thread_id=0,
            func_name="malloc", func_args=[256]
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.HEAP_ALLOC,
            address=base_addr + 0x2100,
            timestamp=ts, thread_id=0,
            heap_size=256, heap_ptr=0x603000
        ))
        ts += 1

        # Populate object with (tainted) network data
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_WRITE,
            address=base_addr + 0x2110,
            timestamp=ts, thread_id=0,
            memory_address=0x603000, memory_size=128,
            memory_value=b"X" * 128
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x2115,
            timestamp=ts, thread_id=0,
            taint_source="memcpy", taint_label=2
        ))
        ts += 1

        # Benign noise before free
        for noise_fn in ["process_request", "validate_header", "log_event"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + 0x2150 + ts,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1

        # free() — releases the object
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x2200,
            timestamp=ts, thread_id=0,
            func_name="free", func_args=[0x603000]
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.HEAP_FREE,
            address=base_addr + 0x2200,
            timestamp=ts, thread_id=0, heap_ptr=0x603000
        ))
        ts += 1

        # Use-after-free: access function pointer in freed object
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_READ,
            address=base_addr + 0x2300,
            timestamp=ts, thread_id=0,
            memory_address=0x603000, memory_size=8, memory_value=None
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.CRASH,
            address=base_addr + 0x2310,
            timestamp=ts, thread_id=0
        ))

        return events

    @staticmethod
    def _generate_format_string_trace() -> List[ExecutionEvent]:
        """
        Generate format string vulnerability trace (CWE-134).

        Attack chain:
          fgets() [INPUT_SOURCE] -> printf with user-controlled format string
          -> arbitrary memory read (%x/%n) -> crash
        """
        events = []
        base_addr = 0x400000
        ts = 0

        # Benign prologue
        for noise_fn in ["__libc_start_main", "setvbuf", "puts"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + ts * 8,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x3000,
            timestamp=ts, thread_id=0, func_name="main"
        ))
        ts += 1

        # === INPUT_SOURCE: fgets() reads user input ===
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x3100,
            timestamp=ts, thread_id=0,
            func_name="fgets",
            func_args=[0x7fff0000, 128, 0]  # stdin
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.SYSCALL,
            address=base_addr + 0x3105,
            timestamp=ts, thread_id=0,
            syscall_number=0, syscall_args=[0, 0x7fff0000, 128]
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x3110,
            timestamp=ts, thread_id=0,
            taint_source="fgets", taint_label=3
        ))
        ts += 1

        # Some processing noise
        for noise_fn in ["strip_newline", "validate_input"]:
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + 0x3150 + ts,
                timestamp=ts, thread_id=0, func_name=noise_fn
            ))
            ts += 1

        # Dangerous sink: printf(user_input) — format string bug
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL,
            address=base_addr + 0x3200,
            timestamp=ts, thread_id=0,
            func_name="printf",
            func_args=[0x7fff0000]  # user-controlled format string
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION,
            address=base_addr + 0x3205,
            timestamp=ts, thread_id=0,
            taint_source="printf", taint_label=3
        ))
        ts += 1

        # Arbitrary memory read via %x/%s specifiers
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_READ,
            address=base_addr + 0x3210,
            timestamp=ts, thread_id=0,
            memory_address=0x41414141, memory_size=4, memory_value=None
        ))
        ts += 1

        events.append(ExecutionEvent(
            event_type=EventType.CRASH,
            address=base_addr + 0x3220,
            timestamp=ts, thread_id=0
        ))

        return events

    @staticmethod
    def _generate_integer_overflow_trace() -> List[ExecutionEvent]:
        """Generate integer overflow trace leading to buffer overflow"""
        events = []
        base_addr = 0x400000

        # main
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x4000,
            timestamp=0, thread_id=0, func_name="main"
        ))

        # atoi / strtoul reads attacker-controlled size
        events.append(ExecutionEvent(
            event_type=EventType.SYSCALL, address=base_addr + 0x4100,
            timestamp=1, thread_id=0, syscall_number=0,
            syscall_args=[0, 0x7fff0000, 32]
        ))
        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION, address=base_addr + 0x4100,
            timestamp=2, thread_id=0, taint_source="read", taint_label=5
        ))

        # atoi converts to integer (tainted)
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x4200,
            timestamp=3, thread_id=0, func_name="atoi",
            func_args=[0x7fff0000]
        ))
        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION, address=base_addr + 0x4200,
            timestamp=4, thread_id=0, taint_source="atoi", taint_label=5
        ))

        # malloc with tainted size (integer overflow: size * 4 wraps)
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x4300,
            timestamp=5, thread_id=0, func_name="malloc",
            func_args=[0x40000000]  # overflowed size
        ))
        events.append(ExecutionEvent(
            event_type=EventType.HEAP_ALLOC, address=base_addr + 0x4300,
            timestamp=6, thread_id=0, heap_size=16, heap_ptr=0x603000
        ))

        # memcpy with original (large) count to small buffer
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x4400,
            timestamp=7, thread_id=0, func_name="memcpy",
            func_args=[0x603000, 0x7fff1000, 0x10000]
        ))
        events.append(ExecutionEvent(
            event_type=EventType.MEMORY_WRITE, address=base_addr + 0x4405,
            timestamp=8, thread_id=0, memory_address=0x603000,
            memory_size=0x10000, memory_value=b'X' * 0x10000
        ))

        # Crash
        events.append(ExecutionEvent(
            event_type=EventType.CRASH, address=base_addr + 0x4500,
            timestamp=9, thread_id=0
        ))
        return events

    @staticmethod
    def _generate_command_injection_trace() -> List[ExecutionEvent]:
        """Generate command injection trace"""
        events = []
        base_addr = 0x400000

        # main
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x5000,
            timestamp=0, thread_id=0, func_name="main"
        ))

        # read user input
        events.append(ExecutionEvent(
            event_type=EventType.SYSCALL, address=base_addr + 0x5100,
            timestamp=1, thread_id=0, syscall_number=0,
            syscall_args=[0, 0x7fff0000, 256]
        ))
        events.append(ExecutionEvent(
            event_type=EventType.TAINT_PROPAGATION, address=base_addr + 0x5100,
            timestamp=2, thread_id=0, taint_source="read", taint_label=6
        ))

        # system() with tainted input
        events.append(ExecutionEvent(
            event_type=EventType.FUNCTION_CALL, address=base_addr + 0x5200,
            timestamp=3, thread_id=0, func_name="system",
            func_args=[0x7fff0000]
        ))
        events.append(ExecutionEvent(
            event_type=EventType.SYSCALL, address=base_addr + 0x5205,
            timestamp=4, thread_id=0, syscall_number=59,  # execve
            syscall_args=[0x7fff0000, 0, 0]
        ))

        # Crash / abnormal termination
        events.append(ExecutionEvent(
            event_type=EventType.CRASH, address=base_addr + 0x5300,
            timestamp=5, thread_id=0
        ))
        return events

    @staticmethod
    def _generate_generic_trace() -> List[ExecutionEvent]:
        """Generate generic execution trace"""
        events = []
        base_addr = 0x400000

        # Include some high-risk functions so filtering doesn't remove everything
        high_risk_funcs = ["main", "strcpy", "memcpy", "malloc", "read", "system"]
        for i, func in enumerate(high_risk_funcs):
            events.append(ExecutionEvent(
                event_type=EventType.FUNCTION_CALL,
                address=base_addr + i * 0x100,
                timestamp=i,
                thread_id=0,
                func_name=func
            ))

        # Add a crash
        events.append(ExecutionEvent(
            event_type=EventType.CRASH,
            address=base_addr + 0x700,
            timestamp=len(high_risk_funcs),
            thread_id=0
        ))

        return events


if __name__ == "__main__":
    print("DynamoRIO Instrumentation Client")
    print("Usage: Import and use DynamoRIOClient or TraceSimulator")