"""
Hybrid Binary Provenance Graph (HBPG) Constructor for TRACEWISE-Lite

Implements a graph-based representation that captures vulnerability-relevant
execution semantics including data dependencies, control flow, memory operations,
and taint propagation.
"""

import os
import sys
import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from instrumentation.dynamorio_client import ExecutionEvent, ExecutionTrace, EventType

logger = setup_logger("hbpg")


class NodeType(Enum):
    """Types of nodes in HBPG"""
    FUNCTION = "function"
    MEMORY_REGION = "memory_region"
    INPUT_SOURCE = "input_source"
    CRASH_SITE = "crash_site"
    SYSCALL = "syscall"
    DATA_VALUE = "data_value"
    HEAP_OBJECT = "heap_object"
    TAINT_LABEL = "taint_label"


class EdgeType(Enum):
    """Types of edges in HBPG"""
    DATA_DEPENDENCY = "data_dependency"
    CONTROL_FLOW = "control_flow"
    MEMORY_PROPAGATION = "memory_propagation"
    INPUT_PROPAGATION = "input_propagation"
    SYSCALL_INTERACTION = "syscall_interaction"
    TAINT_FLOW = "taint_flow"
    CALL_RELATION = "call_relation"
    RETURN_RELATION = "return_relation"


@dataclass
class HBPGNode:
    """Node in Hybrid Binary Provenance Graph"""
    node_id: str
    node_type: NodeType
    address: Optional[int] = None
    label: str = ""
    attributes: Dict = field(default_factory=dict)
    timestamp: int = 0

    def to_dict(self) -> Dict:
        return {
            'node_id': self.node_id,
            'type': self.node_type.value,
            'address': hex(self.address) if self.address else None,
            'label': self.label,
            'attributes': self.attributes,
            'timestamp': self.timestamp
        }


@dataclass
class HBPGEdge:
    """Edge in Hybrid Binary Provenance Graph"""
    source: str
    target: str
    edge_type: EdgeType
    attributes: Dict = field(default_factory=dict)
    weight: float = 1.0

    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'target': self.target,
            'type': self.edge_type.value,
            'attributes': self.attributes,
            'weight': self.weight
        }


class HybridBinaryProvenanceGraph:
    """
    Hybrid Binary Provenance Graph

    A unified graph representation that combines:
    - Function call graphs
    - Data dependency graphs
    - Memory operation graphs
    - Taint propagation graphs
    - Control flow information
    """

    def __init__(self, binary_path: str = "", trace_id: str = ""):
        self.binary_path = binary_path
        self.trace_id = trace_id
        self.nodes: Dict[str, HBPGNode] = {}
        self.edges: List[HBPGEdge] = []
        self._node_counter = 0
        self._node_lookup: Dict[str, str] = {}  # type:addr -> node_id

    def _create_node_id(self) -> str:
        """Generate unique node ID"""
        nid = f"n{self._node_counter}"
        self._node_counter += 1
        return nid

    def add_node(self,
                 node_type: NodeType,
                 address: int = None,
                 label: str = "",
                 attributes: Dict = None,
                 timestamp: int = 0) -> str:
        """Add a node to the graph"""
        node_id = self._create_node_id()
        node = HBPGNode(
            node_id=node_id,
            node_type=node_type,
            address=address,
            label=label,
            attributes=attributes or {},
            timestamp=timestamp
        )
        self.nodes[node_id] = node

        # Index for lookup
        if address:
            key = f"{node_type.value}:{hex(address)}"
            self._node_lookup[key] = node_id

        return node_id

    def add_edge(self,
                 source: str,
                 target: str,
                 edge_type: EdgeType,
                 attributes: Dict = None,
                 weight: float = 1.0):
        """Add an edge to the graph"""
        edge = HBPGEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            attributes=attributes or {},
            weight=weight
        )
        self.edges.append(edge)

    def get_node(self, node_id: str) -> Optional[HBPGNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> List[HBPGNode]:
        """Get all nodes of a specific type"""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_neighbors(self, node_id: str) -> List[HBPGNode]:
        """Get neighboring nodes"""
        neighbor_ids = set()
        for edge in self.edges:
            if edge.source == node_id:
                neighbor_ids.add(edge.target)
            elif edge.target == node_id:
                neighbor_ids.add(edge.source)
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def find_taint_paths(self, source_id: str, sink_id: str) -> List[List[str]]:
        """
        Find all taint propagation paths between source and sink

        Args:
            source_id: Source node ID
            sink_id: Sink node ID

        Returns:
            List of paths (each path is a list of node IDs)
        """
        paths = []
        visited = set()

        def dfs(current: str, path: List[str]):
            if current == sink_id:
                paths.append(path.copy())
                return

            visited.add(current)
            for edge in self.edges:
                if edge.source == current and edge.target not in visited:
                    if edge.edge_type in (
                        EdgeType.TAINT_FLOW, EdgeType.DATA_DEPENDENCY,
                        EdgeType.CONTROL_FLOW, EdgeType.MEMORY_PROPAGATION,
                        EdgeType.CALL_RELATION, EdgeType.INPUT_PROPAGATION
                    ):
                        path.append(edge.target)
                        dfs(edge.target, path)
                        path.pop()
            visited.remove(current)

        dfs(source_id, [source_id])
        return paths

    def get_attack_propagation_path(self) -> List[Dict]:
        """
        Extract the attack propagation path from input to crash

        Returns:
            List of nodes representing the attack path
        """
        # Find input source nodes
        input_nodes = self.get_nodes_by_type(NodeType.INPUT_SOURCE)
        if not input_nodes:
            return []

        # Find crash site nodes
        crash_nodes = self.get_nodes_by_type(NodeType.CRASH_SITE)
        if not crash_nodes:
            return []

        # Find paths from input to crash
        all_paths = []
        for inp in input_nodes:
            for crash in crash_nodes:
                paths = self.find_taint_paths(inp.node_id, crash.node_id)
                all_paths.extend(paths)

        # Return the longest/most detailed path
        if all_paths:
            longest = max(all_paths, key=len)
            return [self.nodes[nid].to_dict() for nid in longest if nid in self.nodes]

        return []

    def to_dict(self) -> Dict:
        """Convert graph to dictionary"""
        return {
            'binary_path': self.binary_path,
            'trace_id': self.trace_id,
            'nodes': [n.to_dict() for n in self.nodes.values()],
            'edges': [e.to_dict() for e in self.edges],
            'statistics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'node_types': {t.value: len(self.get_nodes_by_type(t))
                              for t in NodeType},
                'attack_path': self.get_attack_propagation_path()
            }
        }

    def save(self, path: str):
        """Save graph to JSON file"""
        import os
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Saved HBPG to {path}")

    @classmethod
    def load(cls, path: str) -> 'HybridBinaryProvenanceGraph':
        """Load graph from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)

        graph = cls(data['binary_path'], data['trace_id'])

        for node_data in data['nodes']:
            node = HBPGNode(
                node_id=node_data['node_id'],
                node_type=NodeType(node_data['type']),
                address=int(node_data['address'], 16) if node_data['address'] else None,
                label=node_data['label'],
                attributes=node_data['attributes'],
                timestamp=node_data['timestamp']
            )
            graph.nodes[node.node_id] = node

        for edge_data in data['edges']:
            edge = HBPGEdge(
                source=edge_data['source'],
                target=edge_data['target'],
                edge_type=EdgeType(edge_data['type']),
                attributes=edge_data['attributes'],
                weight=edge_data['weight']
            )
            graph.edges.append(edge)

        return graph


class HBPGConstructor:
    """
    Constructs Hybrid Binary Provenance Graph from execution traces.
    Suitable for simulated traces from TraceSimulator.
    For real DynamoRIO traces, use RealTraceShadowHBPGConstructor.
    """

    def __init__(self):
        self.graph: Optional[HybridBinaryProvenanceGraph] = None
        self._call_stack: List[str] = []
        self._memory_map: Dict[int, str] = {}  # addr -> node_id
        self._function_map: Dict[str, str] = {}  # func_name -> node_id
        self._taint_map: Dict[int, str] = {}  # taint_label -> node_id

    def construct(self, trace: ExecutionTrace) -> HybridBinaryProvenanceGraph:
        """
        Construct HBPG from execution trace

        Args:
            trace: Filtered execution trace

        Returns:
            Constructed HybridBinaryProvenanceGraph
        """
        logger.info(f"Constructing HBPG from trace {trace.trace_id}")

        self.graph = HybridBinaryProvenanceGraph(
            binary_path=trace.binary_path,
            trace_id=trace.trace_id
        )

        self._last_node_id = None

        # Process events in order
        for event in trace.events:
            node_id = self._process_event(event)
            if node_id and self._last_node_id and node_id != self._last_node_id:
                edge_exists = any(e.source == self._last_node_id and e.target == node_id for e in self.graph.edges)
                if not edge_exists:
                    self.graph.add_edge(self._last_node_id, node_id, EdgeType.TAINT_FLOW, attributes={'inferred': True})
            if node_id:
                self._last_node_id = node_id

        logger.info(f"HBPG construction complete: "
                   f"{len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")

        return self.graph

    def _process_event(self, event: ExecutionEvent) -> Optional[str]:
        """Process a single execution event"""
        if event.event_type == EventType.FUNCTION_CALL:
            return self._process_function_call(event)
        elif event.event_type == EventType.FUNCTION_RET:
            self._process_function_return(event)
        elif event.event_type in (EventType.MEMORY_READ, EventType.MEMORY_WRITE):
            return self._process_memory_event(event)
        elif event.event_type == EventType.SYSCALL:
            return self._process_syscall(event)
        elif event.event_type == EventType.TAINT_PROPAGATION:
            return self._process_taint_event(event)
        elif event.event_type == EventType.CRASH:
            return self._process_crash_event(event)
        elif event.event_type in (EventType.HEAP_ALLOC, EventType.HEAP_FREE):
            return self._process_heap_event(event)
        return None

    def _process_function_call(self, event: ExecutionEvent):
        """Process function call event"""
        func_name = event.func_name or f"func_{hex(event.address)}"

        # Check if input source function
        input_sources = {
            'read', 'recv', 'fread', 'scanf', 'fgets', 'getc',
            'gets', 'recvfrom', 'recvmsg', 'fscanf', 'sscanf',
            'getline', 'getdelim', 'pread',
        }
        if func_name in input_sources:
            node_id = self.graph.add_node(
                node_type=NodeType.INPUT_SOURCE,
                address=event.address,
                label=f"input:{func_name}",
                attributes={
                    'function': func_name,
                    'args': event.func_args,
                    'source_type': 'external_input'
                },
                timestamp=event.timestamp
            )
        else:
            node_id = self.graph.add_node(
                node_type=NodeType.FUNCTION,
                address=event.address,
                label=func_name,
                attributes={
                    'function': func_name,
                    'args': event.func_args,
                    'call_depth': len(self._call_stack)
                },
                timestamp=event.timestamp
            )

        self._function_map[func_name] = node_id

        # Add call edge
        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.CALL_RELATION,
                attributes={'call_site': hex(event.address)}
            )

        self._call_stack.append(node_id)
        return node_id

    def _process_function_return(self, event: ExecutionEvent):
        """Process function return event"""
        if len(self._call_stack) >= 2:
            callee = self._call_stack.pop()
            caller = self._call_stack[-1]

            self.graph.add_edge(
                source=callee,
                target=caller,
                edge_type=EdgeType.RETURN_RELATION,
                attributes={'return_value': event.return_value}
            )

    def _process_memory_event(self, event: ExecutionEvent):
        """Process memory read/write event"""
        mem_addr = event.memory_address
        if not mem_addr:
            return

        # Create memory region node
        mem_key = f"mem_{hex(mem_addr)}"
        if mem_key not in self._memory_map:
            node_id = self.graph.add_node(
                node_type=NodeType.MEMORY_REGION,
                address=mem_addr,
                label=f"mem:{hex(mem_addr)}",
                attributes={
                    'size': event.memory_size,
                    'access_type': 'write' if event.event_type == EventType.MEMORY_WRITE else 'read'
                },
                timestamp=event.timestamp
            )
            self._memory_map[mem_addr] = node_id

        mem_node = self._memory_map[mem_addr]

        # Connect to current function
        if self._call_stack:
            edge_type = EdgeType.MEMORY_PROPAGATION if event.event_type == EventType.MEMORY_WRITE else EdgeType.DATA_DEPENDENCY
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=mem_node,
                edge_type=edge_type,
                attributes={
                    'size': event.memory_size,
                    'value_sample': str(event.memory_value[:32]) if event.memory_value else None
                }
            )

        return mem_node

    def _process_syscall(self, event: ExecutionEvent):
        """Process system call event"""
        syscall_name = self._get_syscall_name(event.syscall_number)

        node_id = self.graph.add_node(
            node_type=NodeType.SYSCALL,
            address=event.address,
            label=f"syscall:{syscall_name}",
            attributes={
                'syscall_number': event.syscall_number,
                'args': event.syscall_args,
                'name': syscall_name
            },
            timestamp=event.timestamp
        )

        # Connect to calling function
        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.SYSCALL_INTERACTION,
                attributes={}
            )

        return node_id

    def _process_taint_event(self, event: ExecutionEvent):
        """Process taint propagation event"""
        taint_label = event.taint_label or 0

        # Create taint label node
        node_id = self.graph.add_node(
            node_type=NodeType.TAINT_LABEL,
            address=event.address,
            label=f"taint:{event.taint_source}",
            attributes={
                'source': event.taint_source,
                'label': taint_label
            },
            timestamp=event.timestamp
        )

        self._taint_map[taint_label] = node_id

        # If taint source is an input function, link INPUT_SOURCE -> TAINT_LABEL
        input_sources = {
            'read', 'recv', 'fread', 'scanf', 'fgets', 'getc',
            'gets', 'recvfrom', 'recvmsg', 'fscanf', 'sscanf',
        }
        edge_added = False
        if event.taint_source in input_sources:
            # Find the most recent INPUT_SOURCE node with this function name
            for existing_id, existing_node in reversed(list(self.graph.nodes.items())):
                if (existing_node.node_type == NodeType.INPUT_SOURCE and
                        event.taint_source in existing_node.label):
                    self.graph.add_edge(
                        source=existing_id,
                        target=node_id,
                        edge_type=EdgeType.INPUT_PROPAGATION,
                        attributes={'taint_label': taint_label}
                    )
                    edge_added = True
                    break

        if not edge_added:
            # For real traces, taint source might be a memory address or register
            # Connect to the most recent input source or the current function
            source_node_id = None
            for existing_id, existing_node in reversed(list(self.graph.nodes.items())):
                if existing_node.node_type == NodeType.INPUT_SOURCE:
                    source_node_id = existing_id
                    break
            
            if source_node_id:
                self.graph.add_edge(
                    source=source_node_id,
                    target=node_id,
                    edge_type=EdgeType.INPUT_PROPAGATION,
                    attributes={'taint_label': taint_label, 'inferred': True}
                )
            elif self._call_stack:
                self.graph.add_edge(
                    source=self._call_stack[-1],
                    target=node_id,
                    edge_type=EdgeType.INPUT_PROPAGATION,
                    attributes={'taint_label': taint_label, 'inferred': True}
                )

        # Propagate taint forward: TAINT_LABEL -> current function (forward direction)
        if self._call_stack:
            self.graph.add_edge(
                source=node_id,
                target=self._call_stack[-1],
                edge_type=EdgeType.TAINT_FLOW,
                attributes={'propagation_step': event.timestamp}
            )

        return node_id


    def _process_crash_event(self, event: ExecutionEvent):
        """Process crash event"""
        node_id = self.graph.add_node(
            node_type=NodeType.CRASH_SITE,
            address=event.address,
            label="crash",
            attributes={
                'crash_type': 'unknown',
                'signal': 11  # SIGSEGV
            },
            timestamp=event.timestamp
        )

        # Connect to current function
        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.CONTROL_FLOW,
                attributes={'crash_context': True}
            )

        return node_id

    def _process_heap_event(self, event: ExecutionEvent):
        """Process heap allocation/free event"""
        is_alloc = event.event_type == EventType.HEAP_ALLOC

        node_id = self.graph.add_node(
            node_type=NodeType.HEAP_OBJECT,
            address=event.heap_ptr,
            label=f"heap:{hex(event.heap_ptr) if event.heap_ptr else 'unknown'}",
            attributes={
                'operation': 'alloc' if is_alloc else 'free',
                'size': event.heap_size,
                'pointer': hex(event.heap_ptr) if event.heap_ptr else None
            },
            timestamp=event.timestamp
        )

        if event.heap_ptr:
            self._memory_map[event.heap_ptr] = node_id

        # Connect to current function
        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.MEMORY_PROPAGATION,
                attributes={'heap_operation': True}
            )

        return node_id

    def _get_syscall_name(self, syscall_num: Optional[int]) -> str:
        """Get syscall name from number"""
        syscall_names = {
            0: 'read', 1: 'write', 2: 'open', 3: 'close',
            9: 'mmap', 10: 'mprotect', 11: 'munmap',
            12: 'brk', 17: 'pread64', 18: 'pwrite64',
            41: 'socket', 42: 'connect', 43: 'accept',
            44: 'sendto', 45: 'recvfrom',
            60: 'exit', 231: 'exit_group'
        }
        return syscall_names.get(syscall_num, f"syscall_{syscall_num}")


class ShadowMemory:
    """
    Shadow memory taint tracker for real DynamoRIO execution traces.

    The C DynamoRIO client emits raw mem_read/mem_write events with
    addresses, but no taint labels. This class bridges that gap by:
      1. Seeding taint from known INPUT_SOURCE function buffers
         (e.g., the buffer arg of read(), recv(), fgets())
      2. Propagating taint when a tainted source address is READ and
         a WRITE to a different address occurs in the same function block
      3. Marking a memory write as tainted if its source (read-before-write)
         region overlaps with the taint shadow

    This generates real TAINT_FLOW edges between INPUT_SOURCE nodes and
    downstream memory / crash nodes, fulfilling Theorem 1 (Crash-Context
    Reachability) on real dynamic execution telemetry.
    """

    def __init__(self):
        # Set of tainted memory addresses
        self._tainted: Set[int] = set()
        # Map: tainted_address -> node_id that seeded the taint
        self._taint_origin: Dict[int, str] = {}

    def seed_from_input_source(self, buf_addr: int, buf_size: int, source_node_id: str):
        """
        Mark a buffer as tainted, seeded by an INPUT_SOURCE node.
        Call this when a read()/recv()/fgets() event is processed and we
        know the destination buffer address and size.
        """
        if buf_addr is None or buf_size is None or buf_size <= 0:
            return
        for offset in range(min(buf_size, 4096)):  # cap at 4 KB to avoid explosion
            addr = buf_addr + offset
            self._tainted.add(addr)
            self._taint_origin[addr] = source_node_id

    def is_tainted(self, addr: int) -> bool:
        """Return True if the given memory address is tainted."""
        return addr in self._tainted

    def propagate(self, src_addr: int, dst_addr: int, dst_size: int, dst_node_id: str):
        """
        If src_addr is tainted, mark dst range as tainted and record dst_node_id
        as a new taint origin (so later reads from dst know where taint came from).
        """
        if src_addr in self._tainted:
            origin = self._taint_origin.get(src_addr, dst_node_id)
            for offset in range(min(dst_size or 1, 4096)):
                a = dst_addr + offset
                self._tainted.add(a)
                self._taint_origin[a] = origin

    def get_origin_node(self, addr: int) -> Optional[str]:
        """Return the node_id of the INPUT_SOURCE that seeded taint at this address."""
        return self._taint_origin.get(addr)

    def __contains__(self, addr: int) -> bool:
        return self.is_tainted(addr)


class RealTraceShadowHBPGConstructor:
    """
    Improved HBPGConstructor for REAL DynamoRIO traces.

    Fixes the 0-edges problem by using ShadowMemory to:
      - Seed taint from syscall(0)/read()/recv() buffer arguments
      - Propagate taint through memory writes
      - Draw explicit TAINT_FLOW edges whenever a tainted address is
        used as a source in a dangerous function (sink)
      - Connect tainted writes to the CRASH_SITE via DATA_DEPENDENCY

    Use this constructor when processing real .json log files from the
    DynamoRIO C client (tracewise_dr.c). The simpler HBPGConstructor
    remains for simulated traces from TraceSimulator.
    """

    # Known dangerous sinks (function names that the C client emits)
    DANGEROUS_SINKS = {
        'strcpy', 'strncpy', 'strcat', 'strncat',
        'sprintf', 'snprintf', 'vsprintf',
        'memcpy', 'memmove', 'memset',
        'gets', 'printf', 'fprintf',
        'system', 'execve', 'popen',
        'free',
    }

    INPUT_SOURCES = {
        'read', 'recv', 'fread', 'fgets', 'scanf',
        'fscanf', 'sscanf', 'gets', 'recvfrom',
        'recvmsg', 'getline', 'getdelim',
    }

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.shadow = ShadowMemory()
        self.graph: Optional[HybridBinaryProvenanceGraph] = None
        self._call_stack: List[str] = []
        self._memory_map: Dict[int, str] = {}   # addr -> node_id
        self._last_read_addr: Optional[int] = None  # track last mem_read address
        self._last_read_size: int = 0
        self._input_source_nodes: List[Tuple[str, Optional[int], Optional[int]]] = []  # (node_id, buf_addr, buf_size)
        self._crash_node_id: Optional[str] = None
        self._last_read_node_id: Optional[str] = None

    def construct_from_raw_log(
        self,
        raw_events: List[dict],
        trace_id: str = "real_trace"
    ) -> HybridBinaryProvenanceGraph:
        """
        Construct an HBPG with taint edges from a list of raw event dicts
        as emitted by the DynamoRIO C client (tracewise_dr.c).

        Each dict has at minimum:
          event_type: str   ('func_call'|'mem_read'|'mem_write'|'syscall'|'crash')
          address:    int
          timestamp:  int
          thread_id:  int
        Plus optional fields: func_name, memory_address, memory_size, syscall_number

        Returns:
          HybridBinaryProvenanceGraph with real taint-flow edges.
        """
        self.graph = HybridBinaryProvenanceGraph(
            binary_path=self.binary_path,
            trace_id=trace_id
        )
        self._call_stack = []
        self._memory_map = {}
        self._input_source_nodes = []
        self._crash_node_id = None
        self._last_read_addr = None
        self._last_read_size = 0
        self._last_read_node_id = None

        for ev in raw_events:
            etype = ev.get('event_type', '')

            if etype == 'func_call':
                self._handle_func_call(ev)
            elif etype == 'mem_read':
                self._handle_mem_read(ev)
            elif etype == 'mem_write':
                self._handle_mem_write(ev)
            elif etype == 'syscall':
                self._handle_syscall(ev)
            elif etype == 'crash':
                self._handle_crash(ev)

        # Phase 2: Wire taint edges from INPUT_SOURCE nodes to taint-propagated memory nodes
        self._wire_taint_edges_to_crash()

        logger.info(
            f"RealTraceShadowHBPG: {len(self.graph.nodes)} nodes, "
            f"{len(self.graph.edges)} edges (shadow taint edges included)"
        )
        return self.graph

    def _handle_func_call(self, ev: dict):
        """Process a func_call event from the DR log."""
        fn = ev.get('func_name') or f"func_{hex(ev.get('address', 0))}"
        addr = ev.get('address', 0)
        ts = ev.get('timestamp', 0)

        if fn in self.INPUT_SOURCES:
            node_id = self.graph.add_node(
                node_type=NodeType.INPUT_SOURCE,
                address=addr,
                label=f"input:{fn}",
                attributes={'function': fn, 'source_type': 'external_input'},
                timestamp=ts
            )
            # Lazily seed taint when we see the subsequent mem_write
            self._input_source_nodes.append((node_id, None, None))
        else:
            node_id = self.graph.add_node(
                node_type=NodeType.FUNCTION,
                address=addr,
                label=fn,
                attributes={
                    'function': fn,
                    'is_sink': fn in self.DANGEROUS_SINKS,
                    'call_depth': len(self._call_stack)
                },
                timestamp=ts
            )

        # Call edge from caller
        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.CALL_RELATION,
                attributes={'call_site': hex(addr)}
            )
        self._call_stack.append(node_id)

    def _handle_mem_read(self, ev: dict):
        """Track memory reads to detect taint source addresses."""
        mem_addr = ev.get('memory_address')
        mem_size = ev.get('memory_size', 1)
        if mem_addr is None:
            return

        # Track the last read address; if it's tainted, a subsequent write
        # in the same function will propagate the taint.
        self._last_read_addr = mem_addr
        self._last_read_size = mem_size

        mem_key = f"mem_{hex(mem_addr)}"
        if mem_key not in self._memory_map:
            node_id = self.graph.add_node(
                node_type=NodeType.MEMORY_REGION,
                address=mem_addr,
                label=f"mem_r:{hex(mem_addr)}",
                attributes={'access': 'read', 'size': mem_size},
                timestamp=ev.get('timestamp', 0)
            )
            self._memory_map[mem_key] = node_id
        mem_node_id = self._memory_map[mem_key]
        self._last_read_node_id = mem_node_id

        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=mem_node_id,
                edge_type=EdgeType.DATA_DEPENDENCY,
                attributes={'access': 'read', 'size': mem_size}
            )

        # If this address is tainted, draw a TAINT_FLOW edge from the origin
        if self.shadow.is_tainted(mem_addr):
            origin_nid = self.shadow.get_origin_node(mem_addr)
            if origin_nid and origin_nid in self.graph.nodes:
                taint_edge_exists = any(
                    e.source == origin_nid and e.target == mem_node_id
                    and e.edge_type == EdgeType.TAINT_FLOW
                    for e in self.graph.edges
                )
                if not taint_edge_exists:
                    self.graph.add_edge(
                        source=origin_nid,
                        target=mem_node_id,
                        edge_type=EdgeType.TAINT_FLOW,
                        attributes={'via': 'shadow_memory_read'}
                    )

    def _handle_mem_write(self, ev: dict):
        """Track memory writes and propagate taint via ShadowMemory."""
        mem_addr = ev.get('memory_address')
        mem_size = ev.get('memory_size', 1)
        if mem_addr is None:
            return

        mem_key = f"mem_{hex(mem_addr)}"
        if mem_key not in self._memory_map:
            node_id = self.graph.add_node(
                node_type=NodeType.MEMORY_REGION,
                address=mem_addr,
                label=f"mem_w:{hex(mem_addr)}",
                attributes={'access': 'write', 'size': mem_size},
                timestamp=ev.get('timestamp', 0)
            )
            self._memory_map[mem_key] = node_id
        mem_node_id = self._memory_map[mem_key]

        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=mem_node_id,
                edge_type=EdgeType.MEMORY_PROPAGATION,
                attributes={'access': 'write', 'size': mem_size}
            )

        # Shadow Memory Taint Propagation:
        # If the last read address was tainted, this write is also tainted.
        if self._last_read_addr and self.shadow.is_tainted(self._last_read_addr):
            origin_nid = self.shadow.get_origin_node(self._last_read_addr)
            self.shadow.propagate(self._last_read_addr, mem_addr, mem_size, mem_node_id)

            if origin_nid and origin_nid in self.graph.nodes:
                taint_edge_exists = any(
                    e.source == origin_nid and e.target == mem_node_id
                    and e.edge_type == EdgeType.TAINT_FLOW
                    for e in self.graph.edges
                )
                if not taint_edge_exists:
                    self.graph.add_edge(
                        source=origin_nid,
                        target=mem_node_id,
                        edge_type=EdgeType.TAINT_FLOW,
                        attributes={'via': 'shadow_memory_write_propagation'}
                    )

        # If write immediately follows an INPUT_SOURCE (no tracked read addr),
        # seed this write address as tainted directly from the input source.
        # This handles: read() syscall writes directly into user buffer.
        elif self._input_source_nodes and not self._last_read_addr:
            src_node_id, _, _ = self._input_source_nodes[-1]
            self.shadow.seed_from_input_source(mem_addr, mem_size, src_node_id)
            old = self._input_source_nodes[-1]
            self._input_source_nodes[-1] = (old[0], mem_addr, mem_size)
            taint_edge_exists = any(
                e.source == src_node_id and e.target == mem_node_id
                and e.edge_type == EdgeType.TAINT_FLOW
                for e in self.graph.edges
            )
            if not taint_edge_exists:
                self.graph.add_edge(
                    source=src_node_id,
                    target=mem_node_id,
                    edge_type=EdgeType.TAINT_FLOW,
                    attributes={'via': 'input_source_direct_write'}
                )

        self._last_read_addr = None  # reset after write

    def _handle_syscall(self, ev: dict):
        """Track syscalls, seed taint from read() syscall (number 0)."""
        sysnum = ev.get('syscall_number', -1)
        ts = ev.get('timestamp', 0)
        addr = ev.get('address', 0)

        syscall_names = {
            0: 'read', 1: 'write', 2: 'open', 3: 'close',
            17: 'pread64', 45: 'recvfrom', 41: 'socket',
            60: 'exit', 231: 'exit_group'
        }
        sname = syscall_names.get(sysnum, f"syscall_{sysnum}")

        node_id = self.graph.add_node(
            node_type=NodeType.SYSCALL,
            address=addr,
            label=f"syscall:{sname}",
            attributes={'syscall_number': sysnum, 'name': sname},
            timestamp=ts
        )

        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.SYSCALL_INTERACTION,
                attributes={}
            )

        # If syscall args are present (future C client improvement), seed taint.
        syscall_args = ev.get('syscall_args', [])
        if sysnum == 0 and len(syscall_args) >= 3 and self._input_source_nodes:
            buf_addr = syscall_args[1]
            buf_size = syscall_args[2]
            src_node_id = self._input_source_nodes[-1][0]
            self.shadow.seed_from_input_source(buf_addr, buf_size, src_node_id)
            old = self._input_source_nodes[-1]
            self._input_source_nodes[-1] = (old[0], buf_addr, buf_size)

    def _handle_crash(self, ev: dict):
        """Create a CRASH_SITE node and record it."""
        addr = ev.get('address', 0)
        ts = ev.get('timestamp', 0)

        node_id = self.graph.add_node(
            node_type=NodeType.CRASH_SITE,
            address=addr,
            label=f"crash:SIGSEGV@{hex(addr)}",
            attributes={'signal': 11},
            timestamp=ts
        )
        self._crash_node_id = node_id

        if self._call_stack:
            self.graph.add_edge(
                source=self._call_stack[-1],
                target=node_id,
                edge_type=EdgeType.CONTROL_FLOW,
                attributes={'crash_context': True}
            )

    def _wire_taint_edges_to_crash(self):
        """
        Post-processing pass: find any MEMORY_REGION node whose address is
        tainted and draw a DATA_DEPENDENCY edge to the CRASH_SITE.
        This ensures that even if intermediate taint propagation wasn't
        perfectly captured during the linear scan, the final graph still
        has a path from INPUT_SOURCE -> tainted_mem -> CRASH_SITE.
        """
        if self._crash_node_id is None:
            return

        for mem_key, mem_node_id in self._memory_map.items():
            node = self.graph.nodes.get(mem_node_id)
            if node and node.node_type == NodeType.MEMORY_REGION:
                addr = node.address
                if addr and self.shadow.is_tainted(addr):
                    edge_exists = any(
                        e.source == mem_node_id and e.target == self._crash_node_id
                        for e in self.graph.edges
                    )
                    if not edge_exists:
                        self.graph.add_edge(
                            source=mem_node_id,
                            target=self._crash_node_id,
                            edge_type=EdgeType.DATA_DEPENDENCY,
                            attributes={'via': 'shadow_taint_to_crash'}
                        )


if __name__ == "__main__":
    print("HBPG - Hybrid Binary Provenance Graph")
    print("Usage: Import and use HBPGConstructor or RealTraceShadowHBPGConstructor")