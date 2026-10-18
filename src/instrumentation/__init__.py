"""
TRACEWISE-Lite Instrumentation Module

DynamoRIO client interface and trace simulation for binary execution monitoring.
"""

from .dynamorio_client import (
    DynamoRIOClient,
    TraceSimulator,
    ExecutionEvent,
    ExecutionTrace,
    EventType
)

__all__ = [
    'DynamoRIOClient', 'TraceSimulator',
    'ExecutionEvent', 'ExecutionTrace', 'EventType'
]