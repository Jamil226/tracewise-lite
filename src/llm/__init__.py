"""
TRACEWISE-Lite LLM Module

LLM-assisted reasoning for vulnerability classification, root cause analysis,
and exploitability assessment using locally deployable models via Ollama.
"""

from .reasoning import (
    LLMReasoningModule,
    VulnerabilityAnalysis,
    LLMResponse,
    OllamaClient
)

__all__ = ['LLMReasoningModule', 'VulnerabilityAnalysis', 'LLMResponse', 'OllamaClient']