"""
LLM Reasoning Module for TRACEWISE-Lite

Integrates lightweight locally deployable LLMs via Ollama
to analyze compressed provenance summaries and infer:
- Vulnerability classes
- Attack propagation paths
- Exploitability likelihood
- Root-cause explanations
"""

import os
import sys
import json
import time
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.logger import setup_logger
from utils.config import get_config

logger = setup_logger("llm")


@dataclass
class VulnerabilityAnalysis:
    """Result of LLM vulnerability analysis"""
    vulnerability_class: str
    cwe_id: str
    severity: str
    confidence: float
    root_cause: str
    attack_path: str
    exploitability: str
    exploitability_score: float
    remediation: str
    raw_response: str


@dataclass
class LLMResponse:
    """Raw LLM response with metadata"""
    content: str
    model: str
    tokens_used: int
    response_time: float
    timestamp: float


class OllamaClient:
    """
    Client for Ollama LLM inference

    Supports local deployment of lightweight models:
    - tinyllama (1.1B parameters)
    - phi (2.7B parameters)
    - deepseek-coder (1.3B parameters)
    """

    def __init__(self, config=None):
        self.config = config or get_config().llm
        self.base_url = self.config.ollama_host.rstrip('/')
        self.session = requests.Session()

    def is_available(self) -> bool:
        """Check if Ollama server is running"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            return False

    def list_models(self) -> List[str]:
        """List available models"""
        try:
            response = self.session.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [m['name'] for m in data.get('models', [])]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
        return []

    def generate(self,
                 prompt: str,
                 system_prompt: str = None,
                 temperature: float = None,
                 max_tokens: int = None) -> LLMResponse:
        """
        Generate text using Ollama

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            LLMResponse with generated content
        """
        url = f"{self.base_url}/api/generate"

        payload = {
            'model': self.config.model_name,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': temperature or self.config.temperature,
                'num_predict': max_tokens or self.config.max_tokens
            }
        }

        if system_prompt:
            payload['system'] = system_prompt

        start_time = time.time()

        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            data = response.json()
            elapsed = time.time() - start_time

            return LLMResponse(
                content=data.get('response', ''),
                model=self.config.model_name,
                tokens_used=data.get('eval_count', 0),
                response_time=elapsed,
                timestamp=time.time()
            )

        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama. Is it running?")
            raise
        except requests.exceptions.Timeout:
            logger.error("LLM request timed out")
            raise
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise

    def chat(self,
             messages: List[Dict[str, str]],
             temperature: float = None) -> LLMResponse:
        """
        Chat completion using Ollama

        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature

        Returns:
            LLMResponse
        """
        url = f"{self.base_url}/api/chat"

        payload = {
            'model': self.config.model_name,
            'messages': messages,
            'stream': False,
            'options': {
                'temperature': temperature or self.config.temperature
            }
        }

        start_time = time.time()

        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            data = response.json()
            elapsed = time.time() - start_time

            return LLMResponse(
                content=data.get('message', {}).get('content', ''),
                model=self.config.model_name,
                tokens_used=data.get('eval_count', 0),
                response_time=elapsed,
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Chat failed: {e}")
            raise


class LLMReasoningModule:
    """
    LLM-assisted reasoning for vulnerability analysis

    Uses compressed provenance summaries to infer vulnerability
    information through structured prompting.
    """

    # Vulnerability class taxonomy
    VULN_CLASSES = {
        'buffer_overflow': ['CWE-120', 'CWE-121', 'CWE-122', 'CWE-124'],
        'heap_overflow': ['CWE-122'],
        'stack_overflow': ['CWE-121'],
        'use_after_free': ['CWE-416'],
        'double_free': ['CWE-415'],
        'format_string': ['CWE-134'],
        'integer_overflow': ['CWE-190', 'CWE-191'],
        'command_injection': ['CWE-78'],
        'path_traversal': ['CWE-22'],
        'memory_leak': ['CWE-401'],
        'null_pointer': ['CWE-476'],
        'race_condition': ['CWE-362', 'CWE-367']
    }

    def __init__(self, config=None):
        self.config = config or get_config().llm
        self.client = OllamaClient(config)
        self._analysis_cache = {}

    def analyze_provenance_summary(self,
                                   provenance_summary: Dict,
                                   crash_info: Dict = None) -> VulnerabilityAnalysis:
        """
        Analyze provenance summary to identify vulnerability

        Args:
            provenance_summary: Compressed HBPG summary
            crash_info: Optional crash information

        Returns:
            VulnerabilityAnalysis result
        """
        # Build analysis prompt
        prompt = self._build_analysis_prompt(provenance_summary, crash_info)

        # System prompt for security analysis
        system_prompt = """You are a cybersecurity vulnerability analysis expert.
Analyze the provided execution trace summary and identify the vulnerability type,
root cause, and exploitability. Be specific and technical.
Respond in JSON format with the following fields:
- vulnerability_class: The type of vulnerability
- cwe_id: Relevant CWE identifier
- severity: Critical/High/Medium/Low
- confidence: 0.0-1.0
- root_cause: Technical explanation of the root cause
- attack_path: Description of the attack propagation path
- exploitability: Description of exploitability
- exploitability_score: 0.0-1.0
- remediation: Suggested fix"""

        try:
            response = self.client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.3,
                max_tokens=2048
            )

            # Parse response
            analysis = self._parse_analysis_response(response.content)
            analysis.raw_response = response.content

            return analysis

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return self._fallback_analysis(provenance_summary)

    def classify_vulnerability(self,
                               provenance_summary: Dict) -> Tuple[str, float]:
        """
        Classify vulnerability type from provenance summary

        Args:
            provenance_summary: Compressed HBPG summary

        Returns:
            (vulnerability_class, confidence)
        """
        prompt = f"""Classify the vulnerability type based on this execution trace summary.
Choose from: buffer_overflow, heap_overflow, stack_overflow, use_after_free,
double_free, format_string, integer_overflow, command_injection, path_traversal,
memory_leak, null_pointer, race_condition, unknown.

Trace Summary:
{json.dumps(provenance_summary, indent=2)[:2000]}

Respond with ONLY the vulnerability class and confidence (0.0-1.0) in this format:
CLASS: <class_name>
CONFIDENCE: <0.0-1.0>"""

        try:
            response = self.client.generate(prompt=prompt, temperature=0.1)
            return self._parse_classification(response.content)
        except Exception as e:
            logger.warning(f"Classification failed: {e}")
            return ("unknown", 0.0)

    def explain_root_cause(self,
                          provenance_summary: Dict,
                          crash_info: Dict = None) -> str:
        """
        Generate human-readable root cause explanation

        Args:
            provenance_summary: Compressed HBPG summary
            crash_info: Optional crash information

        Returns:
            Root cause explanation string
        """
        prompt = self._build_explanation_prompt(provenance_summary, crash_info)

        system_prompt = """You are a security researcher explaining a vulnerability
to a development team. Provide a clear, technical explanation of the root cause,
how the vulnerability can be exploited, and how to fix it. Be concise but thorough."""

        try:
            response = self.client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.4
            )
            return response.content

        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return "Failed to generate explanation. See raw trace for details."

    def assess_exploitability(self,
                             provenance_summary: Dict,
                             crash_info: Dict = None) -> Tuple[str, float]:
        """
        Assess exploitability of vulnerability

        Args:
            provenance_summary: Compressed HBPG summary
            crash_info: Optional crash information

        Returns:
            (exploitability_description, score)
        """
        prompt = f"""Assess the exploitability of this vulnerability based on the trace summary.
Consider: control flow hijacking, data corruption, information disclosure,
remote vs local exploitation.

Trace Summary:
{json.dumps(provenance_summary, indent=2)[:2000]}

Rate exploitability from 0.0 (not exploitable) to 1.0 (easily exploitable).
Provide a brief justification.

Format:
SCORE: <0.0-1.0>
JUSTIFICATION: <brief explanation>"""

        try:
            response = self.client.generate(prompt=prompt, temperature=0.2)
            return self._parse_exploitability(response.content)
        except Exception as e:
            logger.warning(f"Exploitability assessment failed: {e}")
            return ("unknown", 0.0)

    def _build_analysis_prompt(self,
                               provenance_summary: Dict,
                               crash_info: Dict = None) -> str:
        """Build prompt for vulnerability analysis"""
        prompt_parts = [
            "Analyze the following binary execution trace summary to identify vulnerabilities.",
            "",
            "Trace Summary:",
            json.dumps(provenance_summary, indent=2)[:3000],
        ]

        if crash_info:
            prompt_parts.extend([
                "",
                "Crash Information:",
                json.dumps(crash_info, indent=2)[:1000]
            ])

        prompt_parts.extend([
            "",
            "Provide a comprehensive vulnerability analysis in JSON format."
        ])

        return "\n".join(prompt_parts)

    def _build_explanation_prompt(self,
                                  provenance_summary: Dict,
                                  crash_info: Dict = None) -> str:
        """Build prompt for root cause explanation"""
        prompt = f"""Explain the root cause of this vulnerability in detail.

Execution Trace Summary:
{json.dumps(provenance_summary, indent=2)[:3000]}
"""
        if crash_info:
            prompt += f"""
Crash Details:
{json.dumps(crash_info, indent=2)[:1000]}
"""

        prompt += """
Provide:
1. Root cause explanation
2. How the vulnerability can be triggered
3. Potential impact
4. Recommended fix
"""
        return prompt

    def _parse_analysis_response(self, content: str) -> VulnerabilityAnalysis:
        """Parse LLM response into VulnerabilityAnalysis"""
        # Try to extract JSON from response
        try:
            # Find JSON block
            start = content.find('{')
            end = content.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = content[start:end]
                data = json.loads(json_str)

                return VulnerabilityAnalysis(
                    vulnerability_class=data.get('vulnerability_class', 'unknown'),
                    cwe_id=self._normalize_cwe(data.get('cwe_id', 'CWE-Unknown')),
                    severity=data.get('severity', 'Unknown'),
                    confidence=float(data.get('confidence', 0.5)),
                    root_cause=data.get('root_cause', 'Unknown'),
                    attack_path=data.get('attack_path', 'Unknown'),
                    exploitability=data.get('exploitability', 'Unknown'),
                    exploitability_score=float(data.get('exploitability_score', 0.0)),
                    remediation=data.get('remediation', 'Review code manually'),
                    raw_response=content
                )
        except Exception as e:
            logger.warning(f"Failed to parse JSON response: {e}")

        # Fallback: extract information from text
        return self._extract_from_text(content)

    def _extract_from_text(self, content: str) -> VulnerabilityAnalysis:
        """Extract analysis from free-form text"""
        content_lower = content.lower()

        # Detect vulnerability class
        vuln_class = "unknown"
        for vc in self.VULN_CLASSES.keys():
            if vc.replace('_', ' ') in content_lower or vc in content_lower:
                vuln_class = vc
                break

        # Detect severity
        severity = "Unknown"
        for sev in ["Critical", "High", "Medium", "Low"]:
            if sev.lower() in content_lower:
                severity = sev
                break

        # Extract first paragraph as root cause
        lines = content.split('\n')
        root_cause = lines[0][:500] if lines else "See full response"

        return VulnerabilityAnalysis(
            vulnerability_class=vuln_class,
            cwe_id="CWE-Unknown",
            severity=severity,
            confidence=0.5,
            root_cause=root_cause,
            attack_path="See full response",
            exploitability="Unknown",
            exploitability_score=0.0,
            remediation="Review code manually",
            raw_response=content
        )

    def _parse_classification(self, content: str) -> Tuple[str, float]:
        """Parse classification response"""
        vuln_class = "unknown"
        confidence = 0.0

        for line in content.split('\n'):
            if line.startswith('CLASS:'):
                vuln_class = line.split(':', 1)[1].strip().lower()
            elif line.startswith('CONFIDENCE:'):
                try:
                    confidence = float(line.split(':', 1)[1].strip())
                except:
                    pass

        return vuln_class, confidence

    def _parse_exploitability(self, content: str) -> Tuple[str, float]:
        """Parse exploitability response"""
        score = 0.0
        justification = "Unknown"

        for line in content.split('\n'):
            if line.startswith('SCORE:'):
                try:
                    score = float(line.split(':', 1)[1].strip())
                except:
                    pass
            elif line.startswith('JUSTIFICATION:'):
                justification = line.split(':', 1)[1].strip()

        return justification, score

    def _fallback_analysis(self, provenance_summary: Dict) -> VulnerabilityAnalysis:
        """Generate fallback analysis when LLM is unavailable"""
        # Try to infer from graph structure
        if isinstance(provenance_summary, dict):
            node_types = provenance_summary.get('statistics', {}).get('node_types', {})
            attack_path = provenance_summary.get('statistics', {}).get('attack_path', [])
        else:
            node_types = {}
            attack_path = []

        # Heuristic classification
        if node_types.get('memory_region', 0) > 5:
            vuln_class = "buffer_overflow"
            cwe = "CWE-121"
        elif node_types.get('heap_object', 0) > 2:
            vuln_class = "use_after_free"
            cwe = "CWE-416"
        else:
            vuln_class = "unknown"
            cwe = "CWE-Unknown"

        return VulnerabilityAnalysis(
            vulnerability_class=vuln_class,
            cwe_id=self._normalize_cwe(cwe),
            severity="Unknown",
            confidence=0.3,
            root_cause="LLM analysis unavailable. Heuristic classification applied.",
            attack_path=str(attack_path[:3]) if attack_path else "Unknown",
            exploitability="Unknown",
            exploitability_score=0.0,
            remediation="Manual analysis required",
            raw_response=""
        )

    def _normalize_cwe(self, cwe: str) -> str:
        """Ensure CWE ID has the correct 'CWE-' prefix and no trailing text"""
        if not cwe or cwe == 'Unknown':
            return 'CWE-Unknown'
        cwe = str(cwe).strip().upper()
        
        import re
        m = re.search(r'\d+', cwe)
        if m:
            return f"CWE-{m.group(0)}"
            
        return 'CWE-Unknown'

    def generate_report(self,
                       analysis: VulnerabilityAnalysis,
                       compression_summary: Dict = None,
                       output_path: str = None) -> str:
        """
        Generate structured vulnerability report

        Args:
            analysis: Vulnerability analysis result
            compression_summary: Optional compression statistics
            output_path: Optional path to save report

        Returns:
            Report string
        """
        report_lines = [
            "=" * 70,
            "TRACEWISE-Lite Vulnerability Analysis Report",
            "=" * 70,
            "",
            f"Vulnerability Class: {analysis.vulnerability_class}",
            f"CWE ID: {analysis.cwe_id}",
            f"Severity: {analysis.severity}",
            f"Confidence: {analysis.confidence:.2f}",
            "",
            "-" * 70,
            "ROOT CAUSE ANALYSIS",
            "-" * 70,
            analysis.root_cause,
            "",
            "-" * 70,
            "ATTACK PROPAGATION PATH",
            "-" * 70,
            analysis.attack_path,
            "",
            "-" * 70,
            "EXPLOITABILITY ASSESSMENT",
            "-" * 70,
            f"Score: {analysis.exploitability_score:.2f}/1.0",
            f"Details: {analysis.exploitability}",
            "",
            "-" * 70,
            "RECOMMENDED REMEDIATION",
            "-" * 70,
            analysis.remediation,
        ]

        if compression_summary:
            report_lines.extend([
                "",
                "-" * 70,
                "COMPRESSION STATISTICS",
                "-" * 70,
                json.dumps(compression_summary, indent=2)
            ])

        report_lines.extend([
            "",
            "=" * 70,
            "End of Report",
            "=" * 70
        ])

        report = "\n".join(report_lines)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {output_path}")

        return report


if __name__ == "__main__":
    print("LLM Reasoning Module")
    print("Usage: Import and use LLMReasoningModule")