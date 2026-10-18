#!/usr/bin/env python3
"""
static_baseline.py
TRACEWISE-Lite — Phase 2 Baseline

Addresses the critical reviewer question:
  "Why do we need dynamic binary tracing at all?
   Can't the LLM just read the vulnerable C source code?"

This script feeds the RAW Juliet C source code directly to the LLM
(without any DynamoRIO trace, without HBPG compression) and measures
CWE classification accuracy.

Comparison goal:
  Static-Source LLM Accuracy  vs.  TRACEWISE-Lite Accuracy
  - If TRACEWISE-Lite > Static Source → dynamic tracing adds value
  - If Static Source >= TRACEWISE-Lite → we have a problem (tracing is pointless)

Expected outcome (hypothesis):
  Static Source will FAIL on stripped/complex binaries where source is unavailable.
  TRACEWISE-Lite will succeed because it works on ANY compiled binary without source.

Usage:
    python3 evaluation/static_baseline.py \\
        --juliet-dir ./juliet/C/testcases \\
        --model qwen2.5-coder:1.5b \\
        --output experiments/results/static_baseline.json
"""

import os
import sys
import json
import time
import re
import glob
import argparse
import statistics
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict

import requests

# CWE ground truth from Juliet directory structure
CWE_GROUND_TRUTH_MAP = {
    'CWE121': 'CWE-121',
    'CWE122': 'CWE-122',
    'CWE190': 'CWE-190',
    'CWE134': 'CWE-134',
    'CWE416': 'CWE-416',
    'CWE415': 'CWE-415',
    'CWE476': 'CWE-476',
    'CWE78':  'CWE-78',
    'CWE22':  'CWE-22',
    'CWE401': 'CWE-401',
}

OLLAMA_URL = "http://localhost:11434/api/generate"


@dataclass
class StaticBaselineResult:
    """Result for one source file."""
    source_file:      str
    ground_truth_cwe: str
    predicted_cwe:    str = ''
    correct:          bool = False
    latency_s:        float = 0.0
    token_count:      int = 0
    raw_response:     str = ''
    error:            Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


def extract_cwe_from_response(text: str) -> str:
    """
    Extract a CWE identifier from LLM response text.
    Handles: 'CWE-121', 'CWE121', '121', 'cwe-121'.
    """
    if not text:
        return 'CWE-Unknown'
    m = re.search(r'CWE[-\s]?(\d{2,4})', text, re.IGNORECASE)
    if m:
        return f'CWE-{m.group(1)}'
    # Try plain digit (e.g. model outputs "121" without prefix)
    m = re.search(r'\b(\d{3})\b', text)
    if m:
        return f'CWE-{m.group(1)}'
    return 'CWE-Unknown'


def call_ollama(prompt: str, model: str, timeout: int = 90) -> tuple:
    """
    Call Ollama with a prompt. Returns (response_text, latency_s, token_count).
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 256,
        }
    }
    t0 = time.time()
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        text = data.get("response", "")
        tokens = data.get("eval_count", 0)
        return text, time.time() - t0, tokens
    except Exception as e:
        return "", time.time() - t0, 0


def build_static_prompt(source_code: str, filename: str) -> str:
    """
    Build a prompt that gives the LLM only the raw C source code.
    This is the baseline: no dynamic trace, no graph, just source.
    Truncated to 3000 chars to fit context window.
    """
    code_excerpt = source_code[:3000]
    return f"""You are a binary vulnerability analysis expert.
Below is a C source file named: {filename}

Source code:
```c
{code_excerpt}
```

Analyze the code and classify the vulnerability.
Respond ONLY with a JSON object:
{{
  "reasoning": "<step-by-step analysis>",
  "cwe_id": "<e.g. CWE-121>",
  "cwe_name": "<full CWE name>",
  "confidence": <0.0-1.0>,
  "root_cause": "<one sentence root cause>"
}}
"""


def find_juliet_source_files(juliet_dir: str, max_per_cwe: int = 10) -> List[Dict]:
    """
    Scan the Juliet test suite directory and collect source files
    with their ground truth CWE.

    Juliet structure: CWE121_Stack_Based_Buffer_Overflow/s01/*.c
    """
    samples = []
    for cwe_prefix, cwe_id in CWE_GROUND_TRUTH_MAP.items():
        pattern = os.path.join(juliet_dir, f"{cwe_prefix}_*", "**", "*.c")
        files = glob.glob(pattern, recursive=True)
        # Only "bad" files contain actual vulnerable code
        bad_files = [f for f in files if '_bad' in os.path.basename(f).lower()]
        bad_files = bad_files[:max_per_cwe]

        for f in bad_files:
            samples.append({
                'source_file': f,
                'ground_truth': cwe_id,
                'cwe_prefix': cwe_prefix
            })

    return samples


def evaluate_static_baseline(
    juliet_dir: str,
    model: str = 'qwen2.5-coder:1.5b',
    max_per_cwe: int = 10,
    output_path: Optional[str] = None,
) -> Dict:
    """
    Run the static source code baseline.

    For each Juliet source file:
      - Read the C source code
      - Feed directly to LLM (no trace, no graph)
      - Measure CWE prediction accuracy

    Returns a summary dict with overall accuracy and per-CWE breakdown.
    """
    print(f"[StaticBaseline] Scanning Juliet directory: {juliet_dir}")
    samples = find_juliet_source_files(juliet_dir, max_per_cwe=max_per_cwe)
    print(f"[StaticBaseline] Found {len(samples)} source files across {len(CWE_GROUND_TRUTH_MAP)} CWEs")

    if not samples:
        print("[StaticBaseline] No Juliet files found. Check your --juliet-dir path.")
        return {}

    results: List[StaticBaselineResult] = []

    # Check Ollama availability
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        if r.status_code != 200:
            raise ConnectionError
        print(f"[StaticBaseline] Ollama available. Using model: {model}")
    except Exception:
        print("[StaticBaseline] WARNING: Ollama unavailable. Running in dry-run mode (no LLM calls).")
        model = None

    for i, sample in enumerate(samples):
        src_path = sample['source_file']
        gt_cwe = sample['ground_truth']
        fname = os.path.basename(src_path)

        print(f"  [{i+1}/{len(samples)}] {fname} (GT: {gt_cwe})")

        result = StaticBaselineResult(
            source_file=src_path,
            ground_truth_cwe=gt_cwe
        )

        try:
            with open(src_path, 'r', errors='replace') as f:
                source_code = f.read()

            if model:
                prompt = build_static_prompt(source_code, fname)
                raw_text, latency, tokens = call_ollama(prompt, model)
                result.latency_s = round(latency, 2)
                result.token_count = tokens
                result.raw_response = raw_text[:500]

                # Parse JSON response
                start = raw_text.find('{')
                end = raw_text.rfind('}') + 1
                pred_cwe = 'CWE-Unknown'
                if start >= 0 and end > start:
                    try:
                        parsed = json.loads(raw_text[start:end])
                        raw_cwe = parsed.get('cwe_id', '')
                        pred_cwe = extract_cwe_from_response(raw_cwe)
                    except json.JSONDecodeError:
                        pred_cwe = extract_cwe_from_response(raw_text)
                else:
                    pred_cwe = extract_cwe_from_response(raw_text)

                result.predicted_cwe = pred_cwe
                result.correct = (pred_cwe == gt_cwe)
                print(f"    Predicted: {pred_cwe}  Correct: {result.correct}  Latency: {latency:.1f}s")
            else:
                # Dry-run: no LLM call
                result.predicted_cwe = 'DRY_RUN'
                result.correct = False

        except Exception as e:
            result.error = str(e)
            print(f"    ERROR: {e}")

        results.append(result)

    # Compute summary
    total = len(results)
    correct = sum(1 for r in results if r.correct)
    overall_acc = correct / total if total > 0 else 0.0

    latencies = [r.latency_s for r in results if r.latency_s > 0]
    mean_latency = statistics.mean(latencies) if latencies else 0.0

    token_counts = [r.token_count for r in results if r.token_count > 0]
    mean_tokens = statistics.mean(token_counts) if token_counts else 0.0

    per_cwe = defaultdict(lambda: {'n': 0, 'correct': 0})
    for r in results:
        per_cwe[r.ground_truth_cwe]['n'] += 1
        per_cwe[r.ground_truth_cwe]['correct'] += int(r.correct)

    per_cwe_acc = {
        cwe: round(v['correct'] / v['n'], 3) if v['n'] > 0 else 0.0
        for cwe, v in per_cwe.items()
    }

    summary = {
        'model': model,
        'mode': 'static_source_code',
        'total_samples': total,
        'correct': correct,
        'overall_accuracy': round(overall_acc, 4),
        'mean_latency_s': round(mean_latency, 2),
        'mean_tokens': round(mean_tokens, 1),
        'per_cwe_accuracy': per_cwe_acc,
        'note': (
            'This baseline feeds raw C source code directly to the LLM. '
            'TRACEWISE-Lite compresses dynamic execution traces instead. '
            'If TRACEWISE-Lite accuracy > static baseline on stripped binaries '
            'without source code, dynamic tracing is justified.'
        ),
    }

    print("\n" + "=" * 60)
    print(f"  STATIC SOURCE BASELINE RESULTS ({model})")
    print("=" * 60)
    print(f"  Overall CWE Accuracy:   {overall_acc:.1%}  ({correct}/{total})")
    print(f"  Mean Latency:           {mean_latency:.1f}s")
    print(f"  Per-CWE accuracy:       {per_cwe_acc}")
    print("=" * 60)

    # Save results
    if output_path:
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump({
                'summary': summary,
                'results': [r.to_dict() for r in results]
            }, f, indent=2)
        print(f"  Results saved to: {output_path}")

    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Static Source Code Baseline for TRACEWISE-Lite comparison'
    )
    parser.add_argument(
        '--juliet-dir',
        default='./juliet/C/testcases',
        help='Path to Juliet Test Suite C/testcases directory'
    )
    parser.add_argument(
        '--model',
        default='qwen2.5-coder:1.5b',
        help='Ollama model name (use same model as TRACEWISE-Lite for fair comparison)'
    )
    parser.add_argument(
        '--max-per-cwe',
        type=int,
        default=10,
        help='Maximum number of source files to evaluate per CWE class'
    )
    parser.add_argument(
        '--output',
        default='experiments/results/static_baseline.json',
        help='Output JSON file path'
    )
    args = parser.parse_args()

    summary = evaluate_static_baseline(
        juliet_dir=args.juliet_dir,
        model=args.model,
        max_per_cwe=args.max_per_cwe,
        output_path=args.output,
    )
    sys.exit(0 if summary else 1)
