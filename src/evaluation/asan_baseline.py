"""
asan_baseline.py
TRACEWISE-Lite — Correct AddressSanitizer Baseline

IMPORTANT CONSTRAINT:
    ASan cannot be injected into a pre-compiled binary.
    The target binary MUST be recompiled with -fsanitize=address.
    This script handles that recompilation step.

    If you only have a stripped binary with no source → use the
    stripped_binary_baseline() function instead (GDB stack-trace only).

Usage:
    python asan_baseline.py --src path/to/target.c --input crashing_input
    python asan_baseline.py --binary path/to/stripped_elf --input crashing_input
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("tracewise.asan_baseline")
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s | %(name)s | %(message)s")

# Canonical CWE pattern table — matches ASan summary lines
ASAN_CWE_PATTERNS = [
    (re.compile(r"stack-buffer-overflow",        re.I), "CWE-121"),
    (re.compile(r"heap-buffer-overflow",         re.I), "CWE-122"),
    (re.compile(r"heap-use-after-free",          re.I), "CWE-416"),
    (re.compile(r"use-after-poison",             re.I), "CWE-416"),
    (re.compile(r"stack-use-after-return",       re.I), "CWE-562"),
    (re.compile(r"global-buffer-overflow",       re.I), "CWE-121"),
    (re.compile(r"null.*dereference|"
                r"SEGV on unknown address 0x0{6,}", re.I), "CWE-476"),
    (re.compile(r"signed integer overflow|"
                r"unsigned integer overflow",    re.I), "CWE-190"),
    (re.compile(r"format-string",                re.I), "CWE-134"),
]


@dataclass
class BaselineResult:
    method:          str              # "asan_recompile" | "gdb_stripped"
    predicted_cwe:   Optional[str]   # e.g. "CWE-121" or None if unknown
    raw_report:      str             # full ASan / GDB stderr output
    crash_function:  Optional[str]   # top of stack trace
    crash_address:   Optional[str]
    success:         bool
    error_message:   Optional[str]   # populated on failure

    def to_dict(self) -> dict:
        return {
            "method":         self.method,
            "predicted_cwe":  self.predicted_cwe,
            "crash_function": self.crash_function,
            "crash_address":  self.crash_address,
            "success":        self.success,
            "error_message":  self.error_message,
        }


# ─── CWE extraction from ASan stderr ─────────────────────────────────────────

def _parse_cwe_from_asan(stderr: str) -> Optional[str]:
    for pattern, cwe in ASAN_CWE_PATTERNS:
        if pattern.search(stderr):
            return cwe
    return None


def _parse_crash_function(stderr: str) -> Optional[str]:
    """Extract top frame function name from ASan or GDB stack trace."""
    # ASan format:  #0 0xdeadbeef in function_name /path/file.c:42
    asan_frame = re.search(r"#0\s+0x[0-9a-f]+\s+in\s+(\S+)", stderr)
    if asan_frame:
        return asan_frame.group(1)
    # GDB format:   #0  function_name (args) at file.c:42
    gdb_frame = re.search(r"#0\s+(\w+)\s*\(", stderr)
    if gdb_frame:
        return gdb_frame.group(1)
    return None


def _parse_crash_address(stderr: str) -> Optional[str]:
    addr = re.search(r"0x([0-9a-f]{6,16})", stderr)
    return "0x" + addr.group(1) if addr else None


# ─── Verify ASan toolchain is available ──────────────────────────────────────

def _check_asan_available() -> tuple[bool, str]:
    """Return (ok, message)."""
    if not shutil.which("gcc") and not shutil.which("clang"):
        return False, "No C compiler found. Install gcc or clang."

    # Try a trivial ASan compile
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
        f.write("int main(){return 0;}\n")
        tmp = f.name
    try:
        r = subprocess.run(
            ["gcc", "-fsanitize=address", "-o", "/dev/null", tmp],
            capture_output=True, timeout=120
        )
        if r.returncode != 0:
            return False, (
                "gcc -fsanitize=address failed. "
                "Install libasan: sudo apt install gcc libasan6"
            )
        return True, "ok"
    except FileNotFoundError:
        return False, "gcc not found"
    finally:
        os.unlink(tmp)


# ─── Path 1: Source available — recompile with ASan ─────────────────────────

def asan_source_baseline(
    source_path:    str,
    input_path:     str,
    input_mode:     str  = "stdin",   # "stdin" | "file_arg" | "argv"
    argv_template:  list = None,      # e.g. ["@@"] — @@ replaced by input file path
    compiler:       str  = "gcc",
    extra_flags:    list = None,
    timeout:        int  = 30,
) -> BaselineResult:
    """
    Recompile source with ASan, run crashing input, parse report.

    Parameters
    ----------
    source_path    : path to the .c file
    input_path     : path to the crashing input file
    input_mode     : how to deliver input to the binary
                     "stdin"    — pipe input_path contents to stdin (default)
                     "file_arg" — pass input file path as argv[1]
                     "argv"     — use argv_template; "@@" is replaced with input path
    argv_template  : only used when input_mode="argv"
                     e.g. ["@@"] or ["-i", "@@", "-o", "/dev/null"]
    compiler       : "gcc" or "clang"
    extra_flags    : additional compiler flags e.g. ["-lm"]
    timeout        : seconds before killing the instrumented binary
    """
    """
    Recompile source with ASan, run crashing input, parse report.

    Parameters
    ----------
    source_path : path to the .c file
    input_path  : path to the crashing input file
    compiler    : "gcc" or "clang"
    extra_flags : additional compiler flags e.g. ["-lm", "-I./include"]
    timeout     : seconds before killing the instrumented binary
    """
    ok, msg = _check_asan_available()
    if not ok:
        return BaselineResult(
            method="asan_recompile", predicted_cwe=None, raw_report="",
            crash_function=None, crash_address=None,
            success=False, error_message=msg
        )

    extra_flags = extra_flags or []

    with tempfile.NamedTemporaryFile(suffix="_asan", delete=False) as tf:
        asan_binary = tf.name

    try:
        # ── Step 1: compile ──────────────────────────────────────────────────
        compile_cmd = [
            compiler,
            source_path,
            "-o", asan_binary,
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-fno-stack-protector",    # ADD THIS — stack canary kills before ASan reports
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
            "-g",                      # keep symbols for better traces
            "-O1",                     # ASan works best at O1
        ] + extra_flags

        log.info("Compiling: %s", " ".join(compile_cmd))
        cr = subprocess.run(compile_cmd, capture_output=True, timeout=60)
        if cr.returncode != 0:
            err = cr.stderr.decode("utf-8", errors="replace")
            log.error("Compilation failed:\n%s", err)
            return BaselineResult(
                method="asan_recompile", predicted_cwe=None, raw_report=err,
                crash_function=None, crash_address=None,
                success=False, error_message=f"Compilation failed: {err[:200]}"
            )

        # ── Step 2: run with crashing input ─────────────────────────────────
        asan_env = os.environ.copy()
        asan_env.update({
            "ASAN_OPTIONS":           "halt_on_error=1:print_stacktrace=1:color=never",
            "ASAN_SYMBOLIZER_PATH":   shutil.which("llvm-symbolizer") or "",
            "UBSAN_OPTIONS":          "print_stacktrace=1",
        })

        with open(input_path, "rb") as inp:
            crashing_input = inp.read()

        # Write input to temp file for file_arg / argv modes
        input_tmp = None
        with tempfile.NamedTemporaryFile(delete=False, suffix="_input") as tf:
            tf.write(crashing_input)
            input_tmp = tf.name

        try:
            if input_mode == "stdin":
                run_args   = [asan_binary]
                stdin_data = crashing_input
            elif input_mode == "file_arg":
                # Binary takes input file path as argv[1]: ./prog <input_file>
                run_args   = [asan_binary, input_tmp]
                stdin_data = None
            elif input_mode == "argv":
                # Binary takes arbitrary args; @@ is replaced with input file path
                template = argv_template or ["@@"]
                run_args = [asan_binary] + [
                    input_tmp if a == "@@" else a for a in template
                ]
                stdin_data = None
            else:
                run_args   = [asan_binary]
                stdin_data = crashing_input

            log.info("Running ASan binary (%s mode, %d bytes input)…",
                     input_mode, len(crashing_input))
            rr = subprocess.run(
                run_args,
                input=stdin_data,
                capture_output=True,
                env=asan_env,
                timeout=timeout,
            )
        finally:
            if input_tmp and os.path.exists(input_tmp):
                os.unlink(input_tmp)

        stderr = rr.stderr.decode("utf-8", errors="replace")



        # ── Step 3: parse ────────────────────────────────────────────────────
        predicted_cwe  = _parse_cwe_from_asan(stderr)
        crash_function = _parse_crash_function(stderr)
        crash_address  = _parse_crash_address(stderr)

        if predicted_cwe is None and rr.returncode == 0:
            log.warning("Binary did not crash on this input under ASan.")
            return BaselineResult(
                method="asan_recompile", predicted_cwe=None, raw_report=stderr,
                crash_function=None, crash_address=None,
                success=False, error_message="Binary did not crash (input may need re-verification)"
            )

        log.info("ASan result: CWE=%s  function=%s", predicted_cwe, crash_function)
        return BaselineResult(
            method="asan_recompile",
            predicted_cwe=predicted_cwe,
            raw_report=stderr,
            crash_function=crash_function,
            crash_address=crash_address,
            success=True,
            error_message=None,
        )

    except subprocess.TimeoutExpired:
        return BaselineResult(
            method="asan_recompile", predicted_cwe=None, raw_report="",
            crash_function=None, crash_address=None,
            success=False, error_message="Timeout — binary hung on input"
        )
    finally:
        if os.path.exists(asan_binary):
            os.unlink(asan_binary)


# ─── Path 2: Stripped binary — GDB stack trace only ──────────────────────────

def stripped_binary_baseline(
    binary_path: str,
    input_path:  str,
    timeout:     int = 30,
) -> BaselineResult:
    """
    For pre-compiled stripped binaries where you cannot recompile.
    GDB gives a stack trace but NO vulnerability type classification.
    This is the honest baseline for stripped binary triage.

    NOTE: This is strictly weaker than ASan — GDB cannot tell you
    CWE-121 vs CWE-122, only that a SIGSEGV occurred and where.
    Your paper should present this separately to show ASan requires
    source while TRACEWISE-Lite and GDB both work on stripped binaries.
    """
    if not shutil.which("gdb"):
        return BaselineResult(
            method="gdb_stripped", predicted_cwe=None, raw_report="",
            crash_function=None, crash_address=None,
            success=False, error_message="gdb not found: sudo apt install gdb"
        )

    gdb_commands = (
        "run\n"
        "bt\n"
        "info registers\n"
        "quit\n"
    )

    with open(input_path, "rb") as f:
        crashing_input = f.read()

    # Write input to temp file (some binaries need file arg not stdin)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(crashing_input)
        input_tmp = tf.name

    try:
        gdb_cmd = [
            "gdb", "--batch",
            "--ex", f"set args < {input_tmp}",
            "--ex", "run",
            "--ex", "bt",
            "--ex", "info registers",
            "--ex", "quit",
            binary_path,
        ]
        result = subprocess.run(
            gdb_cmd,
            capture_output=True,
            timeout=timeout,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

        # GDB cannot determine CWE type from stripped binary
        # Record crash function and address only
        crash_function = _parse_crash_function(output)
        crash_address  = _parse_crash_address(output)

        crashed = ("SIGSEGV" in output or "SIGABRT" in output
                   or "SIGFPE" in output or "Segmentation fault" in output)

        return BaselineResult(
            method="gdb_stripped",
            predicted_cwe=None,          # intentionally None — GDB cannot determine this
            raw_report=output,
            crash_function=crash_function,
            crash_address=crash_address,
            success=crashed,
            error_message=None if crashed else "No crash signal detected",
        )

    except subprocess.TimeoutExpired:
        return BaselineResult(
            method="gdb_stripped", predicted_cwe=None, raw_report="",
            crash_function=None, crash_address=None,
            success=False, error_message="Timeout"
        )
    finally:
        os.unlink(input_tmp)


# ─── Evaluation comparison helper ────────────────────────────────────────────

def compare_with_tracewise(
    asan_result:      BaselineResult,
    tracewise_cwe:    Optional[str],
    ground_truth_cwe: str,
) -> dict:
    """
    Produce the comparison dict that goes into your evaluation table.
    Call this once per binary; collect results into a list; write to CSV.

    Returns the row dict for your results table.
    """
    def _match(predicted, ground_truth):
        if predicted is None:
            return False
        # Exact match
        if predicted == ground_truth:
            return True
        # Hierarchical partial credit: same CWE family (e.g. CWE-12x)
        return predicted[:6] == ground_truth[:6]

    asan_correct       = _match(asan_result.predicted_cwe, ground_truth_cwe)
    tracewise_correct  = _match(tracewise_cwe, ground_truth_cwe)

    return {
        "ground_truth":            ground_truth_cwe,
        "asan_prediction":         asan_result.predicted_cwe,
        "asan_correct":            asan_correct,
        "asan_requires_source":    True,    # always — honest limitation
        "tracewise_prediction":    tracewise_cwe,
        "tracewise_correct":       tracewise_correct,
        "tracewise_source_needed": False,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TRACEWISE-Lite ASan baseline runner"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--src",    help="C source file path (enables ASan recompile)")
    group.add_argument("--binary", help="Pre-compiled stripped binary (GDB only)")
    parser.add_argument("--input", required=True, help="Crashing input file path")
    parser.add_argument("--compiler", default="gcc", choices=["gcc", "clang"])
    parser.add_argument("--ground-truth", default=None,
                        help="Ground truth CWE (for accuracy reporting)")
    args = parser.parse_args()

    if args.src:
        result = asan_source_baseline(args.src, args.input, args.compiler)
    else:
        result = stripped_binary_baseline(args.binary, args.input)

    import json
    print(json.dumps(result.to_dict(), indent=2))

    if args.ground_truth:
        row = compare_with_tracewise(result, None, args.ground_truth)
        print("\nComparison row (no TRACEWISE-Lite result provided):")
        print(json.dumps(row, indent=2))
