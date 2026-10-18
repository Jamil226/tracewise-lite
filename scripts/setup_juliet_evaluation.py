import os
import subprocess
import json
import glob
from pathlib import Path

JULIET_ROOT  = Path.home() / "Documents" / "research-portfolio" / "TRACEWISE-lite" / "tracewise-lite" / "juliet"
MANIFEST_OUT = Path.home() / "tracewise_cvs" / "juliet_manifest.json"
BUILD_DIR    = Path.home() / "tracewise_cvs" / "juliet_built"

# The 8 CWE classes from your paper
# Maps CWE ID → Juliet directory name fragment
TARGET_CWE = {
    "CWE121": "CWE-121",
    "CWE122": "CWE-122",
    "CWE134": "CWE-134",
    "CWE190": "CWE-190",
    "CWE416": "CWE-416",
    "CWE476": "CWE-476",
    "CWE78":  "CWE-78",
    "CWE22":  "CWE-22",
}

# Juliet programs need a shared support file
SUPPORT_FILES = list(JULIET_ROOT.glob("**/support/*.c")) + \
                list(JULIET_ROOT.glob("**/testcasesupport/*.c"))

def compile_juliet_binary(source_file: Path, output_path: Path,
                          cwe_id: str) -> bool:
    """
    Compile one Juliet bad() test case to a binary.
    Only compile the _bad variant — ground truth is always the CWE.
    """
    if "_good" in source_file.name:
        return False   # skip good variants

    support = " ".join(str(s) for s in SUPPORT_FILES[:3])  # limit support files
    
    cmd = [
        "gcc",
        str(source_file),
        "-o", str(output_path),
        "-I", str(JULIET_ROOT / "C" / "testcasesupport"),
        "-fno-stack-protector",
        "-U_FORTIFY_SOURCE",
        "-DINCLUDEMAIN",
        "-g",
        "-O1",
        "-w",           # suppress warnings — Juliet generates many
        "-lm",
        "-ldl",
    ]

    # Add support files if they exist
    for sf in SUPPORT_FILES[:3]:
        if sf.suffix == ".c":
            cmd.append(str(sf))

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=30
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def generate_crashing_input(binary_path: Path, cwe_id: str) -> bytes:
    """
    Generate a crashing input appropriate for each CWE class.
    Juliet bad() functions typically crash with oversized string input.
    These are NOT synthetic vulnerable programs — they are crash triggers
    for independently written Juliet programs.
    """
    inputs = {
        "CWE121": b"A" * 500,          # overflow stack buffer
        "CWE122": b"A" * 500,          # overflow heap buffer
        "CWE134": b"%s%s%s%s%s%s",    # format string
        "CWE190": b"99999999999",      # large integer
        "CWE416": b"trigger",          # any input triggers UAF
        "CWE476": b"",                 # null ptr needs no input
        "CWE78":  b"test; ls",         # command injection
        "CWE22":  b"../../../etc/passwd",  # path traversal
    }
    return inputs.get(cwe_id, b"A" * 200)


def main():
    BUILD_DIR.mkdir(exist_ok=True)

    manifest = []
    compiled  = 0
    failed    = 0

    for juliet_dir_name, cwe_label in TARGET_CWE.items():
        # Find Juliet source files for this CWE
        source_files = [f for f in JULIET_ROOT.rglob("*.c") if juliet_dir_name in str(f)]

        # Limit to 10 per CWE — enough for statistics, manageable runtime
        bad_files = [
            f for f in source_files
            if f.name.endswith("_01.c")
        ][:10]

        print(f"{cwe_label}: found {len(bad_files)} bad() test cases")

        for src in bad_files:
            binary_name = f"{juliet_dir_name}_{src.stem}"
            binary_path = BUILD_DIR / binary_name

            success = compile_juliet_binary(src, binary_path, juliet_dir_name)

            if success:
                # Write crashing input to file
                input_path = BUILD_DIR / f"{binary_name}.input"
                input_path.write_bytes(
                    generate_crashing_input(binary_path, juliet_dir_name)
                )

                manifest.append({
                    "bug_id":       binary_name,
                    "target":       juliet_dir_name,
                    "ground_truth": cwe_label,
                    "binary_path":  str(binary_path),
                    "input_path":   str(input_path),
                    "source_path":  str(src),
                    "input_mode":   "stdin",
                    "source":       "juliet_1.3_nist",   # explicit provenance
                    "status":       "ready",
                })
                compiled += 1
            else:
                failed += 1

    print(f"\nCompiled: {compiled}  Failed: {failed}")

    with open(MANIFEST_OUT, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Juliet manifest: {MANIFEST_OUT} ({compiled} entries)")


if __name__ == "__main__":
    main()
