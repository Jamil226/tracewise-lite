import json
import os
from pathlib import Path

MANIFEST_PATH = Path("/home/zeeshan/tracewise_cvs/magma_manifest.json")
EXPANSION_DIR = Path("/tmp/cve_expansion")
MAGMA_DIR     = EXPANSION_DIR / "magma"

def get_corpus_file(target_name: str) -> str:
    """Find the first file in the corpus directory for the target."""
    corpus_dir = MAGMA_DIR / "targets" / target_name / "corpus"
    if corpus_dir.exists():
        for root, dirs, files in os.walk(corpus_dir):
            for file in files:
                if not file.startswith("."):
                    return str(Path(root) / file)
    return "/home/zeeshan/tracewise_cvs/inputs/placeholder.bin"

def expand_manifest():
    if not MANIFEST_PATH.exists():
        print(f"Error: {MANIFEST_PATH} not found.")
        return

    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)

    # 1. sudo (CVE-2021-3156)
    sudo_bin = "/tmp/cve_expansion/CVE-2021-3156/sudo" # Assuming it builds here
    if os.path.exists(sudo_bin):
        manifest.append({
            "bug_id": "cve_2021_3156_sudo",
            "target": "sudo",
            "ground_truth": "CWE-787", # Out of bounds write
            "binary_path": sudo_bin,
            "input_path": "/home/zeeshan/tracewise_cvs/inputs/cwe122_crash.bin", # Placeholder, sudo triggers via argv usually
            "source_path": sudo_bin, # Simplified
            "note": "CVE-2021-3156 Baron Samedit",
            "status": "ready",
            "input_mode": "argv",
            "argv_template": ["-s", "\\"] # Standard trigger
        })
        print("Added sudo (CVE-2021-3156)")

    # 2. libpng 1.6.36
    libpng_bin = "/tmp/cve_expansion/libpng-1.6.36/.libs/pngtest" # Or other test binary
    if os.path.exists(libpng_bin):
        manifest.append({
            "bug_id": "libpng_1_6_36",
            "target": "libpng",
            "ground_truth": "CWE-125",
            "binary_path": libpng_bin,
            "input_path": get_corpus_file("libpng"),
            "source_path": libpng_bin,
            "note": "libpng vulnerability",
            "status": "ready",
            "input_mode": "argv",
            "argv_template": ["@@_content"]
        })
        print("Added libpng 1.6.36")

    # 3. expat 2.2.6 (CVE-2018-20843)
    expat_bin = "/tmp/cve_expansion/expat-2.2.6/xmlwf/.libs/xmlwf"
    if os.path.exists(expat_bin):
        manifest.append({
            "bug_id": "cve_2018_20843_expat",
            "target": "expat",
            "ground_truth": "CWE-125",
            "binary_path": expat_bin,
            "input_path": get_corpus_file("libxml2"), # Using libxml2 corpus as fallback
            "source_path": expat_bin,
            "note": "CVE-2018-20843",
            "status": "ready",
            "input_mode": "argv",
            "argv_template": ["@@_content"]
        })
        print("Added expat (CVE-2018-20843)")

    # 4. binutils 2.26 (readelf)
    binutils_bin = "/tmp/cve_expansion/binutils-2.26/binutils/readelf"
    if os.path.exists(binutils_bin):
        manifest.append({
            "bug_id": "binutils_2_26_readelf",
            "target": "binutils",
            "ground_truth": "CWE-122",
            "binary_path": binutils_bin,
            "input_path": get_corpus_file("readelf") if get_corpus_file("readelf") != "/home/zeeshan/tracewise_cvs/inputs/placeholder.bin" else get_corpus_file("libpng"),
            "source_path": binutils_bin,
            "note": "binutils readelf CWE-125/122",
            "status": "ready",
            "input_mode": "argv",
            "argv_template": ["-a", "@@_content"]
        })
        print("Added binutils 2.26")

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest expanded to {len(manifest)} entries.")

if __name__ == "__main__":
    expand_manifest()
