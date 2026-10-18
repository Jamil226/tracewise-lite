import os
import json
import subprocess

WORK_DIR = os.path.expanduser("~/tracewise_cvs")
BUILD_DIR = os.path.join(WORK_DIR, "build")
BINS_DIR = os.path.join(WORK_DIR, "binaries")
INPUTS_DIR = os.path.join(WORK_DIR, "inputs")
MANIFEST = os.path.join(WORK_DIR, "magma_manifest.json")

os.makedirs(BUILD_DIR, exist_ok=True)
os.makedirs(BINS_DIR, exist_ok=True)
os.makedirs(INPUTS_DIR, exist_ok=True)

# Load existing manifest
with open(MANIFEST) as f:
    manifest = json.load(f)

generated_entries = []

templates = [
    # CWE-121 (Stack Overflow)
    ("cwe121", "CWE-121", "cwe121_crash_{i}.bin", b"A"*300, """
#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[]) {{
    char buf[{size}];
    if (argc > 1) strcpy(buf, argv[1]);
    return 0;
}}
"""),
    # CWE-122 (Heap Overflow)
    ("cwe122", "CWE-122", "cwe122_crash_{i}.bin", b"B"*300, """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {{
    char *buf = malloc({size});
    if (argc > 1) strcpy(buf, argv[1]);
    free(buf);
    return 0;
}}
"""),
    # CWE-416 (Use-After-Free)
    ("cwe416", "CWE-416", "cwe416_crash_{i}.bin", b"trigger", """
#include <stdio.h>
#include <stdlib.h>
typedef struct {{ void (*fn)(); }} Obj;
void crash() {{ printf("Crashed\\n"); }}
int main(int argc, char *argv[]) {{
    Obj *o = malloc(sizeof(Obj));
    o->fn = crash;
    free(o);
    if (argc > 1) o->fn();
    return 0;
}}
"""),
    # CWE-476 (NULL Deref)
    ("cwe476", "CWE-476", "cwe476_crash_{i}.bin", b"0", """
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {{
    int *p = NULL;
    if (argc > 1 && atoi(argv[1]) == 0) {{
        printf("%d", *p);
    }}
    return 0;
}}
""")
]

counter = 1
for i in range(25):
    t_idx = i % 4
    prefix, cwe, input_name, payload, src_code = templates[t_idx]
    
    bug_id = f"synthetic_{prefix}_{i}"
    bin_name = f"vuln_{bug_id}"
    bin_path = os.path.join(BINS_DIR, bin_name)
    src_path = os.path.join(BUILD_DIR, f"{bin_name}.c")
    inp_path = os.path.join(INPUTS_DIR, input_name.format(i=i))
    
    # Write source
    with open(src_path, "w") as f:
        f.write(src_code.format(size=64 + (i*8)))
        
    # Write input
    with open(inp_path, "wb") as f:
        f.write(payload)
        
    # Compile
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-g", "-o", bin_path, src_path])
    
    # Add to manifest
    generated_entries.append({
        "bug_id": bug_id,
        "target": bug_id,
        "ground_truth": cwe,
        "binary_path": bin_path,
        "input_path": inp_path,
        "source_path": src_path,
        "note": f"Synthetic {cwe} test case {i}",
        "status": "ready"
    })

# Add generated entries to manifest
manifest.extend(generated_entries)

with open(MANIFEST, "w") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated 25 new binaries. Total binaries in manifest: {len(manifest)}")
