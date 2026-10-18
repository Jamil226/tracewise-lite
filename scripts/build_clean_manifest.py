import json
import os

REAL_CVES = [
    {
        "bug_id":       "libpng_cve_2018_13785",
        "target":       "libpng",
        "ground_truth": "CWE-190",
        "binary_path":  os.path.expanduser("~/tracewise_real_cves/binaries/libpng_pngtest"),
        "input_path":   os.path.expanduser("~/tracewise_real_cves/inputs/cwe190_libpng.png"),
        "input_mode":   "file_arg",
        "source":       "real_cve",
        "cve_id":       "CVE-2018-13785",
        "status":       "ready",
    },
    {
        "bug_id":       "expat_cve_2018_20843",
        "target":       "expat",
        "ground_truth": "CWE-190",
        "binary_path":  os.path.expanduser("~/tracewise_real_cves/binaries/expat_xmlwf"),
        "input_path":   os.path.expanduser("~/tracewise_real_cves/inputs/cwe190_expat.xml"),
        "input_mode":   "file_arg",
        "source":       "real_cve",
        "cve_id":       "CVE-2018-20843",
        "status":       "ready",
    },
    {
        "bug_id":       "binutils_cve_2016_4487",
        "target":       "binutils",
        "ground_truth": "CWE-122",
        "binary_path":  os.path.expanduser("~/tracewise_real_cves/binaries/binutils_readelf"),
        "input_path":   os.path.expanduser("~/tracewise_real_cves/inputs/cwe122_elf.elf"),
        "input_mode":   "argv",
        "argv_template": ["-a", "@@"],
        "source":       "real_cve",
        "cve_id":       "CVE-2016-4487",
        "status":       "ready",
    },
]

output = os.path.expanduser("~/tracewise_cvs/manifest_real_cves_only.json")
with open(output, "w") as f:
    json.dump(REAL_CVES, f, indent=2)

print(f"Clean manifest written: {output}")
print(f"Entries: {len(REAL_CVES)}")
print("Sources:", set(e['source'] for e in REAL_CVES))
