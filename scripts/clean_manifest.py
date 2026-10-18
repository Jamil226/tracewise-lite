import json
import os

manifest_path = os.path.expanduser('~/tracewise_cvs/magma_manifest.json')
clean_path = os.path.expanduser('~/tracewise_cvs/magma_manifest_clean.json')

with open(manifest_path) as f:
    manifest = json.load(f)

# Keep only the original 7 binaries (which start with 'custom_cwe' or 'cve_')
real_entries = [e for e in manifest if not e.get('bug_id', '').startswith('synthetic_')]

with open(clean_path, 'w') as f:
    json.dump(real_entries, f, indent=2)

print(f"Cleaned manifest. Kept {len(real_entries)} real/custom entries, removed {len(manifest) - len(real_entries)} synthetic entries.")
