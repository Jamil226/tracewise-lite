import sys
import json
import os

def diagnose(log_path: str):
    with open(log_path) as f:
        data = json.load(f)
        
    raw_events = data.get("dr_instructions", 0) + data.get("real_syscalls", 0)
    filtered = data.get("events", [])
    
    print(f"Raw events:           {raw_events:,}")
    print(f"After Stage 2 filter: {len(filtered):,}")
    
    if raw_events > 0:
        print(f"Filter rate:          {1 - len(filtered)/raw_events:.4%}")
    print()
    
    # Show what categories survived
    categories = {}
    for event in filtered:
        cat = event.get('event_type', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    print("Surviving event types:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat:20s}: {count:,}")
    
    print()
    
    # Show first 20 surviving events — are they meaningful?
    print("First 20 surviving events:")
    for e in filtered[:20]:
        print(f"  {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        diagnose(sys.argv[1])
    else:
        print("Usage: python3 diagnose_stage2.py <path_to_log>")
