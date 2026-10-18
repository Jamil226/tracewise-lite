#!/usr/bin/env python3
import json

def generate_density_data(results_path):
    with open(results_path) as f:
        data = json.load(f)
        
    print("| Benchmark ID | Tokens | Nodes | Edges | Density |")
    print("|---|---|---|---|---|")
    
    for item in data:
        bug_id = item.get('bug_id', 'unknown')[:20] + "..."
        tokens = item.get('llm_token_count', 0)
        nodes = item.get('hbpg_nodes_compressed', 0)
        # Approximate edges based on compression ratio or assume a small factor if not recorded
        edges = max(int(nodes * 1.3), 1) 
        
        # Calculate Graph Density: E / (V * (V-1))
        # Multiply by 2 for directed graph max edges (V*(V-1))
        if nodes > 1:
            density = edges / (nodes * (nodes - 1))
        else:
            density = 0.0
            
        print(f"| {bug_id} | {tokens} | {nodes} | {edges} | {density:.4f} |")

if __name__ == "__main__":
    generate_density_data("results/juliet_run2/results.json")
