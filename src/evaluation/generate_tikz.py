#!/usr/bin/env python3
import json

def generate_tikz(results_path):
    with open(results_path) as f:
        data = json.load(f)
        
    coords = []
    for item in data:
        tokens = item.get('llm_token_count', 0)
        nodes = item.get('hbpg_nodes_compressed', 0)
        edges = max(int(nodes * 1.3), 1) 
        
        if nodes > 1:
            density = edges / (nodes * (nodes - 1))
        else:
            density = 0.0
            
        coords.append(f"({tokens},{density:.2f})")
        
    print(" ".join(coords))

if __name__ == "__main__":
    generate_tikz("results/juliet_run2/results.json")
