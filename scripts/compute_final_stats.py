import json
import glob
import numpy as np
from pathlib import Path

def load_results(results_dir_pattern: str) -> list[dict]:
    """Load all results.json files matching a pattern."""
    all_results = []
    for path in glob.glob(results_dir_pattern):
        with open(path) as f:
            all_results.append(json.load(f))
    return all_results

def compute_stats(run_results: list[list[dict]]) -> dict:
    """
    run_results: list of runs, each run is a list of per-binary result dicts.
    Computes mean ± std across runs, per-CWE breakdown.
    """
    # Per-run accuracy
    run_accuracies = []
    for run in run_results:
        valid = [r for r in run if not r.get("error")]
        if not valid:
            continue
        acc = sum(1 for r in valid if r.get("tracewise_correct")) / len(valid)
        run_accuracies.append(acc)

    # Per-CWE accuracy across all runs
    cwe_data = {}
    for run in run_results:
        for r in run:
            if r.get("error"):
                continue
            cwe = r["ground_truth"]
            cwe_data.setdefault(cwe, {"correct": [], "total": 0})
            cwe_data[cwe]["correct"].append(int(bool(r.get("tracewise_correct"))))
            cwe_data[cwe]["total"] += 1

    # Latency stats
    all_latencies = [
        r["pipeline_latency_s"]
        for run in run_results
        for r in run
        if not r.get("error") and r.get("pipeline_latency_s")
    ]

    # Compression stats
    all_compression = [
        r["mean_true_compression"]
        for run in run_results
        for r in run
        if not r.get("error") and r.get("mean_true_compression")
    ]

    # Prediction distribution
    from collections import Counter
    preds = [
        r.get("tracewise_prediction") 
        for run in run_results for r in run 
        if not r.get("error") and r.get("tracewise_prediction")
    ]
    pred_dist = dict(Counter(preds).most_common())

    return {
        "overall": {
            "mean_accuracy":   round(float(np.mean(run_accuracies)), 4) if run_accuracies else 0.0,
            "std_accuracy":    round(float(np.std(run_accuracies)), 4) if run_accuracies else 0.0,
            "n_runs":          len(run_accuracies),
            "n_binaries":      len(run_results[0]) if run_results else 0,
        },
        "latency": {
            "mean_s":          round(float(np.mean(all_latencies)), 2) if all_latencies else 0.0,
            "std_s":           round(float(np.std(all_latencies)), 2) if all_latencies else 0.0,
            "p95_s":           round(float(np.percentile(all_latencies, 95)), 2) if all_latencies else 0.0,
        },
        "compression": {
            "mean_ratio":      round(float(np.mean(all_compression)), 4) if all_compression else 0.0,
            "std_ratio":       round(float(np.std(all_compression)), 4) if all_compression else 0.0,
        },
        "prediction_distribution": pred_dist,
        "per_cwe": {
            cwe: {
                "n":            data["total"],
                "accuracy":     round(float(np.mean(data["correct"])), 3) if data["correct"] else 0.0,
                "std":          round(float(np.std(data["correct"])), 3) if data["correct"] else 0.0,
            }
            for cwe, data in sorted(cwe_data.items())
        }
    }

if __name__ == "__main__":
    import sys

    dataset = sys.argv[1] if len(sys.argv) > 1 else "real_cve"

    # Load the three runs
    run_files = sorted(glob.glob(f"./results/{dataset}_run*/results.json"))

    if not run_files:
        print(f"No result files found matching: ./results/{dataset}_run*/results.json")
        sys.exit(1)

    print(f"Loading {len(run_files)} runs from: {run_files}")

    all_runs = []
    for f in run_files:
        with open(f) as fh:
            all_runs.append(json.load(fh))

    stats = compute_stats(all_runs)

    output_path = f"./results/{dataset}_final_stats.json"
    with open(output_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(json.dumps(stats, indent=2))
    print(f"\nWritten to: {output_path}")
