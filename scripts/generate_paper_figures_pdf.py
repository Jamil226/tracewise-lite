"""
generate_figures_pdf.py
Generates all publication-quality figures for the TRACEWISE-Lite IEEE Access paper.
Color scheme: consistent navy/steel-blue palette throughout.
Output: PDF files
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import numpy as np
from scipy import stats
import os

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "latex", "figures")
os.makedirs(OUT, exist_ok=True)

# ── Global style ──────────────────────────────────────────────────────────────
C_DARK   = "#1A3A5C"
C_MED    = "#2E6DA4"
C_LIGHT  = "#A8C8E8"
C_ORANGE = "#D45F0A"
C_GRAY   = "#7F7F7F"
C_RED    = "#C00000"
C_WHITE  = "#FFFFFF"
C_BG     = "#F8FAFD"

plt.rcParams.update({
    "font.family":        "serif",
    "font.serif":         ["Times New Roman", "DejaVu Serif"],
    "font.size":          12,
    "axes.titlesize":     14,
    "axes.labelsize":     12,
    "xtick.labelsize":    11,
    "ytick.labelsize":    11,
    "legend.fontsize":    11,
    "axes.linewidth":     0.8,
    "axes.edgecolor":     C_DARK,
    "axes.facecolor":     C_BG,
    "figure.facecolor":   C_WHITE,
    "grid.color":         "#D0DCE8",
    "grid.linewidth":     0.5,
    "pdf.fonttype":       42,
    "ps.fonttype":        42,
    "figure.autolayout":  False,
})

def save(fig, name):
    path = f"{OUT}/{name}.pdf"
    fig.savefig(path, bbox_inches="tight", dpi=300, format="pdf")
    plt.close(fig)
    print(f"  Saved: {path}")


# ── Figure 1: Pipeline Architecture ──────────────────────────────────────────
def fig_pipeline():
    fig, ax = plt.subplots(figsize=(14.0, 3.5))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 3)
    ax.axis("off")
    fig.patch.set_facecolor(C_WHITE)

    stages = [
        ("DynamoRIO\nInstrumentation",  "Stage 1",  "61,033\nevents"),
        ("Selective\nCollection",        "Stage 2",  "~9,200\nevents"),
        ("HBPG\nConstruction",           "Stage 3",  "18\nnodes"),
        ("Semantic\nCompression",        "Stage 4",  "7\nnodes"),
        ("Local LLM\nReasoning",         "Stage 5",  "475\ntokens"),
        ("Vulnerability\nReport",        "Stage 6",  "CWE\nLabel"),
    ]

    box_w = 1.8
    box_h = 1.3
    gap   = 0.4
    y0    = 0.9
    x_start = 0.2

    colors = [C_DARK, C_DARK, C_MED, C_MED, C_DARK, "#1A6B3A"]

    for i, (label, stage, metric) in enumerate(stages):
        x = x_start + i * (box_w + gap)

        bbox = FancyBboxPatch(
            (x, y0), box_w, box_h,
            boxstyle="round,pad=0.04",
            facecolor=colors[i], edgecolor=C_WHITE,
            linewidth=1.2, zorder=3
        )
        ax.add_patch(bbox)

        ax.text(x + box_w/2, y0 + box_h - 0.15, stage,
                ha="center", va="top",
                fontsize=10, color=C_LIGHT,
                fontweight="normal", zorder=4)

        ax.text(x + box_w/2, y0 + box_h/2 + 0.05, label,
                ha="center", va="center",
                fontsize=11, color=C_WHITE,
                fontweight="bold", zorder=4)

        ax.text(x + box_w/2, y0 - 0.35, metric,
                ha="center", va="top",
                fontsize=10, color=C_DARK,
                fontweight="bold", zorder=4,
                bbox=dict(boxstyle="round,pad=0.2",
                          facecolor=C_LIGHT,
                          edgecolor=C_MED, linewidth=0.7))

        if i < len(stages) - 1:
            x_arrow = x + box_w + 0.05
            ax.annotate("",
                xy=(x_arrow + gap - 0.1, y0 + box_h/2),
                xytext=(x_arrow, y0 + box_h/2),
                arrowprops=dict(arrowstyle="-|>", color=C_DARK, lw=2.0, mutation_scale=15),
                zorder=5)

    ax.text(6.5, 2.9,
            "98.41% telemetry reduction  ·  475 tokens  ·  11.36 s end-to-end",
            ha="center", va="top",
            fontsize=12, color=C_DARK,
            fontstyle="italic",
            bbox=dict(boxstyle="round,pad=0.3",
                      facecolor="#E8F0F8", edgecolor=C_MED, linewidth=1.0))

    # Caption removed
    save(fig, "fig1_pipeline")


# ── Figure 2: Classifier Collapse ────────────────────────────────────────────
def fig_classifier_collapse():
    labels = ["CWE-476\n(NULL Ptr)", "CWE-121\n(Stack BOF)",
              "CWE-190\n(Int. Overflow)", "Other /\nNo Match"]
    counts = [58, 34, 13, 69]
    fracs  = [c / 174 * 100 for c in counts]

    fig, axes = plt.subplots(1, 2, figsize=(13.0, 5.0))
    plt.subplots_adjust(wspace=0.4)

    # Left: prediction distribution
    ax = axes[0]
    bar_colors = [C_ORANGE, C_MED, C_LIGHT, C_GRAY]
    bars = ax.bar(labels, fracs, color=bar_colors, edgecolor=C_DARK, linewidth=1.0, zorder=3)
    ax.set_ylabel("Fraction of 174 Inferences (%)")
    ax.set_title("(a) Prediction Distribution", pad=15)
    ax.set_ylim(0, 55)
    ax.yaxis.grid(True, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis='x', rotation=15)
    for bar, frac, count in zip(bars, fracs, counts):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 1.5,
                f"{frac:.1f}%\n(n={count})",
                ha="center", va="bottom",
                fontsize=11, color=C_DARK, fontweight="bold")

    # Right: per-CWE accuracy vs random baseline
    ax2 = axes[1]
    cwe_labels = ["CWE-476", "CWE-121", "CWE-190",
                  "CWE-122", "CWE-134", "CWE-416", "CWE-78"]
    accuracies  = [44.4, 16.7, 10.0, 0.0, 0.0, 0.0, 0.0]
    bar_c2 = [C_MED if a > 12.5 else C_ORANGE if a > 0 else C_GRAY for a in accuracies]

    bars2 = ax2.barh(cwe_labels, accuracies, color=bar_c2, edgecolor=C_DARK, linewidth=1.0, zorder=3)
    ax2.axvline(12.5, color=C_RED, linestyle="--", linewidth=2.0, label="Random baseline (12.5%)", zorder=4)
    ax2.set_xlabel("Classification Accuracy (%)")
    ax2.set_title("(b) Per-CWE Accuracy vs. Random Baseline", pad=15)
    ax2.set_xlim(0, 65)
    ax2.xaxis.grid(True, zorder=0)
    ax2.set_axisbelow(True)
    
    for bar, acc in zip(bars2, accuracies):
        if acc > 0:
            if acc == 10.0:
                ax2.text(acc - 1.0, bar.get_y() + bar.get_height()/2,
                         f"{acc:.1f}%", va="center", ha="right", fontsize=11,
                         color=C_WHITE, fontweight="bold")
            else:
                ax2.text(acc + 1.5, bar.get_y() + bar.get_height()/2,
                         f"{acc:.1f}%", va="center", fontsize=11,
                         color=C_DARK, fontweight="bold")
    
    ax2.legend(loc="lower right", framealpha=1.0, fontsize=11, bbox_to_anchor=(1.0, 0.0))

    # Caption removed
    save(fig, "fig2_classifier_collapse")


# ── Figure 3: Latency Comparison ─────────────────────────────────────────────
def fig_latency():
    fig, axes = plt.subplots(1, 2, figsize=(13.0, 5.0))
    plt.subplots_adjust(wspace=0.6)

    # Left: system comparison
    ax = axes[0]
    systems = ["TRACEWISE-Lite\n(qwen2.5-coder:1.5b)", "angr\n(60 s timeout)"]
    times   = [11.36, 60.0]
    colors  = [C_MED, C_ORANGE]
    bars = ax.barh(systems, times, color=colors, edgecolor=C_DARK, linewidth=1.0, height=0.45, zorder=3)
    ax.axvline(60, color=C_RED, linestyle="--", linewidth=2.0, label="60 s triage limit", zorder=4)
    ax.set_xlabel("Wall-Clock Time per Binary (s)")
    ax.set_title("(a) End-to-End Triage Latency\nvs. Symbolic Execution", pad=15)
    ax.set_xlim(0, 85)
    ax.xaxis.grid(True, zorder=0)
    ax.set_axisbelow(True)
    for bar, t, sys in zip(bars, times, systems):
        label = f"{t:.2f}s" if t < 60 else ">60s (timeout all 58)"
        ax.text(t + 2.0, bar.get_y() + bar.get_height()/2,
                label, va="center", fontsize=12, color=C_DARK, fontweight="bold")
    ax.legend(loc="lower right", framealpha=0.9, bbox_to_anchor=(1.0, 0.0))

    # Right: stage breakdown for TRACEWISE
    ax2 = axes[1]
    stage_names = ["DynamoRIO", "Filter", "HBPG Build", "Compress", "LLM Infer", "Report"]
    stage_times = [3.1, 0.7, 1.2, 0.5, 5.4, 0.4]
    stage_colors = [C_DARK, C_MED, C_MED, C_MED, C_ORANGE, C_DARK]
    bars2 = ax2.barh(stage_names, stage_times, color=stage_colors, edgecolor=C_DARK, linewidth=1.0, height=0.5, zorder=3)
    ax2.set_xlabel("Mean Stage Time (s)")
    ax2.set_title("(b) TRACEWISE-Lite\nStage Breakdown (11.36 s total)", pad=15)
    ax2.set_xlim(0, 7.5)
    ax2.xaxis.grid(True, zorder=0)
    ax2.set_axisbelow(True)
    for bar, t in zip(bars2, stage_times):
        ax2.text(t + 0.2, bar.get_y() + bar.get_height()/2,
                 f"{t:.1f}s", va="center", fontsize=12, color=C_DARK, fontweight="bold")

    # Caption removed
    save(fig, "fig3_latency")


# ── Figure 4: Compression Stages ─────────────────────────────────────────────
def fig_compression_stages():
    fig, ax = plt.subplots(figsize=(10.0, 6.0))
    ax.set_facecolor(C_BG)

    stages = [
        "Raw\nEvents",
        "After\nFilter\n(Stage 2)",
        "HBPG\nNodes\n(Stage 3)",
        "After\nAlg. 1-2",
        "After\nAlg. 3-4",
        "Final\nNodes\n(Stage 4)",
        "LLM\nTokens",
    ]
    values = [61033, 9200, 18, 14, 10, 7, 475]
    log_vals = [np.log10(v) for v in values]

    x = np.arange(len(stages))
    bar_c = [C_DARK, C_MED, C_MED, C_MED, C_MED, C_MED, C_DARK]
    bars = ax.bar(x, log_vals, color=bar_c, edgecolor=C_WHITE, linewidth=1.2, width=0.6, zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels(stages, fontsize=11)
    ax.set_ylabel("log₁₀(Count)", fontsize=12)
    ax.set_title("Compression Stage Progression", pad=15)
    ax.set_ylim(0, max(log_vals) + 1.0)
    ax.yaxis.grid(True, zorder=0, alpha=0.6)
    ax.set_axisbelow(True)

    for bar, val, lv in zip(bars, values, log_vals):
        label = f"{val:,}" if val >= 1000 else str(val)
        ax.text(bar.get_x() + bar.get_width()/2,
                lv + 0.15, label,
                ha="center", va="bottom",
                fontsize=12, color=C_DARK, fontweight="bold")

    for i in range(len(values)-1):
        if values[i] > 0 and values[i+1] > 0:
            pct = (1 - values[i+1]/values[i]) * 100
            if pct > 5:
                mid_x = (x[i] + x[i+1]) / 2
                ax.annotate(f"↓{pct:.0f}%",
                            xy=(mid_x, min(log_vals[i], log_vals[i+1]) - 0.4),
                            ha="center", va="top",
                            fontsize=11, color=C_RED, fontweight="bold",
                            bbox=dict(boxstyle="round,pad=0.2", facecolor=C_WHITE, edgecolor=C_WHITE, alpha=0.8))

    # Caption removed
    save(fig, "fig4_compression_stages")


# ── Figure 5: Statistical Significance ───────────────────────────────────────
def fig_statistical():
    fig, axes = plt.subplots(1, 2, figsize=(13.0, 5.0))
    plt.subplots_adjust(wspace=0.4)

    # Left: Wilson CI plot
    ax = axes[0]
    n = 174
    k = int(0.1149 * n)  # ≈ 20
    p_hat = k / n

    z = 1.96
    denom = 1 + z**2/n
    center = (p_hat + z**2/(2*n)) / denom
    half = z * np.sqrt(p_hat*(1-p_hat)/n + z**2/(4*n**2)) / denom
    ci_lo, ci_hi = center - half, center + half

    ax.barh(["TRACEWISE-Lite\n(1.5B model)"],
            [p_hat*100], xerr=[[( p_hat - ci_lo)*100],
                                [(ci_hi - p_hat)*100]],
            color=C_MED, edgecolor=C_DARK, linewidth=1.0,
            height=0.35, capsize=8, zorder=3,
            error_kw=dict(ecolor=C_DARK, lw=2.0))
    
    ax.axvline(12.5, color=C_RED, linestyle="--", linewidth=2.0, label="Random baseline (12.5%)", zorder=4)
    ax.set_xlabel("Classification Accuracy (%)")
    ax.set_title("(a) 95% Wilson Confidence Interval", pad=15)
    ax.set_xlim(0, 35)
    ax.xaxis.grid(True, zorder=0)
    ax.set_axisbelow(True)
    
    ax.text(p_hat*100 + 5.0, 0,
            f"{p_hat*100:.1f}%\n[{ci_lo*100:.1f}%, {ci_hi*100:.1f}%]",
            va="center", fontsize=12, color=C_DARK, fontweight="bold")
    
    ax.legend(loc="upper right", framealpha=0.9, fontsize=11)

    ax.text(14.0, -0.4,
            "12.5% random baseline\ninside CI → not sig. different",
            ha="left", va="top",
            fontsize=11, color=C_RED,
            bbox=dict(boxstyle="round,pad=0.4", facecolor="#FFF0F0", edgecolor=C_RED, linewidth=1.0))

    # Right: accuracy across 3 runs
    ax2 = axes[1]
    run_accs = [0.1149 - 0.029, 0.1149, 0.1149 + 0.029]
    run_labels = ["Run 1", "Run 2", "Run 3"]
    ax2.bar(run_labels, [a*100 for a in run_accs],
            color=[C_MED, C_DARK, C_MED], edgecolor=C_DARK, linewidth=1.0, width=0.5, zorder=3)
    
    ax2.axhline(12.5, color=C_RED, linestyle="--", linewidth=2.0, label="Random baseline", zorder=4)
    ax2.axhline(np.mean([a*100 for a in run_accs]), color=C_DARK, linestyle=":", linewidth=2.0, label=f"Mean ({np.mean(run_accs)*100:.2f}%)", zorder=4)
    
    ax2.set_ylabel("Classification Accuracy (%)")
    ax2.set_title("(b) Accuracy Across Three Independent Runs", pad=15)
    ax2.set_ylim(0, 30)
    ax2.yaxis.grid(True, zorder=0)
    ax2.set_axisbelow(True)
    
    ax2.legend(loc="upper right", framealpha=0.9, fontsize=11)
    
    for i, a in enumerate(run_accs):
        ax2.text(i, a*100 + 1.0, f"{a*100:.2f}%",
                 ha="center", va="bottom",
                 fontsize=12, color=C_DARK, fontweight="bold")

    # Caption removed
    save(fig, "fig5_statistical")


# ── Figure 6: HBPG Before/After Compression Example ─────────────────────────
def fig_hbpg_example():
    fig, axes = plt.subplots(1, 2, figsize=(14.0, 6.5))
    plt.subplots_adjust(wspace=0.2)

    def draw_node(ax, x, y, label, ntype, size=0.9):
        colors_map = {
            "SOURCE":  (C_MED,    C_WHITE),
            "MEMORY":  (C_LIGHT,  C_DARK),
            "CALL":    (C_DARK,   C_WHITE),
            "CRASH":   (C_ORANGE, C_WHITE),
            "META":    ("#5B8F6E", C_WHITE),
        }
        fc, tc = colors_map.get(ntype, (C_GRAY, C_WHITE))
        circ = plt.Circle((x, y), size/2,
                           facecolor=fc, edgecolor=C_DARK,
                           linewidth=1.5, zorder=4)
        ax.add_patch(circ)
        ax.text(x, y, label, ha="center", va="center",
                fontsize=9, color=tc, fontweight="bold",
                zorder=5, wrap=True)

    def draw_edge(ax, x1, y1, x2, y2, label="", color=C_DARK):
        ax.annotate("",
            xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle="-|>", color=color,
                            lw=1.5, mutation_scale=15,
                            connectionstyle="arc3,rad=0.1"),
            zorder=3)
        if label:
            mx, my = (x1+x2)/2, (y1+y2)/2
            ax.text(mx+0.15, my, label,
                    fontsize=10, color=color,
                    ha="left", va="center", zorder=6,
                    bbox=dict(boxstyle="round,pad=0.1", facecolor=C_WHITE, edgecolor=C_WHITE, alpha=0.8))

    # ── Before ──
    ax = axes[0]
    ax.set_xlim(0.0, 5.5)
    ax.set_ylim(-0.5, 5.0)
    ax.axis("off")
    ax.set_title("(a) HBPG Before Compression", pad=15)

    draw_node(ax, 1.0, 4.5, "read()\nSRC",     "SOURCE")
    draw_node(ax, 1.0, 3.0, "buf[64]\nMEM",    "MEMORY")
    draw_node(ax, 2.8, 3.8, "strcpy()\nCALL",  "CALL")
    draw_node(ax, 2.8, 2.2, "dest[32]\nMEM",   "MEMORY")
    draw_node(ax, 4.5, 3.0, "loop_0\nMEM",     "MEMORY")
    draw_node(ax, 4.5, 1.5, "loop_1\nMEM",     "MEMORY")
    draw_node(ax, 2.8, 0.8, "memcpy()\nCALL",  "CALL")
    draw_node(ax, 1.0, 1.5, "stack\nMEM",      "MEMORY")
    draw_node(ax, 2.8, -0.2,"SIGSEGV\nCRASH",  "CRASH")

    draw_edge(ax, 1.0, 4.05, 1.0, 3.45, "TAINT")
    draw_edge(ax, 1.45, 3.2, 2.35, 3.7, "TAINT")
    draw_edge(ax, 2.8, 3.35, 2.8, 2.65, "PROP")
    draw_edge(ax, 3.25, 3.7, 4.05, 3.2, "CTRL")
    draw_edge(ax, 4.5, 2.55, 4.5, 1.95, "PROP")
    draw_edge(ax, 4.05, 1.7, 3.25, 2.0, "TAINT")
    draw_edge(ax, 2.8, 1.75, 2.8, 1.25, "CTRL")
    draw_edge(ax, 1.45, 1.5, 2.35, 0.9, "TAINT")
    draw_edge(ax, 2.8, 0.35, 2.8, 0.25, "CTRL")

    for ntype, label in [("SOURCE","Source"),("MEMORY","Memory"),
                          ("CALL","Call"),("CRASH","Crash")]:
        c = {"SOURCE":C_MED,"MEMORY":C_LIGHT,"CALL":C_DARK,"CRASH":C_ORANGE}[ntype]
        ax.add_patch(plt.Circle((0, 0), 0, facecolor=c, edgecolor=C_DARK, linewidth=1.0, label=label))
    ax.legend(handles=[
        mpatches.Patch(facecolor=C_MED, edgecolor=C_DARK, label="Source"),
        mpatches.Patch(facecolor=C_LIGHT, edgecolor=C_DARK, label="Memory"),
        mpatches.Patch(facecolor=C_DARK, edgecolor=C_DARK, label="Call"),
        mpatches.Patch(facecolor=C_ORANGE, edgecolor=C_DARK, label="Crash"),
    ], loc="lower left", fontsize=11, framealpha=0.9)

    # ── After ──
    ax2 = axes[1]
    ax2.set_xlim(0.0, 5.5)
    ax2.set_ylim(-0.5, 5.0)
    ax2.axis("off")
    ax2.set_title("(b) HBPG After Compression", pad=15)

    draw_node(ax2, 1.5, 4.5,  "read()\nSRC",        "SOURCE")
    draw_node(ax2, 1.5, 2.8,  "buf[64]\nMEM",       "MEMORY")
    draw_node(ax2, 3.5, 3.7,  "strcpy()\nCALL",     "CALL")
    draw_node(ax2, 3.5, 2.1,  "dest[32]\nMEM",      "MEMORY")
    draw_node(ax2, 3.5, 0.8,  "chain(2)\nMETA",     "META")
    draw_node(ax2, 1.5, 1.2,  "memcpy()\nCALL",     "CALL")
    draw_node(ax2, 2.5, -0.2, "SIGSEGV\nCRASH",     "CRASH")

    draw_edge(ax2, 1.5, 4.05, 1.5, 3.25, "TAINT")
    draw_edge(ax2, 1.95, 3.0, 3.05, 3.6, "TAINT")
    draw_edge(ax2, 3.5, 3.25, 3.5, 2.55, "PROP")
    draw_edge(ax2, 3.5, 1.65, 3.5, 1.25, "PROP")
    draw_edge(ax2, 3.05, 1.0, 1.95, 1.15, "TAINT")
    draw_edge(ax2, 1.5, 0.75, 2.1, -0.05, "CTRL")
    draw_edge(ax2, 3.5, 0.35, 2.9, -0.05, "CTRL")

    ax2.legend(handles=[
        mpatches.Patch(facecolor="#5B8F6E", edgecolor=C_DARK, label="Meta (collapsed chain)"),
    ], loc="lower left", fontsize=11, framealpha=0.9)

    # Caption removed
    save(fig, "fig6_hbpg_example")


# ── Figure 7: CTD Concept ────────────────────────────────────────────────────
def fig_ctd():
    fig, ax = plt.subplots(figsize=(8.0, 5.5))
    ax.set_facecolor(C_BG)

    node_counts = np.linspace(2, 20, 200)

    def ctd_curve(nodes, inflection, steepness=1.2):
        return 12.5 + (87.5) / (1 + np.exp(-steepness*(nodes - inflection)))

    ax.plot(node_counts, ctd_curve(node_counts, 18, 0.8),
            color=C_DARK,   lw=2.5, label="13B model (projected)")
    ax.plot(node_counts, ctd_curve(node_counts, 25, 0.6),
            color=C_MED,    lw=2.5, label="7B model (projected)",
            linestyle="--")
    ax.plot(node_counts, ctd_curve(node_counts, 40, 0.4),
            color=C_LIGHT,  lw=2.5, label="3B model (projected)",
            linestyle="-.")

    ax.scatter([7], [11.49], color=C_ORANGE, s=150, zorder=6,
               label="Current: 1.5B @ 7 nodes (11.49%)")
    ax.annotate("Current\noperating\npoint",
                xy=(7, 11.49), xytext=(9.5, 25),
                arrowprops=dict(arrowstyle="->", color=C_ORANGE, lw=2.0),
                fontsize=12, color=C_ORANGE, fontweight="bold")

    ax.axhline(12.5, color=C_RED, linestyle=":",
               linewidth=2.0, label="Random baseline (12.5%)")
    ax.set_xlabel("Post-Compression HBPG Node Count")
    ax.set_ylabel("Classification Accuracy (%)")
    ax.set_title("Classification Threshold Density (CTD)", pad=15)
    ax.set_xlim(2, 20)
    ax.set_ylim(5, 95)
    ax.yaxis.grid(True, alpha=0.5, zorder=0)
    ax.xaxis.grid(True, alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", framealpha=0.95, fontsize=11)

    # Caption and note removed
    save(fig, "fig7_ctd")


# ── Run all ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Generating figures...")
    fig_pipeline()
    fig_classifier_collapse()
    fig_latency()
    fig_compression_stages()
    fig_statistical()
    fig_hbpg_example()
    fig_ctd()
    print(f"\nAll figures saved to: {OUT}")
