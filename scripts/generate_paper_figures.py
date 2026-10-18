import matplotlib.pyplot as plt
import numpy as np

# Set IEEE Access style parameters
plt.rcParams.update({
    'font.size': 10,
    'font.family': 'serif',
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.autolayout': True
})

def plot_classifier_collapse():
    fig, ax = plt.subplots(figsize=(6, 4))
    
    categories = ['CWE-476\n(Null Ptr)', 'CWE-121\n(Stack Overflow)', 'CWE-190\n(Int Overflow)', 'Other/None']
    counts = [58, 34, 13, 69]
    percentages = [33.3, 19.5, 7.5, 39.7]
    
    colors = ['#d73027', '#fc8d59', '#fee090', '#91bfdb']
    bars = ax.bar(categories, counts, color=colors, edgecolor='black', linewidth=1.2)
    
    # Add percentage labels on top of bars
    for bar, pct in zip(bars, percentages):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{pct}%', ha='center', va='bottom', fontweight='bold')
        
    ax.set_ylabel('Number of Inferences (Total=174)')
    ax.set_title('Classifier Collapse in 1.5B Parameter Model')
    ax.set_ylim(0, 80)
    
    # Add a horizontal line showing uniform distribution
    ax.axhline(y=174/8, color='black', linestyle='--', alpha=0.5, label='Expected Uniform Dist.')
    ax.legend()
    
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'plots')
    os.makedirs(out_dir, exist_ok=True)
    plt.savefig(os.path.join(out_dir, 'classifier_collapse.pdf'), format='pdf', bbox_inches='tight')
    plt.close()

def plot_latency_comparison():
    fig, ax = plt.subplots(figsize=(6, 4))
    
    systems = ['angr (Timeout)', 'TRACEWISE-Lite']
    latency = [60.0, 11.36]
    
    bars = ax.barh(systems, latency, color=['#d73027', '#4575b4'], edgecolor='black', height=0.5)
    
    ax.set_xlabel('End-to-End Triage Latency (seconds)')
    ax.set_title('Latency Comparison (Lower is Better)')
    ax.set_xlim(0, 70)
    
    # Add value labels
    ax.text(latency[0] + 1, 0, '> 60.0s', va='center', fontweight='bold')
    ax.text(latency[1] + 1, 1, '11.36s (mean)', va='center', fontweight='bold')
    
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'plots')
    os.makedirs(out_dir, exist_ok=True)
    plt.savefig(os.path.join(out_dir, 'latency_comparison.pdf'), format='pdf', bbox_inches='tight')
    plt.close()

if __name__ == '__main__':
    plot_classifier_collapse()
    plot_latency_comparison()
    print("Figures generated successfully as PDFs.")
