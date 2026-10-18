from pathlib import Path
import json, glob

REPO_ROOT = Path(__file__).resolve().parent.parent

print('='*70)
print('FULL AUDIT: Per-binary predictions across all 3 runs')
print('='*70)

for dataset in ['real_cve', 'juliet']:
    runs = sorted(glob.glob(
        str(REPO_ROOT / 'results' / f'{dataset}_run*' / 'results.json')
    ))
    if not runs:
        print(f'No runs found for {dataset}')
        continue

    print(f'\n### {dataset.upper()} ({len(runs)} runs) ###\n')

    by_bug = {}
    for run_path in runs:
        with open(run_path) as f:
            data = json.load(f)
        for entry in data:
            bid = entry.get('bug_id', '?')
            if bid not in by_bug:
                by_bug[bid] = {
                    'gt': entry.get('ground_truth'),
                    'preds': [], 'correct': [],
                    'parse_status': [], 'asan': [], 'error': []
                }
            by_bug[bid]['preds'].append(entry.get('tracewise_prediction'))
            by_bug[bid]['correct'].append(entry.get('tracewise_correct'))
            by_bug[bid]['parse_status'].append(entry.get('parse_status'))
            by_bug[bid]['asan'].append(entry.get('asan_prediction'))
            by_bug[bid]['error'].append(entry.get('error'))

    total, correct_count, errors, parse_fails = 0, 0, 0, 0
    col_bug   = 'Bug ID'
    col_gt    = 'GT'
    col_preds = 'Preds (3 runs)'
    col_cor   = 'Correct'
    col_parse = 'ParseStatus'
    col_asan  = 'ASan'
    header = f"{col_bug:<45} {col_gt:<10} {col_preds:<40} {col_cor:<20} {col_parse:<35} {col_asan}"
    print(header)
    print('-' * len(header))

    for bid, d in by_bug.items():
        gt     = d['gt'] or 'N/A'
        preds  = ', '.join(str(p) for p in d['preds'])
        cors   = ', '.join(str(c) for c in d['correct'])
        parse  = ', '.join(str(p) for p in d['parse_status'])
        asan   = ', '.join(str(a) for a in set(d['asan']) if a)
        err    = any(e for e in d['error'] if e)

        n_correct = sum(1 for c in d['correct'] if c is True)
        n_total   = sum(1 for c in d['correct'] if c is not None)
        total         += n_total
        correct_count += n_correct
        if err: errors += 1
        if 'total_failure' in parse or 'None' in parse:
            parse_fails += 1

        print(f"{bid:<45} {gt:<10} {preds:<40} {cors:<20} {parse:<35} {asan}")

    print()
    print(f"Summary: {correct_count}/{total} correct  |  errors: {errors}  |  parse_fails: {parse_fails}")
    if total > 0:
        acc = correct_count / total
        print(f"Accuracy: {acc:.4f}  ({acc*100:.1f}%)")
    print(f"Random baseline (8 classes): 0.1250  (12.5%)")
    print(f"Above random: {'YES' if total > 0 and correct_count/total > 0.125 else 'NO'}")
