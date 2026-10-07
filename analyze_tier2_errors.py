"""
analyze_tier2_errors.py
=======================
Step 1 -- Data ceiling analysis for the Tier 2 model.
  A. Dataset-wide duplicate / label-conflict analysis -> Bayes-style accuracy ceiling
  B. Top-20 False Positives / Top-20 False Negatives on the (Tier-1-identical) val set
  C. For each error: does an IDENTICAL sequence exist with the opposite label?
Output is printed and saved to tier2_error_analysis.txt
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
import os, json, io
import numpy as np
import torch
from collections import Counter, defaultdict

import train_tier2 as t2

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "tier2_error_analysis.txt")
lines = []


def P(s=""):
    print(s)
    lines.append(s)


def key(seq):          # padded-sequence identity (trailing zeros removed)
    s = list(seq)
    while s and s[-1] == 0:
        s.pop()
    return tuple(s)


os.chdir(BASE)
raw = json.load(open(t2.DATASET_PATH, encoding="utf-8"))
seqs = [key(r["event_sequence"][:t2.SEQ_LENGTH]) for r in raw]
labels = [int(r["label"]) for r in raw]
N = len(raw)

# ───────────── A. dataset-wide ceiling ─────────────
P("=" * 78)
P(" A. DATASET-WIDE DUPLICATE / CONFLICT ANALYSIS")
P("=" * 78)
groups = defaultdict(lambda: [0, 0])          # seq -> [benign, malware]
for s, l in zip(seqs, labels):
    groups[s][l] += 1
n_unique = len(groups)
conflict = {s: c for s, c in groups.items() if c[0] > 0 and c[1] > 0}
n_conf_samples = sum(sum(c) for c in conflict.values())
ceiling = sum(max(c) for c in groups.values()) / N
dup_samples = sum(sum(c) for c in groups.values() if sum(c) > 1)
P(f"  Samples                         : {N}")
P(f"  Unique sequences                : {n_unique}  ({n_unique / N * 100:.1f}%)")
P(f"  Samples sharing a sequence      : {dup_samples}  ({dup_samples / N * 100:.1f}%)")
P(f"  Sequences with BOTH labels      : {len(conflict)}")
P(f"  Samples inside conflict groups  : {n_conf_samples}  ({n_conf_samples / N * 100:.1f}%)")
P(f"  >>> Accuracy CEILING for ANY model that sees only the ID sequence: "
  f"{ceiling * 100:.2f}%")
P("      (= predict the majority label of each identical sequence; no model,")
P("       however complex, can beat this on data it has this label noise on)")
P("  Top 10 most ambiguous sequences (conflicting labels):")
for s, c in sorted(conflict.items(), key=lambda kv: -sum(kv[1]))[:10]:
    txt = " ".join(map(str, s[:14])) + (" ..." if len(s) > 14 else "")
    P(f"    benign={c[0]:>3} malware={c[1]:>3} len={len(s):>2} | {txt}")

# ───────────── B/C. validation errors ─────────────
tr_idx, va_idx = t2.stratified_split_indices([float(l) for l in labels])
train_keys = defaultdict(lambda: [0, 0])
for i in tr_idx:
    train_keys[seqs[i]][labels[i]] += 1

X_val = torch.tensor([list(seqs[i]) + [0] * (t2.SEQ_LENGTH - len(seqs[i])) for i in va_idx])
y_val = np.array([labels[i] for i in va_idx])
model = t2.Tier2HybridCloudAnalyzer().to(t2.DEVICE)
model.load_state_dict(torch.load(t2.OUTPUT_PT, map_location=t2.DEVICE))
probs, attn = t2.predict_all(model, X_val)

THR = 0.5
P()
P("=" * 78)
P(f" B. VALIDATION ERRORS @ threshold {THR}  (Tier-2 model, {len(y_val)} val samples)")
P("=" * 78)
fp = np.where((y_val == 0) & (probs >= THR))[0]
fn = np.where((y_val == 1) & (probs < THR))[0]
P(f"  False Positives: {len(fp)}   False Negatives: {len(fn)}")


def describe(i):
    s = seqs[va_idx[i]]
    tc = train_keys.get(s)
    opp = None
    if tc is not None:
        opp = tc[1 - y_val[i]]
    uniq = sorted(set(s))
    txt = " ".join(map(str, s[:22])) + (" ..." if len(s) > 22 else "")
    return s, opp, uniq, txt


def report(title, idxs, order_key):
    P()
    P(f"  --- {title} (top {min(20, len(idxs))} of {len(idxs)}) ---")
    P(f"  {'#':>2} {'p':>6} {'len':>3} {'uniq':>4} {'opp-label twins in train':>24} | sequence")
    n_twin = 0
    shown = sorted(idxs, key=order_key)[:20]
    for r, i in enumerate(shown, 1):
        s, opp, uniq, txt = describe(i)
        twin = "-" if opp is None else str(opp)
        if opp:
            n_twin += 1
        P(f"  {r:>2} {probs[i]:>6.3f} {len(s):>3} {len(uniq):>4} {twin:>24} | {txt}")
    return n_twin


tw_fp = report("FALSE POSITIVES (benign flagged malware; most confident first)",
               fp, lambda i: -probs[i])
tw_fn = report("FALSE NEGATIVES (malware missed; most confident-benign first)",
               fn, lambda i: probs[i])

# ───────────── C. summary stats over ALL errors ─────────────
P()
P("=" * 78)
P(" C. ARE THE ERRORS DISTINGUISHABLE? (all errors, not just top 20)")
P("=" * 78)


def stats(idxs, name):
    if len(idxs) == 0:
        P(f"  {name}: none")
        return
    twins = sum(1 for i in idxs if (train_keys.get(seqs[va_idx[i]]) or [0, 0])[1 - y_val[i]] > 0)
    seen = sum(1 for i in idxs if seqs[va_idx[i]] in train_keys)
    lens = [len(seqs[va_idx[i]]) for i in idxs]
    uniq = [len(set(seqs[va_idx[i]])) for i in idxs]
    P(f"  {name}: n={len(idxs)} | seq also in train: {seen} ({seen / len(idxs) * 100:.0f}%) | "
      f"with an OPPOSITE-label identical twin in train: {twins} ({twins / len(idxs) * 100:.0f}%) | "
      f"median len={int(np.median(lens))} | median #unique IDs={int(np.median(uniq))}")


stats(fp, "False Positives")
stats(fn, "False Negatives")
ok = np.where(((y_val == 1) & (probs >= THR)) | ((y_val == 0) & (probs < THR)))[0]
stats(ok, "Correct (for contrast)")

# val samples whose exact sequence is label-ambiguous in train
amb = [i for i in range(len(y_val))
       if (train_keys.get(seqs[va_idx[i]]) or [0, 0])[0] > 0
       and (train_keys.get(seqs[va_idx[i]]) or [0, 0])[1] > 0]
P(f"\n  Val samples whose exact sequence has BOTH labels in train: {len(amb)} / {len(y_val)}")

# ceiling restricted to validation: best possible using train-majority rule
correct_rule = 0
covered = 0
for i in range(len(y_val)):
    c = train_keys.get(seqs[va_idx[i]])
    if c is not None and c[0] != c[1]:
        covered += 1
        correct_rule += int((1 if c[1] > c[0] else 0) == y_val[i])
P(f"  Lookup-table baseline (identical seq seen in train, unambiguous): covers "
  f"{covered}/{len(y_val)}, correct {correct_rule}/{covered}"
  f"{'' if covered == 0 else f' ({correct_rule / covered * 100:.1f}%)'}")

P()
P("  VERDICT GUIDE:")
P("   * Large 'opposite-label twin' share / low ceiling  -> data ceiling is hit; a bigger")
P("     model cannot help, need richer features (args, paths, timing, counts).")
P("   * Errors with unique sequences and no twins        -> model/training problem;")
P("     proceed to Step 2 (hard-example weighting).")

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print(f"\nSaved -> {OUT}")
