"""
eval_clean_split.py
===================
Step 1 of the data-quality fix: build a SEQUENCE-DISJOINT (leak-free)
train/val split and measure the HONEST baseline for Tier 1 and Tier 2.

Split rule: all samples with an identical event sequence live in ONE side only
(group split by sequence). So no val sequence is ever seen in train.

Models are retrained on the clean split but saved to *separate* files, so the
production artifacts (tier1_edr.onnx, tier2_cloud_model.pt) are untouched.

Outputs: dataset/clean_split.json (seed-42 indices), tier2_clean_baseline.txt
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
import os, io, json, random, tempfile, contextlib
import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict
from sklearn.metrics import roc_auc_score, roc_curve
from torch.utils.data import TensorDataset, DataLoader

import train_tier1 as t1
import train_tier2 as t2

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
SEEDS = [42, 1, 2, 3, 4]
OUT_TXT = os.path.join(BASE, "tier2_clean_baseline.txt")
OUT_SPLIT = os.path.join("dataset", "clean_split.json")
out = []


def P(s=""):
    print(s)
    out.append(s)


def seq_key(seq):
    s = list(seq)
    while s and s[-1] == 0:
        s.pop()
    return tuple(s)


def load():
    raw = json.load(open(t2.DATASET_PATH, encoding="utf-8"))
    keys, X, y = [], [], []
    for r in raw:
        s = r["event_sequence"][:t2.SEQ_LENGTH]
        keys.append(seq_key(s))
        X.append(s + [0] * (t2.SEQ_LENGTH - len(s)))
        y.append(int(r["label"]))
    return keys, torch.tensor(X, dtype=torch.long), np.array(y)


def group_split(keys, y, seed, val_frac=0.20):
    """Group-by-sequence split, filled per class (group majority label)."""
    groups = defaultdict(list)
    for i, k in enumerate(keys):
        groups[k].append(i)
    maj = {k: int(sum(y[i] for i in idx) * 2 >= len(idx)) for k, idx in groups.items()}
    rng = random.Random(seed)
    val_idx = []
    for cls in (0, 1):
        gl = sorted([k for k in groups if maj[k] == cls])
        rng.shuffle(gl)
        total = sum(len(groups[k]) for k in gl)
        got = 0
        for k in gl:
            if got >= val_frac * total:
                break
            val_idx += groups[k]
            got += len(groups[k])
    vs = set(val_idx)
    train_idx = [i for i in range(len(keys)) if i not in vs]
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    # hard leak check
    assert not ({keys[i] for i in train_idx} & {keys[i] for i in val_idx}), "LEAK"
    return train_idx, val_idx


def loaders(X, y, tr, va, seed):
    yt = torch.tensor(y, dtype=torch.float32).unsqueeze(1)
    g = torch.Generator().manual_seed(seed)
    return (DataLoader(TensorDataset(X[tr], yt[tr]), batch_size=32, shuffle=True, generator=g),
            DataLoader(TensorDataset(X[va], yt[va]), batch_size=32, shuffle=False))


def metrics(yv, p):
    pred = (p >= 0.5).astype(int)
    tp = int(((pred == 1) & (yv == 1)).sum()); fp = int(((pred == 1) & (yv == 0)).sum())
    tn = int(((pred == 0) & (yv == 0)).sum()); fn = int(((pred == 0) & (yv == 1)).sum())
    fpr, tpr, _ = roc_curve(yv, p)
    ok = np.where(fpr < 0.01)[0]
    return {"acc": (tp + tn) / len(yv), "auc": roc_auc_score(yv, p),
            "fpr05": fp / max(1, fp + tn), "tpr05": tp / max(1, tp + fn),
            "tpr_at_fpr1": float(tpr[ok[-1]])}


def run_seed(seed, keys, X, y, save=False):
    tr, va = group_split(keys, y, seed)
    yv = y[va]
    Xv = X[va]
    tl, vl = loaders(X, y, tr, va, seed)

    # ── Tier 1 (CNN) ──
    torch.manual_seed(seed)
    m1 = t1.Tier1EDR().to(t1.DEVICE)
    with contextlib.redirect_stdout(io.StringIO()):
        m1 = t1.train_model(m1, tl, vl)
    m1.eval()
    with torch.no_grad():
        p1 = torch.sigmoid(m1(Xv.to(t1.DEVICE))).squeeze(1).cpu().numpy()

    # ── Tier 2 (BiLSTM+Attn, Focal) ──
    torch.manual_seed(seed)
    m2 = t2.Tier2HybridCloudAnalyzer().to(t2.DEVICE)
    t2.OUTPUT_PT = os.path.join(BASE, "tier2_clean.pt") if save else \
        os.path.join(tempfile.gettempdir(), f"t2_clean_{seed}.pt")
    with contextlib.redirect_stdout(io.StringIO()):
        m2 = t2.train_model(m2, tl, vl)
    p2, _ = t2.predict_all(m2, Xv)

    info = {"n_train": len(tr), "n_val": len(va),
            "val_mal": int(yv.sum()), "val_unique": len({keys[i] for i in va}),
            "train_unique": len({keys[i] for i in tr}),
            "majority": max(yv.mean(), 1 - yv.mean())}
    return info, metrics(yv, p1), metrics(yv, p2), (tr, va)


def main():
    keys, X, y = load()
    N = len(y)
    P("=" * 78)
    P(" CLEAN (SEQUENCE-DISJOINT) SPLIT -- HONEST BASELINE")
    P("=" * 78)
    P(f"  samples={N}, unique sequences={len(set(keys))}")
    P("  Old leaky split reference (val seqs seen in train = 76%):")
    P("      Tier 1 acc 83.70% | Tier 2 acc 85.00% | Tier 2 AUC 0.9147")
    P()
    rows = []
    for seed in SEEDS:
        info, m1, m2, (tr, va) = run_seed(seed, keys, X, y, save=(seed == 42))
        rows.append((info, m1, m2))
        if seed == 42:
            json.dump({"seed": 42, "train_idx": tr, "val_idx": va,
                       "rule": "group split: identical sequences never straddle train/val"},
                      open(OUT_SPLIT, "w"))
        P(f"  seed {seed:>2}: train={info['n_train']} (uniq {info['train_unique']}) "
          f"val={info['n_val']} (uniq {info['val_unique']}, mal {info['val_mal']}) "
          f"majority-baseline={info['majority'] * 100:.1f}% | leak=0")
        for tag, m in (("Tier1", m1), ("Tier2", m2)):
            P(f"           {tag}: acc={m['acc'] * 100:5.2f}% AUC={m['auc']:.4f} "
              f"@0.5 TPR={m['tpr05'] * 100:5.1f}% FPR={m['fpr05'] * 100:5.1f}% | "
              f"TPR@FPR<1%={m['tpr_at_fpr1'] * 100:5.1f}%")

    P()
    P("-" * 78)
    P(f" MEAN +/- STD over {len(SEEDS)} group-split seeds")
    P("-" * 78)
    for tag, idx in (("Tier 1 (CNN)", 1), ("Tier 2 (BiLSTM+Attn)", 2)):
        for name, key in (("accuracy", "acc"), ("AUC", "auc"),
                          ("TPR @ FPR<1%", "tpr_at_fpr1"), ("FPR @0.5", "fpr05")):
            v = np.array([r[idx][key] for r in rows])
            scale = 100 if key != "auc" else 1
            P(f"  {tag:<22} {name:<14}: {v.mean() * scale:6.2f} +/- {v.std() * scale:5.2f}"
              f"{'%' if key != 'auc' else ''}")
    mj = np.mean([r[0]['majority'] for r in rows])
    P(f"  Majority-class baseline        : {mj * 100:6.2f}%")
    P()
    P("  Seed-42 clean split saved -> " + OUT_SPLIT)
    P("  Seed-42 clean Tier-2 model -> tier2_clean.pt (production model untouched)")
    open(OUT_TXT, "w", encoding="utf-8").write("\n".join(out))


if __name__ == "__main__":
    main()
