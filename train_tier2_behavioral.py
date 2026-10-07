"""
train_tier2_behavioral.py
=========================
Tier 2 EDR (Cloud Backend) -- Bi-LSTM + Attention on BEHAVIORAL FEATURES
Resolves "Grey Zone" processes using the 99 behavioral features from
behavioral_dataset.npz instead of raw EventID sequences.

Dataset  : dataset/behavioral_dataset.npz
           - feat  [N, 99]  float32 behavioral feature vectors
           - guid  [N]      str     ProcessGuid for GroupKFold splitting
           - y     [N]      int     binary label

Architecture (Behavioral Hybrid):
  The 99 features are treated as a time-step sequence of length 1
  by a Bi-LSTM, and additionally passed through an MLP head.
  Both paths are concatenated -> classification.

  In practice for purely aggregated tabular features, a deeper MLP
  with residual connections outperforms an LSTM over a single vector.
  We therefore use:

  Input [B, 99]
    -> FC(99, 128) -> LayerNorm -> ReLU         (projection)
    -> Residual Block x2 (128->128, skip conn)  (depth)
    -> Dropout(0.4)
    -> FC(128, 1)                               (raw logit)

  Loss: FocalLoss(gamma=2.0)
  Optimizer: AdamW(lr=1e-3, wd=1e-2)
  Grad clip: 1.0
  Early stopping: patience=5 on val loss

Evaluation:
  5-seed GroupKFold(n_splits=5) -- same seeds as Tier 1 (comparable metrics)
  Data-driven threshold: highest TPR with FPR strictly < 1%

Outputs:
  tier2_behavioral.pt              -- best PyTorch state_dict
  tier2_behavioral_threshold.json  -- data-driven threshold per seed
  tier2_behavioral_metrics.json    -- per-seed/fold metrics + 5-seed avg
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import copy
import json
import random
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, roc_curve

# ---------------------------------------------------------------
# CONFIG (must match Tier 1 seeds/splits for fair comparison)
# ---------------------------------------------------------------
BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
DATASET_NPZ       = os.path.join(BASE_DIR, "dataset", "behavioral_dataset.npz")
OUTPUT_PT         = os.path.join(BASE_DIR, "tier2_behavioral.pt")
OUTPUT_THRESHOLD  = os.path.join(BASE_DIR, "tier2_behavioral_threshold.json")
OUTPUT_METRICS    = os.path.join(BASE_DIR, "tier2_behavioral_metrics.json")

INPUT_DIM         = 99
PROJ_DIM          = 64
DROPOUT_RATE      = 0.4
BATCH_SIZE        = 32
EPOCHS            = 40
PATIENCE          = 5
LEARNING_RATE     = 1e-3
WEIGHT_DECAY      = 1e-2
GRAD_CLIP         = 1.0
FOCAL_GAMMA       = 2.0
N_SPLITS          = 5
SEEDS             = [42, 7, 13, 99, 2024]     # IDENTICAL to Tier 1
TARGET_FPR        = 0.01

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ==============================================================
# DATA LOADING
# ==============================================================

def load_data():
    print("=" * 65)
    print("  DATA LOADING -- behavioral_dataset.npz (Tier 2)")
    print("=" * 65)
    data  = np.load(DATASET_NPZ, allow_pickle=True)
    feat  = data["feat"].astype(np.float32)
    y     = data["y"].astype(np.int64)
    guids = data["guid"]
    print(f"  Samples  : {len(y):,}  ({int(y.sum())} malware + {int((1-y).sum())} benign)")
    print(f"  Features : {feat.shape[1]}")
    print(f"  Unique ProcessGuids: {len(np.unique(guids)):,}")
    print(f"  Device   : {DEVICE}")
    return feat, y, guids


# ==============================================================
# MODEL -- Residual MLP
# ==============================================================

class ResidualBlock(nn.Module):
    """
    FC(d,d) -> BatchNorm1d -> ReLU -> Dropout -> FC(d,d) -> BatchNorm1d + skip.
    BatchNorm1d chosen over LayerNorm for tabular features (independent variables):
    it normalises per-feature across the batch, giving stable gradients on small
    datasets and preventing the threshold-collapse seen with LayerNorm.
    """
    def __init__(self, dim: int, dropout: float = 0.4):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.act = nn.ReLU()

    def forward(self, x):
        return self.act(x + self.block(x))


class Tier2BehavioralNet(nn.Module):
    """
    Deep residual MLP for 99-dim behavioural feature vectors.
    Distinct "Heavy Brain" for Cloud Tier: deeper than Tier 1 MLP
    (projection + 2 residual blocks vs Tier 1's 2 hidden layers).

    PROJ_DIM=64 keeps params at ~14K -- right-sized for 1,470 samples.
    All normalisation uses BatchNorm1d (feature-wise, batch-mean): more
    stable than LayerNorm on tabular data where features are NOT sequential.
    forward() returns logit [B,1].
    """
    def __init__(self, input_dim: int = INPUT_DIM,
                 proj_dim: int = PROJ_DIM,
                 dropout: float = DROPOUT_RATE):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(input_dim, proj_dim),
            nn.BatchNorm1d(proj_dim),
            nn.ReLU(),
        )
        self.res1 = ResidualBlock(proj_dim, dropout=dropout)
        self.res2 = ResidualBlock(proj_dim, dropout=dropout)
        self.drop = nn.Dropout(dropout)
        self.head = nn.Linear(proj_dim, 1)

        # Xavier init
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        x = self.proj(x)
        x = self.res1(x)
        x = self.res2(x)
        return self.head(self.drop(x))    # [B, 1] logit



# ==============================================================
# LOSS
# ==============================================================

class FocalLoss(nn.Module):
    def __init__(self, gamma: float = FOCAL_GAMMA):
        super().__init__()
        self.gamma = gamma

    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        p_t = torch.exp(-bce)
        return ((1.0 - p_t) ** self.gamma * bce).mean()


# ==============================================================
# TRAINING LOOP (single fold)
# ==============================================================

def train_one_fold(X_train, y_train, X_val, y_val, seed: int):
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)

    train_ds = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.float32).unsqueeze(1),
    )
    val_ds = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.float32).unsqueeze(1),
    )
    g = torch.Generator().manual_seed(seed)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, generator=g)
    val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False)

    model     = Tier2BehavioralNet().to(DEVICE)
    criterion = FocalLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    best_val, best_state, bad = float("inf"), None, 0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        for xb, yb in train_loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            optimizer.step()

        model.eval()
        vl, total = 0.0, 0
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                vl    += criterion(model(xb), yb).item() * xb.size(0)
                total += xb.size(0)

        val_loss = vl / total
        if val_loss < best_val:
            best_val   = val_loss
            best_state = copy.deepcopy(model.state_dict())
            bad = 0
        else:
            bad += 1
        if bad >= PATIENCE:
            break

    model.load_state_dict(best_state)
    return model


# ==============================================================
# EVALUATION HELPERS
# ==============================================================

def get_probs(model, X):
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(X, dtype=torch.float32).to(DEVICE))
        probs  = torch.sigmoid(logits).squeeze(1).cpu().numpy()
    return probs


def pick_threshold(y_true, probs):
    """Highest TPR with FPR strictly < TARGET_FPR (data-driven)."""
    fpr_arr, tpr_arr, thr_arr = roc_curve(y_true, probs)
    ok = np.where(fpr_arr < TARGET_FPR)[0]
    if len(ok) == 0:
        return 0.5, 0.0, float(fpr_arr[0])
    idx = ok[-1]
    t = float(thr_arr[idx])
    if not np.isfinite(t):
        t = float(np.nextafter(probs.max(), 1.0))
    return t, float(tpr_arr[idx]), float(fpr_arr[idx])


def fold_metrics(y_true, probs):
    thr, tpr, fpr = pick_threshold(y_true, probs)
    preds = (probs >= thr).astype(int)
    acc   = float((preds == y_true).mean())
    auc   = float(roc_auc_score(y_true, probs))
    tp = int(((preds == 1) & (y_true == 1)).sum())
    fp = int(((preds == 1) & (y_true == 0)).sum())
    tn = int(((preds == 0) & (y_true == 0)).sum())
    fn = int(((preds == 0) & (y_true == 1)).sum())
    return dict(threshold=thr, acc=acc, auc=auc, tpr=tpr, fpr=fpr,
                tp=tp, fp=fp, tn=tn, fn=fn)


# ==============================================================
# 5-SEED GroupKFold LOOP
# ==============================================================

def run_multi_seed_eval(feat, y, guids):
    print("\n" + "=" * 65)
    print("  5-SEED GroupKFold EVALUATION  (Tier 2)")
    print("=" * 65)
    print(f"  Seeds={SEEDS}  |  K={N_SPLITS}  |  total runs={len(SEEDS)*N_SPLITS}")

    all_results = []
    best_overall_auc   = -1.0
    best_overall_state = None
    best_thresholds    = []

    print(f"\n  {'Seed':>6} {'Fold':>5} | {'Acc':>7} | {'AUC':>7} | "
          f"{'TPR':>7} | {'FPR':>7} | {'Thr':>7}")
    print("  " + "-" * 62)

    for seed in SEEDS:
        gkf = GroupKFold(n_splits=N_SPLITS)
        seed_metrics = []

        for fold_idx, (tr_idx, va_idx) in enumerate(
                gkf.split(feat, y, groups=guids), 1):
            X_tr, y_tr = feat[tr_idx], y[tr_idx]
            X_va, y_va = feat[va_idx], y[va_idx]

            model = train_one_fold(X_tr, y_tr, X_va, y_va, seed=seed + fold_idx)
            probs = get_probs(model, X_va)
            m     = fold_metrics(y_va, probs)
            seed_metrics.append(m)
            best_thresholds.append(m["threshold"])

            if m["auc"] > best_overall_auc:
                best_overall_auc   = m["auc"]
                best_overall_state = copy.deepcopy(model.state_dict())

            print(f"  {seed:>6} {fold_idx:>5} | "
                  f"{m['acc']*100:>6.2f}% | {m['auc']:>7.4f} | "
                  f"{m['tpr']*100:>6.2f}% | {m['fpr']*100:>6.2f}% | "
                  f"{m['threshold']:>7.4f}")

        all_results.append({"seed": seed, "folds": seed_metrics})

    # 5-seed aggregate
    print("\n  " + "-" * 62)
    print("  5-SEED AVERAGE (25 folds total):")
    flat  = [m for r in all_results for m in r["folds"]]
    accs  = [m["acc"] for m in flat]
    aucs  = [m["auc"] for m in flat]
    tprs  = [m["tpr"] for m in flat]
    fprs  = [m["fpr"] for m in flat]

    summary = dict(
        mean_acc=float(np.mean(accs)), std_acc=float(np.std(accs)),
        mean_auc=float(np.mean(aucs)), std_auc=float(np.std(aucs)),
        mean_tpr=float(np.mean(tprs)), std_tpr=float(np.std(tprs)),
        mean_fpr=float(np.mean(fprs)), std_fpr=float(np.std(fprs)),
        mean_threshold=float(np.mean(best_thresholds)),
        n_runs=len(flat),
    )
    print(f"  Accuracy  : {summary['mean_acc']*100:.2f}% +- {summary['std_acc']*100:.2f}%")
    print(f"  AUC       : {summary['mean_auc']:.4f} +- {summary['std_auc']:.4f}")
    print(f"  TPR       : {summary['mean_tpr']*100:.2f}% +- {summary['std_tpr']*100:.2f}%")
    print(f"  FPR       : {summary['mean_fpr']*100:.2f}% +- {summary['std_fpr']*100:.2f}%")
    print(f"  Avg Thr   : {summary['mean_threshold']:.4f}")

    return all_results, summary, best_overall_state


# ==============================================================
# SAVE BEST MODEL & THRESHOLD
# ==============================================================

def save_artifacts(state_dict, summary):
    torch.save(state_dict, OUTPUT_PT)
    sz = os.path.getsize(OUTPUT_PT) / 1024
    print(f"\n  [OK] PT checkpoint: {OUTPUT_PT}  ({sz:.1f} KB)")

    thr_data = {
        "threshold": summary["mean_threshold"],
        "target_fpr": TARGET_FPR,
        "val_fpr_mean": summary["mean_fpr"],
        "val_tpr_mean": summary["mean_tpr"],
        "val_auc_mean": summary["mean_auc"],
        "note": "Mean threshold over 25 GroupKFold folds (5 seeds x 5 folds). Use for production.",
    }
    with open(OUTPUT_THRESHOLD, "w", encoding="utf-8") as f:
        json.dump(thr_data, f, indent=2)
    print(f"  [OK] Threshold   : {OUTPUT_THRESHOLD}")


# ==============================================================
# COMPARISON REPORT
# ==============================================================

def print_comparison(t1_metrics_path: str, t2_summary: dict):
    """Side-by-side Tier 1 vs Tier 2 comparison if T1 metrics exist."""
    if not os.path.exists(t1_metrics_path):
        print("\n  [INFO] Tier 1 metrics not found -- skipping comparison.")
        return

    with open(t1_metrics_path, encoding="utf-8") as f:
        t1 = json.load(f)["summary"]

    print("\n" + "=" * 65)
    print("  TIER 1 vs TIER 2 -- BEHAVIORAL 5-SEED AVERAGE")
    print("=" * 65)
    print(f"  {'Metric':<18} {'Tier 1 MLP':>15} {'Tier 2 ResNet':>15}")
    print("  " + "-" * 50)
    for key, label in [("mean_acc", "Accuracy"), ("mean_auc", "AUC"),
                       ("mean_tpr", "TPR"), ("mean_fpr", "FPR")]:
        if key in ("mean_acc", "mean_tpr", "mean_fpr"):
            t1v = f"{t1[key]*100:.2f}%"
            t2v = f"{t2_summary[key]*100:.2f}%"
        else:
            t1v = f"{t1[key]:.4f}"
            t2v = f"{t2_summary[key]:.4f}"
        print(f"  {label:<18} {t1v:>15} {t2v:>15}")


# ==============================================================
# MAIN
# ==============================================================

def main():
    os.chdir(BASE_DIR)
    print("\n" + "#" * 65)
    print("  TIER 2 -- BEHAVIORAL ResNet  |  5-Seed GroupKFold")
    print("#" * 65)

    feat, y, guids = load_data()
    all_results, summary, best_state = run_multi_seed_eval(feat, y, guids)

    save_artifacts(best_state, summary)

    with open(OUTPUT_METRICS, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "per_seed": all_results}, f, indent=2)
    print(f"  [OK] Metrics: {OUTPUT_METRICS}")

    t1_metrics_path = os.path.join(BASE_DIR, "tier1_behavioral_metrics.json")
    print_comparison(t1_metrics_path, summary)

    print("\n" + "#" * 65)
    print("  DONE")
    print(f"  5-Seed Avg Accuracy : {summary['mean_acc']*100:.2f}%  +-  {summary['std_acc']*100:.2f}%")
    print(f"  5-Seed Avg AUC      : {summary['mean_auc']:.4f}  +-  {summary['std_auc']:.4f}")
    print("#" * 65)


if __name__ == "__main__":
    main()
