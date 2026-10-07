"""
train_tier1_behavioral.py
=========================
Tier 1 EDR — MLP on BEHAVIORAL FEATURES
Retrains Tier 1 on the leak-free behavioral_dataset.npz using
5-seed GroupKFold (grouped by ProcessGuid) for stable metrics.

Dataset  : dataset/behavioral_dataset.npz
           - feat  [N, 99]  float32 behavioural feature vectors
           - seq   [N, 50]  int64   EventID sequences (kept for reference)
           - guid  [N]      str     ProcessGuid for group-aware splitting
           - y     [N]      int     binary label (1=malware, 0=benign)

Architecture (Behavioral MLP):
  Input [batch, 99] float32
    -> Linear(99, 128) -> BN -> ReLU -> Dropout(0.3)
    -> Linear(128, 64) -> BN -> ReLU -> Dropout(0.3)
    -> Linear(64, 1)   (raw logit)

  Loss: FocalLoss(gamma=2.0)  [consistent with Tier 2]
  Optimizer: AdamW(lr=1e-3, wd=1e-2)
  Early stopping: patience=5 on val loss

Evaluation:
  5-seed GroupKFold(n_splits=5) -> average Accuracy, AUC, TPR@FPR<1%
  Final model saved = best checkpoint over ALL folds of seed=42.

Outputs:
  tier1_behavioral.onnx   -- production ONNX (Sigmoid baked in)
  tier1_behavioral.pt     -- best PyTorch state_dict
  tier1_behavioral_metrics.json -- per-seed/fold metrics + 5-seed avg
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
# CONFIG
# ---------------------------------------------------------------
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATASET_NPZ     = os.path.join(BASE_DIR, "dataset", "behavioral_dataset.npz")
OUTPUT_ONNX     = os.path.join(BASE_DIR, "tier1_behavioral.onnx")
OUTPUT_PT       = os.path.join(BASE_DIR, "tier1_behavioral.pt")
OUTPUT_METRICS  = os.path.join(BASE_DIR, "tier1_behavioral_metrics.json")

INPUT_DIM       = 99
HIDDEN1         = 128
HIDDEN2         = 64
DROPOUT_RATE    = 0.3
BATCH_SIZE      = 32
EPOCHS          = 40
PATIENCE        = 5
LEARNING_RATE   = 1e-3
WEIGHT_DECAY    = 1e-2
FOCAL_GAMMA     = 2.0
N_SPLITS        = 5
SEEDS           = [42, 7, 13, 99, 2024]
TARGET_FPR      = 0.01

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ==============================================================
# DATA LOADING
# ==============================================================

def load_data():
    print("=" * 65)
    print("  DATA LOADING -- behavioral_dataset.npz")
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
# MODEL
# ==============================================================

class Tier1BehavioralMLP(nn.Module):
    """3-layer MLP with BatchNorm for 99-dim behavioral features."""
    def __init__(self, input_dim: int = INPUT_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, HIDDEN1),
            nn.BatchNorm1d(HIDDEN1),
            nn.ReLU(),
            nn.Dropout(DROPOUT_RATE),
            nn.Linear(HIDDEN1, HIDDEN2),
            nn.BatchNorm1d(HIDDEN2),
            nn.ReLU(),
            nn.Dropout(DROPOUT_RATE),
            nn.Linear(HIDDEN2, 1),
        )
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        return self.net(x)


class ModelForExport(nn.Module):
    """Bakes Sigmoid into ONNX graph so agent gets probabilities."""
    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, x):
        return torch.sigmoid(self.model(x))


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

    model     = Tier1BehavioralMLP().to(DEVICE)
    criterion = FocalLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    best_val, best_state, bad = float("inf"), None, 0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        for xb, yb in train_loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            criterion(model(xb), yb).backward()
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
    """Highest TPR with FPR strictly < TARGET_FPR."""
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
    print("  5-SEED GroupKFold EVALUATION")
    print("=" * 65)
    print(f"  Seeds={SEEDS}  |  K={N_SPLITS}  |  total runs={len(SEEDS)*N_SPLITS}")

    all_results = []
    best_overall_auc   = -1.0
    best_overall_state = None

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
        n_runs=len(flat),
    )
    print(f"  Accuracy : {summary['mean_acc']*100:.2f}% +- {summary['std_acc']*100:.2f}%")
    print(f"  AUC      : {summary['mean_auc']:.4f} +- {summary['std_auc']:.4f}")
    print(f"  TPR      : {summary['mean_tpr']*100:.2f}% +- {summary['std_tpr']*100:.2f}%")
    print(f"  FPR      : {summary['mean_fpr']*100:.2f}% +- {summary['std_fpr']*100:.2f}%")

    return all_results, summary, best_overall_state


# ==============================================================
# ONNX EXPORT
# ==============================================================

def export_onnx(state_dict):
    import onnx
    import onnxruntime as ort

    print("\n" + "=" * 65)
    print("  ONNX EXPORT")
    print("=" * 65)

    model = Tier1BehavioralMLP().cpu()
    model.load_state_dict(state_dict)
    model.eval()
    export_model = ModelForExport(model)
    export_model.eval()

    dummy = torch.zeros(1, INPUT_DIM, dtype=torch.float32)
    torch.onnx.export(
        export_model, dummy, OUTPUT_ONNX,
        export_params=True, opset_version=14, do_constant_folding=True,
        input_names=["features"], output_names=["probability"],
        dynamic_axes={"features": {0: "batch_size"}, "probability": {0: "batch_size"}},
    )
    onnx.checker.check_model(onnx.load(OUTPUT_ONNX))
    session = ort.InferenceSession(OUTPUT_ONNX)
    out = session.run(None, {"features": np.zeros((1, INPUT_DIM), dtype=np.float32)})[0][0][0]
    assert 0.0 <= out <= 1.0, f"ONNX output {out} out of [0,1]"
    sz_onnx = os.path.getsize(OUTPUT_ONNX) / 1024
    print(f"  [OK] ONNX  : {OUTPUT_ONNX}  ({sz_onnx:.1f} KB)")
    print(f"  [OK] Sanity: zeros -> prob={out:.6f}")

    torch.save(state_dict, OUTPUT_PT)
    sz_pt = os.path.getsize(OUTPUT_PT) / 1024
    print(f"  [OK] PT    : {OUTPUT_PT}  ({sz_pt:.1f} KB)")


# ==============================================================
# MAIN
# ==============================================================

def main():
    os.chdir(BASE_DIR)
    print("\n" + "#" * 65)
    print("  TIER 1 -- BEHAVIORAL MLP  |  5-Seed GroupKFold")
    print("#" * 65)

    feat, y, guids = load_data()
    all_results, summary, best_state = run_multi_seed_eval(feat, y, guids)

    with open(OUTPUT_METRICS, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "per_seed": all_results}, f, indent=2)
    print(f"\n  Metrics saved -> {OUTPUT_METRICS}")

    export_onnx(best_state)

    print("\n" + "#" * 65)
    print("  DONE")
    print(f"  5-Seed Avg Accuracy : {summary['mean_acc']*100:.2f}%  +-  {summary['std_acc']*100:.2f}%")
    print(f"  5-Seed Avg AUC      : {summary['mean_auc']:.4f}  +-  {summary['std_auc']:.4f}")
    print("#" * 65)


if __name__ == "__main__":
    main()
