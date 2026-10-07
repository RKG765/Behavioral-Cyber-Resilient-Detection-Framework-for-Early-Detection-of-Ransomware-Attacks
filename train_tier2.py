"""
train_tier2.py
==============
Tier 2 EDR (Cloud Backend) -- Bi-LSTM + Bahdanau Attention Classifier
Resolves "Grey Zone" sequences that Tier 1 (1D-CNN) could not decide.

Dataset : dataset/balanced_training_sequences.json (2,298 sequences)
Input   : Padded Sysmon EventID sequences (length=50, 0 = padding)
Output  : tier2_cloud_model.pt  (native PyTorch state_dict, NO ONNX)
          tier2_threshold.json  (data-driven cloud threshold, FPR < 1%)
          tier2_xai_sample.json (attention sanity-check dump)

Design decisions:
  1. EXACT Tier-1 split (same seed, same shuffle order) -- asserted at runtime
     against train_tier1.load_and_prepare_data() so metrics are comparable.
  2. Focal Loss (gamma=2.0): focuses gradients on hard / ambiguous samples.
  3. Padding-masked Bahdanau attention: padded steps get EXACTLY 0.0 weight.
  4. Xavier-uniform init for attention W, v (+ LSTM init best practices).
  5. AdamW(wd=1e-2), grad clipping, early stopping on val loss (patience 5).
  6. Threshold chosen from roc_curve: highest TPR with FPR strictly < 1%.
  7. Grey-zone evaluation: only samples Tier 1 scored in (0.10, 0.90).
  8. XAI check: padding weight == 0.0, rows sum to 1, top-3 Event IDs.
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")

import os
import io
import json
import copy
import random
import contextlib
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import roc_curve, roc_auc_score

# ──────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH     = os.path.join("dataset", "balanced_training_sequences.json")
TIER1_ONNX_PATH  = os.path.join(BASE_DIR, "tier1_edr.onnx")
OUTPUT_PT        = os.path.join(BASE_DIR, "tier2_cloud_model.pt")
OUTPUT_THRESHOLD = os.path.join(BASE_DIR, "tier2_threshold.json")
OUTPUT_XAI       = os.path.join(BASE_DIR, "tier2_xai_sample.json")

SEED             = 42            # MUST equal train_tier1.py
SEQ_LENGTH       = 50
NUM_EMBEDDINGS   = 24            # max EventID 23 + 1 (0 = padding)
EMBEDDING_DIM    = 32
LSTM_HIDDEN      = 64            # x2 (bidirectional) = 128
ATTN_DIM         = 64
DROPOUT_RATE     = 0.4
BATCH_SIZE       = 32
EPOCHS           = 25
PATIENCE         = 5
LEARNING_RATE    = 0.001
WEIGHT_DECAY     = 1e-2
GRAD_CLIP        = 1.0
VAL_SPLIT        = 0.20
FOCAL_GAMMA      = 2.0

CLOUD_THRESHOLD_FIXED = 0.70     # reference report
TARGET_FPR            = 0.01     # data-driven threshold: FPR strictly < 1%
T1_SAFE, T1_THREAT    = 0.10, 0.90   # Tier-1 grey zone = (0.10, 0.90)

SYSMON_EVENT_NAMES = {
    1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
    4: "SysmonStateChange", 5: "ProcessTerminate", 6: "DriverLoad",
    7: "ImageLoad", 8: "CreateRemoteThread", 9: "RawAccessRead",
    10: "ProcessAccess", 11: "FileCreate", 12: "RegistryObject",
    13: "RegistryValueSet", 14: "RegistryRename", 15: "FileCreateStreamHash",
    16: "ServiceConfigChange", 17: "PipeCreated", 18: "PipeConnected",
    19: "WmiFilter", 20: "WmiConsumer", 21: "WmiBinding", 22: "DnsQuery",
    23: "FileDelete",
}

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ══════════════════════════════════════════════════════════════
# PHASE 1: DATA (exact Tier-1 split)
# ══════════════════════════════════════════════════════════════

def stratified_split_indices(labels):
    """
    Replicates train_tier1.py's split exactly: with random.seed(SEED) the
    sequence of shuffles is  mal -> ben -> train -> val.
    A private Random(SEED) yields the identical Mersenne-Twister stream.
    """
    rng = random.Random(SEED)
    mal = [i for i, l in enumerate(labels) if l == 1.0]
    ben = [i for i, l in enumerate(labels) if l == 0.0]
    rng.shuffle(mal)
    rng.shuffle(ben)
    ms = int(len(mal) * (1 - VAL_SPLIT))
    bs = int(len(ben) * (1 - VAL_SPLIT))
    train_idx = mal[:ms] + ben[:bs]
    val_idx = mal[ms:] + ben[bs:]
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    return train_idx, val_idx


def assert_split_parity(X_val, y_val):
    """Hard guarantee that Tier-1 and Tier-2 validate on identical samples."""
    import train_tier1
    with contextlib.redirect_stdout(io.StringIO()):
        _, _, t1_X_val, t1_y_val = train_tier1.load_and_prepare_data()
    assert torch.equal(X_val, t1_X_val) and torch.equal(y_val, t1_y_val), \
        "SPLIT MISMATCH vs train_tier1.py -- metrics would not be comparable!"
    print("  [OK] Validation set is IDENTICAL to Tier 1's (X_val, y_val, order)")


def load_and_prepare_data():
    print("=" * 65)
    print("  PHASE 1 -- DATA LOADING (exact Tier-1 split)")
    print("=" * 65)
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    print(f"  Loaded {len(raw):,} sequences from {DATASET_PATH}")

    seqs, labels = [], []
    for rec in raw:
        s = rec["event_sequence"][:SEQ_LENGTH]
        seqs.append(s + [0] * (SEQ_LENGTH - len(s)))
        labels.append(float(rec["label"]))

    X = torch.tensor(seqs, dtype=torch.long)
    y = torch.tensor(labels, dtype=torch.float32).unsqueeze(1)
    print(f"  X: {tuple(X.shape)} {X.dtype} | y: {tuple(y.shape)} {y.dtype}")
    assert int(X.max()) < NUM_EMBEDDINGS, "EventID out of embedding range"

    tr, va = stratified_split_indices(labels)
    X_train, y_train = X[tr], y[tr]
    X_val, y_val = X[va], y[va]
    print(f"  Train: {len(y_train):,} ({int(y_train.sum())} mal + "
          f"{len(y_train) - int(y_train.sum())} ben)")
    print(f"  Val  : {len(y_val):,} ({int(y_val.sum())} mal + "
          f"{len(y_val) - int(y_val.sum())} ben)")

    assert_split_parity(X_val, y_val)

    g = torch.Generator().manual_seed(SEED)
    train_loader = DataLoader(TensorDataset(X_train, y_train),
                              batch_size=BATCH_SIZE, shuffle=True, generator=g)
    val_loader = DataLoader(TensorDataset(X_val, y_val),
                            batch_size=BATCH_SIZE, shuffle=False)
    return train_loader, val_loader, X_val, y_val


# ══════════════════════════════════════════════════════════════
# PHASE 2: MODEL
# ══════════════════════════════════════════════════════════════

class BahdanauAttention(nn.Module):
    """
    Additive attention:  e_t = v^T tanh(W h_t),  a = softmax(e) over valid t,
    context = sum_t a_t h_t.  Padded steps are masked with -inf, so their
    weight is EXACTLY 0.0.  W and v use Xavier/Glorot-uniform init.
    """

    def __init__(self, in_dim: int, attn_dim: int):
        super().__init__()
        self.W = nn.Linear(in_dim, attn_dim)
        self.v = nn.Linear(attn_dim, 1, bias=False)
        nn.init.xavier_uniform_(self.W.weight)
        nn.init.zeros_(self.W.bias)
        nn.init.xavier_uniform_(self.v.weight)

    def forward(self, h, mask):
        # h: [B,T,D]  mask: [B,T] bool (True = real event)
        scores = self.v(torch.tanh(self.W(h))).squeeze(-1)           # [B,T]
        all_pad = ~mask.any(dim=1, keepdim=True)                     # [B,1]
        scores = scores.masked_fill(~mask, float("-inf"))
        scores = scores.masked_fill(all_pad, 0.0)                    # avoid NaN
        weights = torch.softmax(scores, dim=-1)
        weights = weights.masked_fill(all_pad, 0.0)                  # empty -> 0
        context = torch.bmm(weights.unsqueeze(1), h).squeeze(1)      # [B,D]
        return context, weights


class Tier2HybridCloudAnalyzer(nn.Module):
    """
    Embedding(24,32,pad=0) -> BiLSTM(32,64) -> Bahdanau attention
    -> Dropout(0.4) -> Linear(128,1)  (raw logit)
    forward() returns (logit [B,1], attn_weights [B,T]).
    """

    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(NUM_EMBEDDINGS, EMBEDDING_DIM, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size=EMBEDDING_DIM, hidden_size=LSTM_HIDDEN, num_layers=1,
            batch_first=True, bidirectional=True,
        )
        self.attention = BahdanauAttention(2 * LSTM_HIDDEN, ATTN_DIM)
        self.dropout = nn.Dropout(p=DROPOUT_RATE)
        self.classifier = nn.Linear(2 * LSTM_HIDDEN, 1)
        self._init_lstm()

    def _init_lstm(self):
        for name, p in self.lstm.named_parameters():
            if "weight_ih" in name:
                nn.init.xavier_uniform_(p)
            elif "weight_hh" in name:
                nn.init.orthogonal_(p)
            elif "bias" in name:
                nn.init.zeros_(p)
                if "bias_ih" in name:                       # forget-gate bias = 1
                    p.data[LSTM_HIDDEN:2 * LSTM_HIDDEN].fill_(1.0)

    def forward(self, x):
        mask = x != 0                                       # [B,T]
        emb = self.embedding(x)                             # [B,T,32]
        out, _ = self.lstm(emb)                             # [B,T,128]
        context, weights = self.attention(out, mask)        # [B,128], [B,T]
        return self.classifier(self.dropout(context)), weights


class FocalLoss(nn.Module):
    """Binary focal loss on logits: (1 - p_t)^gamma * BCE."""

    def __init__(self, gamma: float = 2.0):
        super().__init__()
        self.gamma = gamma

    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        p_t = torch.exp(-bce)
        return ((1.0 - p_t) ** self.gamma * bce).mean()


# ══════════════════════════════════════════════════════════════
# PHASE 3: TRAINING
# ══════════════════════════════════════════════════════════════

def train_model(model, train_loader, val_loader):
    print("\n" + "=" * 65)
    print("  PHASE 3 -- TRAINING (Focal Loss, AdamW, Early Stopping)")
    print("=" * 65)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"  Parameters: {n_params:,}  | device: {DEVICE}")

    criterion = FocalLoss(FOCAL_GAMMA)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE,
                                  weight_decay=WEIGHT_DECAY)
    best_val, best_state, best_epoch, bad = float("inf"), None, 0, 0

    print(f"\n  {'Epoch':>5} | {'Train Loss':>10} | {'Val Loss':>9} | {'Val Acc':>8} |")
    print("  " + "-" * 45)
    for epoch in range(1, EPOCHS + 1):
        model.train()
        tl, tn = 0.0, 0
        for xb, yb in train_loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            logits, _ = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            optimizer.step()
            tl += loss.item() * xb.size(0)
            tn += xb.size(0)

        model.eval()
        vl, vn, correct = 0.0, 0, 0
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                logits, _ = model(xb)
                vl += criterion(logits, yb).item() * xb.size(0)
                vn += xb.size(0)
                correct += ((logits > 0).float() == yb).sum().item()
        train_loss, val_loss, val_acc = tl / tn, vl / vn, correct / vn

        flag = ""
        if val_loss < best_val:
            best_val, best_epoch, bad = val_loss, epoch, 0
            best_state = copy.deepcopy(model.state_dict())
            flag = " *best"
        else:
            bad += 1
        print(f"  {epoch:>5} | {train_loss:>10.4f} | {val_loss:>9.4f} | "
              f"{val_acc * 100:>7.2f}% |{flag}")
        if bad >= PATIENCE:
            print(f"\n  Early stopping at epoch {epoch} "
                  f"(best epoch {best_epoch}, val loss {best_val:.4f})")
            break

    model.load_state_dict(best_state)
    torch.save(best_state, OUTPUT_PT)
    print(f"  Saved best state_dict (epoch {best_epoch}) -> {OUTPUT_PT}")
    return model


# ══════════════════════════════════════════════════════════════
# PHASE 4: EVALUATION
# ══════════════════════════════════════════════════════════════

def confusion(y_true, y_pred):
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    acc = (tp + tn) / max(1, tp + fp + tn + fn)
    return tp, fp, tn, fn, tpr, fpr, acc


def print_conf(tag, y_true, probs, thr):
    tp, fp, tn, fn, tpr, fpr, acc = confusion(y_true, (probs >= thr).astype(int))
    print(f"  {tag:<34} thr={thr:.4f} | TP={tp:>3} FP={fp:>3} TN={tn:>3} FN={fn:>3} "
          f"| TPR={tpr * 100:6.2f}% FPR={fpr * 100:5.2f}% Acc={acc * 100:6.2f}%")
    return tp, fp, tn, fn, tpr, fpr, acc


def predict_all(model, X):
    model.eval()
    with torch.no_grad():
        logits, attn = model(X.to(DEVICE))
    return torch.sigmoid(logits).squeeze(1).cpu().numpy(), attn.cpu().numpy()


def pick_threshold_roc(y_true, probs):
    """Highest-TPR operating point whose FPR is strictly < TARGET_FPR."""
    fpr, tpr, thr = roc_curve(y_true, probs)
    ok = np.where(fpr < TARGET_FPR)[0]
    idx = ok[-1]                                  # fpr is non-decreasing -> max tpr
    t = float(thr[idx])
    if not np.isfinite(t):                        # sklearn's sentinel (+inf)
        t = float(np.nextafter(probs.max(), 1.0))
    return t, float(tpr[idx]), float(fpr[idx]), float(roc_auc_score(y_true, probs))


def tier1_scores(X_val):
    import onnxruntime as ort
    sess = ort.InferenceSession(TIER1_ONNX_PATH, providers=["CPUExecutionProvider"])
    out = sess.run(None, {sess.get_inputs()[0].name: X_val.numpy().astype(np.int64)})
    return out[0].reshape(-1)


def evaluate(model, X_val, y_val):
    print("\n" + "=" * 65)
    print("  PHASE 4 -- EVALUATION")
    print("=" * 65)
    y = y_val.squeeze(1).numpy().astype(int)
    probs, attn = predict_all(model, X_val)

    # ── 4a. Data-driven threshold via ROC ───────────────────
    thr, tpr_s, fpr_s, auc = pick_threshold_roc(y, probs)
    print(f"\n  [4a] ROC-derived threshold (FPR strictly < {TARGET_FPR * 100:.0f}%)")
    print(f"       AUC = {auc:.4f}")
    print(f"       Selected threshold = {thr:.4f}  (TPR={tpr_s * 100:.2f}%, FPR={fpr_s * 100:.2f}%)")
    r = print_conf("ROC-selected (data-driven)", y, probs, thr)
    print_conf("Fixed reference (0.70)", y, probs, CLOUD_THRESHOLD_FIXED)
    print_conf("Default (0.50)", y, probs, 0.5)
    assert r[5] < TARGET_FPR, "selected threshold violates FPR target"
    print("       NOTE: threshold is selected AND reported on the same validation set")
    print("             (no separate test split, because the Tier-1 split is mandatory),")
    print("             so these numbers are slightly optimistic.")

    with open(OUTPUT_THRESHOLD, "w", encoding="utf-8") as f:
        json.dump({"threshold": thr, "target_fpr": TARGET_FPR,
                   "val_fpr": fpr_s, "val_tpr": tpr_s, "val_auc": auc}, f, indent=2)
    print(f"       Saved -> {OUTPUT_THRESHOLD}")

    # ── 4b. Tier-1 grey-zone isolation ──────────────────────
    print(f"\n  [4b] Tier-1 GREY ZONE evaluation "
          f"(samples tier1_edr.onnx scored in ({T1_SAFE}, {T1_THREAT}))")
    t1 = tier1_scores(X_val)
    t1_all = confusion(y, (t1 >= 0.5).astype(int))
    print(f"       Tier 1 overall val accuracy @0.50 : {t1_all[6] * 100:.2f}%")
    grey = (t1 > T1_SAFE) & (t1 < T1_THREAT)
    n_grey = int(grey.sum())
    print(f"       Grey-zone samples: {n_grey} / {len(y)} "
          f"({int(y[grey].sum())} malware, {n_grey - int(y[grey].sum())} benign)")
    if n_grey == 0:
        print("       (none -- Tier 1 was never uncertain on this validation set)")
    else:
        yg, pg = y[grey], probs[grey]
        t1g_acc = confusion(yg, (t1[grey] >= 0.5).astype(int))[6]
        print(f"       Tier 1 accuracy on grey zone      : {t1g_acc * 100:.2f}%")
        gr = print_conf("Tier 2 grey zone (ROC thr)", yg, pg, thr)
        print_conf("Tier 2 grey zone (0.70)", yg, pg, CLOUD_THRESHOLD_FIXED)
        print_conf("Tier 2 grey zone (0.50)", yg, pg, 0.5)
        print(f"       >>> TIER 2 GREY-ZONE ACCURACY: {gr[6] * 100:.2f}%  "
              f"(vs Tier 1: {t1g_acc * 100:.2f}%)")
        if len(np.unique(yg)) < 2:
            print("       (grey zone contains a single class -> FPR/TPR partly undefined)")

    # ── 4c. XAI sanity check ────────────────────────────────
    print("\n  [4c] XAI / ATTENTION sanity check")
    xv = X_val.numpy()
    pad = xv == 0
    pad_max = float(attn[pad].max()) if pad.any() else 0.0
    row_err = float(np.abs(attn.sum(axis=1) - 1.0).max())
    print(f"       Max attention weight on padding positions : {pad_max!r} "
          f"({int(pad.sum())} padded cells)")
    print(f"       Max |sum(weights) - 1| over all rows      : {row_err:.2e}")
    assert pad_max == 0.0, "padding mask FAILED: non-zero weight on padding"
    assert row_err < 1e-5, "attention rows do not sum to 1"
    print("       [OK] Padding gets exactly 0.0 weight; every row sums to 1.")

    cand = np.where((y == 1) & (probs >= thr))[0]
    if len(cand) == 0:
        cand = np.where(y == 1)[0]
    i = int(cand[np.argmax(probs[cand])])
    seq = xv[i]
    valid = int((seq != 0).sum())
    w = attn[i]
    per_id = {}
    for eid, wt in zip(seq[:valid], w[:valid]):
        per_id[int(eid)] = per_id.get(int(eid), 0.0) + float(wt)
    top3 = sorted(per_id.items(), key=lambda kv: kv[1], reverse=True)[:3]
    print(f"\n       Known malware sample (val idx {i}): "
          f"Tier-2 p={probs[i]:.4f}, Tier-1 p={t1[i]:.4f}, length={valid}")
    print(f"       Sequence: {seq[:valid].tolist()}")
    print("       Top-3 Event IDs by attention (weight summed per ID):")
    for rank, (eid, wt) in enumerate(top3, 1):
        print(f"         {rank}. EventID {eid:>2} ({SYSMON_EVENT_NAMES.get(eid, '?'):<20}) "
              f"weight={wt:.4f}")
    print(f"       Weight mass on real events: {w[:valid].sum():.6f} | "
          f"on padding: {w[valid:].sum():.1f}")

    with open(OUTPUT_XAI, "w", encoding="utf-8") as f:
        json.dump({
            "val_index": i, "label": int(y[i]),
            "tier2_probability": float(probs[i]), "tier1_probability": float(t1[i]),
            "sequence_length": valid, "sequence": seq.tolist(),
            "attention_weights": [float(a) for a in w],
            "top3_event_ids": [{"event_id": e, "name": SYSMON_EVENT_NAMES.get(e, "?"),
                                "weight": wt} for e, wt in top3],
            "padding_weight_max_over_val": pad_max,
            "row_sum_max_error_over_val": row_err,
        }, f, indent=2)
    print(f"       Saved -> {OUTPUT_XAI}")
    return probs


def verify_saved_model(X_val, probs):
    """Reload tier2_cloud_model.pt into a fresh model: outputs must match."""
    fresh = Tier2HybridCloudAnalyzer().to(DEVICE)
    fresh.load_state_dict(torch.load(OUTPUT_PT, map_location=DEVICE))
    p2, _ = predict_all(fresh, X_val)
    diff = float(np.abs(p2 - probs).max())
    print(f"\n  [verify] Reloaded {os.path.basename(OUTPUT_PT)}: max |delta p| = {diff:.2e}")
    assert diff < 1e-6, "saved model does not reproduce predictions"


def main():
    os.chdir(BASE_DIR)
    train_loader, val_loader, X_val, y_val = load_and_prepare_data()
    model = Tier2HybridCloudAnalyzer().to(DEVICE)
    model = train_model(model, train_loader, val_loader)
    probs = evaluate(model, X_val, y_val)
    verify_saved_model(X_val, probs)
    print("\n  DONE.")


if __name__ == "__main__":
    main()
