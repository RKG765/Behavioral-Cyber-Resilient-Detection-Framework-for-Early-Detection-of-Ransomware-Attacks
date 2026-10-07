"""
train_tier1.py
==============
Tier 1 EDR -- 1D-CNN Malware Sequence Classifier
Training Pipeline -> PyTorch Model -> ONNX Production Export

Dataset : balanced_training_sequences.json (2,298 sequences, 50/50 split)
Input   : Padded Sysmon EventID sequences (length=50)
Output  : tier1_edr.onnx (probability 0.0-1.0), tier1_edr.pt (checkpoint)

Architecture:
  Embedding(24,16) -> Conv1d(16,32,k=3) -> ReLU -> AdaptiveMaxPool1d(1)
  -> Dropout(0.3) -> Linear(32,1) -> [Sigmoid baked into ONNX wrapper]

Corrections Applied:
  1. num_embeddings=24 (max EventID=23, index 0 reserved for padding)
  2. Dropout(0.3) to prevent overfitting on 2,298 samples
  3. Zero-padding for 1,739 variable-length sequences
  4. Stratified 80/20 split preserving label balance
  5. ModelForExport wrapper bakes Sigmoid into ONNX graph
  6. AdamW weight_decay=1e-2 for decoupled L2 regularization
  7. FPR validation at 0.90 threshold to prove thresholds are safe
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import random
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

# ──────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────
DATASET_PATH     = os.path.join("dataset", "balanced_training_sequences.json")
OUTPUT_ONNX      = "tier1_edr.onnx"
OUTPUT_PT        = "tier1_edr.pt"

SEED             = 42
SEQ_LENGTH       = 50          # fixed padded length
NUM_EMBEDDINGS   = 24          # max EventID (23) + 1  — index 0 = padding
EMBEDDING_DIM    = 16          # intentionally small for 16 unique IDs
CONV_CHANNELS    = 32          # output channels for Conv1d
KERNEL_SIZE      = 3           # trigram pattern detection
DROPOUT_RATE     = 0.3         # regularization for small dataset
BATCH_SIZE       = 32
EPOCHS           = 15
LEARNING_RATE    = 0.001
WEIGHT_DECAY     = 1e-2        # decoupled weight decay for AdamW
VAL_SPLIT        = 0.20        # 80/20 stratified split
THREAT_THRESHOLD = 0.90        # ≥0.90 → kill, used for FPR analysis
SAFE_THRESHOLD   = 0.10        # ≤0.10 → safe, used for FPR analysis

# Reproducibility
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ══════════════════════════════════════════════════════════════
# PHASE 2: DATA LOADING & TENSOR PREPARATION
# ══════════════════════════════════════════════════════════════

def load_and_prepare_data():
    """
    Load JSON dataset, pad sequences to fixed length, create tensors,
    and perform a stratified 80/20 train/val split.
    """
    print("=" * 65)
    print("  PHASE 2 — DATA LOADING & TENSOR PREPARATION")
    print("=" * 65)

    # ── Load raw JSON ──
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    print(f"  Loaded {len(raw_data):,} sequences from {DATASET_PATH}")

    # ── Pad sequences to fixed length 50 ──
    # Right-pad with 0 (padding_idx) for sequences shorter than SEQ_LENGTH
    sequences = []
    labels = []
    for record in raw_data:
        seq = record["event_sequence"][:SEQ_LENGTH]  # truncate if somehow > 50
        padded = seq + [0] * (SEQ_LENGTH - len(seq))  # right-pad with 0
        sequences.append(padded)
        labels.append(float(record["label"]))

    X_tensor = torch.tensor(sequences, dtype=torch.long)    # [2298, 50]
    y_tensor = torch.tensor(labels, dtype=torch.float32).unsqueeze(1)  # [2298, 1]

    print(f"  X_tensor shape: {X_tensor.shape}  dtype: {X_tensor.dtype}")
    print(f"  y_tensor shape: {y_tensor.shape}  dtype: {y_tensor.dtype}")

    # ── Stratified Split ──
    # Separate indices by class, then split each class 80/20
    mal_indices = [i for i in range(len(labels)) if labels[i] == 1.0]
    ben_indices = [i for i in range(len(labels)) if labels[i] == 0.0]

    random.shuffle(mal_indices)
    random.shuffle(ben_indices)

    mal_split = int(len(mal_indices) * (1 - VAL_SPLIT))
    ben_split = int(len(ben_indices) * (1 - VAL_SPLIT))

    train_indices = mal_indices[:mal_split] + ben_indices[:ben_split]
    val_indices   = mal_indices[mal_split:] + ben_indices[ben_split:]

    random.shuffle(train_indices)
    random.shuffle(val_indices)

    X_train, y_train = X_tensor[train_indices], y_tensor[train_indices]
    X_val,   y_val   = X_tensor[val_indices],   y_tensor[val_indices]

    # Verify balance
    train_mal = y_train.sum().item()
    train_ben = len(y_train) - train_mal
    val_mal   = y_val.sum().item()
    val_ben   = len(y_val) - val_mal

    print(f"\n  ┌─ Stratified Split (seed={SEED}) ─────────────────────┐")
    print(f"  │  Train: {len(y_train):,} samples  "
          f"({int(train_mal)} mal + {int(train_ben)} ben)     │")
    print(f"  │  Val  : {len(y_val):,} samples  "
          f"({int(val_mal)} mal + {int(val_ben)} ben)      │")
    print(f"  └─────────────────────────────────────────────────────┘")

    # ── DataLoaders ──
    train_dataset = TensorDataset(X_train, y_train)
    val_dataset   = TensorDataset(X_val, y_val)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader   = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

    return train_loader, val_loader, X_val, y_val


# ══════════════════════════════════════════════════════════════
# PHASE 3: MODEL ARCHITECTURE
# ══════════════════════════════════════════════════════════════

class Tier1EDR(nn.Module):
    """
    Lightweight 1D-CNN for Sysmon EventID sequence classification.

    Pipeline:
      Input [batch, 50] (LongTensor of padded Event IDs)
        → Embedding(24, 16, padding_idx=0)   → [batch, 50, 16]
        → Permute                             → [batch, 16, 50]
        → Conv1d(16, 32, kernel_size=3, pad=1)→ [batch, 32, 50]
        → ReLU
        → AdaptiveMaxPool1d(1)                → [batch, 32, 1]
        → Flatten                             → [batch, 32]
        → Dropout(0.3)
        → Linear(32, 1)                       → [batch, 1]  (raw logit)
    """

    def __init__(self):
        super().__init__()

        # Embedding: discrete Event IDs → dense vectors
        # padding_idx=0 ensures padding tokens produce zero vectors
        self.embedding = nn.Embedding(
            num_embeddings=NUM_EMBEDDINGS,
            embedding_dim=EMBEDDING_DIM,
            padding_idx=0,
        )

        # Conv1d: extract temporal trigram patterns
        # padding=1 preserves sequence length (50 → 50)
        self.conv1d = nn.Conv1d(
            in_channels=EMBEDDING_DIM,
            out_channels=CONV_CHANNELS,
            kernel_size=KERNEL_SIZE,
            padding=1,
        )

        self.relu = nn.ReLU()

        # Note: We use torch.max(dim=2) instead of AdaptiveMaxPool1d
        # because PyTorch 2.11's ONNX exporter cannot decompose
        # aten.adaptive_max_pool2d. torch.max is functionally identical
        # for output_size=1 and is fully ONNX-compatible.

        # Dropout: prevents overfitting on 2,298 samples
        self.dropout = nn.Dropout(p=DROPOUT_RATE)

        # Classification head: single logit for BCEWithLogitsLoss
        self.fc = nn.Linear(CONV_CHANNELS, 1)

    def forward(self, x):
        # x: [batch, 50] LongTensor
        x = self.embedding(x)          # → [batch, 50, 16]
        x = x.permute(0, 2, 1)         # → [batch, 16, 50]  (channels-first for Conv1d)
        x = self.conv1d(x)             # → [batch, 32, 50]
        x = self.relu(x)               # -> [batch, 32, 50]
        x, _ = torch.max(x, dim=2)     # -> [batch, 32]  (global max pool)
        x = self.dropout(x)            # → [batch, 32]
        x = self.fc(x)                 # → [batch, 1]   (raw logit)
        return x


class ModelForExport(nn.Module):
    """
    ONNX export wrapper that bakes Sigmoid into the computational graph.

    Why: BCEWithLogitsLoss applies sigmoid internally during training,
    so the base model outputs raw logits (e.g., -4.5 or 3.2).
    The Endpoint Agent expects probabilities (0.0 to 1.0) for
    threshold-based routing: <0.10 → Safe, >0.90 → Kill.

    Without this wrapper, the agent would receive meaningless logits
    and all threshold comparisons would break silently.
    """

    def __init__(self, trained_model):
        super().__init__()
        self.trained_model = trained_model

    def forward(self, x):
        logits = self.trained_model(x)
        return torch.sigmoid(logits)   # → probability [0.0, 1.0]


# ══════════════════════════════════════════════════════════════
# PHASE 4: TRAINING ENGINE
# ══════════════════════════════════════════════════════════════

def train_model(model, train_loader, val_loader):
    """
    Standard PyTorch training loop with:
      - BCEWithLogitsLoss (numerically stable)
      - AdamW with explicit weight_decay=1e-2
      - Per-epoch: train loss, val loss, val accuracy
      - Best model checkpoint based on lowest val loss
    """
    print("\n" + "=" * 65)
    print("  PHASE 4 — TRAINING ENGINE")
    print("=" * 65)

    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY,    # Decoupled L2 — critical for small datasets
    )

    best_val_loss = float("inf")
    best_state = None

    print(f"\n  Config: {EPOCHS} epochs | AdamW(lr={LEARNING_RATE}, wd={WEIGHT_DECAY})"
          f" | BCEWithLogitsLoss | Device: {DEVICE}")
    print(f"  {'─'*61}")
    print(f"  {'Epoch':>8s} │ {'Train Loss':>11s} │ {'Val Loss':>11s} │ {'Val Acc':>9s}")
    print(f"  {'─'*61}")

    for epoch in range(1, EPOCHS + 1):
        # ── Training ──
        model.train()
        train_loss_sum = 0.0
        train_batches = 0

        for X_batch, y_batch in train_loader:
            X_batch = X_batch.to(DEVICE)
            y_batch = y_batch.to(DEVICE)

            optimizer.zero_grad()
            logits = model(X_batch)
            loss = criterion(logits, y_batch)
            loss.backward()
            optimizer.step()

            train_loss_sum += loss.item()
            train_batches += 1

        avg_train_loss = train_loss_sum / train_batches

        # ── Validation ──
        model.eval()
        val_loss_sum = 0.0
        val_batches = 0
        correct = 0
        total = 0

        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch = X_batch.to(DEVICE)
                y_batch = y_batch.to(DEVICE)

                logits = model(X_batch)
                loss = criterion(logits, y_batch)
                val_loss_sum += loss.item()
                val_batches += 1

                # Accuracy: apply sigmoid to logits, threshold at 0.5
                probs = torch.sigmoid(logits)
                preds = (probs >= 0.5).float()
                correct += (preds == y_batch).sum().item()
                total += y_batch.size(0)

        avg_val_loss = val_loss_sum / val_batches
        val_accuracy = (correct / total) * 100.0

        # ── Checkpoint best model ──
        marker = ""
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_state = model.state_dict().copy()
            # Deep copy state dict
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            marker = " ← best"

        print(f"  {epoch:>5d}/{EPOCHS} │ {avg_train_loss:>11.4f} │ "
              f"{avg_val_loss:>11.4f} │ {val_accuracy:>8.2f}%{marker}")

    print(f"  {'─'*61}")
    print(f"  Best Val Loss: {best_val_loss:.4f}")

    # Restore best weights
    if best_state is not None:
        model.load_state_dict(best_state)
        print("  ✅ Restored best model weights")

    return model


# ══════════════════════════════════════════════════════════════
# PHASE 4.5: FPR VALIDATION AT THREAT THRESHOLD
# ══════════════════════════════════════════════════════════════

def fpr_validation(model, X_val, y_val):
    """
    Compute False Positive Rate (FPR) at the production threshold.

    In EDR context:
      - False Positive = benign process flagged as malware → user disruption
      - FPR = FP / (FP + TN) = how often we wrongly kill safe processes

    This mathematically proves whether the 0.90 threshold is safe for
    deployment. A high FPR means the agent will break legitimate workflows.
    """
    print("\n" + "=" * 65)
    print("  PHASE 4.5 — FALSE POSITIVE RATE (FPR) ANALYSIS")
    print("=" * 65)

    model.eval()
    with torch.no_grad():
        X_val_dev = X_val.to(DEVICE)
        logits = model(X_val_dev)
        probs = torch.sigmoid(logits).cpu().numpy().flatten()

    labels = y_val.numpy().flatten()

    # Isolate benign samples (label == 0)
    benign_mask = labels == 0.0
    benign_probs = probs[benign_mask]
    total_benign = benign_mask.sum()

    # Isolate malware samples (label == 1)
    malware_mask = labels == 1.0
    malware_probs = probs[malware_mask]
    total_malware = malware_mask.sum()

    # ── FPR at THREAT_THRESHOLD (0.90) ──
    # False Positives: benign samples scored ≥ 0.90 (would be killed)
    fp_at_threat = (benign_probs >= THREAT_THRESHOLD).sum()
    fpr_at_threat = fp_at_threat / total_benign if total_benign > 0 else 0.0

    # ── True Positive Rate (Recall) at THREAT_THRESHOLD ──
    tp_at_threat = (malware_probs >= THREAT_THRESHOLD).sum()
    tpr_at_threat = tp_at_threat / total_malware if total_malware > 0 else 0.0

    # ── Safe zone: benign samples scored ≤ 0.10 (correctly passed) ──
    safe_benign = (benign_probs <= SAFE_THRESHOLD).sum()
    safe_rate = safe_benign / total_benign if total_benign > 0 else 0.0

    # ── Grey zone: samples between 0.10 and 0.90 (need cloud/manual review) ──
    grey_all = ((probs > SAFE_THRESHOLD) & (probs < THREAT_THRESHOLD)).sum()

    print(f"\n  Threshold Configuration:")
    print(f"    Safe  (auto-pass) : prob ≤ {SAFE_THRESHOLD}")
    print(f"    Kill  (auto-block): prob ≥ {THREAT_THRESHOLD}")
    print(f"    Grey  (escalate)  : {SAFE_THRESHOLD} < prob < {THREAT_THRESHOLD}")

    print(f"\n  ┌─ Results on Validation Set ({len(labels)} samples) ─────────┐")
    print(f"  │                                                       │")
    print(f"  │  Benign samples total     : {total_benign:>6d}                │")
    print(f"  │  False Positives (≥{THREAT_THRESHOLD})    : {fp_at_threat:>6d}  "
          f"(FPR = {fpr_at_threat:.4f})  │")
    print(f"  │  Safely passed  (≤{SAFE_THRESHOLD})    : {safe_benign:>6d}  "
          f"({safe_rate:.2%})       │")
    print(f"  │                                                       │")
    print(f"  │  Malware samples total    : {total_malware:>6d}                │")
    print(f"  │  True Positives (≥{THREAT_THRESHOLD})    : {tp_at_threat:>6d}  "
          f"(TPR = {tpr_at_threat:.4f})  │")
    print(f"  │                                                       │")
    print(f"  │  Grey zone (needs review) : {grey_all:>6d}                │")
    print(f"  └───────────────────────────────────────────────────────┘")

    if fpr_at_threat == 0.0:
        print("\n  ✅ VERDICT: Zero false positives at 0.90 threshold — safe for deployment")
    elif fpr_at_threat <= 0.01:
        print(f"\n  ✅ VERDICT: FPR = {fpr_at_threat:.4f} (≤1%) — acceptable for deployment")
    elif fpr_at_threat <= 0.05:
        print(f"\n  ⚠️  VERDICT: FPR = {fpr_at_threat:.4f} (1-5%) — review before deployment")
    else:
        print(f"\n  ❌ VERDICT: FPR = {fpr_at_threat:.4f} (>5%) — threshold needs adjustment!")

    return fpr_at_threat


# ══════════════════════════════════════════════════════════════
# PHASE 5: ONNX PRODUCTION EXPORT
# ══════════════════════════════════════════════════════════════

def export_onnx(model):
    """
    Export trained model to ONNX format with:
      - Sigmoid baked into the graph (ModelForExport wrapper)
      - Dynamic batch axis for variable-size inference
      - Validation via onnx.checker and onnxruntime sanity check
    """
    print("\n" + "=" * 65)
    print("  PHASE 5 — ONNX PRODUCTION EXPORT")
    print("=" * 65)

    import onnx
    import onnxruntime as ort

    # ── Wrap model with Sigmoid for ONNX ──
    model.eval()
    model.cpu()  # ONNX export on CPU
    export_model = ModelForExport(model)
    export_model.eval()

    # ── Dummy input ──
    dummy_input = torch.zeros(1, SEQ_LENGTH, dtype=torch.long)

    # ── Export ──
    print(f"  Exporting to {OUTPUT_ONNX} ...")
    torch.onnx.export(
        export_model,
        dummy_input,
        OUTPUT_ONNX,
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input":  {0: "batch_size"},
            "output": {0: "batch_size"},
        },
    )
    onnx_size = os.path.getsize(OUTPUT_ONNX) / 1024
    print(f"  ✅ ONNX exported: {OUTPUT_ONNX} ({onnx_size:.1f} KB)")

    # ── Validate ONNX graph ──
    print("  Validating ONNX graph ...")
    onnx_model = onnx.load(OUTPUT_ONNX)
    onnx.checker.check_model(onnx_model)
    print("  ✅ ONNX graph is valid")

    # ── Sanity inference with onnxruntime ──
    print("  Running sanity inference with onnxruntime ...")
    session = ort.InferenceSession(OUTPUT_ONNX)
    test_input = np.zeros((1, SEQ_LENGTH), dtype=np.int64)
    result = session.run(None, {"input": test_input})
    output_val = result[0][0][0]
    print(f"  Sanity check — zeros input → probability: {output_val:.6f}")

    # Verify output is in [0, 1] range (sigmoid was baked in)
    assert 0.0 <= output_val <= 1.0, (
        f"ONNX output {output_val} is outside [0,1] — Sigmoid wrapper failed!"
    )
    print("  ✅ Output is in [0.0, 1.0] range — Sigmoid correctly baked into ONNX")

    # ── Save PyTorch checkpoint ──
    torch.save(model.state_dict(), OUTPUT_PT)
    pt_size = os.path.getsize(OUTPUT_PT) / 1024
    print(f"  ✅ PyTorch checkpoint: {OUTPUT_PT} ({pt_size:.1f} KB)")

    return OUTPUT_ONNX, OUTPUT_PT


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print("\n" + "█" * 65)
    print("  TIER 1 EDR — 1D-CNN MALWARE CLASSIFIER")
    print("  Training Pipeline → ONNX Production Export")
    print("█" * 65)
    print(f"  Device: {DEVICE}")

    # Phase 2: Data
    train_loader, val_loader, X_val, y_val = load_and_prepare_data()

    # Phase 3: Model
    print("\n" + "=" * 65)
    print("  PHASE 3 — MODEL ARCHITECTURE")
    print("=" * 65)
    model = Tier1EDR().to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Model: Tier1EDR")
    print(f"  Total parameters    : {total_params:,}")
    print(f"  Trainable parameters: {trainable_params:,}")
    print(f"\n{model}")

    # Phase 4: Train
    model = train_model(model, train_loader, val_loader)

    # Phase 4.5: FPR Validation
    fpr = fpr_validation(model, X_val, y_val)

    # Phase 5: ONNX Export
    onnx_path, pt_path = export_onnx(model)

    # ── Final Summary ──
    print("\n" + "█" * 65)
    print("  PIPELINE COMPLETE — OUTPUT FILES")
    print("█" * 65)
    print(f"  ONNX Model  : {onnx_path}")
    print(f"  PT Checkpoint: {pt_path}")
    print(f"  FPR @ {THREAT_THRESHOLD}   : {fpr:.4f}")
    print("█" * 65)


if __name__ == "__main__":
    main()
