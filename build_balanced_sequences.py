"""
build_balanced_sequences.py
===========================
The 50/50 Sequence Rule — Data Preparation Pipeline

Reads the labelled LMD-2023 CSV, groups raw Sysmon rows by ProcessGuid
into chronological event sequences, then builds a perfectly balanced
(50% malware / 50% benign) training dataset at the SEQUENCE level.

Outputs:
  - dataset/balanced_training_sequences.json
  - dataset/balanced_training_sequences.xlsx
  - dataset/sequence_stats.json  (metadata / audit report)
"""

import os
import json
import time
import random
import warnings
import pandas as pd
import numpy as np

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────
INPUT_CSV = os.path.join(
    "dataset",
    "LMD-2023 [1.87M Elements]",
    "LMD-2023 [1.87M Elements]Checked",
    "Labelled LMD-2023",
    "LMD-2023 [1.87M Elements][Labelled]checked.csv",
)

OUTPUT_DIR    = "dataset"
OUTPUT_JSON   = os.path.join(OUTPUT_DIR, "balanced_training_sequences.json")
OUTPUT_EXCEL  = os.path.join(OUTPUT_DIR, "balanced_training_sequences.xlsx")
OUTPUT_STATS  = os.path.join(OUTPUT_DIR, "sequence_stats.json")

# Columns we need from the giant CSV
COLS_NEEDED   = ["ProcessGuid", "EventID", "UtcTime", "Label"]
CHUNK_SIZE    = 250_000          # rows per chunk while reading
RANDOM_SEED   = 42

# Sequence length constraints
MIN_SEQ_LENGTH = 3               # drop sequences shorter than this (no behavioral context)
MAX_SEQ_LENGTH = 50              # truncate to first N events (initial execution window)

# ──────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────

def ts():
    """Compact timestamp for progress logs."""
    return time.strftime("%H:%M:%S")


def classify_label(lbl):
    """Binary classification: 0 → benign, anything else → malware (1)."""
    try:
        return 0 if int(float(lbl)) == 0 else 1
    except (ValueError, TypeError):
        return -1  # will be dropped


# ──────────────────────────────────────────────────────────────
# STEP 1 — LOAD & EXTRACT KEY COLUMNS (chunk-wise)
# ──────────────────────────────────────────────────────────────

def load_data():
    """
    Read the CSV in chunks, keeping only the 4 columns we care about.
    Returns a single DataFrame with [ProcessGuid, EventID, UtcTime, Label].
    """
    print(f"[{ts()}] ⏳ Loading data from:\n       {INPUT_CSV}")
    frames = []
    rows_read = 0

    for chunk in pd.read_csv(
        INPUT_CSV,
        usecols=COLS_NEEDED,
        chunksize=CHUNK_SIZE,
        low_memory=False,
        dtype={"ProcessGuid": str, "EventID": str, "Label": str},
    ):
        frames.append(chunk)
        rows_read += len(chunk)
        print(f"       ... {rows_read:>10,} rows loaded", end="\r")

    df = pd.concat(frames, ignore_index=True)
    print(f"\n[{ts()}] ✅ Loaded {len(df):,} rows  |  Memory ≈ {df.memory_usage(deep=True).sum()/1e6:.1f} MB")
    return df


# ──────────────────────────────────────────────────────────────
# STEP 2 — CLEAN & PREPARE
# ──────────────────────────────────────────────────────────────

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    - Drop rows with missing ProcessGuid (can't form a sequence without it)
    - Convert Label to binary (0/1)
    - Coerce EventID to int
    - Drop garbage rows
    """
    print(f"[{ts()}] 🧹 Cleaning data ...")
    before = len(df)

    # Drop rows where ProcessGuid is NaN or '0' or empty
    df = df[df["ProcessGuid"].notna()]
    df = df[df["ProcessGuid"].astype(str).str.strip() != ""]
    df = df[df["ProcessGuid"].astype(str).str.strip() != "0"]

    # Binary label
    df["BinaryLabel"] = df["Label"].apply(classify_label)
    df = df[df["BinaryLabel"] != -1]

    # Coerce EventID to numeric (some rows may have NaN)
    df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce")
    df = df[df["EventID"].notna()]
    df["EventID"] = df["EventID"].astype(int)

    after = len(df)
    print(f"[{ts()}] ✅ Cleaned: {before:,} → {after:,} rows  (dropped {before - after:,})")
    return df


# ──────────────────────────────────────────────────────────────
# STEP 3 — GROUP BY ProcessGuid → SEQUENCES
# ──────────────────────────────────────────────────────────────

def build_sequences(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group rows by ProcessGuid.  For each group:
      - Sort by UtcTime
      - Collect the list of EventIDs as the 'sequence'
      - Take the majority label of the group as the sequence label
      - Record sequence length
    
    Returns a DataFrame with columns:
      [ProcessGuid, event_sequence, seq_length, label]
    """
    print(f"[{ts()}] 🔗 Grouping {len(df):,} rows by ProcessGuid ...")

    # Sort globally first — faster than sorting inside each group
    df = df.sort_values(["ProcessGuid", "UtcTime"], na_position="last")

    grouped = df.groupby("ProcessGuid", sort=False)

    records = []
    for i, (pguid, grp) in enumerate(grouped):
        event_ids = grp["EventID"].tolist()
        # Majority-vote label for the sequence
        label = int(grp["BinaryLabel"].mode().iloc[0])
        records.append(
            {
                "ProcessGuid": pguid,
                "event_sequence": event_ids,
                "seq_length": len(event_ids),
                "label": label,
            }
        )
        if (i + 1) % 25_000 == 0:
            print(f"       ... {i + 1:>8,} sequences built", end="\r")

    seq_df = pd.DataFrame(records)
    print(f"\n[{ts()}] ✅ Built {len(seq_df):,} unique sequences from {len(df):,} rows")
    return seq_df


# ──────────────────────────────────────────────────────────────
# STEP 4 — FILTER SHORT SEQUENCES + TRUNCATE LONG ONES
# ──────────────────────────────────────────────────────────────

def filter_and_truncate(seq_df: pd.DataFrame) -> pd.DataFrame:
    """
    1) Drop ultra-short sequences (< MIN_SEQ_LENGTH events).
       Single-event processes don't provide enough behavioral signal.
    2) Truncate all sequences to MAX_SEQ_LENGTH events.
       The initial execution / initialization phase is where malware
       typically reveals itself (code injection, persistence, C2 callbacks).
    3) Recalculate seq_length after truncation.
    """
    print(f"[{ts()}] 🔍 Filtering & truncating sequences ...")
    before = len(seq_df)

    # --- Drop ultra-short ---
    seq_df = seq_df[seq_df["seq_length"] >= MIN_SEQ_LENGTH].copy()
    after_drop = len(seq_df)
    dropped = before - after_drop
    print(f"       Dropped {dropped:,} sequences with < {MIN_SEQ_LENGTH} events  "
          f"({before:,} → {after_drop:,})")

    # --- Truncate to fixed window ---
    truncated_count = (seq_df["seq_length"] > MAX_SEQ_LENGTH).sum()
    seq_df["event_sequence"] = seq_df["event_sequence"].apply(
        lambda seq: seq[:MAX_SEQ_LENGTH]
    )
    seq_df["seq_length"] = seq_df["event_sequence"].apply(len)
    print(f"       Truncated {truncated_count:,} sequences to max {MAX_SEQ_LENGTH} events")

    print(f"[{ts()}] ✅ After filter+truncate: {len(seq_df):,} sequences  "
          f"(length range: {seq_df['seq_length'].min()}–{seq_df['seq_length'].max()})")
    return seq_df


# ──────────────────────────────────────────────────────────────
# STEP 5 — 50/50 BALANCE
# ──────────────────────────────────────────────────────────────

def balance_sequences(seq_df: pd.DataFrame) -> pd.DataFrame:
    """
    Step A: Take ALL malware sequences (label == 1).
    Step B: Randomly sample EXACTLY the same count of benign sequences (label == 0).
    Result: 50% malware, 50% benign at the sequence level.
    """
    print(f"[{ts()}] ⚖️  Balancing sequences (50/50 rule) ...")

    malware_seqs = seq_df[seq_df["label"] == 1].copy()
    benign_seqs  = seq_df[seq_df["label"] == 0].copy()

    n_malware = len(malware_seqs)
    n_benign  = len(benign_seqs)

    print(f"       Total malware sequences : {n_malware:,}")
    print(f"       Total benign sequences  : {n_benign:,}")

    if n_benign < n_malware:
        print(f"       ⚠️  Benign count ({n_benign:,}) < malware count ({n_malware:,}).")
        print(f"       → Taking ALL benign and down-sampling malware to match.")
        malware_seqs = malware_seqs.sample(n=n_benign, random_state=RANDOM_SEED)
        sample_count = n_benign
    else:
        benign_seqs = benign_seqs.sample(n=n_malware, random_state=RANDOM_SEED)
        sample_count = n_malware

    balanced = pd.concat([malware_seqs, benign_seqs], ignore_index=True)
    # Shuffle the final dataset
    balanced = balanced.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    print(f"[{ts()}] ✅ Balanced dataset: {len(balanced):,} sequences  "
          f"({sample_count:,} malware + {sample_count:,} benign)")
    return balanced


# ──────────────────────────────────────────────────────────────
# STEP 6 — EXPORT (JSON + Excel)
# ──────────────────────────────────────────────────────────────

def export_json(balanced: pd.DataFrame):
    """
    Save as JSON — ideal for PyTorch DataLoader / model training.
    Structure: list of dicts, each with ProcessGuid, event_sequence, seq_length, label.
    """
    print(f"[{ts()}] 💾 Writing JSON → {OUTPUT_JSON}")
    data = balanced.to_dict(orient="records")
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    size_mb = os.path.getsize(OUTPUT_JSON) / 1e6
    print(f"[{ts()}] ✅ JSON saved ({size_mb:.1f} MB)")


def export_excel(balanced: pd.DataFrame):
    """
    Save as Excel — for manual inspection / sharing.
    The event_sequence list is stored as a comma-separated string for readability.
    """
    print(f"[{ts()}] 💾 Writing Excel → {OUTPUT_EXCEL}")
    excel_df = balanced.copy()
    # Convert list → string for Excel compatibility
    excel_df["event_sequence"] = excel_df["event_sequence"].apply(
        lambda seq: ", ".join(str(e) for e in seq)
    )
    excel_df.to_excel(OUTPUT_EXCEL, index=False, engine="openpyxl")
    size_mb = os.path.getsize(OUTPUT_EXCEL) / 1e6
    print(f"[{ts()}] ✅ Excel saved ({size_mb:.1f} MB)")


def export_stats(seq_df_raw: pd.DataFrame, seq_df_filtered: pd.DataFrame, balanced: pd.DataFrame):
    """
    Save a small metadata JSON for auditing.
    Includes raw → filtered → balanced counts at each stage.
    """
    stats = {
        "pipeline": "50/50 Sequence Rule (with filter+truncate)",
        "source_file": INPUT_CSV,
        "random_seed": RANDOM_SEED,
        "min_sequence_length_filter": MIN_SEQ_LENGTH,
        "max_sequence_length_window": MAX_SEQ_LENGTH,
        "stage_1_raw_sequences": {
            "total": int(len(seq_df_raw)),
            "malware": int((seq_df_raw["label"] == 1).sum()),
            "benign": int((seq_df_raw["label"] == 0).sum()),
        },
        "stage_2_after_filter_truncate": {
            "total": int(len(seq_df_filtered)),
            "malware": int((seq_df_filtered["label"] == 1).sum()),
            "benign": int((seq_df_filtered["label"] == 0).sum()),
            "dropped": int(len(seq_df_raw) - len(seq_df_filtered)),
        },
        "stage_3_balanced_50_50": {
            "total": int(len(balanced)),
            "malware": int((balanced["label"] == 1).sum()),
            "benign": int((balanced["label"] == 0).sum()),
        },
        "final_sequence_stats": {
            "avg_length_malware": round(float(
                balanced[balanced["label"] == 1]["seq_length"].mean()
            ), 2),
            "avg_length_benign": round(float(
                balanced[balanced["label"] == 0]["seq_length"].mean()
            ), 2),
            "median_length_malware": float(
                balanced[balanced["label"] == 1]["seq_length"].median()
            ),
            "median_length_benign": float(
                balanced[balanced["label"] == 0]["seq_length"].median()
            ),
            "max_length": int(balanced["seq_length"].max()),
            "min_length": int(balanced["seq_length"].min()),
        },
    }
    with open(OUTPUT_STATS, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"[{ts()}] ✅ Stats saved → {OUTPUT_STATS}")


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  50/50 SEQUENCE RULE — Balanced Training Dataset Builder")
    print("=" * 65)

    # 1) Load
    df = load_data()

    # 2) Clean
    df = clean_data(df)

    # 3) Build sequences
    seq_df_raw = build_sequences(df)

    # Free memory — raw df no longer needed
    del df

    # Print RAW sequence-level stats
    print(f"\n{'─'*65}")
    print(f"  STAGE 1 — RAW SEQUENCES (before filtering)")
    print(f"{'─'*65}")
    for lbl, name in [(0, "Benign"), (1, "Malware")]:
        subset = seq_df_raw[seq_df_raw["label"] == lbl]
        print(f"  {name:8s}: {len(subset):>8,} sequences  |  "
              f"avg len {subset['seq_length'].mean():>7.1f}  |  "
              f"median {subset['seq_length'].median():>5.0f}  |  "
              f"max {subset['seq_length'].max():>6,}")
    print(f"{'─'*65}\n")

    # 4) Filter short sequences + truncate long ones
    seq_df_filtered = filter_and_truncate(seq_df_raw)

    # Print FILTERED sequence-level stats
    print(f"\n{'─'*65}")
    print(f"  STAGE 2 — AFTER FILTER (>= {MIN_SEQ_LENGTH} events) + TRUNCATE (max {MAX_SEQ_LENGTH})")
    print(f"{'─'*65}")
    for lbl, name in [(0, "Benign"), (1, "Malware")]:
        subset = seq_df_filtered[seq_df_filtered["label"] == lbl]
        print(f"  {name:8s}: {len(subset):>8,} sequences  |  "
              f"avg len {subset['seq_length'].mean():>7.1f}  |  "
              f"median {subset['seq_length'].median():>5.0f}  |  "
              f"max {subset['seq_length'].max():>6,}")
    print(f"{'─'*65}\n")

    # 5) Balance 50/50
    balanced = balance_sequences(seq_df_filtered)

    # 6) Export
    export_json(balanced)
    export_excel(balanced)
    export_stats(seq_df_raw, seq_df_filtered, balanced)

    # Final summary
    print(f"\n{'='*65}")
    print(f"  DONE — Training dataset ready!")
    print(f"{'='*65}")
    print(f"  JSON  : {OUTPUT_JSON}")
    print(f"  Excel : {OUTPUT_EXCEL}")
    print(f"  Stats : {OUTPUT_STATS}")
    print(f"  Total : {len(balanced):,} sequences (50/50 split)")
    print(f"  Seq length range: {MIN_SEQ_LENGTH}–{MAX_SEQ_LENGTH}")
    print(f"{'='*65}")


if __name__ == "__main__":
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)
    main()
