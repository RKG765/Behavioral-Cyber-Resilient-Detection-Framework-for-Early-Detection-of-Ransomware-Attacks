"""
parity_check.py
===============
Proves the Rust extractor computes the SAME 99 features the models were
trained on. For every process in dataset/behavioral_dataset.npz it re-reads
that process's raw Sysmon rows from the LMD-2023 CSV, runs them through
edr_sensor.compute_features(), and compares against the stored training row.

Run:  python edr_sensor/parity_check.py [--limit N]
Exit code 0 = every process matches within 1e-5.
"""
import os
import sys
import json
import argparse
from collections import defaultdict

import numpy as np
import pandas as pd

import edr_sensor

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(BASE, "dataset", "LMD-2023 [1.87M Elements]", "LMD-2023 [1.87M Elements]Checked",
                   "Labelled LMD-2023", "LMD-2023 [1.87M Elements][Labelled]checked.csv")
NPZ = os.path.join(BASE, "dataset", "behavioral_dataset.npz")
META = os.path.join(BASE, "dataset", "behavioral_dataset_meta.json")
FIELDS = ["Image", "ParentImage", "CommandLine", "IntegrityLevel", "DestinationIp", "DestinationPort",
          "ImageLoaded", "Signed", "SignatureStatus", "TargetFilename", "TargetObject", "QueryName",
          "GrantedAccess"]
ATOL = 1e-5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="check only the first N processes")
    args = ap.parse_args()

    names = json.load(open(META, encoding="utf-8"))["features"]
    assert edr_sensor.feature_names() == names, "feature order differs from training meta"

    d = np.load(NPZ, allow_pickle=True)
    guids, feat = d["guid"], d["feat"]
    if args.limit:
        guids, feat = guids[:args.limit], feat[:args.limit]
    want = set(guids.tolist())
    print(f"checking {len(want)} processes against {os.path.basename(NPZ)}")

    events = defaultdict(list)
    cols = ["ProcessGuid", "EventID", "SystemTime", "Label"] + FIELDS
    for chunk in pd.read_csv(CSV, usecols=cols, dtype=str, chunksize=250_000, low_memory=False):
        c = chunk[chunk.ProcessGuid.isin(want) & chunk.Label.notna()]
        if not len(c):
            continue
        c = c.fillna("")
        for rec in c.to_dict("records"):          # file order == builder's row tie-break
            events[rec.pop("ProcessGuid")].append(rec)

    bad = defaultdict(int)
    worst = 0.0
    n_bad = 0
    for g, ref in zip(guids, feat):
        got = np.asarray(edr_sensor.compute_features(events[g]), dtype=np.float32)
        diff = np.abs(got - ref)
        worst = max(worst, float(diff.max()))
        if (diff > ATOL).any():
            n_bad += 1
            for i in np.where(diff > ATOL)[0]:
                bad[names[i]] += 1

    print(f"processes matching: {len(guids) - n_bad}/{len(guids)}   max |diff| = {worst:.2e}")
    for k, v in sorted(bad.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<28} mismatched in {v} processes")
    sys.exit(1 if n_bad else 0)


if __name__ == "__main__":
    main()
