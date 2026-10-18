"""
build_holdout.py -- held-out split + evaluation models for the live test.

Every malicious process available on disk was used to train the production
models (LMD-2023 [1.75M] is a subset of [1.87M]), so live-testing the
production model on them would only measure memorisation. Instead:

  1. Split behavioral_dataset.npz 80/20. Processes with identical feature
     vectors are grouped, so an exact duplicate can't sit on both sides.
  2. Split the 80% again into train / calibration (also grouped).
  3. Train EVALUATION copies of Tier 1 (MLP) and Tier 2 (ResNet) on train only.
     Early stopping and the Tier-2 threshold use calibration only -- the held-out
     20% is never touched. Production models are not modified.
  4. Pull the held-out processes' raw Sysmon rows from the CSV so live_eval.py
     can replay them into the live sensor, and check they reproduce the stored
     feature vectors exactly.

Output: edr_sensor/live/holdout/
  tier1_holdout.onnx, tier2_holdout.pt, tier2_holdout_threshold.json,
  holdout_processes.json.gz, offline_metrics.json
"""
import os
import sys
import gzip
import json
import hashlib

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import edr_sensor                       # noqa: E402
import train_tier1_behavioral as t1     # noqa: E402
import train_tier2_behavioral as t2     # noqa: E402

OUT = os.path.join(HERE, "holdout")
NPZ = os.path.join(ROOT, "dataset", "behavioral_dataset.npz")
CSV = os.path.join(ROOT, "dataset", "LMD-2023 [1.87M Elements]", "LMD-2023 [1.87M Elements]Checked",
                   "Labelled LMD-2023", "LMD-2023 [1.87M Elements][Labelled]checked.csv")
FIELDS = ["Image", "ParentImage", "CommandLine", "IntegrityLevel", "DestinationIp", "DestinationPort",
          "ImageLoaded", "Signed", "SignatureStatus", "TargetFilename", "TargetObject", "QueryName",
          "GrantedAccess"]
SEED = 42
HOLDOUT_FRAC, CALIB_FRAC = 0.20, 0.15


def groups_for(feat):
    """Identical (rounded) feature vectors share a group."""
    return np.array([hashlib.sha1(np.round(r, 5).tobytes()).hexdigest() for r in feat])


def export_t1(model, path):
    exp = t1.ModelForExport(model.cpu()).eval()
    torch.onnx.export(
        exp, torch.zeros(1, t1.INPUT_DIM), path, export_params=True, opset_version=14,
        do_constant_folding=True, input_names=["features"], output_names=["probability"],
        dynamic_axes={"features": {0: "batch_size"}, "probability": {0: "batch_size"}},
    )


def metrics(y, p, thr):
    pred = (p >= thr).astype(int)
    return dict(auc=float(roc_auc_score(y, p)), acc=float((pred == y).mean()),
                tpr=float(pred[y == 1].mean()), fpr=float(pred[y == 0].mean()), threshold=float(thr))


def main():
    os.makedirs(OUT, exist_ok=True)
    d = np.load(NPZ, allow_pickle=True)
    feat, y, guids = d["feat"].astype(np.float32), d["y"].astype(np.int64), d["guid"]
    grp = groups_for(feat)
    print(f"samples={len(y)}  unique feature vectors={len(set(grp))}")

    gss = GroupShuffleSplit(n_splits=1, test_size=HOLDOUT_FRAC, random_state=SEED)
    rest, hold = next(gss.split(feat, y, grp))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=CALIB_FRAC, random_state=SEED + 1)
    tr_i, ca_i = next(gss2.split(feat[rest], y[rest], grp[rest]))
    tr, ca = rest[tr_i], rest[ca_i]
    assert not (set(grp[hold]) & set(grp[rest])), "duplicate vector leaked into hold-out"
    print(f"train={len(tr)}  calib={len(ca)}  holdout={len(hold)} "
          f"(malicious {int(y[hold].sum())} / benign {int((1 - y[hold]).sum())})")

    # ── Tier 1 ──
    m1 = t1.train_one_fold(feat[tr], y[tr], feat[ca], y[ca], seed=SEED)
    p1_hold = t1.get_probs(m1, feat[hold])
    export_t1(m1, os.path.join(OUT, "tier1_holdout.onnx"))

    # ── Tier 2 ──
    m2 = t2.train_one_fold(feat[tr], y[tr], feat[ca], y[ca], seed=SEED)
    thr2, _, _ = t2.pick_threshold(y[ca], t2.get_probs(m2, feat[ca]))
    p2_hold = t2.get_probs(m2, feat[hold])
    torch.save(m2.cpu().state_dict(), os.path.join(OUT, "tier2_holdout.pt"))
    json.dump({"threshold": thr2, "picked_on": "calibration split (never the hold-out)"},
              open(os.path.join(OUT, "tier2_holdout_threshold.json"), "w"), indent=2)

    # ── offline (vector-level) hold-out metrics, for comparison with the live run ──
    yh = y[hold]
    route = np.where(p1_hold >= 0.90, 1, np.where(p1_hold <= 0.10, 0, (p2_hold >= thr2).astype(int)))
    off = {
        "tier1_at_0.5": metrics(yh, p1_hold, 0.5),
        "tier2_at_calib_threshold": metrics(yh, p2_hold, thr2),
        "two_tier_pipeline": dict(acc=float((route == yh).mean()), tpr=float(route[yh == 1].mean()),
                                  fpr=float(route[yh == 0].mean()),
                                  grey_rate=float(((p1_hold > 0.10) & (p1_hold < 0.90)).mean())),
        "n_holdout": int(len(hold)),
    }
    json.dump(off, open(os.path.join(OUT, "offline_metrics.json"), "w"), indent=2)
    print(json.dumps(off, indent=2))

    # ── raw events of the held-out processes ──
    want = {g: i for i, g in zip(hold, guids[hold])}
    events = {g: [] for g in want}
    cols = ["ProcessGuid", "EventID", "SystemTime", "Label"] + FIELDS
    for c in pd.read_csv(CSV, usecols=cols, dtype=str, chunksize=250_000, low_memory=False):
        c = c[c.ProcessGuid.isin(want) & c.Label.notna()].fillna("")
        for rec in c.to_dict("records"):
            g = rec.pop("ProcessGuid")
            rec.pop("Label")
            events[g].append(rec)

    out, bad = [], 0
    for g, i in want.items():
        evs = events[g]
        got = np.asarray(edr_sensor.compute_features(evs), dtype=np.float32)
        bad += int(np.abs(got - feat[i]).max() > 1e-5)
        # keep the 50-event window + creation row only (what the sensor would keep)
        evs = sorted(evs, key=lambda e: (pd.to_datetime(e["SystemTime"], errors="coerce").value
                                         if e["SystemTime"] else np.iinfo(np.int64).max))
        first1 = next((e for e in evs if pd.to_numeric(e["EventID"], errors="coerce") == 1), None)
        keep = evs[:50] + ([first1] if first1 is not None and first1 not in evs[:50] else [])
        out.append({"guid": g, "label": int(y[i]), "events": keep})
    print(f"replay parity: {len(out) - bad}/{len(out)} held-out processes reproduce their training vector")
    assert bad == 0
    with gzip.open(os.path.join(OUT, "holdout_processes.json.gz"), "wt", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"saved -> {OUT}")


if __name__ == "__main__":
    main()
